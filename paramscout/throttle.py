"""Rate limiting, concurrency limits and request budgets.

Everything in this module is deliberately simple and *fail closed*: when a
budget is exhausted, the caller is told "no" rather than silently allowed.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import UTC

from paramscout.models import ThrottleEvent


class IntervalLimiter:
    """A minimum-interval limiter with adjustable speed.

    This is a smoother and more predictable shape of traffic than a token
    bucket for a politeness-oriented tool: requests are spaced at least
    ``1 / rate`` seconds apart, and :meth:`slow_down` widens the gap when the
    target starts answering 429/503.
    """

    def __init__(self, rate_per_second: float, *, name: str = "global") -> None:
        self.name = name
        self.base_rate = max(0.0, float(rate_per_second))
        self.rate = self.base_rate
        self._min_interval = self._interval_for(self.rate)
        self._next_allowed = 0.0
        self._lock = asyncio.Lock()
        self.total_wait = 0.0
        self.slowdowns = 0

    @staticmethod
    def _interval_for(rate: float) -> float:
        return 0.0 if rate <= 0 else 1.0 / rate

    async def acquire(self) -> float:
        """Wait until a slot is available; returns the seconds waited."""

        if self._min_interval <= 0:
            return 0.0
        loop = asyncio.get_running_loop()
        async with self._lock:
            now = loop.time()
            wait = max(0.0, self._next_allowed - now)
            self._next_allowed = max(now, self._next_allowed) + self._min_interval
        if wait > 0:
            self.total_wait += wait
            await asyncio.sleep(wait)
        return wait

    def slow_down(self, factor: float, *, cap: float = 300.0) -> float:
        """Widen the interval; returns the new interval in seconds."""

        self.rate = max(0.02, self.rate / max(1.0, factor))
        self._min_interval = min(cap, self._interval_for(self.rate))
        self.slowdowns += 1
        return self._min_interval

    def reset_rate(self) -> None:
        self.rate = self.base_rate
        self._min_interval = self._interval_for(self.rate)


class SemaphoreBank:
    """Per-key semaphore bank plus an optional global cap."""

    def __init__(self, per_key: int, *, global_limit: int | None = None) -> None:
        self.per_key = max(1, per_key)
        self._semaphores: dict[str, asyncio.Semaphore] = {}
        self._global = asyncio.Semaphore(max(1, global_limit)) if global_limit else None

    def _semaphore_for(self, key: str) -> asyncio.Semaphore:
        semaphore = self._semaphores.get(key)
        if semaphore is None:
            semaphore = asyncio.Semaphore(self.per_key)
            self._semaphores[key] = semaphore
        return semaphore

    async def acquire(self, key: str) -> list[asyncio.Semaphore]:
        acquired: list[asyncio.Semaphore] = []
        if self._global is not None:
            await self._global.acquire()
            acquired.append(self._global)
        await self._semaphore_for(key).acquire()
        acquired.append(self._semaphores[key])
        return acquired

    @staticmethod
    def release(acquired: list[asyncio.Semaphore]) -> None:
        for semaphore in acquired:
            semaphore.release()


class BudgetExhausted(RuntimeError):
    """Raised internally when a request budget is spent."""


@dataclass
class RequestBudget:
    """Global and per-endpoint request accounting."""

    total: int
    per_endpoint: int = 0
    used: int = 0
    per_endpoint_used: dict[str, int] = field(default_factory=dict)
    denied_global: int = 0
    denied_endpoint: int = 0

    def remaining(self) -> int:
        if self.total <= 0:
            return 10**9
        return max(0, self.total - self.used)

    def remaining_for(self, endpoint: str) -> int:
        if self.per_endpoint <= 0:
            return self.remaining()
        return max(0, min(self.remaining(), self.per_endpoint - self.per_endpoint_used.get(endpoint, 0)))

    def can_request(self, endpoint: str) -> bool:
        return self.remaining_for(endpoint) > 0

    def consume(self, endpoint: str) -> bool:
        """Reserve one request.  Returns False when the budget is spent."""

        if not self.can_request(endpoint):
            if self.remaining() <= 0:
                self.denied_global += 1
            else:
                self.denied_endpoint += 1
            return False
        self.used += 1
        self.per_endpoint_used[endpoint] = self.per_endpoint_used.get(endpoint, 0) + 1
        return True

    def to_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "per_endpoint": self.per_endpoint,
            "used": self.used,
            "remaining": self.remaining(),
            "denied_global": self.denied_global,
            "denied_endpoint": self.denied_endpoint,
            "per_endpoint_used": dict(self.per_endpoint_used),
        }


@dataclass
class ThrottleState:
    """Tracks 429/503 pressure per host and decides when to back off or stop."""

    slowdown_after: int = 2
    stop_after: int = 6
    factor: float = 2.0
    consecutive: dict[str, int] = field(default_factory=dict)
    halted: set[str] = field(default_factory=set)
    events: list[ThrottleEvent] = field(default_factory=list)

    def record_success(self, host: str) -> None:
        self.consecutive[host] = 0

    def record_throttle(
        self, host: str, status: int, url: str, *, retry_after: float | None
    ) -> str:
        """Return the action taken: ``"continue"``, ``"slow_down"`` or ``"stop"``."""

        count = self.consecutive.get(host, 0) + 1
        self.consecutive[host] = count
        if count >= self.stop_after:
            action = "stop"
            self.halted.add(host)
        elif count >= self.slowdown_after:
            action = "slow_down"
        else:
            action = "continue"
        self.events.append(
            ThrottleEvent(
                host=host,
                status=status,
                url=url,
                action=action,
                retry_after=retry_after,
            )
        )
        return action

    def is_halted(self, host: str) -> bool:
        return host in self.halted

    def to_dict(self) -> dict[str, object]:
        return {
            "consecutive": dict(self.consecutive),
            "halted": sorted(self.halted),
            "events": [event.to_dict() for event in self.events],
        }


def parse_retry_after(value: str | None, *, cap: float = 60.0) -> float | None:
    """Parse a ``Retry-After`` header (seconds or HTTP-date) into seconds."""

    if not value:
        return None
    value = value.strip()
    try:
        return min(cap, max(0.0, float(value)))
    except ValueError:
        pass
    from email.utils import parsedate_to_datetime

    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    from datetime import datetime

    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    delta = (when - datetime.now(UTC)).total_seconds()
    return min(cap, max(0.0, delta))


def backoff_delay(attempt: int, *, base: float = 0.8, cap: float = 20.0) -> float:
    """Exponential backoff with jitter (deterministic-friendly, capped)."""

    import random

    raw = min(cap, base * (2 ** max(0, attempt - 1)))
    return round(raw * (0.5 + random.random() * 0.5), 3)


class Clock:
    """Monotonic clock wrapper so tests can measure elapsed time consistently."""

    def __init__(self) -> None:
        self._start = time.monotonic()

    def elapsed(self) -> float:
        return round(time.monotonic() - self._start, 3)
