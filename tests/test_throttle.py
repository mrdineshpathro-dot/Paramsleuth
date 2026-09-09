"""Rate limiting, retries, Retry-After handling and request budgets."""

from __future__ import annotations

import asyncio
import time

from conftest import fast_config
from mockapp import MockApp

from paramscout.http_client import FetchOptions, ParamScoutClient
from paramscout.models import ScanStats
from paramscout.throttle import (
    IntervalLimiter,
    RequestBudget,
    ThrottleState,
    backoff_delay,
    parse_retry_after,
)


def test_interval_limiter_spaces_requests() -> None:
    async def scenario() -> float:
        limiter = IntervalLimiter(20.0)  # 50ms apart
        started = time.monotonic()
        for _ in range(5):
            await limiter.acquire()
        return time.monotonic() - started

    elapsed = asyncio.run(scenario())
    assert elapsed >= 0.19, elapsed  # four gaps of 50ms
    assert elapsed < 1.5


def test_zero_rate_does_not_block() -> None:
    async def scenario() -> float:
        limiter = IntervalLimiter(0.0)
        started = time.monotonic()
        for _ in range(50):
            await limiter.acquire()
        return time.monotonic() - started

    assert asyncio.run(scenario()) < 0.5


def test_slow_down_widens_the_interval() -> None:
    limiter = IntervalLimiter(10.0)
    assert limiter._min_interval == 0.1
    limiter.slow_down(2.0)
    assert limiter._min_interval > 0.1
    assert limiter.slowdowns == 1


def test_request_budget_is_enforced() -> None:
    budget = RequestBudget(total=3, per_endpoint=2)
    assert budget.consume("/a")
    assert budget.consume("/a")
    assert not budget.consume("/a")  # per-endpoint cap reached
    assert budget.denied_endpoint == 1
    assert budget.consume("/b")
    assert not budget.consume("/b")  # global budget spent
    assert budget.denied_global == 1
    assert budget.remaining() == 0


def test_retry_after_parsing() -> None:
    assert parse_retry_after("3") == 3.0
    assert parse_retry_after("0") == 0.0
    assert parse_retry_after("999") == 60.0  # capped
    assert parse_retry_after(None) is None
    assert parse_retry_after("nonsense") is None
    http_date = "Wed, 21 Oct 2015 07:28:00 GMT"
    assert parse_retry_after(http_date) == 0.0  # in the past -> no wait


def test_backoff_grows_and_is_capped() -> None:
    first = backoff_delay(1, base=1.0, cap=20.0)
    third = backoff_delay(3, base=1.0, cap=20.0)
    assert 0.5 <= first <= 1.0
    assert third > first
    assert backoff_delay(50, base=1.0, cap=20.0) <= 20.0


def test_throttle_state_escalates() -> None:
    state = ThrottleState(slowdown_after=2, stop_after=4)
    assert state.record_throttle("h", 429, "u", retry_after=None) == "continue"
    assert state.record_throttle("h", 429, "u", retry_after=None) == "slow_down"
    assert state.record_throttle("h", 503, "u", retry_after=None) == "slow_down"
    assert state.record_throttle("h", 503, "u", retry_after=None) == "stop"
    assert state.is_halted("h")
    state.record_success("other")
    assert not state.is_halted("other")


def test_client_retries_and_honours_retry_after(app: MockApp) -> None:
    async def scenario() -> tuple[ScanStats, ThrottleState, int]:
        config = fast_config()
        config.request.retries = 3
        stats = ScanStats()
        throttle = ThrottleState(slowdown_after=2, stop_after=10)
        async with ParamScoutClient(
            scope=config.scope, request_config=config.request, stats=stats, throttle_state=throttle
        ) as client:
            result = await client.fetch(app.base + "/limited", FetchOptions(purpose="test"))
            assert result.status == 200
            assert result.attempts >= 3
        return stats, throttle, result.attempts

    stats, throttle, attempts = asyncio.run(scenario())
    assert stats.retries >= 2
    assert attempts >= 3
    assert throttle.events, "a throttling event must be recorded"
    assert any(event.action == "slow_down" for event in throttle.events)
    assert all(event.retry_after is not None for event in throttle.events)


def test_client_stops_a_host_that_keeps_throttling(app: MockApp) -> None:
    async def scenario() -> ThrottleState:
        config = fast_config()
        config.request.retries = 0
        config.request.throttle_slowdown_after = 1
        config.request.throttle_stop_after = 2
        throttle = ThrottleState(
            slowdown_after=config.request.throttle_slowdown_after,
            stop_after=config.request.throttle_stop_after,
        )
        async with ParamScoutClient(
            scope=config.scope,
            request_config=config.request,
            stats=ScanStats(),
            throttle_state=throttle,
        ) as client:
            for _ in range(4):
                await client.fetch(app.base + "/limited", FetchOptions(purpose="test"))
            final = await client.fetch(app.base + "/limited", FetchOptions(purpose="test"))
            assert final.blocked, "a halted host must not be requested again"
        return throttle

    throttle = asyncio.run(scenario())
    assert throttle.is_halted("127.0.0.1")


def test_global_request_budget_is_enforced_end_to_end(app: MockApp) -> None:
    async def scenario() -> tuple[ScanStats, RequestBudget]:
        config = fast_config()
        config.request.max_requests = 4
        stats = ScanStats()
        budget = RequestBudget(total=4)
        async with ParamScoutClient(
            scope=config.scope,
            request_config=config.request,
            stats=stats,
            budget=budget,
        ) as client:
            results = [
                await client.fetch(f"{app.base}/static-page?n={index}", FetchOptions(purpose="test"))
                for index in range(10)
            ]
        assert sum(1 for item in results if item.ok) == 4
        assert sum(1 for item in results if item.blocked) == 6
        return stats, budget

    stats, budget = asyncio.run(scenario())
    assert stats.requests_total == 4
    assert budget.used == 4
    assert budget.denied_global == 6


def test_per_endpoint_budget_is_enforced(app: MockApp) -> None:
    async def scenario() -> RequestBudget:
        config = fast_config()
        config.request.max_requests = 100
        budget = RequestBudget(total=100, per_endpoint=2)
        async with ParamScoutClient(
            scope=config.scope, request_config=config.request, stats=ScanStats(), budget=budget
        ) as client:
            results = [
                await client.fetch(f"{app.base}/static-page?n={index}", FetchOptions(purpose="test"))
                for index in range(5)
            ]
        assert sum(1 for item in results if item.ok) == 2
        return budget

    budget = asyncio.run(scenario())
    assert budget.denied_endpoint == 3


def test_response_size_cap_truncates(app: MockApp) -> None:
    async def scenario() -> bool:
        config = fast_config()
        config.request.max_response_bytes = 64
        async with ParamScoutClient(
            scope=config.scope, request_config=config.request, stats=ScanStats()
        ) as client:
            result = await client.fetch(app.base + "/static-page", FetchOptions(purpose="test"))
            assert len(result.body) <= 64
            return result.truncated

    assert asyncio.run(scenario()) is True


def test_off_scope_requests_are_never_sent(app: MockApp) -> None:
    async def scenario() -> ScanStats:
        config = fast_config()  # scope is 127.0.0.1 only
        stats = ScanStats()
        async with ParamScoutClient(
            scope=config.scope, request_config=config.request, stats=stats
        ) as client:
            result = await client.fetch("https://evil.example.test/x", FetchOptions(purpose="test"))
            assert result.blocked
            assert "not in the allowlist" in (result.error or "")
        return stats

    stats = asyncio.run(scenario())
    assert stats.requests_total == 0
    assert len(stats.skipped_off_scope) == 1
