"""Async HTTP client with scope, budget, rate and credential enforcement.

Responsibilities, in the order they are applied to *every* request:

1. Scope check on the URL (and again on every redirect hop).
2. Host halt check (a host that kept answering 429/503 is stopped).
3. Request budget reservation (global + per endpoint).
4. Concurrency semaphore (per host, plus a global cap).
5. Rate limiter (per host, plus a global cap).
6. Send with an explicit timeout, retry with backoff + jitter, honour
   ``Retry-After``, and cap the response body size while streaming.
7. Redact anything that gets logged.

Redirects are followed manually (``follow_redirects=False``) so that every hop
is scope-checked before it is requested, and so that credentials are never
forwarded to a different origin.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

from paramscout.config import RequestConfig
from paramscout.models import ScanStats
from paramscout.redaction import SENSITIVE_HEADERS, redact_headers, redact_url
from paramscout.scope import Scope
from paramscout.throttle import (
    IntervalLimiter,
    RequestBudget,
    SemaphoreBank,
    ThrottleState,
    backoff_delay,
    parse_retry_after,
)
from paramscout.urls import endpoint_key, split_url

EventSink = Callable[[str, dict[str, Any]], None]


@dataclass
class FetchOptions:
    """Per-request intent."""

    purpose: str = "fetch"
    endpoint: str | None = None
    use_credentials: bool = True
    extra_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class RedirectHop:
    """One 3xx hop encountered while following a response."""

    url: str
    status: int
    followed: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": redact_url(self.url),
            "status": self.status,
            "followed": self.followed,
            "reason": self.reason,
        }


@dataclass
class FetchResult:
    """Outcome of one logical fetch (possibly spanning redirect hops)."""

    requested_url: str
    final_url: str
    status: int | None
    headers: dict[str, str]
    body: bytes
    truncated: bool
    elapsed_ms: float
    attempts: int
    purpose: str
    endpoint: str
    error: str | None = None
    blocked: bool = False
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    throttled: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and not self.blocked and self.status is not None

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def summary(self) -> dict[str, Any]:
        return {
            "requested_url": redact_url(self.requested_url),
            "final_url": redact_url(self.final_url),
            "status": self.status,
            "content_type": self.content_type,
            "bytes": len(self.body),
            "truncated": self.truncated,
            "attempts": self.attempts,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "blocked": self.blocked,
            "redirects": [hop.to_dict() for hop in self.redirect_chain],
        }


class ParamScoutClient:
    """The only object in ParamScout that is allowed to touch the network."""

    def __init__(
        self,
        *,
        scope: Scope,
        request_config: RequestConfig,
        stats: ScanStats,
        budget: RequestBudget | None = None,
        throttle_state: ThrottleState | None = None,
        event_sink: EventSink | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.scope = scope
        self.config = request_config
        self.stats = stats
        self.budget = budget or RequestBudget(total=request_config.max_requests)
        self.throttle = throttle_state or ThrottleState(
            slowdown_after=request_config.throttle_slowdown_after,
            stop_after=request_config.throttle_stop_after,
            factor=request_config.throttle_slowdown_factor,
        )
        self._event = event_sink or (lambda _name, _payload: None)

        self.host_limiters: dict[str, IntervalLimiter] = {}
        self.global_limiter = IntervalLimiter(request_config.global_rate, name="global")
        self.semaphores = SemaphoreBank(
            request_config.concurrency,
            global_limit=request_config.global_concurrency if request_config.concurrency_scope == "host" else None,
        )
        self.global_semaphore = (
            asyncio.Semaphore(max(1, request_config.global_concurrency))
            if request_config.concurrency_scope == "global"
            else None
        )
        self.global_only_limiter = (
            IntervalLimiter(request_config.rate, name="global") if request_config.rate_scope == "global" else None
        )
        self._client: httpx.AsyncClient | None = None
        self._transport = transport
        self.closed = False

    # -- lifecycle -------------------------------------------------------

    async def __aenter__(self) -> ParamScoutClient:
        await self.start()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    async def start(self) -> None:
        if self._client is not None:
            return
        timeout = httpx.Timeout(self.config.timeout, connect=self.config.connect_timeout)
        limits = httpx.Limits(
            max_connections=max(self.config.global_concurrency * 2, 4),
            max_keepalive_connections=max(self.config.concurrency, 1),
        )
        kwargs: dict[str, Any] = {
            "timeout": timeout,
            "limits": limits,
            "follow_redirects": False,
            "verify": self.config.verify_tls,
            "headers": {"User-Agent": self.config.user_agent, "Accept": "*/*"},
        }
        if self.config.proxy:
            kwargs["proxy"] = self.config.proxy
        if self._transport is not None:
            kwargs["transport"] = self._transport
        self._client = httpx.AsyncClient(**kwargs)

    async def close(self) -> None:
        if self._client is not None and not self.closed:
            await self._client.aclose()
            self.closed = True

    # -- helpers ---------------------------------------------------------

    def _limiter_for(self, host: str) -> IntervalLimiter:
        limiter = self.host_limiters.get(host)
        if limiter is None:
            rate = self.config.rate if self.config.rate_scope == "host" else 10**6
            limiter = IntervalLimiter(rate, name=host)
            self.host_limiters[host] = limiter
        return limiter

    def _origin_of(self, url: str) -> tuple[str, str]:
        parts = split_url(url)
        return parts.host, parts.origin

    def _headers_for(self, url: str, origin: str, extra: dict[str, str], use_credentials: bool) -> dict[str, str]:
        """Build request headers, dropping credentials for foreign origins."""

        target_host, target_origin = self._origin_of(url)
        headers = {name: value for name, value in self.config.headers.items()}
        if use_credentials:
            cookies = self.config.cookies
            foreign = target_origin != origin
            if foreign:
                # Never forward an Authorization/Cookie/API-key header to a
                # different origin than the one the operator configured.
                headers = {
                    name: value
                    for name, value in headers.items()
                    if name.lower() not in SENSITIVE_HEADERS
                }
                cookies = {}
            if cookies:
                cookie_value = "; ".join(f"{name}={value}" for name, value in cookies.items())
                if cookie_value:
                    headers["Cookie"] = cookie_value
        headers.update(extra)
        return headers

    # -- public API ------------------------------------------------------

    async def fetch(self, url: str, options: FetchOptions | None = None) -> FetchResult:
        """Fetch *url* with all safeguards applied."""

        options = options or FetchOptions()
        decision = self.scope.check(url)
        endpoint = options.endpoint or endpoint_key(url)
        if not decision.allowed:
            self.stats.skipped_off_scope.append(f"{redact_url(url)} :: {decision.reason}")
            self._event("scope_blocked", {"url": redact_url(url), "reason": decision.reason})
            return FetchResult(
                requested_url=url,
                final_url=url,
                status=None,
                headers={},
                body=b"",
                truncated=False,
                elapsed_ms=0.0,
                attempts=0,
                purpose=options.purpose,
                endpoint=endpoint,
                error=f"off-scope: {decision.reason}",
                blocked=True,
            )

        host, origin = self._origin_of(url)
        if self.throttle.is_halted(host):
            self.stats.skipped_budget += 1
            return FetchResult(
                requested_url=url,
                final_url=url,
                status=None,
                headers={},
                body=b"",
                truncated=False,
                elapsed_ms=0.0,
                attempts=0,
                purpose=options.purpose,
                endpoint=endpoint,
                error=f"host '{host}' halted after repeated throttling",
                blocked=True,
            )

        if not self.budget.consume(endpoint):
            self.stats.skipped_budget += 1
            self._event("budget_exhausted", {"endpoint": endpoint})
            return FetchResult(
                requested_url=url,
                final_url=url,
                status=None,
                headers={},
                body=b"",
                truncated=False,
                elapsed_ms=0.0,
                attempts=0,
                purpose=options.purpose,
                endpoint=endpoint,
                error="request budget exhausted",
                blocked=True,
            )

        acquired: list[asyncio.Semaphore] = []
        started = asyncio.get_running_loop().time()
        try:
            if self.global_semaphore is not None:
                await self.global_semaphore.acquire()
            acquired = await self.semaphores.acquire(host)
            await self._throttle_wait(host)
            return await self._fetch_with_redirects(url, origin, options, endpoint, started)
        finally:
            SemaphoreBank.release(acquired)
            if self.global_semaphore is not None:
                self.global_semaphore.release()

    async def _throttle_wait(self, host: str) -> None:
        limiter = self._limiter_for(host)
        await limiter.acquire()
        if self.global_only_limiter is not None:
            await self.global_only_limiter.acquire()
        if self.config.rate_scope == "host":
            await self.global_limiter.acquire()

    async def _fetch_with_redirects(
        self,
        url: str,
        origin: str,
        options: FetchOptions,
        endpoint: str,
        started: float,
    ) -> FetchResult:
        current = url
        chain: list[RedirectHop] = []
        attempts_total = 0
        last: FetchResult | None = None

        for _hop in range(self.config.max_redirects + 1):
            result = await self._single_request(current, origin, options, endpoint)
            attempts_total += result.attempts
            last = result
            if result.error is not None or result.status is None:
                break
            location = result.headers.get("location")
            if result.status < 300 or result.status >= 400 or not location:
                break
            resolved = urljoin(current, location)
            hop_decision = self.scope.check(resolved)
            if not hop_decision.allowed:
                chain.append(
                    RedirectHop(
                        url=resolved,
                        status=result.status,
                        followed=False,
                        reason=f"not followed: {hop_decision.reason}",
                    )
                )
                self.stats.skipped_off_scope.append(
                    f"{redact_url(resolved)} :: redirect blocked: {hop_decision.reason}"
                )
                self._event("redirect_blocked", {"url": redact_url(resolved), "reason": hop_decision.reason})
                break
            if not self.budget.can_request(endpoint):
                chain.append(
                    RedirectHop(url=resolved, status=result.status, followed=False, reason="budget exhausted")
                )
                break
            self.budget.consume(endpoint)
            chain.append(RedirectHop(url=resolved, status=result.status, followed=True, reason="in scope"))
            current = resolved

        assert last is not None
        last.attempts = attempts_total
        last.requested_url = url
        last.redirect_chain = chain
        last.elapsed_ms = round((asyncio.get_running_loop().time() - started) * 1000, 2)
        return last

    async def _single_request(
        self, url: str, origin: str, options: FetchOptions, endpoint: str
    ) -> FetchResult:
        assert self._client is not None, "client not started"
        headers = self._headers_for(url, origin, options.extra_headers, options.use_credentials)
        attempt = 0
        last_error: str | None = None

        while True:
            attempt += 1
            try:
                body, status, resp_headers, truncated, elapsed = await self._send(url, headers)
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                self.stats.record_request(options.purpose, None, last_error)
                self._event("transport_error", {"url": redact_url(url), "error": last_error})
                if attempt > self.config.retries:
                    break
                await asyncio.sleep(backoff_delay(attempt, base=self.config.backoff_base, cap=self.config.backoff_max))
                self.stats.retries += 1
                continue

            self.stats.record_request(options.purpose, status, None)
            lower_headers = {name.lower(): value for name, value in resp_headers.items()}

            if status in self.config.throttle_status:
                retry_after = parse_retry_after(lower_headers.get("retry-after"))
                action = self.throttle.record_throttle(split_url(url).host, status, redact_url(url), retry_after=retry_after)
                if action == "slow_down":
                    limiter = self._limiter_for(split_url(url).host)
                    new_interval = limiter.slow_down(self.throttle.factor)
                    self._event("throttle_slowdown", {"host": split_url(url).host, "interval": new_interval})
                elif action == "stop":
                    self._event("throttle_stop", {"host": split_url(url).host})
                if retry_after:
                    await asyncio.sleep(retry_after)
                if attempt <= self.config.retries and action != "stop":
                    self.stats.retries += 1
                    await asyncio.sleep(
                        backoff_delay(attempt, base=self.config.backoff_base, cap=self.config.backoff_max)
                    )
                    continue
                return FetchResult(
                    requested_url=url,
                    final_url=url,
                    status=status,
                    headers=resp_headers,
                    body=body,
                    truncated=truncated,
                    elapsed_ms=elapsed,
                    attempts=attempt,
                    purpose=options.purpose,
                    endpoint=endpoint,
                    throttled=True,
                )

            if status >= 500 and attempt <= self.config.retries:
                self.stats.retries += 1
                await asyncio.sleep(backoff_delay(attempt, base=self.config.backoff_base, cap=self.config.backoff_max))
                continue

            self.throttle.record_success(split_url(url).host)
            # httpx keeps its own cookie jar; we manage cookies explicitly per
            # origin, so drop anything the server tried to set.
            self._client.cookies.clear()
            return FetchResult(
                requested_url=url,
                final_url=url,
                status=status,
                headers=resp_headers,
                body=body,
                truncated=truncated,
                elapsed_ms=elapsed,
                attempts=attempt,
                purpose=options.purpose,
                endpoint=endpoint,
            )

        return FetchResult(
            requested_url=url,
            final_url=url,
            status=None,
            headers={},
            body=b"",
            truncated=False,
            elapsed_ms=0.0,
            attempts=attempt,
            purpose=options.purpose,
            endpoint=endpoint,
            error=last_error,
        )

    async def _send(
        self, url: str, headers: dict[str, str]
    ) -> tuple[bytes, int, dict[str, str], bool, float]:
        """One HTTP GET with a hard response-size cap."""

        assert self._client is not None
        loop = asyncio.get_running_loop()
        started = loop.time()
        chunks: list[bytes] = []
        total = 0
        truncated = False
        async with self._client.stream("GET", url, headers=headers) as response:
            async for chunk in response.aiter_bytes():
                chunks.append(chunk)
                total += len(chunk)
                if total > self.config.max_response_bytes:
                    truncated = True
                    break
            status = response.status_code
            resp_headers = dict(response.headers)
        if truncated:
            self.stats.truncated_responses += 1
            keep = self.config.max_response_bytes
            body = b"".join(chunks)[:keep]
        else:
            body = b"".join(chunks)
        return body, status, resp_headers, truncated, round((loop.time() - started) * 1000, 2)

    # -- introspection ---------------------------------------------------

    def describe(self) -> dict[str, Any]:
        """Human-readable description of the client's safeguards."""

        return {
            "rate_per_second": self.config.rate,
            "rate_scope": self.config.rate_scope,
            "concurrency": self.config.concurrency,
            "concurrency_scope": self.config.concurrency_scope,
            "global_rate_per_second": self.config.global_rate,
            "global_concurrency": self.config.global_concurrency,
            "timeout_seconds": self.config.timeout,
            "retries": self.config.retries,
            "max_redirects": self.config.max_redirects,
            "max_response_bytes": self.config.max_response_bytes,
            "verify_tls": self.config.verify_tls,
            "proxy": self.config.proxy,
            "user_agent": self.config.user_agent,
            "credential_headers": sorted(
                name for name in self.config.headers if name.lower() in SENSITIVE_HEADERS
            ),
            "redacted_headers": redact_headers(self.config.headers),
        }


async def fetch_many(
    client: ParamScoutClient, requests: list[tuple[str, FetchOptions]]
) -> list[FetchResult]:
    """Convenience helper: fetch a batch while respecting all client limits."""

    coroutines: list[Awaitable[FetchResult]] = [client.fetch(url, options) for url, options in requests]
    return list(await asyncio.gather(*coroutines))
