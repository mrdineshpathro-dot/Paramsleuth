"""HTTP client with strict safeguards.

Every network request (crawling, baselines, controls, probes, retries,
redirect hops, JS/robots/sitemap fetches) passes through :meth:`HttpClient.send`
so it can be:

- validated against scope before sending (including every redirect hop),
- rate-limited per host,
- concurrency-limited per host,
- metered against global/per-endpoint budgets,
- retried conservatively with backoff, jitter and ``Retry-After`` respect,
- sized-limited and TLS-verified.

Credentials never cross origins: cookies and custom headers are only attached
to hosts that were explicitly designated (scope hosts by default), and cookie
storage is host-scoped.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

import httpx

from . import __about__
from .redaction import Redactor
from .scope import Scope
from .urlutils import host_of, netloc_of, normalize_url

log = logging.getLogger("paramscout.http")


class BudgetExceeded(Exception):
    """Raised when the global request budget would be exceeded."""


class ThrottleStop(Exception):
    """Raised when repeated throttling indicates the target is under stress."""


class RequestError(Exception):
    """A request failed after retries (connection, timeout, protocol)."""


@dataclass
class ResponseInfo:
    """Normalized response used across ParamScout."""

    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    truncated: bool = False
    final_url: str = ""
    content_type: str = ""
    elapsed_ms: float = 0.0
    redirect_hops: list[tuple[int, str]] = field(default_factory=list)
    # -- not actually sent / refused paths --
    skipped: bool = False
    skip_reason: str = ""

    @property
    def text(self) -> str:
        try:
            return self.body.decode("utf-8", "replace")
        except Exception:
            return ""

    def header(self, name: str) -> str:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return ""


class _HostGate:
    """Per-host rate + concurrency limiter."""

    def __init__(self, interval: float, concurrency: int):
        self.interval = max(0.0, interval)
        self.semaphore = asyncio.Semaphore(max(1, concurrency))
        self._last = 0.0


class HttpClient:
    """Stateful, scope-checking HTTP client."""

    def __init__(
        self,
        scope: Scope,
        redactor: Redactor,
        *,
        rate: float = 0.1,
        concurrency: int = 3,
        timeout: float = 15.0,
        retries: int = 2,
        backoff_base: float = 1.0,
        backoff_max: float = 30.0,
        jitter: float = 0.25,
        max_redirects: int = 5,
        max_response_bytes: int = 2 * 1024 * 1024,
        proxy: str | None = None,
        verify_tls: bool = True,
        user_agent: str | None = None,
        cookies: dict[str, dict[str, str]] | None = None,
        custom_headers: dict[str, str] | None = None,
        auth_hosts: Iterable[str] = (),
        meter: Callable[[str, str], None] | None = None,
        on_skip: Callable[[str, str], None] | None = None,
        on_throttle: Callable[[str, int, int], None] | None = None,
        throttle_stop_after: int = 6,
        throttle_slowdown: float = 3.0,
    ) -> None:
        self.scope = scope
        self.redactor = redactor
        self.rate = rate
        self.concurrency = concurrency
        self.max_redirects = max_redirects
        self.max_response_bytes = max_response_bytes
        self.retries = retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.jitter = jitter
        self.meter = meter
        self.on_skip = on_skip
        self.on_throttle = on_throttle
        self.throttle_stop_after = throttle_stop_after
        self.throttle_slowdown = throttle_slowdown
        self.user_agent = user_agent or __about__.user_agent()
        # Auth headers/cookies apply per *hostname* (origin), never across
        # hosts. Port-qualified or scheme-qualified entries are normalized.
        self.auth_hosts = {_hostname_only(h) for h in auth_hosts if h}
        # Cookies keyed by lowercase hostname.
        self.cookies: dict[str, dict[str, str]] = {}
        for key, values in (cookies or {}).items():
            host_key = _hostname_only(str(key))
            if host_key and values:
                self.cookies.setdefault(host_key, {}).update(dict(values))
        self.custom_headers = dict(custom_headers or {})
        self.gates: dict[str, _HostGate] = {}
        self._gate_lock = asyncio.Lock()
        self._consecutive_throttle: dict[str, int] = {}
        transport = httpx.AsyncHTTPTransport(
            retries=0, verify=verify_tls, proxy=proxy
        )
        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(timeout, connect=10.0),
            follow_redirects=False,
        )

    # ------------------------------------------------------------------
    async def _gate_for(self, host_key: str) -> _HostGate:
        gate = self.gates.get(host_key)
        if gate is None:
            async with self._gate_lock:
                gate = self.gates.get(host_key)
                if gate is None:
                    gate = _HostGate(self.rate, self.concurrency)
                    self.gates[host_key] = gate
        return gate

    async def send(
        self,
        url: str,
        *,
        purpose: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> ResponseInfo:
        """Send one request chain (method + redirects + retries).

        Returns a ``skipped=True`` response when the URL is off-scope without
        sending anything. Every actual HTTP attempt is metered.
        """
        normalized = normalize_url(url)
        if not normalized:
            self._note_skip(url, "invalid or non-http(s) URL")
            return ResponseInfo(skipped=True, skip_reason="invalid URL")
        decision = self.scope.check(normalized)
        if not decision.allowed:
            self._note_skip(normalized, decision.reason)
            return ResponseInfo(
                skipped=True,
                skip_reason=f"off-scope: {self.redactor.redact_url(url)} -> {decision.reason}",
                final_url=normalized,
            )

        current = normalized
        redirect_hops: list[tuple[int, str]] = []
        hop = 0
        while True:
            resp = await self._send_chain(current, purpose=purpose, method=method, headers=headers)
            if resp.skipped:
                return resp
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.header("location")
                if not location:
                    return resp
                if hop >= self.max_redirects:
                    resp.headers = dict(resp.headers)
                    resp.skip_reason = "redirect limit exceeded"
                    resp.skipped = True
                    self._note_skip(current, "max redirects reached")
                    return resp
                try:
                    next_url = httpx.URL(current).join(location).__str__()
                except Exception:
                    return ResponseInfo(skipped=True, skip_reason="malformed redirect Location")
                if not normalize_url(next_url):
                    resp.skipped = True
                    resp.skip_reason = f"redirect to non-http(s) target: {location!r}"
                    self._note_skip(current, "non-http(s) redirect target")
                    return resp
                # Validate every redirect destination before requesting it.
                redirect_decision = self.scope.check(next_url)
                if not redirect_decision.allowed:
                    resp.skipped = True
                    resp.skip_reason = (
                        f"redirect destination off-scope: "
                        f"{self.redactor.redact_url(next_url)} -> {redirect_decision.reason}"
                    )
                    resp.redirect_hops = list(redirect_hops)
                    self._note_skip(current, f"off-scope redirect to {host_of(next_url)}")
                    return resp
                redirect_hops.append((resp.status_code, self.redactor.redact_url(location)))
                hop += 1
                current = next_url
                continue
            resp.final_url = current
            resp.redirect_hops = redirect_hops
            return resp

    async def _send_chain(self, url: str, *, purpose: str, method: str, headers: dict[str, str] | None) -> ResponseInfo:
        host = host_of(url)
        host_key = netloc_of(url) or host
        gate = await self._gate_for(host_key)
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            # Meter before every attempt so retries and redirect hops count
            # toward budgets exactly as required.
            if self.meter is not None:
                self.meter(purpose, host)
            try:
                async with gate.semaphore:
                    if self.rate > 0 and gate.interval > 0:
                        now = time.monotonic()
                        wait = gate._last + gate.interval - now
                        if wait > 0:
                            await asyncio.sleep(wait)
                        gate._last = time.monotonic()
                    request_headers = self._headers_for(url, extra=headers)
                    started = time.monotonic()
                    response = await self._client.request(
                        method, url, headers=request_headers
                    )
                    elapsed = (time.monotonic() - started) * 1000.0
                    body, truncated = await self._read_body(response)
                    info = ResponseInfo(
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        body=body,
                        truncated=truncated,
                        content_type=response.headers.get("content-type", "").split(";")[0].strip().lower(),
                        elapsed_ms=elapsed,
                        final_url=str(response.url),
                    )
                    self._store_cookies(url, response.headers)
                    if response.status_code in (429, 503):
                        await self._handle_throttle(host, url, response.status_code, response.headers)
                    if self._is_retryable(response.status_code):
                        last_error = RequestError(
                            f"HTTP {response.status_code} on {self.redactor.redact_url(url)}"
                        )
                        await self._backoff_sleep(attempt, response.headers)
                        continue
                    return info
            except httpx.HTTPError as exc:
                last_error = exc
                await self._backoff_sleep(attempt, None)
            except asyncio.CancelledError:
                raise
        if last_error is not None:
            raise RequestError(
                f"request failed after {self.retries} retries: {self.redactor.scrub_credentials_from_text(str(last_error))}"
            )
        raise RequestError("request failed")

    # ------------------------------------------------------------------
    def _is_retryable(self, status: int) -> bool:
        if status in (429, 503):
            return True
        return status >= 500

    def _auth_allowed(self, host: str) -> bool:
        """True when credentials may be attached for *host*.

        Credentials never cross origins: when an explicit auth-host list is
        given, only those hostnames receive credentials. Otherwise (no explicit
        list) credentials follow the scope's own host rules. A redirect to a
        different hostname therefore always drops cookies and auth headers.
        """
        if self.auth_hosts:
            return host in self.auth_hosts
        if self.scope is not None and not self.scope.is_empty:
            return self.scope.authorizes_hostname(host)
        return False

    def _headers_for(self, url: str, extra: dict[str, str] | None = None) -> dict[str, str]:
        host = host_of(url)
        out: dict[str, str] = {"User-Agent": self.user_agent, "Accept": "*/*"}
        if self._auth_allowed(host):
            out.update(self.custom_headers)
        cookie_parts: list[str] = []
        for cookie_host, values in self.cookies.items():
            if not cookie_host:
                continue
            if host == cookie_host or host.endswith("." + cookie_host):
                for name, value in values.items():
                    cookie_parts.append(f"{name}={value}")
        if cookie_parts:
            out["Cookie"] = "; ".join(cookie_parts)
        if extra:
            out.update(extra)
        return out

    def _store_cookies(self, url: str, headers: dict[str, str]) -> None:
        """Store Set-Cookie values keyed by the responding host (Domain honored)."""
        raw = headers.get("set-cookie") or headers.get("Set-Cookie")
        if not raw:
            return
        host = host_of(url)
        # Multiple Set-Cookie headers may be folded with commas; a simple split is
        # enough for a local state store that never persists them.
        for chunk in raw.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            name, _, value = chunk.partition("=")
            if not name:
                continue
            value = value.split(";", 1)[0]
            target = host
            for attr in chunk.split(";")[1:]:
                attr = attr.strip().lower()
                if attr.startswith("domain="):
                    domain = attr.split("=", 1)[1].strip().strip(".")
                    target = domain if domain else host
            self.cookies.setdefault(target.lower(), {})[name.strip()] = value

    async def _read_body(self, response: httpx.Response) -> tuple[bytes, bool]:
        cap = self.max_response_bytes
        chunks: list[bytes] = []
        size = 0
        truncated = False
        async for chunk in response.aiter_bytes():
            if chunk:
                chunks.append(chunk)
                size += len(chunk)
                if size > cap:
                    truncated = True
                    # Drop any content beyond the cap by truncating the last chunk.
                    excess = size - cap
                    if excess < len(chunk):
                        chunks[-1] = chunk[: len(chunk) - excess]
                    else:
                        chunks.pop()
                    size = cap
                    break
        return b"".join(chunks), truncated

    async def _handle_throttle(self, host: str, url: str, status: int, headers: dict[str, str]) -> None:
        consecutive = self._consecutive_throttle.get(host, 0) + 1
        self._consecutive_throttle[host] = consecutive
        if self.on_throttle is not None:
            self.on_throttle(host, status, consecutive)
        log.warning(
            "throttled by %s (HTTP %d, consecutive=%d) url=%s",
            host,
            status,
            consecutive,
            self.redactor.redact_url(url),
        )
        if consecutive >= self.throttle_stop_after:
            raise ThrottleStop(
                f"target {host} returned {status} {consecutive} times in a row; "
                "slowing to a stop as configured (--throttle-stop-after)"
            )
        retry_after = _parse_retry_after(headers.get("retry-after"))
        if retry_after is not None:
            await asyncio.sleep(min(retry_after, 60.0))
        else:
            await asyncio.sleep(self.throttle_slowdown)

    async def _backoff_sleep(self, attempt: int, headers: dict[str, str] | None) -> None:
        if headers is not None:
            retry_after = _parse_retry_after(headers.get("retry-after"))
            if retry_after is not None:
                await asyncio.sleep(min(retry_after, 60.0))
                return
        delay = min(self.backoff_max, self.backoff_base * (2 ** attempt))
        if self.jitter > 0:
            delay += random.uniform(0, self.jitter * delay)
        await asyncio.sleep(delay)

    def _note_skip(self, url: str, reason: str) -> None:
        if self.on_skip is not None:
            self.on_skip(url, reason)

    async def aclose(self) -> None:
        await self._client.aclose()


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(value)
        return max(0.0, (dt - datetime_now_utc()).total_seconds())
    except (TypeError, ValueError):
        return None


def datetime_now_utc():
    import datetime

    return datetime.datetime.now(datetime.timezone.utc)


def _hostname_only(expression: str) -> str:
    """Normalize a host expression (possibly with scheme/port) to a hostname."""
    expr = expression.strip().lower()
    if "://" not in expr:
        expr = "//" + expr
    try:
        return (urlsplit(expr).hostname or "").strip("[]").lower()
    except ValueError:
        host = expression.strip().lower().split(":", 1)[0]
        return host.strip("[]")
