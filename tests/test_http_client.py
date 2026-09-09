"""HTTP client safeguards: scope, redirects, retries, throttles, credentials."""

import asyncio
import pytest

from paramscout.http_client import (
    HttpClient,
    RequestError,
    ResponseInfo,
    ThrottleStop,
)
from paramscout.redaction import Redactor
from paramscout.scope import Scope


def hostname_of(base_url: str) -> str:
    return base_url.removeprefix("http://").split(":", 1)[0]


def make_client(
    scope,
    *,
    retries=1,
    auth_hosts=(),
    cookies=None,
    headers=None,
    meter=None,
    on_skip=None,
    on_throttle=None,
    throttle_stop_after=6,
    max_response_bytes=2 * 1024 * 1024,
    rate=0.0,
):
    # cookies are expected host-keyed: {hostname: {name: value}}
    host_cookies: dict[str, dict[str, str]] = {}
    if cookies:
        flat = all(isinstance(v, str) for v in cookies.values())
        if flat:
            # attach the flat name=value cookies to the first auth host
            if auth_hosts:
                host_cookies[hostname_of(auth_hosts[0])] = dict(cookies)
            else:
                for rule in scope.host_rules:
                    host_cookies[rule.host] = dict(cookies)
                    break
        else:
            for host, values in cookies.items():
                host_cookies[hostname_of(host)] = dict(values)
    return HttpClient(
        scope,
        Redactor(),
        rate=rate,
        concurrency=3,
        timeout=5.0,
        retries=retries,
        backoff_base=0.01,
        backoff_max=0.05,
        jitter=0.0,
        max_redirects=3,
        max_response_bytes=max_response_bytes,
        proxy=None,
        verify_tls=True,
        cookies=host_cookies,
        custom_headers=headers or {},
        auth_hosts=auth_hosts,
        meter=meter,
        on_skip=on_skip,
        on_throttle=on_throttle,
        throttle_stop_after=throttle_stop_after,
        throttle_slowdown=0.01,
    )


def scope_for(*hosts):
    return Scope.from_hosts(list(hosts))


async def test_off_scope_url_rejected_before_request(server_a):
    scope = scope_for(server_a.base.removeprefix("http://"))
    skips = []
    client = make_client(scope, on_skip=lambda url, reason: skips.append((url, reason)))
    try:
        resp = await client.send("http://evil.example.net/x", purpose="crawl")
        assert resp.skipped and "off-scope" in resp.skip_reason
        assert server_a.app.requests == []  # nothing was sent
        assert len(skips) == 1
    finally:
        await client.aclose()


async def test_redirect_in_scope_followed_and_counted(server_a):
    host = server_a.base.removeprefix("http://")
    scope = scope_for(host)
    purposes = []
    client = make_client(scope, meter=lambda purpose, h: purposes.append(purpose))
    try:
        resp = await client.send(server_a.url("/redirect-inscope"), purpose="crawl")
        assert resp.skipped is False
        assert resp.status_code == 200
        assert "redirected" in resp.text
        # initial request + one redirect hop are both counted
        assert purposes == ["crawl", "crawl"]
    finally:
        await client.aclose()


async def test_off_scope_redirect_not_followed(server_a):
    scope = scope_for(server_a.base.removeprefix("http://"))
    purposes = []
    skips = []
    client = make_client(
        scope, meter=lambda p, h: purposes.append(p), on_skip=lambda u, r: skips.append(r)
    )
    try:
        resp = await client.send(server_a.url("/redirect-offscope"), purpose="probe")
        assert resp.skipped is True
        assert "off-scope" in resp.skip_reason
        # exactly one attempt: the redirect destination was never requested
        assert purposes == ["probe"]
        assert len(skips) == 1
    finally:
        await client.aclose()


async def test_retry_after_and_limited_retries(server_a):
    scope = scope_for(server_a.base.removeprefix("http://"))
    purposes = []
    throttles = []
    client = make_client(
        scope,
        retries=1,
        meter=lambda p, h: purposes.append(p),
        on_throttle=lambda host, status, cons: throttles.append((status, cons)),
        throttle_stop_after=10,
    )
    try:
        with pytest.raises(RequestError):
            await client.send(server_a.url("/rate-limit"), purpose="probe")
        # original + 1 retry both counted and both throttled
        assert purposes == ["probe", "probe"]
        assert [t[0] for t in throttles] == [429, 429]
        assert [t[1] for t in throttles] == [1, 2]
    finally:
        await client.aclose()


async def test_repeated_throttling_stops_scan(server_a):
    scope = scope_for(server_a.base.removeprefix("http://"))
    client = make_client(scope, retries=1, throttle_stop_after=2)
    try:
        with pytest.raises(ThrottleStop):
            await client.send(server_a.url("/rate-limit"), purpose="probe")
    finally:
        await client.aclose()


async def test_cookies_and_headers_never_cross_origins(server_pair):
    a, b = server_pair
    host_a = a.base.removeprefix("http://")
    host_b = b.base.removeprefix("http://")
    scope = scope_for(host_a, host_b)
    cookies = {"session": "super-secret-value"}
    headers = {"Authorization": "Bearer top-secret-token", "X-Api-Key": "sekrit-key"}
    client = make_client(
        scope,
        auth_hosts=[host_a],
        cookies=cookies,
        headers=headers,
        retries=0,
    )
    try:
        # same-origin (A): credentials are attached
        resp_a = await client.send(a.url("/private"), purpose="probe")
        assert resp_a.skipped is False
        assert "session=super-secret-value" in resp_a.text
        assert "Bearer top-secret-token" in resp_a.text
        # cross-origin redirect A -> B: nothing sensitive must be forwarded
        resp_b = await client.send(a.url("/redirect-other-origin"), purpose="probe")
        assert resp_b.skipped is False
        assert resp_b.status_code == 200
        assert '"cookies_seen": "(none)"' in resp_b.text
        assert '"authorization_seen": "(none)"' in resp_b.text
    finally:
        await client.aclose()


async def test_response_body_size_cap(server_a):
    scope = scope_for(server_a.base.removeprefix("http://"))
    client = make_client(scope, max_response_bytes=1200, retries=0)
    try:
        resp = await client.send(server_a.url("/reflect?echo=" + "a" * 5000), purpose="probe")
        assert resp.skipped is False
        assert resp.truncated is True
        assert len(resp.body) <= 1200 + 1
    finally:
        await client.aclose()


async def test_set_cookie_stored_per_host_and_not_forwarded(server_pair):
    a, b = server_pair
    host_a = a.base.removeprefix("http://")
    host_b = b.base.removeprefix("http://")
    scope = scope_for(host_a, host_b)
    client = make_client(scope, retries=0)
    try:
        await client.send(a.url("/set-cookie"), purpose="crawl")
        # cookie is stored for host A (keyed by hostname)
        assert "session" in client.cookies.get(hostname_of(host_a), {})
        # redirect to B must not carry A's cookie
        resp = await client.send(a.url("/redirect-other-origin"), purpose="probe")
        assert resp.skipped is False
        assert '"cookies_seen": "(none)"' in resp.text
    finally:
        await client.aclose()
