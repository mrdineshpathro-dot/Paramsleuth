"""ASGI mock application for integration tests (see package docstring)."""

from __future__ import annotations

import html
import json
import time
from collections import defaultdict
from urllib.parse import parse_qs, parse_qsl, urlsplit

DEFAULT_HTML = """<!DOCTYPE html>
<html><head><title>Mock Home</title></head>
<body>
<h1>Mock home</h1>
<p>Welcome to the local mock application.</p>
</body></html>
"""


class MockApp:
    """In-memory ASGI app. Tracks every request it receives."""

    def __init__(self, hostname: str = "127.0.0.1") -> None:
        self.requests: list[dict] = []
        self.hits: dict[str, int] = defaultdict(int)
        self.hostname = hostname
        self.port: int | None = None
        self._cookies_issued: set[str] = set()

    # -- helpers ---------------------------------------------------------
    def _record(self, scope: dict, headers: dict[str, str], body: str = "") -> None:
        query = scope.get("query_string", b"").decode("utf-8", "replace")
        self.requests.append(
            {
                "method": scope["method"],
                "path": scope["path"],
                "query": query,
                "raw_url": (scope.get("raw_path") or scope["path"]).decode("utf-8", "replace"),
                "headers": headers,
                "body": body,
                "host": headers.get("host", ""),
            }
        )
        self.hits[(scope["method"], scope["path"])] += 1

    def base_url(self, path: str = "/") -> str:
        assert self.port is not None, "server not started"
        return f"http://{self.hostname}:{self.port}{path}"

    # -- ASGI --------------------------------------------------------------
    async def __call__(self, scope: dict, receive, send) -> None:
        if scope["type"] != "http":
            await send({"type": "http.response.start", "status": 500, "headers": []})
            await send({"type": "http.response.body", "body": b""})
            return
        path = scope["path"]
        method = scope["method"]
        query_bytes = scope.get("query_string", b"")
        headers_raw = {k.decode(): v.decode() for k, v in scope.get("headers", [])}
        headers_lower = {k.lower(): v for k, v in headers_raw.items()}
        request_body = b""
        while True:
            message = await receive()
            if message["type"] == "http.request":
                request_body += message.get("body", b"")
                if not message.get("more_body", False):
                    break
            else:
                break
        self._record(scope, headers_lower, request_body.decode("utf-8", "replace"))
        params: dict[str, list[str]] = parse_qs(query_bytes.decode("utf-8", "replace"), keep_blank_values=True)

        # ---- routing -------------------------------------------------------
        if method != "GET" and path == "/checkout":
            await self._send(send, 405, b"method not allowed", headers={"Allow": "POST"})
            return
        if path == "/":
            body = (
                "<!DOCTYPE html><html><head><title>Mock Home</title>"
                "<script src='/assets/app.js'></script></head><body>"
                "<h1>Mock home</h1>"
                "<a href='/search?q=alpha'>search alpha</a>"
                "<a href='/item?id=1'>item 1</a>"
                "<a href='?tab=main'>self tab</a>"
                f"<a href='http://{self.hostname}:{self.port}/other'>other page</a>"
                "<a href='http://evil.example.net/phish'>off-scope</a>"
                "<a href='/dynamic'>dynamic</a>"
                "<form method='GET' action='/search'>"
                "<input name='q' type='text'>"
                "<input name='filter' type='hidden' value='all'>"
                "<button name='go' value='1'>Go</button></form>"
                "<form method='POST' action='/checkout'>"
                "<input name='item_id' type='hidden'><button>Buy</button></form>"
                "<script type='application/json' id='cfg'>"
                '{"app":{"params":{"order":"desc","theme":"dark"}}}'
                "</script>"
                "<script>const s = new URLSearchParams(window.location.search);"
                "const v = s.get('preview') || s.getAll('tag')[0];"
                "fetch('/list?page=1&callback=render');</script>"
                "</body></html>"
            )
            await self._send(send, 200, body.encode(), headers={"Content-Type": "text/html; charset=utf-8"})
            return
        if path == "/other":
            await self._send(send, 200, b"<html><body>other</body></html>", headers={"Content-Type": "text/html"})
            return
        if path == "/search":
            q = (params.get("q") or [""])[0]
            theme = (params.get("theme") or ["default"])[0]
            n = (params.get("n") or ["0"])[0]
            title = "Search: " + q if q else "Search"
            body = (
                f"<html><head><title>{html.escape(title)}</title></head><body>"
                f"<h1>Results for {html.escape(q)}</h1>"
                f"<p>theme={html.escape(theme)}</p><p>n={html.escape(n)}</p>"
                "</body></html>"
            )
            await self._send(send, 200, body.encode(), headers={"Content-Type": "text/html; charset=utf-8"})
            return
        if path == "/reflect":
            echoed = (params.get("echo") or [""])[0]
            body = (
                "<html><head><title>Reflector</title></head><body>"
                f"<p>echo: {echoed}</p><p>static</p></body></html>"
            )
            await self._send(send, 200, body.encode(), headers={"Content-Type": "text/html; charset=utf-8"})
            return
        if path == "/ignores":
            await self._send(send, 200, b"<html><head><title>Static</title></head><body><p>always same</p></body></html>",
                             headers={"Content-Type": "text/html; charset=utf-8"})
            return
        if path == "/dynamic":
            now = time.time()
            body = (
                "<html><head><title>Dynamic</title></head><body>"
                f"<p>server-time={now}</p><p>token={now * 1e6:.0f}</p>"
                "</body></html>"
            )
            await self._send(send, 200, body.encode(), headers={"Content-Type": "text/html; charset=utf-8"})
            return
        if path == "/rate-limit":
            await self._send(send, 429, b"too many", headers={"Retry-After": "0", "Content-Type": "text/plain"})
            return
        if path == "/server-error":
            await self._send(send, 503, b"unavailable", headers={"Retry-After": "0"})
            return
        if path == "/redirect-offscope":
            await self._send(send, 302, b"", headers={"Location": "http://evil.example.net/steal", "Content-Type": "text/plain"})
            return
        if path == "/redirect-other-origin":
            other = self.other_base  # set by conftest when two servers run
            await self._send(send, 302, b"", headers={"Location": f"{other}/private", "Content-Type": "text/plain"})
            return
        if path == "/redirect-inscope":
            await self._send(send, 302, b"", headers={"Location": "/search?q=redirected", "Content-Type": "text/plain"})
            return
        if path == "/api/data":
            if "application/json" not in headers_lower.get("accept", ""):
                pass
            payload = {"status": "ok", "count": 3, "items": [{"id": 1}, {"id": 2}, {"id": 3}]}
            body = json.dumps(payload)
            await self._send(send, 200, body.encode(), headers={"Content-Type": "application/json"})
            return
        if path == "/api/echo":
            payload = {"echo": params}
            await self._send(send, 200, json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
            return
        if path == "/private":
            # Always answers 200 and reports which credentials it saw, so tests
            # can assert exactly what was (or was not) forwarded.
            cookie = headers_lower.get("cookie", "")
            auth = headers_lower.get("authorization", "")
            body = json.dumps({"cookies_seen": cookie or "(none)", "authorization_seen": auth or "(none)"})
            await self._send(send, 200, body.encode(), headers={"Content-Type": "application/json"})
            return
        if path == "/set-cookie":
            await self._send(send, 200, b"ok", headers={"Set-Cookie": "session=valid-secret; Path=/"})
            return
        if path == "/assets/app.js":
            js = (
                "const sp = new URLSearchParams(window.location.search);\n"
                "const tab = sp.get('tab');\n"
                "const pageNo = sp.getAll('page')[0];\n"
                "axios.get('/api/list', { params: { sort: 'asc', limit: 10 } });\n"
                "fetch('/list?q=' + encodeURIComponent(sp.get('q')));\n"
                "window.location = '/go?next=' + tab;\n"
                "if (query.search) { }"
            )
            await self._send(send, 200, js.encode(), headers={"Content-Type": "application/javascript"})
            return
        if path == "/robots.txt":
            body = f"User-agent: *\nSitemap: {self.base_url('/sitemap.xml')}\n"
            await self._send(send, 200, body.encode(), headers={"Content-Type": "text/plain"})
            return
        if path == "/sitemap.xml":
            body = (
                '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                f"<url><loc>{self.base_url('/item?id=99')}</loc></url>"
                f"<url><loc>{self.base_url('/search?q=fromsitemap')}</loc></url>"
                "</urlset>"
            )
            await self._send(send, 200, body.encode(), headers={"Content-Type": "application/xml"})
            return
        # fallback: reflect the raw URL in a plain page
        raw_url = (scope.get("raw_path") or scope["path"]).decode("utf-8", "replace")
        if query_bytes:
            raw_url = raw_url + "?" + query_bytes.decode()
        body = f"<html><head><title>Mock catch-all</title></head><body><p>{html.escape(raw_url)}</p></body></html>"
        await self._send(send, 200, body.encode(), headers={"Content-Type": "text/html; charset=utf-8"})

    async def _send(self, send, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        hdrs = headers or {}
        raw_headers = []
        for name, value in hdrs.items():
            raw_headers.append((name.lower().encode(), value.encode()))
        if not any(k[0] == b"content-length" for k in raw_headers):
            raw_headers.append((b"content-length", str(len(body)).encode()))
        await send({"type": "http.response.start", "status": status, "headers": raw_headers})
        await send({"type": "http.response.body", "body": body})


def make_app() -> MockApp:
    return MockApp()
