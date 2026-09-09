"""A local mock web application for the test-suite.

Everything the tests need lives here, on ``127.0.0.1`` / ``localhost``, so the
suite never contacts a public website.  The app deliberately implements each
behaviour ParamScout has to reason about correctly:

======================================  ==========================================
route                                   behaviour
======================================  ==========================================
``/``                                   index: links, forms, inline JS, data-*
``/search``                             ``q`` and ``sort`` change page content
``/profile``                            ``note`` is reflected and nothing else
``/static-page``                        ignores every parameter
``/dynamic``                            timestamps, epoch, nonce on every response
``/limited``                            429 + ``Retry-After`` for the first hits
``/leave``                              302 to a *different host* (off scope)
``/redir-inscope``                      302 to an in-scope URL
``/checkout``                           fake state-changing endpoint (excluded)
``/product``                            ``id`` changes content
``/echoauth``                           reports which credential headers arrived
``/static/app.js``                      target-specific JS parameter evidence
``/robots.txt`` / ``/sitemap.xml``      endpoint discovery sources
======================================  ==========================================
"""

from __future__ import annotations

import json
import random
import socket
import threading
import time
from collections import defaultdict
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

FILLER = (
    "This paragraph exists so that reflected values are a small fraction of the document, "
    "which is how real pages behave. It is repeated below to make the body comfortably large. "
) * 6


class MockState:
    """Shared, thread-safe-enough counters for one mock server."""

    def __init__(self) -> None:
        self.counts: dict[str, int] = defaultdict(int)
        self.limited_hits = 0
        self.requests: list[dict[str, object]] = []
        self.lock = threading.Lock()

    def bump(self, key: str) -> int:
        with self.lock:
            self.counts[key] += 1
            return self.counts[key]

    def record(self, entry: dict[str, object]) -> None:
        with self.lock:
            self.requests.append(entry)

    def canary_requests(self, path_prefix: str) -> list[dict[str, object]]:
        with self.lock:
            return [
                item
                for item in self.requests
                if str(item.get("path", "")).startswith(path_prefix) and "psc" in str(item.get("query", ""))
            ]


class _Handler(BaseHTTPRequestHandler):
    """Request handler bound to a :class:`MockApp` instance."""

    protocol_version = "HTTP/1.1"
    app: MockApp

    #: Explicit route table (paths contain slashes, so attribute lookup will not do).
    ROUTE_MAP = {
        "/": "_route_index",
        "/search": "_route_search",
        "/profile": "_route_profile",
        "/static-page": "_route_static_page",
        "/dynamic": "_route_dynamic",
        "/limited": "_route_limited",
        "/leave": "_route_leave",
        "/redir-inscope": "_route_redir_inscope",
        "/checkout": "_route_checkout",
        "/product": "_route_product",
        "/echoauth": "_route_echoauth",
        "/setcookie": "_route_setcookie",
        "/robots.txt": "_route_robots_txt",
        "/sitemap.xml": "_route_sitemap_xml",
        "/static/app.js": "_route_static_app_js",
        "/elsewhere": "_route_elsewhere",
        "/sensitive": "_route_sensitive",
        "/chaotic": "_route_chaotic",
    }

    # -- plumbing ---------------------------------------------------------

    def log_message(self, *args: object) -> None:
        return None

    def _send(
        self,
        status: int,
        body: str | bytes,
        content_type: str = "text/html; charset=utf-8",
        extra: dict[str, str] | None = None,
    ) -> None:
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _observe(self, path: str, query: str) -> None:
        self.app.state.record(
            {
                "path": path,
                "query": query,
                "authorization": bool(self.headers.get("Authorization")),
                "cookie": bool(self.headers.get("Cookie")),
                "user_agent": self.headers.get("User-Agent", ""),
            }
        )

    # -- routing ----------------------------------------------------------

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        path, query = parts.path, parts.query
        params = parse_qs(query, keep_blank_values=True)
        self._observe(path, query)
        self.app.state.bump("GET")
        method_name = self.ROUTE_MAP.get(path)
        handler = getattr(self, method_name) if method_name else None
        if handler is None:
            self.app.state.bump("404")
            self._send(404, f"<html><head><title>Not found</title></head><body>no route {path}</body></html>")
            return
        handler(params, query)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
        parts = urlsplit(self.path)
        self._observe(parts.path, parts.query)
        self.app.state.bump("POST")
        self.app.state.bump("POST " + parts.path)
        self._send(200, "<html><body>state changed (this endpoint must never be exercised)</body></html>")

    def do_HEAD(self) -> None:
        self.do_GET()

    # -- routes -----------------------------------------------------------

    def _route_index(self, params: dict[str, list[str]], query: str) -> None:
        secondary = self.app.secondary_base
        body = f"""<!doctype html>
<html><head><title>MockApp home</title></head><body>
<h1>MockApp</h1>
<nav>
  <a href="/search?q=widgets&amp;sort=asc">Search widgets</a>
  <a href="/product?id=42">Product 42</a>
  <a href="/profile?note=hello">Profile</a>
  <a href="/static-page?anything=1">Static</a>
  <a href="/dynamic">Dynamic</a>
  <a href="/redir-inscope">In-scope redirect</a>
  <a href="/leave">Off-scope redirect</a>
  <a href="{secondary}/elsewhere">Other host</a>
</nav>
<form action="/search" method="GET">
  <input type="hidden" name="source" value="home">
  <input type="text" name="q">
  <select name="filter"><option>all</option></select>
  <button type="submit">Go</button>
</form>
<form action="/checkout" method="POST">
  <input type="hidden" name="order_id" value="9001">
  <button type="submit">Buy now</button>
</form>
<div data-url="/api/items?category=books&amp;page=2">catalogue widget</div>
<script>
  const sp = new URLSearchParams({{ view: 'grid', theme: 'dark' }});
  sp.set('layout', 'wide');
  fetch('/api/items?category=books&limit=10');
  axios.get('/api/orders', {{ params: {{ status: 'open', owner: 'me' }} }});
  const cfg = {{"endpoint": "/api/v2/items?sort=price", "params": {{"cursor": null}}}};
</script>
<script src="/static/app.js"></script>
<script src="{secondary}/analytics.js"></script>
</body></html>"""
        self._send(200, body)

    def _route_search(self, params: dict[str, list[str]], query: str) -> None:
        """``q`` and ``sort`` change the content; every other parameter is ignored."""

        term = (params.get("q") or [""])[0]
        order = (params.get("sort") or ["asc"])[0]
        if not term:
            body = (
                "<!doctype html><html><head><title>Search</title></head><body>"
                "<h1>Search</h1><p class='empty'>Type something to search.</p>"
                f"<p>{FILLER}</p></body></html>"
            )
            self._send(200, body)
            return
        signature = sum(ord(char) for char in term)
        count = 3 + (signature % 7)
        items = [f"<li>result {index} for term</li>" for index in range(count)]
        if order == "desc":
            items.reverse()
        # The term signature makes *any* different term produce a visibly
        # different page, instead of relying on the result count alone.
        body = (
            "<!doctype html><html><head><title>Search results</title></head><body>"
            f"<h1>Search results</h1><p class='count'>Found {count} items.</p>"
            f"<p class='signature'>Term signature: {signature} ({len(term)} characters).</p>"
            f"<ul class='results'>{''.join(items)}</ul>"
            f"<p>{FILLER}</p></body></html>"
        )
        self._send(200, body)

    def _route_profile(self, params: dict[str, list[str]], query: str) -> None:
        """``note`` is reflected verbatim; nothing else about the page changes."""

        note = (params.get("note") or [""])[0]
        body = (
            "<!doctype html><html><head><title>Profile</title></head><body>"
            "<h1>Your profile</h1>"
            f"<div class='note'>{note}</div>"
            f"<p>{FILLER}</p></body></html>"
        )
        self._send(200, body)

    def _route_static_page(self, params: dict[str, list[str]], query: str) -> None:
        """Ignores every parameter: byte-identical responses."""

        self._send(
            200,
            "<!doctype html><html><head><title>Static page</title></head><body>"
            "<h1>Static page</h1><p>This endpoint ignores all query parameters.</p>"
            f"<p>{FILLER}</p></body></html>",
        )

    def _route_dynamic(self, params: dict[str, list[str]], query: str) -> None:
        """Timestamps, an epoch, a UUID-ish nonce and a rotating attribute."""

        import uuid

        now = datetime.now(UTC)
        body = (
            "<!doctype html><html><head><title>Dashboard</title></head><body>"
            "<h1>Dashboard</h1>"
            f"<p>Rendered at {now.isoformat()} (epoch {int(time.time())}).</p>"
            f"<p>Request id <span class='rid'>{uuid.uuid4()}</span></p>"
            f"<div data-nonce='{uuid.uuid4().hex}'>cached block</div>"
            f"<input type='hidden' name='csrf_token' value='{uuid.uuid4().hex}'>"
            f"<p>{FILLER}</p></body></html>"
        )
        self._send(200, body)

    def _route_limited(self, params: dict[str, list[str]], query: str) -> None:
        """429 + ``Retry-After`` for the first three requests, then 200."""

        hits = self.app.state.bump("limited")
        if hits <= 3:
            self._send(
                429,
                "<html><body>slow down</body></html>",
                extra={"Retry-After": "0"},
            )
            return
        self._send(200, "<html><head><title>Limited</title></head><body>ok</body></html>")

    def _route_leave(self, params: dict[str, list[str]], query: str) -> None:
        """Redirect to a *different host*: must never be followed."""

        target = f"{self.app.secondary_base}/elsewhere"
        self.app.state.bump("leave")
        self._send(302, "", extra={"Location": target})

    def _route_redir_inscope(self, params: dict[str, list[str]], query: str) -> None:
        self.app.state.bump("redir-inscope")
        self._send(302, "", extra={"Location": "/product?id=9"})

    def _route_checkout(self, params: dict[str, list[str]], query: str) -> None:
        """Fake state-changing endpoint.  ParamScout must never probe it."""

        self.app.state.bump("checkout")
        self._send(
            200,
            "<html><head><title>Checkout</title></head><body>"
            "<form action='/checkout' method='POST'>"
            "<input type='hidden' name='order_id' value='9001'>"
            "<input name='coupon'>"
            "<button>Pay</button></form></body></html>",
        )

    def _route_product(self, params: dict[str, list[str]], query: str) -> None:
        """``id`` changes both the text and the structure of the page."""

        identifier = (params.get("id") or ["0"])[0]
        try:
            number = int(identifier)
        except ValueError:
            number = -1
        if number < 0:
            body = (
                "<!doctype html><html><head><title>Product not found</title></head><body>"
                "<h1>Product not found</h1><p class='error'>That identifier is not numeric.</p>"
                f"<p>{FILLER}</p></body></html>"
            )
            self._send(404, body)
            return
        variants = [f"<li>variant {index}</li>" for index in range(number % 4)]
        body = (
            "<!doctype html><html><head><title>Product listing</title></head><body>"
            f"<h1>Product {number}</h1><p>SKU-{number * 7}</p>"
            f"<ul class='variants'>{''.join(variants)}</ul>"
            f"<p>{FILLER}</p></body></html>"
        )
        self._send(200, body)

    def _route_echoauth(self, params: dict[str, list[str]], query: str) -> None:
        """Report *whether* credential headers arrived (never their values)."""

        payload = {
            "authorization_present": bool(self.headers.get("Authorization")),
            "cookie_present": bool(self.headers.get("Cookie")),
            "host": self.headers.get("Host", ""),
        }
        self.app.state.record({"path": "/echoauth", "payload": payload})
        self._send(200, json.dumps(payload), content_type="application/json")

    def _route_setcookie(self, params: dict[str, list[str]], query: str) -> None:
        self._send(
            200,
            "<html><body>cookie set</body></html>",
            extra={"Set-Cookie": "session=abc123; Path=/"},
        )

    def _route_robots_txt(self, params: dict[str, list[str]], query: str) -> None:
        self._send(
            200,
            "User-agent: *\n"
            "Disallow: /admin/\n"
            "Disallow: /search?sort=secret\n"
            "Allow: /product?id=1\n"
            f"Sitemap: {self.app.base}/sitemap.xml\n",
            content_type="text/plain; charset=utf-8",
        )

    def _route_sitemap_xml(self, params: dict[str, list[str]], query: str) -> None:
        body = (
            "<?xml version='1.0' encoding='UTF-8'?>"
            "<urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>"
            f"<url><loc>{self.app.base}/product?id=7</loc></url>"
            f"<url><loc>{self.app.base}/profile?note=sitemap</loc></url>"
            f"<url><loc>{self.app.base}/static-page</loc></url>"
            "</urlset>"
        )
        self._send(200, body, content_type="application/xml")

    def _route_static_app_js(self, params: dict[str, list[str]], query: str) -> None:
        self._send(
            200,
            """
function load(term) {
  const p = new URLSearchParams(location.search);
  p.append('debug', '1');
  p.set('per_page', '25');
  return fetch('/api/search?query=' + encodeURIComponent(term) + '&page=1');
}
$.get('/api/user', { profile: 1, ref: 'nav' });
const exportUrl = "/api/export?format=csv&columns=all";
window.cfg = {"apiUrl": "/api/v2", "params": {"tenant": null}};
""",
            content_type="application/javascript",
        )

    def _route_sensitive(self, params: dict[str, list[str]], query: str) -> None:
        """Reacts to *any* unexpected parameter.

        This is the false-positive trap: the page changes for the parameter
        under test, but it changes exactly the same way for the unrelated
        control parameter, so nothing may be attributed to the candidate.
        """

        known = {"page"}
        unexpected = [name for name in params if name not in known]
        warning = (
            f"<div class='warn'>Unexpected query parameters: {len(unexpected)}.</div>" if unexpected else ""
        )
        title = "Flagged request" if unexpected else "Normal request"
        body = (
            f"<!doctype html><html><head><title>{title}</title></head><body>"
            f"<h1>Gateway</h1>{warning}"
            f"<p>{FILLER}</p></body></html>"
        )
        self._send(200, body)

    def _route_chaotic(self, params: dict[str, list[str]], query: str) -> None:
        """A genuinely unstable endpoint: structure and text differ every time."""

        blocks = random.randint(1, 12)
        sections = "".join(
            f"<section><h2>block {index}</h2><p>{'lorem ipsum ' * random.randint(1, 20)}</p></section>"
            for index in range(blocks)
        )
        body = (
            f"<!doctype html><html><head><title>Chaotic {random.randint(0, 999)}</title></head><body>"
            f"{sections}</body></html>"
        )
        self._send(200, body)

    # -- secondary-host routes ---------------------------------------------

    def _route_elsewhere(self, params: dict[str, list[str]], query: str) -> None:
        """Served by the second host; reaching it means scope enforcement failed."""

        self.app.state.bump("elsewhere")
        self._send(200, "<html><body>off-scope host reached</body></html>")


class MockApp:
    """A threaded local HTTP server implementing the routes above."""

    def __init__(self, host: str = "127.0.0.1", *, port: int = 0, secondary_base: str = "") -> None:
        self.state = MockState()
        self.host = host
        self.requested_port = port
        self.port = port
        self.base = ""
        self._secondary_base = secondary_base
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

        class BoundHandler(_Handler):
            pass

        BoundHandler.app = self
        self._handler_class = BoundHandler

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> MockApp:
        self._server = ThreadingHTTPServer((self.host, self.requested_port), self._handler_class)
        self._server.daemon_threads = True
        port = self._server.server_address[1]
        self.port = port
        self.base = f"http://{self.host}:{port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> MockApp:
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    @property
    def secondary_base(self) -> str:
        return self._secondary_base


def free_port() -> int:
    """Return an unused TCP port (used to pick a second mock host)."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def make_pair() -> tuple[MockApp, MockApp]:
    """Primary app on ``127.0.0.1`` and a second app on ``localhost``.

    The two hosts are distinct as far as scope matching is concerned, which is
    what lets the suite prove that off-scope redirects are never followed and
    that credentials are never forwarded across origins.
    """

    secondary_port = free_port()
    secondary_base = f"http://localhost:{secondary_port}"
    primary = MockApp("127.0.0.1", secondary_base=secondary_base).start()
    secondary = MockApp("localhost", port=secondary_port, secondary_base=secondary_base).start()
    return primary, secondary


def random_token() -> str:
    """An obviously synthetic token, used to seed test fixtures."""

    return f"{random.randint(10**11, 10**12 - 1)}"
