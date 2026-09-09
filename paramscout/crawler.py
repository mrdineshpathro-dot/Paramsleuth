"""Crawl-based passive discovery.

The crawler only requests existing, in-scope resources discovered from HTML
links. It never guesses parameters. Configurable depth, page limits, and
content-type filters bound the crawl; every request counts toward the global
budget through the shared HTTP client.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field

from .config import Config
from .http_client import HttpClient, RequestError, ResponseInfo
from .extractors.base import Collector
from .models import DiscoverySourceKind, SourceRef, Endpoint
from .redaction import Redactor
from .scope import Scope
from .urlutils import netloc_of, normalize_url, split_query
from urllib.parse import urlsplit

log = logging.getLogger("paramscout.crawler")

HTML_TYPES = {"text/html", "application/xhtml+xml"}
JS_TYPES = {"application/javascript", "text/javascript", "application/x-javascript", "text/plain"}


@dataclass
class CrawlResult:
    pages_fetched: int = 0
    external_js_fetched: int = 0
    error_responses: int = 0
    non_html_skipped: int = 0
    robots_fetched: int = 0
    sitemap_fetched: int = 0
    robots_urls: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)


class Crawler:
    """Bounded BFS crawler over explicitly authorized endpoints."""

    def __init__(
        self,
        client: HttpClient,
        scope: Scope,
        collector: Collector,
        cfg: Config,
        redactor: Redactor,
        stats: "object | None" = None,
    ) -> None:
        self.client = client
        self.scope = scope
        self.collector = collector
        self.cfg = cfg
        self.redactor = redactor
        self.stats = stats
        self.result = CrawlResult()

    # ------------------------------------------------------------------
    def _should_stop(self) -> bool:
        return False  # engine aborts through raised exceptions/budget

    async def crawl(self, seed_urls: list[str]) -> CrawlResult:
        queue: deque[tuple[str, int]] = deque()
        visited_urls: set[str] = set()
        for seed in seed_urls:
            normalized = normalize_url(seed)
            if normalized and normalized not in visited_urls:
                visited_urls.add(normalized)
                queue.append((normalized, 0))

        # Optional robots.txt / sitemap.xml (in scope, bounded, never guessed).
        if self.cfg.fetch_robots or self.cfg.fetch_sitemap:
            await self._fetch_robots_sitemap(seed_urls, queue, visited_urls)

        while queue and self.result.pages_fetched < self.cfg.max_pages:
            url, depth = queue.popleft()
            if depth > self.cfg.depth:
                continue
            if self.result.pages_fetched >= self.cfg.max_pages:
                break
            await self._visit_page(url, depth, queue, visited_urls)
        return self.result

    # ------------------------------------------------------------------
    async def _visit_page(
        self,
        url: str,
        depth: int,
        queue: deque[tuple[str, int]],
        visited: set[str],
    ) -> None:
        decision = self.scope.check(url)
        if not decision.allowed:
            return
        try:
            resp = await self.client.send(url, purpose="crawl")
        except RequestError as exc:
            log.warning("crawl request failed: %s", self.redactor.redact(str(exc)))
            self.result.error_responses += 1
            return
        if resp.skipped:
            return  # engine-side on_skip callback already counted it
        if resp.status_code is not None and resp.status_code >= 400:
            self.result.error_responses += 1
            return
        content_type = resp.content_type
        allowed = self._content_allowed(content_type)
        if not allowed or resp.truncated:
            self.result.non_html_skipped += 1
            return
        if resp.status_code in (301, 302, 303, 307, 308):
            return  # redirects are resolved inside HttpClient
        if "html" in content_type:
            self.result.pages_fetched += 1
            await self._handle_html(url, resp, depth, queue, visited)
        elif content_type in JS_TYPES:
            await self._handle_external_js(url, resp)

    def _content_allowed(self, content_type: str) -> bool:
        if self.cfg.content_type_filters:
            return any(content_type == f or content_type.startswith(f) for f in self.cfg.content_type_filters)
        return content_type in HTML_TYPES or content_type in JS_TYPES

    async def _handle_html(
        self,
        url: str,
        resp: ResponseInfo,
        depth: int,
        queue: deque[tuple[str, int]],
        visited: set[str],
    ) -> None:
        from .extractors.html import extract_from_html

        extraction = extract_from_html(
            self.collector,
            resp.text,
            page_url=url,
            redactor=self.redactor,
            inline_js=True,
        )
        next_depth = depth + 1
        if next_depth <= self.cfg.depth:
            for link in extraction.navigable_links:
                normalized = normalize_url(link)
                if not normalized or normalized in visited:
                    continue
                # Pre-filter queue growth; request-time validation still applies.
                if not self.scope.check(normalized).allowed:
                    continue
                visited.add(normalized)
                queue.append((normalized, next_depth))
        # Optional in-scope external JavaScript.
        if self.cfg.extract_js and extraction.script_urls:
            await self._fetch_external_scripts(url, extraction.script_urls)

    async def _fetch_external_scripts(self, page_url: str, script_urls: list[str]) -> None:
        from .extractors.javascript import extract_from_js_text

        page_endpoint = self._endpoint_for_page(page_url)
        for script_url in script_urls:
            if self.result.external_js_fetched >= 50:
                log.warning("external JS fetch limit reached (50/page-session)")
                break
            if not self.scope.check(script_url).allowed:
                continue  # never fetch off-scope scripts
            try:
                resp = await self.client.send(script_url, purpose="js")
            except RequestError as exc:
                log.warning("external JS fetch failed: %s", self.redactor.redact(str(exc)))
                continue
            if resp.skipped or resp.status_code is None or resp.status_code >= 400:
                continue
            self.result.external_js_fetched += 1
            if page_endpoint is None:
                continue
            for source in extract_from_js_text(
                resp.text,
                location=self.redactor.redact_url(script_url),
                redactor=self.redactor,
            ):
                self.collector.add_evidence(page_endpoint, source.param, source.source)

    def _endpoint_for_page(self, url: str) -> Endpoint | None:
        normalized = normalize_url(url)
        if not normalized:
            return None
        return self.collector.record_endpoint(normalized, "page with external JS")

    async def _fetch_robots_sitemap(
        self,
        seeds: list[str],
        queue: deque[tuple[str, int]],
        visited: set[str],
    ) -> None:
        hosts: set[str] = set()
        from .urlutils import netloc_of

        for seed in seeds:
            normalized = normalize_url(seed)
            if normalized:
                hosts.add(netloc_of(normalized))
        for netloc in sorted(hosts):
            # Use the scheme of the seed that introduced this host (default https).
            scheme = "https"
            for seed in seeds:
                if netloc_of(seed) == netloc:
                    scheme = urlsplit(seed).scheme or "https"
                    break
            base = f"{scheme}://{netloc}"
            if self.cfg.fetch_robots:
                try:
                    resp = await self.client.send(f"{base}/robots.txt", purpose="robots")
                except RequestError:
                    resp = ResponseInfo()
                if not resp.skipped and resp.status_code == 200:
                    self.result.robots_fetched += 1
                    urls = self._parse_robots(resp.text)
                    self.result.robots_urls.extend(urls)
                    for u in urls:
                        self._register_discovered(u, queue, visited, "robots.txt")
            if self.cfg.fetch_sitemap:
                try:
                    resp = await self.client.send(f"{base}/sitemap.xml", purpose="sitemap")
                except RequestError:
                    resp = ResponseInfo()
                if not resp.skipped and resp.status_code == 200 and "xml" in resp.content_type:
                    self.result.sitemap_fetched += 1
                    urls = self._parse_sitemap(resp.text)
                    self.result.sitemap_urls.extend(urls)
                    for u in urls:
                        self._register_discovered(u, queue, visited, "sitemap.xml")

    def _register_discovered(
        self,
        url: str,
        queue: deque[tuple[str, int]],
        visited: set[str],
        source: str,
    ) -> None:
        """Register robots/sitemap URLs as endpoints (never fetched unless crawled)."""
        normalized = normalize_url(url)
        if not normalized or normalized in visited:
            return
        visited.add(normalized)
        endpoint = self.collector.record_endpoint(normalized, source)
        if endpoint is not None and not endpoint.virtual:
            query = normalized.split("?", 1)[1] if "?" in normalized else ""
            for name, _value in split_query(query):
                self.collector.add_evidence(
                    endpoint,
                    name,
                    SourceRef(
                        kind=DiscoverySourceKind.SITEMAP if source == "sitemap.xml" else DiscoverySourceKind.ROBOTS,
                        location=normalized,
                        context=f"parameter in {source} URL",
                        weight=0.7,
                    ),
                )
        if self.cfg.depth >= 1:
            queue.append((normalized, 1))

    @staticmethod
    def _parse_robots(text: str) -> list[str]:
        """Extract Sitemap: URLs from robots.txt (Allow/Disallow are not URLs)."""
        urls: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("sitemap:"):
                candidate = line.split(":", 1)[1].strip()
                if candidate:
                    urls.append(candidate)
        return urls

    @staticmethod
    def _parse_sitemap(text: str) -> list[str]:
        """Extract <loc> URLs from sitemap XML (works for sitemap indexes too)."""
        import re

        return re.findall(r"<loc>\s*(https?://[^<\s]+?)\s*</loc>", text, re.IGNORECASE)
