"""Bounded, scope-checked passive crawler.

The crawler fetches pages, it does not interact with them.  Specifically:

* every URL is scope-checked before it is queued **and** before it is fetched;
* only ``http``/``https`` URLs are considered;
* only configured content types are parsed;
* response bodies are capped by the client's ``max_response_bytes``;
* forms are recorded, never submitted;
* external JavaScript is fetched only when it is in scope and the configured
  per-file and per-crawl byte/file budgets allow it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from paramscout.config import CrawlConfig
from paramscout.extractors import ExtractionResult, FormInfo, extract_from_html
from paramscout.extractors.javascript import extract_from_javascript
from paramscout.extractors.jsonblobs import extract_json_blobs_from_javascript
from paramscout.extractors.robots import extract_from_robots
from paramscout.extractors.sitemap import extract_from_sitemap
from paramscout.http_client import FetchOptions, ParamScoutClient
from paramscout.models import Evidence, SourceKind
from paramscout.redaction import redact_url
from paramscout.urls import (
    EndpointGrouping,
    endpoint_key,
    looks_like_javascript,
    normalize_url,
    relative_url,
    split_url,
)

EventSink = Callable[[str, dict[str, object]], None]


@dataclass
class PageRecord:
    """One fetched page."""

    url: str
    status: int | None
    content_type: str
    depth: int
    bytes: int
    final_url: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "url": redact_url(self.url),
            "final_url": redact_url(self.final_url or self.url),
            "status": self.status,
            "content_type": self.content_type,
            "depth": self.depth,
            "bytes": self.bytes,
            "error": self.error,
        }


@dataclass
class CrawlResult:
    """Everything the crawler learned."""

    pages: list[PageRecord] = field(default_factory=list)
    extraction: ExtractionResult = field(default_factory=ExtractionResult)
    forms: list[FormInfo] = field(default_factory=list)
    endpoints: list[tuple[str, Evidence]] = field(default_factory=list)
    scripts_fetched: int = 0
    robots_checked: bool = False
    sitemap_checked: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "pages": [page.to_dict() for page in self.pages],
            "forms": [
                {
                    "action": form.action,
                    "method": form.method,
                    "fields": form.fields,
                    "origin": form.origin,
                }
                for form in self.forms
            ],
            "scripts_fetched": self.scripts_fetched,
            "robots_checked": self.robots_checked,
            "sitemap_checked": self.sitemap_checked,
            "notes": list(self.notes),
        }


async def crawl(
    client: ParamScoutClient,
    seeds: list[str],
    config: CrawlConfig,
    *,
    grouping: EndpointGrouping = EndpointGrouping.STRICT,
    event_sink: EventSink | None = None,
) -> CrawlResult:
    """Breadth-first crawl of the authorized scope."""

    event = event_sink or (lambda _name, _payload: None)
    result = CrawlResult()
    seen: set[str] = set()
    frontier: list[tuple[str, int]] = []

    for seed in seeds:
        normalized = normalize_url(seed)
        if normalized in seen:
            continue
        decision = client.scope.check(seed)
        if not decision.allowed:
            event("seed_rejected", {"url": redact_url(seed), "reason": decision.reason})
            result.notes.append(f"seed rejected: {redact_url(seed)} ({decision.reason})")
            continue
        seen.add(normalized)
        frontier.append((seed, 0))

    if config.fetch_robots:
        await _collect_robots(client, seeds, result, grouping, event)
    if config.fetch_sitemap:
        await _collect_sitemaps(client, seeds, result, grouping, event)

    pages_fetched = 0
    while frontier and pages_fetched < config.max_pages:
        batch = frontier[: max(1, config.max_pages - pages_fetched)]
        frontier = frontier[len(batch) :]
        import asyncio

        results = await asyncio.gather(
            *[client.fetch(url, FetchOptions(purpose="crawl", endpoint=endpoint_key(url, grouping)))
              for url, _depth in batch]
        )
        next_level: list[tuple[str, int]] = []
        for (url, depth), fetch in zip(batch, results, strict=True):
            pages_fetched += 1
            record = PageRecord(
                url=url,
                status=fetch.status,
                content_type=fetch.content_type,
                depth=depth,
                bytes=len(fetch.body),
                final_url=fetch.final_url,
                error=fetch.error,
            )
            result.pages.append(record)
            if fetch.error is not None:
                event("crawl_error", {"url": redact_url(url), "error": fetch.error})
                continue
            if not _content_type_allowed(fetch.content_type, config.allowed_content_types):
                continue
            extracted = extract_from_html(fetch.text, origin=fetch.final_url, extract_js=config.extract_js)
            result.extraction.merge(extracted)
            result.forms.extend(extracted.forms)
            result.endpoints.append(
                (
                    endpoint_key(fetch.final_url, grouping),
                    Evidence(
                        kind=SourceKind.PAGE_DERIVED,
                        origin=fetch.final_url,
                        detail=f"crawled page at depth {depth}",
                    ),
                )
            )
            event("page", {"url": redact_url(fetch.final_url), "status": fetch.status, "depth": depth})

            if depth >= config.depth:
                continue
            for link in extracted.urls:
                if link in {script for script in extracted.scripts}:
                    continue  # scripts are handled by the JS budget below
                candidate = _normalize_link(fetch.final_url, link)
                if candidate is None:
                    continue
                normalized = normalize_url(candidate)
                if normalized in seen:
                    continue
                decision = client.scope.check(candidate)
                if not decision.allowed:
                    event("link_skipped", {"url": redact_url(candidate), "reason": decision.reason})
                    continue
                seen.add(normalized)
                next_level.append((candidate, depth + 1))

            if config.extract_js and config.fetch_external_js:
                for script in extracted.scripts:
                    candidate = _normalize_link(fetch.final_url, script)
                    if candidate is None:
                        continue
                    normalized = normalize_url(candidate)
                    if normalized in seen:
                        continue
                    decision = client.scope.check(candidate)
                    if not decision.allowed:
                        event("script_skipped", {"url": redact_url(candidate), "reason": decision.reason})
                        continue
                    seen.add(normalized)
                    await _fetch_script(
                        client, candidate, grouping, config, result, event, page_url=fetch.final_url
                    )
        frontier.extend(next_level)

    if pages_fetched >= config.max_pages and frontier:
        result.notes.append(
            f"crawl stopped at the page limit ({config.max_pages}); {len(frontier)} URLs left unvisited"
        )
    return result


def _content_type_allowed(content_type: str, allowed: tuple[str, ...]) -> bool:
    if not allowed:
        return True
    ctype = content_type.split(";", 1)[0].strip().lower()
    return ctype in {item.lower() for item in allowed}


def _normalize_link(origin: str, link: str) -> str | None:
    resolved = relative_url(origin, link)
    if resolved is None:
        return None
    parts = split_url(resolved)
    if parts.scheme not in {"http", "https"}:
        return None
    return resolved


async def _fetch_script(
    client: ParamScoutClient,
    url: str,
    grouping: EndpointGrouping,
    config: CrawlConfig,
    result: CrawlResult,
    event: EventSink,
    *,
    page_url: str = "",
) -> None:
    """Fetch one in-scope script and mine it for parameter evidence.

    Candidates that are not tied to a specific URL literal are attributed to
    the page that included the script, not to the ``.js`` file itself: a
    JavaScript file is not an endpoint anyone can send parameters to.
    """

    if result.scripts_fetched >= config.max_js_files:
        result.notes.append(f"external JavaScript fetch limit reached ({config.max_js_files})")
        return
    fetch = await client.fetch(url, FetchOptions(purpose="javascript", endpoint=endpoint_key(url, grouping)))
    if fetch.error is not None:
        return
    if not (looks_like_javascript(fetch.content_type) or url.lower().endswith(".js")):
        return
    result.scripts_fetched += 1
    body = fetch.body[: config.max_js_bytes].decode("utf-8", errors="replace")
    js_result = extract_from_javascript(body, origin=fetch.final_url, kind=SourceKind.JS_EXTERNAL)
    attribution = page_url or url
    for _name, evidence in js_result.params:
        if not evidence.target:
            evidence.target = attribution
        evidence.detail = f"[script {redact_url(fetch.final_url)}] {evidence.detail}"
    result.extraction.merge(js_result)
    blob_result = extract_json_blobs_from_javascript(body, origin=fetch.final_url)
    for _name, evidence in blob_result.params:
        if not evidence.target:
            evidence.target = attribution
        evidence.detail = f"[script {redact_url(fetch.final_url)}] {evidence.detail}"
    result.extraction.merge(blob_result)
    event("javascript", {"url": redact_url(fetch.final_url), "params": len(js_result.params)})


async def _collect_robots(
    client: ParamScoutClient,
    seeds: list[str],
    result: CrawlResult,
    grouping: EndpointGrouping,
    event: EventSink,
) -> None:
    for origin in _origins_of(seeds):
        url = f"{origin}/robots.txt"
        if not client.scope.check(url).allowed:
            continue
        fetch = await client.fetch(url, FetchOptions(purpose="robots", endpoint=endpoint_key(url, grouping)))
        result.robots_checked = True
        if fetch.error is not None or fetch.status != 200:
            continue
        extracted = extract_from_robots(fetch.text, origin=origin)
        result.extraction.merge(extracted)
        for endpoint_url, evidence in extracted.endpoints:
            result.endpoints.append((endpoint_key(endpoint_url, grouping), evidence))
        event("robots", {"origin": origin, "endpoints": len(extracted.endpoints)})


async def _collect_sitemaps(
    client: ParamScoutClient,
    seeds: list[str],
    result: CrawlResult,
    grouping: EndpointGrouping,
    event: EventSink,
) -> None:
    for origin in _origins_of(seeds):
        url = f"{origin}/sitemap.xml"
        if not client.scope.check(url).allowed:
            continue
        fetch = await client.fetch(url, FetchOptions(purpose="sitemap", endpoint=endpoint_key(url, grouping)))
        result.sitemap_checked = True
        if fetch.error is not None or fetch.status != 200:
            continue
        extracted = extract_from_sitemap(fetch.text, origin=origin)
        result.extraction.merge(extracted)
        for endpoint_url, evidence in extracted.endpoints:
            if client.scope.check(endpoint_url).allowed:
                result.endpoints.append((endpoint_key(endpoint_url, grouping), evidence))
        event("sitemap", {"origin": origin, "urls": len(extracted.urls)})


def _origins_of(seeds: list[str]) -> list[str]:
    origins: list[str] = []
    for seed in seeds:
        parts = split_url(seed)
        if not parts.scheme or not parts.host:
            continue
        origin = parts.origin
        if origin not in origins:
            origins.append(origin)
    return origins


def query_bearing_endpoints(urls: list[str], grouping: EndpointGrouping) -> dict[str, str]:
    """Map endpoint -> an example URL that carries a query string."""

    chosen: dict[str, str] = {}
    for url in urls:
        if not urlsplit(url).query:
            continue
        key = endpoint_key(url, grouping)
        chosen.setdefault(key, url)
    return chosen
