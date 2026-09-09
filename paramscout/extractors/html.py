"""HTML-based passive extraction.

Handles links (for crawling), form fields (never submitted - recorded as
passive evidence only), inline JavaScript/JSON, and the URLs embedded in the
document. JavaScript *name* heuristics live in :mod:`.javascript`; here we
collect the script bodies and delegate to it.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from bs4 import BeautifulSoup

from ..models import DiscoverySourceKind, Endpoint, SourceRef
from ..redaction import Redactor
from ..urlutils import normalize_url, resolve_link, split_query
from .base import Collector, classify_hint, param_context_snippet

log = logging.getLogger("paramscout.extract.html")

# Content types we are willing to treat as parseable HTML documents.
HTML_CONTENT_TYPES = {"text/html", "application/xhtml+xml"}
# Attributes whose URL values we resolve but never crawl/fetch.
_RESOURCE_ATTRS = ("src", "href", "action", "data-src", "poster", "cite", "formaction")


@dataclass
class HtmlExtraction:
    """What one HTML document contributed."""

    navigable_links: list[str] = field(default_factory=list)  # crawl candidates
    script_urls: list[str] = field(default_factory=list)  # external JS (optional fetch)
    subresource_urls: list[str] = field(default_factory=list)  # never auto-fetched
    form_count: int = 0
    evidence_count: int = 0


def looks_like_html(text: str) -> bool:
    head = text[:1024].lstrip().lower()
    return head.startswith("<!doctype html") or ("<html" in head[:512])


def _soup(html_text: str) -> BeautifulSoup | None:
    try:
        return BeautifulSoup(html_text, "html.parser")
    except Exception:
        return None


def extract_from_html(
    collector: Collector,
    html_text: str,
    *,
    page_url: str | None = None,  # URL of the page that produced the document
    label: str = "",  # human label when page_url is empty (local file)
    redactor: Redactor,
    inline_js: bool = True,
) -> HtmlExtraction:
    """Parse an HTML document and feed evidence into *collector*.

    Forms are never submitted; their method and field names are recorded as
    passive evidence attached to the form action's endpoint when it resolves to
    an http(s) URL, otherwise to the page endpoint. Returns links/scripts for
    crawl orchestration.
    """
    result = HtmlExtraction()
    soup = _soup(html_text)
    if soup is None:
        return result
    if page_url is not None and not normalize_url(page_url):
        page_url = None
    page_endpoint = None
    if page_url:
        page_endpoint = collector.record_endpoint(page_url, "html document")
    if page_endpoint is None:
        page_endpoint = collector.virtual_endpoint(label or "local html document")

    # <base href> changes how relative links resolve.
    base_href = ""
    base_tag = soup.find("base", href=True)
    if base_tag is not None:
        base_href = base_tag.get("href", "")
    resolver_base = page_url or ""
    if base_href:
        candidate = resolve_link(resolver_base or "http://placeholder.invalid/", base_href)
        if candidate:
            resolver_base = candidate

    base_ctx = page_url or label or "html document"

    # -- forms (never submitted) ---------------------------------------
    for form in soup.find_all("form"):
        result.form_count += 1
        method = (form.get("method") or "get").strip().upper()
        action = (form.get("action") or "").strip()
        action_url = resolve_link(resolver_base, action) if (action and resolver_base) else ""
        target_endpoint = page_endpoint
        if action_url and normalize_url(action_url):
            target_endpoint = collector.record_endpoint(action_url, "form action")
        for field in form.find_all(["input", "select", "textarea", "button"]):
            name = field.get("name")
            if not name:
                continue
            field_type = field.get("type", "").strip().lower() if field.name == "input" else field.name
            html_snippet = str(field)[:180]
            source = SourceRef(
                kind=DiscoverySourceKind.FORM,
                location=f"{base_ctx} [form action={action or '(none)'} method={method}]",
                context=html_snippet,
                method=method,
                weight=0.75,
            )
            collector.add_evidence(target_endpoint, name, source)
            result.evidence_count += 1

    # -- links (crawl candidates) + URL-embedded query params -----------
    seen_links: set[str] = set()
    for anchor in soup.find_all(["a", "area"]):
        raw = anchor.get("href")
        if not raw:
            continue
        # Offline HTML files have no base URL to resolve against, so register
        # the query parameters of un-resolvable relative links on the page
        # endpoint itself. When a base exists, the resolved URL below already
        # carries this evidence to the link's own endpoint (no double counting).
        if not resolver_base and "?" in raw and not raw.lstrip().lower().startswith(("http", "//")):
            _add_raw_query_evidence(collector, page_endpoint, base_ctx, raw)
        link = resolve_link(resolver_base, raw)
        if not link or not normalize_url(link):
            continue
        if link in seen_links:
            continue
        seen_links.add(link)
        result.navigable_links.append(link)
        _add_url_query_evidence(collector, page_endpoint, base_ctx, link)

    # -- external script / stylesheet / asset URLs (never fetched by default)
    for tag in soup.find_all(["script", "link", "img", "iframe", "source"]):
        attr = "src" if tag.name in ("script", "img", "iframe", "source") else "href"
        raw = tag.get(attr) if tag.name != "source" else tag.get("src")
        if not raw:
            continue
        asset = resolve_link(resolver_base, raw)
        if not asset or not normalize_url(asset):
            continue
        if tag.name == "script" and _is_js_url(asset):
            result.script_urls.append(asset)
        else:
            result.subresource_urls.append(asset)
        _add_url_query_evidence(collector, page_endpoint, base_ctx, asset)

    # -- inline scripts ------------------------------------------------
    if inline_js:
        from .javascript import extract_from_js_text

        for script in soup.find_all("script"):
            body = script.string or script.get_text()
            if not body or not body.strip():
                continue
            js_type = (script.get("type") or "").strip().lower()
            is_json_block = "json" in js_type or "ld+json" in js_type
            if is_json_block:
                _extract_json_config(collector, page_endpoint, base_ctx, body)
                continue
            for source in extract_from_js_text(
                body,
                location=f"{base_ctx} [inline <script>]",
                redactor=redactor,
            ):
                collector.add_evidence(page_endpoint, source.param, source.source)
                result.evidence_count += 1
    return result


def _is_js_url(url: str) -> bool:
    from urllib.parse import urlsplit

    path = urlsplit(url).path.lower()
    return path.endswith((".js", ".mjs", ".jsonp")) or ".js?" in url


def _add_raw_query_evidence(
    collector: Collector,
    page_endpoint: Endpoint,
    base_ctx: str,
    raw_href: str,
) -> None:
    """Register query parameters from a relative (non-resolvable) in-page link."""
    query = raw_href.split("?", 1)[1] if "?" in raw_href else ""
    query = query.split("#", 1)[0]
    for name, _value in split_query(query):
        if not name:
            continue
        source = SourceRef(
            kind=DiscoverySourceKind.HTML_LINK,
            location=base_ctx,
            context=f"query parameter {name!r} in relative in-page link {raw_href[:120]!r}",
            weight=0.8,
        )
        collector.add_evidence(page_endpoint, name, source)


def _add_url_query_evidence(
    collector: Collector, page_endpoint: Endpoint, base_ctx: str, url: str
) -> None:
    """Register query parameters embedded in an in-document URL."""
    normalized = normalize_url(url)
    if not normalized:
        return
    query = normalized.split("?", 1)[1] if "?" in normalized else ""
    if not query:
        return
    # Prefer the endpoint the URL belongs to for provenance.
    target = collector.record_endpoint(normalized, "in-document URL")
    target = target or page_endpoint
    for name, _value in split_query(query):
        if not name:
            continue
        source = SourceRef(
            kind=DiscoverySourceKind.HTML_LINK,
            location=base_ctx,
            context=f"query parameter {name!r} in in-page URL {normalized[:160]}",
            weight=0.8,
        )
        collector.add_evidence(target, name, source)


def _extract_json_config(
    collector: Collector, page_endpoint: Endpoint, base_ctx: str, body: str
) -> None:
    """Weak, conservative extraction from embedded JSON/configuration blocks.

    Only dictionary keys found under context keys that plausibly reference URL
    parameters (``params``, ``query``, ``search``, ``querystring``) are kept,
    at low weight. Keys elsewhere in the JSON are ignored.
    """
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return
    if not isinstance(data, dict):
        return
    context_keys = {"params", "param", "query", "querystring", "query_params", "search", "url_params"}
    stack: list[tuple[object, str]] = [(data, "")]
    while stack:
        node, path = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and key.lower() in context_keys and isinstance(value, dict):
                    for pname in value.keys():
                        if not isinstance(pname, str) or len(pname) > 80:
                            continue
                        source = SourceRef(
                            kind=DiscoverySourceKind.JSON,
                            location=f"{base_ctx} [embedded JSON]",
                            context=(
                                f"parameter name {pname!r} inside JSON key "
                                f"{key!r} (heuristic; plausibly a URL parameter)"
                            ),
                            weight=0.4,
                        )
                        collector.add_evidence(page_endpoint, pname, source)
                elif key in ("params", "data", "options", "config", "defaults") and isinstance(value, dict):
                    stack.append((value, f"{path}.{key}"))
                elif isinstance(value, dict):
                    # one level deeper only, to bound the search
                    stack.append((value, f"{path}.{key}"))
        elif isinstance(node, list) and len(node) < 25:
            for item in node:
                if isinstance(item, dict):
                    stack.append((item, path))
