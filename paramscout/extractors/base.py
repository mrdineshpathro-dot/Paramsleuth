"""Core extraction types and the :class:`Collector` used to merge evidence.

The collector keeps all provenance: a candidate is unique per
``(endpoint_id, parameter name)`` and carries every source that evidenced it,
so reports can explain *why* a parameter was discovered.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Iterable

from ..models import Candidate, DiscoverySourceKind, Endpoint, SourceRef
from ..urlutils import append_params, endpoint_key, host_of, netloc_of, normalize_url, split_query

log = logging.getLogger("paramscout.extract")

# Single-evidence base weights used to derive the explainable discovery score.
SOURCE_WEIGHTS: dict[DiscoverySourceKind, float] = {
    DiscoverySourceKind.QUERY: 0.9,
    DiscoverySourceKind.HTML_LINK: 0.8,
    DiscoverySourceKind.FORM: 0.75,
    DiscoverySourceKind.JS: 0.6,  # adjusted by the JS extractor (strong/weak)
    DiscoverySourceKind.JSON: 0.4,
    DiscoverySourceKind.ROBOTS: 0.7,
    DiscoverySourceKind.SITEMAP: 0.7,
    DiscoverySourceKind.USER_FILE: 0.8,
    DiscoverySourceKind.BUILTIN_WORDLIST: 0.15,
    DiscoverySourceKind.USER_WORDLIST: 0.3,
    DiscoverySourceKind.UNKNOWN: 0.2,
}


@dataclass
class SourceEvidence:
    """A single piece of extraction evidence before it is merged."""

    param: str
    endpoint_id: str
    source: SourceRef


@dataclass
class ExtractionReport:
    """Counters describing one extraction pass (printed in dry-run/summary)."""

    urls_parsed: int = 0
    html_documents: int = 0
    js_documents: int = 0
    json_documents: int = 0
    files_scanned: int = 0
    candidates_found: int = 0
    endpoints_found: int = 0
    skipped_malformed: int = 0

    def merge(self, other: "ExtractionReport") -> None:
        for key in self.__dataclass_fields__:  # type: ignore[attr-defined]
            setattr(self, key, getattr(self, key) + getattr(other, key))


class Collector:
    """Accumulates endpoints and parameter candidates with full provenance."""

    def __init__(self, grouping: str = "path") -> None:
        if grouping not in ("path", "host"):
            raise ValueError("endpoint grouping must be 'path' or 'host'")
        self.grouping = grouping
        self.endpoints: dict[str, Endpoint] = {}
        self.candidates: dict[tuple[str, str], Candidate] = {}
        self.report = ExtractionReport()
        self._total_endpoint_count = 0  # includes URLs merged into same endpoint

    # ------------------------------------------------------------------
    def _endpoint_for(self, url: str, source: str, is_seed: bool = False) -> Endpoint | None:
        normalized = normalize_url(url)
        if not normalized:
            self.report.skipped_malformed += 1
            return None
        key = endpoint_key(normalized, grouping=self.grouping)
        if not key:
            return None
        from ..state import StateStore

        eid = StateStore.endpoint_id_for(key)
        self._total_endpoint_count += 1
        existing = self.endpoints.get(eid)
        if existing is not None:
            if is_seed and not existing.is_seed:
                existing.is_seed = True
                existing.source = source
            return existing
        endpoint = Endpoint(
            id=eid,
            key=key,
            url=normalized,
            host=host_of(normalized),
            netloc=netloc_of(normalized),
            source=source,
            is_seed=is_seed,
        )
        self.endpoints[eid] = endpoint
        self.report.endpoints_found += 1
        return endpoint

    # ------------------------------------------------------------------
    def record_endpoint(self, url: str, source: str, is_seed: bool = False) -> Endpoint | None:
        return self._endpoint_for(url, source, is_seed)

    def add_url_query(
        self,
        url: str,
        *,
        source_kind: DiscoverySourceKind = DiscoverySourceKind.QUERY,
        location: str = "",
    ) -> None:
        """Extract parameter candidates from a URL's query string."""
        endpoint = self._endpoint_for(url, source_kind.value, is_seed=False)
        if endpoint is None:
            return
        self.report.urls_parsed += 1
        norm = normalize_url(url)
        query = norm.split("?", 1)[1] if "?" in norm else ""
        if not query:
            return
        redacted_location = location or norm
        for name, _value in split_query(query):
            if not name:
                continue
            source = SourceRef(
                kind=source_kind,
                location=redacted_location,
                context=f"query parameter {name!r} observed in a real URL",
                weight=SOURCE_WEIGHTS[source_kind],
            )
            self._add_candidate(endpoint, name, source)

    def virtual_endpoint(self, label: str) -> Endpoint:
        """Create (once) a local-file endpoint used only by offline extract mode.

        Virtual endpoints never participate in scans or network requests.
        """
        from ..state import StateStore

        key = f"virtual:{label}"
        eid = StateStore.endpoint_id_for(key)
        existing = self.endpoints.get(eid)
        if existing is not None:
            return existing
        endpoint = Endpoint(
            id=eid,
            key=key,
            url=f"(local file) {label}",
            host="",
            netloc="",
            source="local file",
            is_seed=False,
            virtual=True,
        )
        self.endpoints[eid] = endpoint
        self.report.endpoints_found += 1
        return endpoint

    def add_evidence(self, endpoint: Endpoint, name: str, source: SourceRef) -> None:
        """Register one piece of evidence for a candidate on *endpoint*."""
        if not name:
            return
        self._add_candidate(endpoint, name, source)

    def add_wordlist(self, endpoint_ids: Iterable[str], names: Iterable[str], kind: DiscoverySourceKind) -> int:
        """Attach wordlist-derived candidates to endpoints (no requests)."""
        added = 0
        weight = SOURCE_WEIGHTS.get(kind, 0.3)
        for eid in endpoint_ids:
            endpoint = self.endpoints.get(eid)
            if endpoint is None:
                continue
            for raw in names:
                name = raw.strip()
                if not name or len(name) > 512 or "=" in name or "&" in name:
                    continue
                source = SourceRef(
                    kind=kind,
                    location=f"wordlist ({kind.value})",
                    context=f"parameter name from wordlist: {name}",
                    weight=weight,
                )
                self._add_candidate(endpoint, name, source)
                added += 1
        return added

    def _add_candidate(self, endpoint: Endpoint, name: str, source: SourceRef) -> None:
        key = (endpoint.id, name)
        candidate = self.candidates.get(key)
        if candidate is None:
            candidate = Candidate(endpoint_id=endpoint.id, name=name)
            self.candidates[key] = candidate
            self.report.candidates_found += 1
        candidate.merge_source(source)
        candidate.category, candidate.security_relevant = classify_hint(name)
        # Explainable discovery score: highest single-source weight, slightly
        # boosted by corroborating evidence, always < 1.0.
        weights = [s.weight for s in candidate.sources if s.weight]
        highest = max(weights) if weights else SOURCE_WEIGHTS[DiscoverySourceKind.UNKNOWN]
        boost = 1.0 + 0.03 * min(len(candidate.sources) - 1, 5)
        candidate.discovery_score = min(0.99, highest * boost)

    def finalize(self) -> None:
        """Compute rarity across the collected endpoint set and cap sizes."""
        total = len(self.endpoints) or 1
        seen_on: dict[str, int] = {}
        for (eid, name) in self.candidates:
            seen_on[name] = seen_on.get(name, 0) + 1
        for candidate in self.candidates.values():
            occurrences = seen_on.get(candidate.name, 1)
            candidate.rarity = max(0.0, 1.0 - (occurrences / total))

    def snapshot(self) -> tuple[list[Endpoint], list[Candidate]]:
        self.finalize()
        return list(self.endpoints.values()), list(self.candidates.values())


def classify_hint(name: str) -> tuple[str, bool]:
    """Return (category, security_relevant) hint for a parameter name.

    Parameter names are *only* hints: this never implies a vulnerability.
    """
    from ..analysis.classify import classify_parameter

    return classify_parameter(name)


def extract_query_params(query: str) -> list[str]:
    """Return decoded parameter names present in a query string."""
    return [name for name, _value in split_query(query) if name]


def param_context_snippet(text: str, needle: str, radius: int = 60) -> str:
    """Return a short context snippet around *needle* in *text* (for provenance)."""
    idx = text.lower().find(needle.lower())
    if idx == -1:
        idx = 0
    start = max(0, idx - radius)
    end = min(len(text), idx + len(needle) + radius)
    snippet = text[start:end].replace("\n", " ").replace("\r", " ")
    if start > 0:
        snippet = "..." + snippet
    if end < len(text):
        snippet = snippet + "..."
    return snippet


def sniff_document_type(path: str, sample: bytes) -> str:
    """Best-effort classification of a local file: html|js|json|urls|text."""
    lowered = path.lower()
    if lowered.endswith((".html", ".htm")):
        return "html"
    if lowered.endswith(".js") or lowered.endswith(".mjs"):
        return "js"
    if lowered.endswith((".json", ".har")):
        return "json"
    head = sample[:2048].decode("utf-8", "replace").lstrip()
    if head.startswith("<") and ("<html" in head[:512] or "<!doctype" in head[:256]):
        return "html"
    if head.startswith("{"):
        return "json"
    return "urls" if looks_like_url_list(sample[:8192].decode("utf-8", "replace")) else "text"


def looks_like_url_list(text: str) -> bool:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return False
    httpish = sum(1 for ln in lines if ln.startswith(("http://", "https://")))
    return httpish >= max(1, len(lines) // 2)


def load_urls_from_text(text: str) -> list[str]:
    """Extract candidate absolute http(s) URLs from free text.

    Understands plain URL-per-line lists as well as URLs embedded in HTML or
    other text (via a conservative regex). Percent-encoding is preserved.
    """
    import re

    from ..urlutils import is_absolute_http_url

    found: list[str] = []
    seen: set[str] = set()
    pattern = re.compile(r"https?://[^\s<>\"'()\[\]{}\\\^`]+", re.IGNORECASE)
    for match in pattern.finditer(text):
        url = match.group(0).rstrip(".,;:!?")
        url = unquote_repeats_safe(url)
        if not is_absolute_http_url(url):
            continue
        if url in seen:
            continue
        seen.add(url)
        found.append(url)
    return found


def unquote_repeats_safe(url: str) -> str:
    """Collapse nothing; only strip common trailing punctuation kept above."""
    return url


def decode_json(obj: bytes | str) -> dict | None:
    try:
        if isinstance(obj, bytes):
            obj = obj.decode("utf-8", "replace")
        return json.loads(obj)
    except (ValueError, TypeError):
        return None


def append_candidate_to_url(url: str, name: str, value: str) -> str:
    return append_params(url, [(name, value)])
