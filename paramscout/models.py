"""Shared data models used across ParamScout."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ScanMode(str, Enum):
    """The kind of run being executed."""

    EXTRACT = "extract"  # offline: analyze collected URLs / local files only
    SCAN = "scan"  # passive and/or active network discovery


class DiscoverySourceKind(str, Enum):
    """Provenance of a discovered parameter candidate."""

    QUERY = "query"  # parameter observed in a real URL query string
    HTML_LINK = "html_link"  # parameter observed in an HTML link query string
    FORM = "form"  # form field name (including hidden fields)
    JS = "javascript"  # heuristic from JavaScript
    JSON = "json_config"  # embedded JSON/configuration object
    ROBOTS = "robots"  # robots.txt (endpoints / sitemap URLs)
    SITEMAP = "sitemap"  # sitemap.xml (endpoints / query params)
    USER_FILE = "user_url_archive"  # user-supplied URL archive / endpoint list
    BUILTIN_WORDLIST = "builtin_wordlist"  # conservative built-in parameter list
    USER_WORDLIST = "user_wordlist"  # user-supplied wordlist
    UNKNOWN = "unknown"


@dataclass
class SourceRef:
    """One piece of evidence that a parameter name exists/behaves a certain way."""

    kind: DiscoverySourceKind
    location: str = ""  # redacted URL / file the evidence came from
    context: str = ""  # redacted snippet or field context
    method: str = ""  # form method when relevant (e.g. GET/POST)
    # Evidence weight 0..1 used only to derive the explainable discovery score.
    weight: float = 0.5

    def as_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind.value,
            "location": self.location,
            "context": self.context,
            "method": self.method,
        }


@dataclass
class Endpoint:
    """A stable endpoint (host + path, optionally host-only grouping)."""

    id: str  # stable, scoped key used by the state store
    key: str  # grouping key (scheme://host[:port]/path or host-only)
    url: str  # full URL used for requests (may carry an original query)
    host: str  # hostname (lowercase)
    netloc: str  # host[:port]
    source: str = ""  # how it was discovered (seed, crawl, sitemap, ...)
    is_seed: bool = False
    virtual: bool = False  # True for local-file endpoints (extract mode only)
    # Query present on the discovered page URL (kept for realistic baselines).
    base_query: list[tuple[str, str]] = field(default_factory=list)

    @property
    def probe_base(self) -> str:
        """URL without the *discovered* query: used to attach probe params."""
        return self.url.split("?", 1)[0]

    def identity(self) -> str:
        return self.id


@dataclass
class Candidate:
    """A parameter candidate attached to a specific endpoint."""

    endpoint_id: str
    name: str  # decoded parameter name, case/encoding preserved
    sources: list[SourceRef] = field(default_factory=list)
    category: str = "unknown/general-purpose"
    discovery_score: float = 0.0
    security_relevant: bool = False
    rarity: float = 1.0  # 1.0 = never seen on other endpoints; lower = common

    def merge_source(self, source: SourceRef) -> None:
        # Deduplicate identical evidence while preserving all provenance.
        for existing in self.sources:
            if (
                existing.kind == source.kind
                and existing.location == source.location
                and existing.context == source.context
            ):
                return
        self.sources.append(source)


@dataclass
class DiffObservation:
    """One concrete, explainable observed difference for a probe."""

    kind: str  # status|redirect|content_type|size|title|text|structure|json|other
    detail: str = ""  # redacted description

    def as_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "detail": self.detail}


@dataclass
class ProbeResult:
    """Outcome of probing a single candidate parameter on an endpoint."""

    param: str
    canary: str
    http_status: int | None = None
    final_url: str = ""  # redacted
    observed_diffs: list[DiffObservation] = field(default_factory=list)
    reflected: bool = False
    reflect_contexts: list[str] = field(default_factory=list)
    control_similar: bool = True
    unstable_baseline: bool = False
    reproduced: bool | None = None  # True/False after individual re-validation
    error: str | None = None
    attempts: int = 0  # total HTTP requests for this candidate incl. re-test
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "param": self.param,
            "canary": self.canary,
            "http_status": self.http_status,
            "final_url": self.final_url,
            "observed_diffs": [d.as_dict() for d in self.observed_diffs],
            "reflected": self.reflected,
            "reflect_contexts": self.reflect_contexts,
            "control_similar": self.control_similar,
            "unstable_baseline": self.unstable_baseline,
            "reproduced": self.reproduced,
            "error": self.error,
            "attempts": self.attempts,
            "notes": self.notes,
        }


@dataclass
class Finding:
    """The unified record emitted for every reported candidate."""

    endpoint: Endpoint
    param: str
    category: str
    # Explainable confidence values (0..1) plus human labels.
    discovery_score: float = 0.0
    discovery_label: str = "low"
    behavior_score: float | None = None
    behavior_label: str | None = None
    priority: str = "low"  # none|low|medium|high
    priority_reasons: list[str] = field(default_factory=list)
    probe: ProbeResult | None = None
    inconclusive: bool = False
    error: str | None = None
    limitations: list[str] = field(default_factory=list)
    source_summary: list[SourceRef] = field(default_factory=list)


# Priority / confidence labels -------------------------------------------------

def score_to_label(score: float | None) -> str:
    """Turn a 0..1 score into a coarse label (used in reports)."""
    if score is None:
        return "not-tested"
    if score >= 0.75:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def priority_rank(priority: str) -> int:
    return {"none": 0, "low": 1, "medium": 2, "high": 3}.get(priority, 0)
