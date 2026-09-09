"""Core data model shared by every ParamScout stage.

The model deliberately keeps three confidences apart:

``discovery_confidence``
    How sure are we that this parameter *exists* on this endpoint?  Driven by
    provenance only (real URL, form field, target JS, wordlist guess ...).

``behavioral_confidence``
    How sure are we that setting the parameter *changes the response*, based on
    repeatable measurements against baselines and a control?

``review_priority``
    A human triage ordering, with a machine-readable list of reasons.

None of these is a vulnerability severity and none of them implies one.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class SourceKind(StrEnum):
    """Where a parameter candidate came from."""

    URL_QUERY = "url_query"
    HTML_LINK = "html_link"
    HTML_FORM_FIELD = "html_form_field"
    HTML_ATTRIBUTE = "html_attribute"
    JS_INLINE = "js_inline"
    JS_EXTERNAL = "js_external"
    JSON_BLOB = "json_blob"
    ROBOTS = "robots_txt"
    SITEMAP = "sitemap_xml"
    ARCHIVE = "archive"
    WORDLIST = "wordlist"
    PAGE_DERIVED = "page_derived"
    CONTROL = "control"


#: Baseline trust in each source.  A parameter seen in a real query string is
#: nearly certain to exist; a wordlist guess is nearly certain not to be
#: target-specific.
SOURCE_CONFIDENCE: dict[SourceKind, float] = {
    SourceKind.URL_QUERY: 0.95,
    SourceKind.HTML_FORM_FIELD: 0.9,
    SourceKind.ARCHIVE: 0.85,
    SourceKind.HTML_LINK: 0.8,
    SourceKind.SITEMAP: 0.7,
    SourceKind.ROBOTS: 0.65,
    SourceKind.JSON_BLOB: 0.6,
    SourceKind.JS_INLINE: 0.6,
    SourceKind.JS_EXTERNAL: 0.6,
    SourceKind.HTML_ATTRIBUTE: 0.55,
    SourceKind.PAGE_DERIVED: 0.4,
    SourceKind.WORDLIST: 0.08,
    SourceKind.CONTROL: 0.0,
}


class BehavioralStatus(StrEnum):
    """Outcome of active validation for one (endpoint, parameter) pair."""

    NOT_TESTED = "not_tested"
    NO_CHANGE = "no_change"
    REFLECTION_ONLY = "reflection_only"
    BEHAVIORAL_CHANGE = "behavioral_change"
    BEHAVIORAL_CHANGE_UNCONFIRMED = "behavioral_change_unconfirmed"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"
    SKIPPED = "skipped"


class CandidateStatus(StrEnum):
    """Lifecycle of a candidate inside a scan."""

    DISCOVERED = "discovered"
    QUEUED = "queued"
    PROBED = "probed"
    CONFIRMED = "confirmed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class Evidence:
    """A single provenance record for a candidate parameter.

    ``origin`` is where the evidence was *observed* (the page, script or file).
    ``target`` is the URL the parameter actually *belongs to* when that is
    known - a link href, a form action, a ``fetch()`` URL.  They differ
    constantly: an ``<a href="/profile?note=x">`` on ``/`` yields a parameter
    for ``/profile``, not for ``/``.
    """

    kind: SourceKind
    origin: str
    detail: str = ""
    context: str = ""
    line: int | None = None
    confidence: float | None = None
    target: str = ""

    @property
    def effective_confidence(self) -> float:
        if self.confidence is not None:
            return self.confidence
        return SOURCE_CONFIDENCE.get(self.kind, 0.2)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["kind"] = self.kind.value
        data["confidence"] = round(self.effective_confidence, 3)
        return data


@dataclass
class Candidate:
    """A parameter name observed (or guessed) for one endpoint."""

    endpoint: str
    name: str
    evidence: list[Evidence] = field(default_factory=list)
    observed_values: list[str] = field(default_factory=list)
    form_methods: list[str] = field(default_factory=list)
    status: CandidateStatus = CandidateStatus.DISCOVERED
    first_seen_order: int = 0

    @property
    def sources(self) -> list[SourceKind]:
        seen: list[SourceKind] = []
        for item in self.evidence:
            if item.kind not in seen:
                seen.append(item.kind)
        return seen

    def add_evidence(self, evidence: Evidence) -> None:
        self.evidence.append(evidence)
        if evidence.kind is SourceKind.HTML_FORM_FIELD and evidence.detail:
            method = evidence.detail.split(":", 1)[0].upper()
            if method and method not in self.form_methods:
                self.form_methods.append(method)

    @property
    def key(self) -> tuple[str, str]:
        return (self.endpoint, self.name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "name": self.name,
            "sources": [kind.value for kind in self.sources],
            "evidence": [item.to_dict() for item in self.evidence],
            "observed_values": list(self.observed_values),
            "form_methods": list(self.form_methods),
            "status": self.status.value,
        }


@dataclass
class PageFingerprint:
    """Comparable, normalized summary of one HTTP response."""

    status: int
    content_type: str
    length: int
    title: str
    text_hash: str
    structure_hash: str
    json_keys_hash: str
    location: str
    elapsed_ms: float = 0.0
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ResponseDelta:
    """Difference between two :class:`PageFingerprint` values."""

    status_changed: bool = False
    content_type_changed: bool = False
    location_changed: bool = False
    title_changed: bool = False
    structure_changed: bool = False
    json_changed: bool = False
    text_similarity: float = 1.0
    length_delta: int = 0
    length_ratio: float = 0.0
    signals: list[str] = field(default_factory=list)
    details: dict[str, str] = field(default_factory=dict)

    @property
    def magnitude(self) -> float:
        """A single 0..1-ish score summarising how different two pages are."""

        score = 0.0
        if self.status_changed:
            score += 0.5
        if self.content_type_changed:
            score += 0.3
        if self.location_changed:
            score += 0.3
        if self.title_changed:
            score += 0.25
        if self.structure_changed:
            score += 0.3
        if self.json_changed:
            score += 0.25
        score += max(0.0, (1.0 - self.text_similarity)) * 0.6
        score += min(0.3, self.length_ratio)
        return round(score, 4)

    @property
    def changed(self) -> bool:
        return bool(self.signals)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProbeResult:
    """One probe: the request we made and how it compared to the baseline."""

    parameter: str
    canary: str
    url: str
    status: int | None
    error: str | None = None
    delta: ResponseDelta | None = None
    reflection: ReflectionInfo | None = None
    batch: bool = False
    attempt: int = 1


@dataclass
class ReflectionInfo:
    """Exact-canary reflection, tracked *separately* from behaviour change."""

    reflected: bool
    occurrences: int
    locations: list[str] = field(default_factory=list)
    html_encoded_variant: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BehavioralResult:
    """Aggregate active-validation outcome for one (endpoint, parameter)."""

    status: BehavioralStatus
    confidence: float
    attempts: int
    signals: list[str] = field(default_factory=list)
    deltas: list[dict[str, Any]] = field(default_factory=list)
    reflection: ReflectionInfo | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "confidence": round(self.confidence, 3),
            "attempts": self.attempts,
            "signals": list(self.signals),
            "deltas": list(self.deltas),
            "reflection": self.reflection.to_dict() if self.reflection else None,
            "notes": list(self.notes),
        }


@dataclass
class Finding:
    """A reportable (endpoint, parameter) result."""

    endpoint: str
    parameter: str
    category: str
    category_reason: str
    sources: list[str]
    evidence: list[Evidence]
    discovery_confidence: float
    discovery_reasons: list[str]
    behavioral: BehavioralResult | None
    behavioral_confidence: float
    review_priority: int
    priority_reasons: list[str]
    status: CandidateStatus
    observed_values: list[str] = field(default_factory=list)
    form_methods: list[str] = field(default_factory=list)
    reproduction: str = ""
    errors: list[str] = field(default_factory=list)
    inconclusive: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "category": self.category,
            "category_reason": self.category_reason,
            "sources": list(self.sources),
            "evidence": [item.to_dict() for item in self.evidence],
            "discovery_confidence": round(self.discovery_confidence, 3),
            "discovery_reasons": list(self.discovery_reasons),
            "behavioral": self.behavioral.to_dict() if self.behavioral else None,
            "behavioral_confidence": round(self.behavioral_confidence, 3),
            "review_priority": self.review_priority,
            "priority_reasons": list(self.priority_reasons),
            "status": self.status.value,
            "observed_values": list(self.observed_values),
            "form_methods": list(self.form_methods),
            "reproduction": self.reproduction,
            "errors": list(self.errors),
            "inconclusive": self.inconclusive,
        }


@dataclass
class ThrottleEvent:
    """A rate-limit / server-overload observation."""

    host: str
    status: int
    url: str
    action: str
    retry_after: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanStats:
    """Counters shown in every report."""

    requests_total: int = 0
    requests_by_purpose: dict[str, int] = field(default_factory=dict)
    requests_by_status: dict[str, int] = field(default_factory=dict)
    retries: int = 0
    throttle_events: list[ThrottleEvent] = field(default_factory=list)
    skipped_off_scope: list[str] = field(default_factory=list)
    skipped_budget: int = 0
    skipped_excluded: int = 0
    transport_errors: int = 0
    truncated_responses: int = 0
    endpoints_seen: int = 0
    candidates_total: int = 0
    elapsed_seconds: float = 0.0
    interrupted: bool = False

    def record_request(self, purpose: str, status: int | None, error: str | None) -> None:
        self.requests_total += 1
        self.requests_by_purpose[purpose] = self.requests_by_purpose.get(purpose, 0) + 1
        if error:
            self.transport_errors += 1
            key = "error"
        else:
            key = str(status)
        self.requests_by_status[key] = self.requests_by_status.get(key, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["throttle_events"] = [event.to_dict() for event in self.throttle_events]
        return data


def to_json(value: Any, **kwargs: Any) -> str:
    """``json.dumps`` with enum and dataclass support."""

    def default(obj: Any) -> Any:
        if isinstance(obj, StrEnum):
            return obj.value
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        if hasattr(obj, "__dict__"):
            return asdict(obj)
        return str(obj)

    return json.dumps(value, indent=2, default=default, **kwargs)
