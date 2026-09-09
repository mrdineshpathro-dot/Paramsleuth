"""Single-response feature extraction and behavioral-change decisions.

Every decision is explainable: a finding records which concrete dimensions
changed (status, redirect target, content type, size, title, visible text,
tag structure, JSON shape) and how it compares to the endpoint's own baseline
variation and to an unrelated random-parameter control.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from ..http_client import ResponseInfo
from ..models import DiffObservation
from .normalize import (
    json_structure_digest,
    normalize_dynamic_text,
    page_title,
    quick_hash,
    structure_digest,
    text_similarity,
    visible_text,
)
from .reflect import ReflectionInfo, detect_reflection


@dataclass
class ResponseFeatures:
    status: int | None
    destination_key: str  # scheme://host[:port]/path of the *final* response
    location: str  # raw Location header (redacted later if needed)
    content_type: str
    size: int
    truncated: bool
    title: str
    text_hash: str
    normalized_text: str
    structure: str
    json_digest: str | None
    body: str  # decoded body (used for reflection checks only)
    reflection: ReflectionInfo

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "destination_key": self.destination_key,
            "location": self.location,
            "content_type": self.content_type,
            "size": self.size,
            "truncated": self.truncated,
            "title": self.title,
        }


def _destination_key(resp: ResponseInfo) -> str:
    from ..urlutils import endpoint_key

    return endpoint_key(resp.final_url or "")


def features_of_response(resp: ResponseInfo, canary: str = "") -> ResponseFeatures:
    body = resp.text
    json_digest = json_structure_digest(body)
    title = page_title(body) if "html" in resp.content_type else ""
    # Normalize volatile content (timestamps, counters, tokens) *before*
    # hashing and similarity so dynamic pages do not look "changed".
    normalized = normalize_dynamic_text(visible_text(body))
    return ResponseFeatures(
        status=resp.status_code,
        destination_key=_destination_key(resp),
        location=resp.header("location"),
        content_type=resp.content_type,
        size=len(resp.body),
        truncated=resp.truncated,
        title=title,
        text_hash=quick_hash(normalized),
        normalized_text=normalized,
        structure=structure_digest(body) if "html" in resp.content_type else "",
        json_digest=json_digest,
        body=body,
        reflection=detect_reflection(body, canary, content_type=resp.content_type),
    )


@dataclass
class BaselineModel:
    """Statistics describing ordinary response variation of an endpoint."""

    statuses: list[int] = field(default_factory=list)
    sizes: list[int] = field(default_factory=list)
    text_hashes: list[str] = field(default_factory=list)
    titles: list[str] = field(default_factory=list)
    structures: list[str] = field(default_factory=list)
    json_digests: list[str] = field(default_factory=list)
    content_types: list[str] = field(default_factory=list)
    destinations: list[str] = field(default_factory=list)
    samples: list[ResponseFeatures] = field(default_factory=list)
    unstable: bool = False
    instability_reason: str = ""

    @property
    def median_size(self) -> float:
        return float(statistics.median(self.sizes)) if self.sizes else 0.0

    @property
    def size_spread(self) -> float:
        """Relative spread (max-min)/mean of baseline body sizes."""
        if len(self.sizes) < 2 or not self.sizes:
            return 0.0
        mean = statistics.mean(self.sizes) or 1.0
        return (max(self.sizes) - min(self.sizes)) / mean

    @property
    def most_common_status(self) -> int | None:
        if not self.statuses:
            return None
        return max(set(self.statuses), key=self.statuses.count)


def build_baseline(features: list[ResponseFeatures], cfg: Config) -> BaselineModel:
    """Aggregate baseline samples and judge environment stability."""
    model = BaselineModel(
        statuses=[f.status or 0 for f in features],
        sizes=[f.size for f in features],
        text_hashes=[f.text_hash for f in features],
        titles=[f.title for f in features],
        structures=[f.structure for f in features],
        json_digests=[f.json_digest or "" for f in features],
        content_types=[f.content_type for f in features],
        destinations=[f.destination_key for f in features],
        samples=features,
    )
    reasons: list[str] = []
    if len(features) >= 2:
        if model.size_spread > cfg.max_baseline_spread:
            reasons.append(
                f"baseline body sizes vary too widely "
                f"(spread {model.size_spread:.0%} > {cfg.max_baseline_spread:.0%})"
            )
        if len(set(model.statuses)) > 1:
            reasons.append(f"baseline HTTP statuses differ: {sorted(set(model.statuses))}")
        if len(set(model.text_hashes)) > 1:
            reasons.append("baseline normalized visible text differs between samples")
        if len(set(model.destinations)) > 1:
            reasons.append("baseline redirect destinations differ between samples")
    if len(features) < 2:
        reasons.append("fewer than two baseline samples collected")
    if reasons:
        model.unstable = True
        model.instability_reason = "; ".join(reasons[:3])
    return model


def _delta_size(baseline: BaselineModel, feat: ResponseFeatures) -> tuple[int, float]:
    base = baseline.median_size
    diff = abs(feat.size - base)
    ratio = diff / base if base else 0.0
    return diff, ratio


def decide_probe_difference(
    baseline: BaselineModel,
    probe: ResponseFeatures,
    control: ResponseFeatures | None,
    cfg: Config,
) -> tuple[list[DiffObservation], bool]:
    """Return (observed differences, candidate_dominated_by_control).

    A difference counts only when it exceeds the endpoint's ordinary baseline
    variation *and* is not equally produced by the random-parameter control.
    """
    diffs: list[DiffObservation] = []
    dominated = False

    def changed_vs_control(own: bool, ctrl: bool) -> bool:
        nonlocal dominated
        if ctrl and not own:
            dominated = True
            return False
        return own

    # status
    base_status = baseline.most_common_status
    if probe.status is not None and base_status is not None and probe.status != base_status:
        ctrl_status_diff = control is not None and control.status is not None and control.status != base_status
        if changed_vs_control(True, bool(ctrl_status_diff)):
            diffs.append(
                DiffObservation("status", f"HTTP status changed from {base_status} to {probe.status}")
            )
    # redirect destination (never followed off scope)
    if probe.destination_key and base_status is not None and probe.destination_key not in baseline.destinations:
        ctrl_redirect = bool(control and control.destination_key not in baseline.destinations)
        if changed_vs_control(True, ctrl_redirect):
            target = probe.destination_key.replace("http://", "").replace("https://", "")
            diffs.append(DiffObservation("redirect", f"redirected to a different destination ({target})"))
    # content type
    if probe.content_type and baseline.content_types and probe.content_type not in baseline.content_types:
        ctrl_ct = bool(control and control.content_type not in baseline.content_types)
        if changed_vs_control(True, ctrl_ct):
            diffs.append(
                DiffObservation("content_type", f"content type changed to {probe.content_type}")
            )
    # size
    raw_diff, ratio = _delta_size(baseline, probe)
    size_changed = raw_diff >= cfg.min_size_diff_bytes and ratio >= cfg.min_size_diff_ratio
    if size_changed:
        ctrl_diff, ctrl_ratio = _delta_size(baseline, control) if control else (0, 0.0)
        ctrl_size_changed = ctrl_diff >= cfg.min_size_diff_bytes and ctrl_ratio >= cfg.min_size_diff_ratio
        if changed_vs_control(True, bool(ctrl_size_changed)):
            diffs.append(
                DiffObservation(
                    "size",
                    f"body size changed by {raw_diff:+d} bytes "
                    f"({ratio:+.0%} vs baseline median {int(baseline.median_size)})",
                )
            )
    # title
    if probe.title and baseline.titles and all(probe.title != t for t in baseline.titles):
        ctrl_title = bool(control and control.title and all(control.title != t for t in baseline.titles))
        if changed_vs_control(True, ctrl_title):
            diffs.append(DiffObservation("title", f"page title changed to {probe.title[:120]!r}"))
    # text / structure
    if probe.text_hash and baseline.text_hashes and probe.text_hash not in baseline.text_hashes:
        best_sim = max(
            (text_similarity(probe.normalized_text, s.normalized_text) for s in baseline.samples), default=1.0
        )
        ctrl_sim = 1.0
        if control is not None and control.normalized_text:
            ctrl_sim = max(
                (text_similarity(control.normalized_text, s.normalized_text) for s in baseline.samples),
                default=1.0,
            )
        if best_sim < cfg.similarity_threshold:
            text_changed = True
            ctrl_text_changed = ctrl_sim < cfg.similarity_threshold
            if changed_vs_control(text_changed, ctrl_text_changed):
                diffs.append(
                    DiffObservation(
                        "text",
                        f"normalized visible text changed "
                        f"(similarity to baseline {best_sim:.2f})",
                    )
                )
    if probe.structure and baseline.structures and probe.structure not in baseline.structures:
        ctrl_struct = bool(control and control.structure and control.structure not in baseline.structures)
        if changed_vs_control(True, ctrl_struct):
            diffs.append(DiffObservation("structure", "HTML tag structure changed"))
    if probe.json_digest and baseline.json_digests and probe.json_digest not in baseline.json_digests:
        ctrl_json = bool(
            control and control.json_digest and control.json_digest not in baseline.json_digests
        )
        if changed_vs_control(True, ctrl_json):
            diffs.append(DiffObservation("json", "JSON document structure changed"))
    return diffs, dominated
