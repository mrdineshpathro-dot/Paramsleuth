"""Baseline collection and differential assessment.

The method, per endpoint:

1. Request the endpoint several times *unchanged*.  Whatever differs between
   those responses is ordinary variation (timestamps, tokens, ads, cache
   misses) and can never count as evidence.
2. Request the endpoint with one **unrelated random parameter**
   (``psctrlXXXX=pscXXXX``).  That is the control: it measures what the
   application does to *any* unexpected query string.  Many apps redirect,
   strip, log or re-render on unknown parameters, and that reaction must not
   be credited to the parameter under test.
3. Only a candidate whose difference exceeds both the baseline variation and
   the control reaction is treated as a behavioural change.

If the baselines do not agree with each other, the endpoint is marked unstable
and every result from it becomes *inconclusive* rather than a finding.
"""

from __future__ import annotations

import itertools
import secrets
from dataclasses import dataclass, field

from paramscout.analysis.normalization import (
    NormalizerConfig,
    compare_fingerprints,
    fingerprint_response,
    normalize_document,
)
from paramscout.http_client import FetchOptions, FetchResult, ParamScoutClient
from paramscout.models import PageFingerprint, ResponseDelta
from paramscout.urls import build_url, parse_query

#: Above this much ordinary variation we refuse to conclude anything.
UNSTABLE_MAGNITUDE = 0.30
UNSTABLE_SIMILARITY = 0.92


@dataclass
class BaselineSample:
    """One baseline response."""

    fingerprint: PageFingerprint
    text: str
    url: str
    error: str | None = None


@dataclass
class BaselineSet:
    """All baselines for one endpoint plus the derived noise floor."""

    endpoint: str
    url: str
    samples: list[BaselineSample] = field(default_factory=list)
    noise_magnitude: float = 0.0
    min_similarity: float = 1.0
    max_length_ratio: float = 0.0
    statuses: set[int] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return len([sample for sample in self.samples if sample.error is None]) >= 2

    @property
    def stable(self) -> bool:
        return self.usable and self.noise_magnitude < UNSTABLE_MAGNITUDE and self.min_similarity > UNSTABLE_SIMILARITY

    @property
    def fingerprints(self) -> list[PageFingerprint]:
        return [sample.fingerprint for sample in self.samples if sample.error is None]

    def primary(self) -> BaselineSample | None:
        for sample in self.samples:
            if sample.error is None:
                return sample
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "url": self.url,
            "samples": len(self.samples),
            "usable": self.usable,
            "stable": self.stable,
            "noise_magnitude": self.noise_magnitude,
            "min_similarity": self.min_similarity,
            "max_length_ratio": self.max_length_ratio,
            "statuses": sorted(self.statuses),
            "notes": list(self.notes),
        }


@dataclass
class ControlResult:
    """The unrelated-random-parameter control measurement."""

    parameter: str
    canary: str
    url: str
    delta: ResponseDelta | None
    error: str | None = None
    reflected: bool = False

    @property
    def magnitude(self) -> float:
        return self.delta.magnitude if self.delta else 0.0

    @property
    def reacts_to_unknown_parameters(self) -> bool:
        return bool(self.delta and self.delta.changed)

    def to_dict(self) -> dict[str, object]:
        return {
            "parameter": self.parameter,
            "url": self.url,
            "magnitude": self.magnitude,
            "signals": list(self.delta.signals) if self.delta else [],
            "error": self.error,
            "reflected": self.reflected,
        }


@dataclass
class DeltaAssessment:
    """Whether a candidate's difference is meaningful."""

    significant: bool
    signals: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def make_canary(prefix: str = "psc") -> str:
    """A safe, alphanumeric-only canary value.

    Alphanumeric by design: it cannot form a payload, cannot break out of a
    quoted context, and any reflection of it is unambiguous.
    """

    return f"{prefix}{secrets.token_hex(5)}"


def make_control_parameter(prefix: str = "psctrl") -> str:
    """A parameter name that is vanishingly unlikely to exist on the target."""

    return f"{prefix}{secrets.token_hex(4)}"


def _sample_from_result(
    result: FetchResult, config: NormalizerConfig
) -> BaselineSample:
    if result.error is not None:
        return BaselineSample(
            fingerprint=PageFingerprint(
                status=0,
                content_type="",
                length=0,
                title="",
                text_hash="",
                structure_hash="",
                json_keys_hash="",
                location="",
            ),
            text="",
            url=result.final_url,
            error=result.error,
        )
    fingerprint = fingerprint_response(
        status=result.status or 0,
        headers=result.headers,
        body=result.body,
        content_type=result.content_type,
        truncated=result.truncated,
        elapsed_ms=result.elapsed_ms,
        config=config,
    )
    document = normalize_document(
        result.text, content_type=result.content_type, config=config
    )
    return BaselineSample(fingerprint=fingerprint, text=document.text, url=result.final_url)


async def collect_baseline(
    client: ParamScoutClient,
    url: str,
    endpoint: str,
    *,
    count: int,
    config: NormalizerConfig | None = None,
) -> BaselineSet:
    """Fetch *url* ``count`` times and characterise ordinary variation."""

    config = config or NormalizerConfig()
    baseline = BaselineSet(endpoint=endpoint, url=url)
    for index in range(max(2, count)):
        result = await client.fetch(
            url, FetchOptions(purpose="baseline", endpoint=endpoint, use_credentials=True)
        )
        sample = _sample_from_result(result, config)
        baseline.samples.append(sample)
        if result.error is not None:
            baseline.notes.append(f"baseline {index + 1} failed: {result.error}")
        else:
            baseline.statuses.add(result.status or 0)

    good = [sample for sample in baseline.samples if sample.error is None]
    if len(good) >= 2:
        for left, right in itertools.combinations(good, 2):
            delta = compare_fingerprints(
                left.fingerprint, right.fingerprint, baseline_text=left.text, candidate_text=right.text
            )
            baseline.noise_magnitude = max(baseline.noise_magnitude, delta.magnitude)
            baseline.min_similarity = min(baseline.min_similarity, delta.text_similarity)
            baseline.max_length_ratio = max(baseline.max_length_ratio, delta.length_ratio)
        if len(baseline.statuses) > 1:
            baseline.notes.append(
                f"baseline status codes varied across identical requests: {sorted(baseline.statuses)}"
            )
            baseline.noise_magnitude = max(baseline.noise_magnitude, 0.5)
        if baseline.noise_magnitude >= UNSTABLE_MAGNITUDE:
            baseline.notes.append(
                f"endpoint responses vary by {baseline.noise_magnitude:.2f} between identical requests"
            )
        if baseline.min_similarity <= UNSTABLE_SIMILARITY:
            baseline.notes.append(
                f"identical requests only agree {baseline.min_similarity:.2%} on normalized text"
            )
    else:
        baseline.notes.append("fewer than two usable baselines; endpoint cannot be assessed")
    return baseline


def _existing_pairs(base_url: str) -> list[tuple[str, str]]:
    return [
        (pair.name, pair.value)
        for pair in parse_query(base_url.split("?", 1)[1] if "?" in base_url else "")
    ]


def build_probe_url(base_url: str, parameter: str, canary: str, *, max_length: int = 2000) -> str | None:
    """Set ``parameter`` to *canary* on *base_url*, preserving other pairs.

    Existing occurrences of *parameter* are **replaced**, not appended to.
    Appending would leave the endpoint reading its original value
    (``?note=hello&note=canary`` is read as ``hello`` by most frameworks) and
    the probe would silently test nothing.

    Returns ``None`` when the result would exceed *max_length*.
    """

    pairs = [pair for pair in _existing_pairs(base_url) if pair[0] != parameter]
    pairs.append((parameter, canary))
    candidate = build_url(base_url, pairs)
    if len(candidate) > max_length:
        return None
    return candidate


def build_batch_probe_url(
    base_url: str, assignments: list[tuple[str, str]], *, max_length: int = 2000
) -> tuple[str | None, list[tuple[str, str]]]:
    """Build one URL carrying several ``name=distinct_canary`` pairs.

    Pairs that would push the URL past *max_length* are dropped and reported so
    the caller can fall back to individual probes for them.
    """

    base_pairs = [
        pair
        for pair in _existing_pairs(base_url)
        if pair[0] not in {name for name, _ in assignments}
    ]
    included: list[tuple[str, str]] = []
    for name, canary in assignments:
        trial = build_url(base_url, base_pairs + included + [(name, canary)])
        if len(trial) > max_length:
            continue
        included.append((name, canary))
    if not included:
        return None, []
    return build_url(base_url, base_pairs + included), included


async def measure_control(
    client: ParamScoutClient,
    baseline: BaselineSet,
    *,
    config: NormalizerConfig | None = None,
    canary_prefix: str = "psc",
    max_url_length: int = 2000,
) -> ControlResult:
    """Send one request with an unrelated random parameter."""

    config = config or NormalizerConfig()
    control_name = make_control_parameter()
    canary = make_canary(canary_prefix)
    url = build_probe_url(baseline.url, control_name, canary, max_length=max_url_length)
    if url is None:
        return ControlResult(
            parameter=control_name, canary=canary, url=baseline.url, delta=None, error="URL length limit"
        )
    result = await client.fetch(url, FetchOptions(purpose="control", endpoint=baseline.endpoint))
    if result.error is not None:
        return ControlResult(
            parameter=control_name, canary=canary, url=url, delta=None, error=result.error
        )
    sample = _sample_from_result(result, config)
    primary = baseline.primary()
    delta = None
    if primary is not None:
        delta = compare_fingerprints(
            primary.fingerprint, sample.fingerprint, baseline_text=primary.text, candidate_text=sample.text
        )
    from paramscout.analysis.normalization import check_reflection

    reflection = check_reflection(result.body, canary)
    return ControlResult(
        parameter=control_name,
        canary=canary,
        url=url,
        delta=delta,
        reflected=reflection.reflected,
    )


def assess_delta(
    delta: ResponseDelta,
    baseline: BaselineSet,
    control: ControlResult | None,
) -> DeltaAssessment:
    """Decide whether *delta* is real evidence or ordinary noise.

    Each signal has to clear **both** the baseline variation and the control
    reaction before it counts.
    """

    signals: list[str] = []
    reasons: list[str] = []
    control_delta = control.delta if control else None

    if not baseline.stable:
        return DeltaAssessment(
            significant=False,
            signals=[],
            reasons=["baseline responses are not stable enough to attribute a change to this parameter"],
        )

    # -- status ----------------------------------------------------------
    if delta.status_changed:
        control_status_changed = bool(control_delta and control_delta.status_changed)
        if len(baseline.statuses) <= 1 and not control_status_changed:
            signals.append(f"HTTP status changed ({delta.details.get('status', 'n/a')})")
            reasons.append("status differs from every baseline and from the control request")
        else:
            reasons.append("status also varies in baselines or under the control parameter - ignored")

    # -- title ------------------------------------------------------------
    if delta.title_changed:
        control_title_changed = bool(control_delta and control_delta.title_changed)
        if not control_title_changed:
            signals.append("page title changed")
            reasons.append("title is stable across baselines and the control request")
        else:
            reasons.append("title also changes for the control parameter - ignored")

    # -- structure ---------------------------------------------------------
    if delta.structure_changed:
        control_structure_changed = bool(control_delta and control_delta.structure_changed)
        if not control_structure_changed:
            signals.append("DOM structure changed")
            reasons.append("tag sequence is stable across baselines and the control request")
        else:
            reasons.append("structure also changes for the control parameter - ignored")

    # -- JSON structure ------------------------------------------------------
    if delta.json_changed:
        control_json_changed = bool(control_delta and control_delta.json_changed)
        if not control_json_changed:
            signals.append("JSON key structure changed")
            reasons.append("JSON shape is stable across baselines and the control request")

    # -- redirect location -----------------------------------------------------
    if delta.location_changed:
        control_location_changed = bool(control_delta and control_delta.location_changed)
        if not control_location_changed:
            signals.append(f"redirect Location changed ({delta.details.get('location', 'n/a')})")
            reasons.append("Location header is stable across baselines and the control request")
        else:
            reasons.append("redirect target also changes for the control parameter - ignored")

    # -- content type -----------------------------------------------------------
    if delta.content_type_changed:
        control_ctype_changed = bool(control_delta and control_delta.content_type_changed)
        if not control_ctype_changed:
            signals.append("content-type changed")
            reasons.append("content-type is stable across baselines and the control request")

    # -- text similarity ------------------------------------------------------------
    similarity_threshold = min(baseline.min_similarity, control_delta.text_similarity if control_delta else 1.0) - 0.02
    if delta.text_similarity < similarity_threshold:
        signals.append(f"normalized text similarity dropped to {delta.text_similarity:.3f}")
        reasons.append(
            f"text similarity {delta.text_similarity:.3f} is below the noise floor "
            f"{similarity_threshold:.3f} (baseline/control)"
        )
    elif delta.text_similarity < 0.999:
        reasons.append(
            f"text similarity {delta.text_similarity:.3f} is within baseline/control variation "
            f"({similarity_threshold:.3f})"
        )

    # -- body size ------------------------------------------------------------------
    length_floor = max(0.02, baseline.max_length_ratio * 1.5)
    control_length_ratio = control_delta.length_ratio if control_delta else 0.0
    if delta.length_ratio >= length_floor and abs(delta.length_delta) >= 32 and delta.length_ratio > control_length_ratio:
        signals.append(f"body size changed by {delta.length_delta:+d} bytes")
        reasons.append(
            f"size change {delta.length_ratio:.1%} exceeds baseline floor {length_floor:.1%} and "
            f"control {control_length_ratio:.1%}"
        )
    elif delta.length_ratio > 0:
        reasons.append(
            f"size change {delta.length_ratio:.1%} is within baseline ({baseline.max_length_ratio:.1%}) "
            f"or control ({control_length_ratio:.1%}) variation"
        )

    if control and control.reacts_to_unknown_parameters and not signals:
        reasons.append(
            f"the application also reacts to the unrelated control parameter '{control.parameter}' "
            f"({', '.join(control.delta.signals[:2]) if control.delta else 'n/a'}), so generic "
            "query-string handling cannot be attributed to this parameter"
        )

    return DeltaAssessment(significant=bool(signals), signals=signals, reasons=reasons)


def _truncate(value: str, limit: int) -> str:
    if limit and len(value) > limit:
        return value[:limit]
    return value
