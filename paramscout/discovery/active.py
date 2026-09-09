"""Advanced (opt-in) active parameter discovery.

Guarded behind ``--active``.  Everything here is **GET-only**, uses
alphanumeric canaries, never submits a form and never sends an exploit payload.

Per endpoint the sequence is:

1. collect several unchanged baselines and measure ordinary variation;
2. send one request with an unrelated random control parameter;
3. probe candidates (one per request by default) inside the request budget;
4. re-test every promising candidate individually;
5. classify from repeatable evidence only.

Endpoints whose baselines disagree are reported as *inconclusive* instead of
producing findings, and endpoints matching the exclusion list are never probed
at all.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from paramscout.analysis.normalization import NormalizerConfig, check_reflection, compare_fingerprints
from paramscout.config import ActiveConfig
from paramscout.discovery.baseline import (
    BaselineSet,
    ControlResult,
    assess_delta,
    build_batch_probe_url,
    build_probe_url,
    collect_baseline,
    make_canary,
    measure_control,
)
from paramscout.http_client import FetchOptions, ParamScoutClient
from paramscout.models import (
    BehavioralResult,
    BehavioralStatus,
    Candidate,
    ResponseDelta,
    SourceKind,
)
from paramscout.redaction import redact_url
from paramscout.urls import split_url

DEFAULT_GET_ONLY_WARNING = (
    "Active discovery sends GET requests only, but GET endpoints can still have side "
    "effects (logging, cache poisoning, state changes on badly designed apps). "
    "Review --exclude-path before enabling --active."
)


@dataclass
class ProbeOutcome:
    """Full record of what happened for one (endpoint, parameter)."""

    parameter: str
    status: BehavioralStatus = BehavioralStatus.NOT_TESTED
    canary: str = ""
    attempts: int = 0
    deltas: list[ResponseDelta] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    reflection_count: int = 0
    reflected: bool = False
    probe_urls: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_behavioral(self) -> BehavioralResult:
        from paramscout.models import ReflectionInfo

        return BehavioralResult(
            status=self.status,
            confidence=0.0,  # filled in by the scoring layer
            attempts=self.attempts,
            signals=list(self.signals),
            deltas=[delta.to_dict() for delta in self.deltas],
            reflection=ReflectionInfo(
                reflected=self.reflected,
                occurrences=self.reflection_count,
                locations=["response body"] if self.reflected else [],
            ),
            notes=list(self.notes),
        )


@dataclass
class EndpointOutcome:
    """Everything learned about one endpoint during active discovery."""

    endpoint: str
    url: str
    baseline: BaselineSet | None = None
    control: ControlResult | None = None
    outcomes: dict[str, ProbeOutcome] = field(default_factory=dict)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    excluded: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "url": redact_url(self.url),
            "baseline": self.baseline.to_dict() if self.baseline else None,
            "control": self.control.to_dict() if self.control else None,
            "probed": [
                {
                    "parameter": outcome.parameter,
                    "status": outcome.status.value,
                    "attempts": outcome.attempts,
                    "signals": outcome.signals,
                    "notes": outcome.notes,
                    "reflected": outcome.reflected,
                }
                for outcome in self.outcomes.values()
            ],
            "skipped": [{"parameter": name, "reason": reason} for name, reason in self.skipped],
            "excluded": self.excluded,
            "notes": list(self.notes),
        }


def _signal_kind(signal: str) -> str:
    """Collapse a signal to its kind so repeated measurements do not pile up."""

    import re as _re

    return _re.sub(r"[0-9]+(?:\.[0-9]+)?", "#", signal.split(" (")[0])


def dedupe_signals(signals: list[str]) -> list[str]:
    """Keep the first occurrence of each signal kind, preserving order."""

    seen: set[str] = set()
    out: list[str] = []
    for signal in signals:
        kind = _signal_kind(signal)
        if kind in seen:
            continue
        seen.add(kind)
        out.append(signal)
    return out


def endpoint_is_excluded(endpoint: str, patterns: Sequence[re.Pattern[str] | str]) -> str | None:
    """Return the reason an endpoint is excluded, or ``None``."""

    path = split_url(endpoint).path or "/"
    lowered = endpoint.lower()
    for pattern in patterns:
        compiled = pattern if isinstance(pattern, re.Pattern) else re.compile(pattern)
        if compiled.search(path) or compiled.search(lowered):
            return f"matches exclusion rule '{compiled.pattern}'"
    return None


def compile_exclusions(patterns: list[str]) -> list[re.Pattern[str]]:
    compiled: list[re.Pattern[str]] = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern))
        except re.error:
            compiled.append(re.compile(re.escape(pattern)))
    return compiled


def rank_candidates(candidates: list[Candidate], confidence: dict[str, float]) -> list[Candidate]:
    """Order candidates: strongest provenance first, discovery order as tiebreak."""

    return sorted(
        candidates,
        key=lambda item: (-confidence.get(item.name, 0.0), item.first_seen_order),
    )


def has_real_provenance(candidate: Candidate) -> bool:
    """True when a candidate has at least one non-wordlist source."""

    return bool(set(candidate.sources) - {SourceKind.WORDLIST})


async def prepare_endpoint(
    client: ParamScoutClient,
    *,
    endpoint: str,
    url: str,
    active: ActiveConfig,
    normalizer: NormalizerConfig,
    exclusions: list[re.Pattern[str]] | None = None,
) -> EndpointOutcome:
    """Exclusion check, baselines, control request and stability verdict."""

    outcome = EndpointOutcome(endpoint=endpoint, url=url)
    exclusions = exclusions or []

    exclusion_reason = endpoint_is_excluded(endpoint, exclusions)
    if exclusion_reason:
        outcome.notes.append(f"endpoint not probed: {exclusion_reason}")
        outcome.excluded = exclusion_reason
        return outcome

    baseline = await collect_baseline(
        client, url, endpoint, count=active.baselines, config=normalizer
    )
    outcome.baseline = baseline
    if not baseline.usable:
        outcome.notes.append("could not collect two usable baselines; endpoint marked inconclusive")
        return outcome

    control = await measure_control(
        client,
        baseline,
        config=normalizer,
        canary_prefix=active.canary_prefix,
        max_url_length=client.config.max_url_length,
    )
    outcome.control = control
    if control.error:
        outcome.notes.append(f"control request failed: {control.error}")
    elif control.reacts_to_unknown_parameters:
        outcome.notes.append(
            f"the application reacts to the unrelated control parameter '{control.parameter}'; "
            "generic query-string handling is excluded from all findings here"
        )

    if not baseline.stable:
        outcome.notes.append(
            "baseline responses vary too much to attribute changes; all results are inconclusive"
        )
    return outcome


def mark_all_inconclusive(outcome: EndpointOutcome, candidates: list[Candidate], note: str) -> None:
    """Record every candidate as inconclusive with a shared explanation."""

    for candidate in candidates:
        outcome.outcomes[candidate.name] = ProbeOutcome(
            parameter=candidate.name,
            status=BehavioralStatus.INCONCLUSIVE,
            notes=[note],
        )


async def probe_candidates(
    client: ParamScoutClient,
    outcome: EndpointOutcome,
    candidates: list[Candidate],
    *,
    active: ActiveConfig,
    normalizer: NormalizerConfig,
    confidence: dict[str, float] | None = None,
) -> None:
    """Probe ``candidates`` against an endpoint that has already been prepared."""

    confidence = confidence or {}
    baseline = outcome.baseline
    control = outcome.control
    if not candidates:
        return
    if outcome.excluded:
        for candidate in candidates:
            outcome.outcomes.setdefault(
                candidate.name,
                ProbeOutcome(
                    parameter=candidate.name,
                    status=BehavioralStatus.SKIPPED,
                    notes=[f"endpoint excluded: {outcome.excluded}"],
                ),
            )
        return
    if baseline is None:
        mark_all_inconclusive(outcome, candidates, "no usable baseline responses")
        return
    if not baseline.stable:
        mark_all_inconclusive(outcome, candidates, "; ".join(baseline.notes) or "unstable baseline")
        return

    if active.batch_size > 1:
        await _probe_in_batches(client, outcome, baseline, control, candidates, active, normalizer)
        return
    for candidate in candidates:
        await _probe_single(
            client, outcome, baseline, control, candidate.name, active, normalizer, confirm=True
        )


def select_candidates(
    candidates: list[Candidate],
    active: ActiveConfig,
    confidence: dict[str, float] | None = None,
) -> tuple[list[Candidate], list[Candidate]]:
    """Split candidates into (target-specific, wordlist guesses), both ranked.

    Target-specific evidence is always probed first so a limited request budget
    is spent on parameters the application actually told us about.
    """

    confidence = confidence or {}
    limit = max(1, active.max_candidates_per_endpoint)
    ranked = rank_candidates(candidates, confidence)
    real = [item for item in ranked if has_real_provenance(item)][:limit]
    remaining = limit - len(real)
    guesses = [item for item in ranked if not has_real_provenance(item)][: max(0, remaining)]
    return real, guesses


async def probe_endpoint(
    client: ParamScoutClient,
    *,
    endpoint: str,
    url: str,
    candidates: list[Candidate],
    active: ActiveConfig,
    normalizer: NormalizerConfig,
    confidence: dict[str, float] | None = None,
    exclusions: list[re.Pattern[str]] | None = None,
) -> EndpointOutcome:
    """Run the full active-discovery sequence for one endpoint."""

    outcome = await prepare_endpoint(
        client,
        endpoint=endpoint,
        url=url,
        active=active,
        normalizer=normalizer,
        exclusions=exclusions,
    )
    real, guesses = select_candidates(candidates, active, confidence)
    dropped = len(candidates) - len(real) - len(guesses)
    if dropped > 0:
        outcome.notes.append(f"{dropped} candidates skipped by --max-candidates-per-endpoint")
    await probe_candidates(
        client, outcome, real, active=active, normalizer=normalizer, confidence=confidence
    )
    await probe_candidates(
        client, outcome, guesses, active=active, normalizer=normalizer, confidence=confidence
    )
    return outcome


async def _probe_single(
    client: ParamScoutClient,
    outcome: EndpointOutcome,
    baseline: BaselineSet,
    control: ControlResult | None,
    parameter: str,
    active: ActiveConfig,
    normalizer: NormalizerConfig,
    *,
    confirm: bool,
) -> ProbeOutcome:
    """Probe one parameter, then re-test it individually if it looked interesting."""

    record = ProbeOutcome(parameter=parameter)
    if client.budget.remaining_for(baseline.endpoint) <= 0:
        record.status = BehavioralStatus.SKIPPED
        record.notes.append("request budget exhausted before this candidate could be probed")
        outcome.skipped.append((parameter, record.notes[-1]))
        outcome.outcomes[parameter] = record
        return record
    canary = make_canary(active.canary_prefix)
    record.canary = canary
    url = build_probe_url(baseline.url, parameter, canary, max_length=client.config.max_url_length)
    if url is None:
        record.status = BehavioralStatus.SKIPPED
        record.notes.append("probe URL would exceed the configured maximum URL length")
        outcome.skipped.append((parameter, record.notes[-1]))
        outcome.outcomes[parameter] = record
        return record

    record.probe_urls.append(redact_url(url))
    result = await client.fetch(url, FetchOptions(purpose="probe", endpoint=baseline.endpoint))
    record.attempts += 1
    if result.error is not None:
        record.status = BehavioralStatus.ERROR
        record.errors.append(result.error)
        record.notes.append(f"probe failed: {result.error}")
        outcome.outcomes[parameter] = record
        return record

    from paramscout.discovery.baseline import (
        _sample_from_result,
    )

    sample = _sample_from_result(result, normalizer)
    primary = baseline.primary()
    delta = None
    if primary is not None:
        delta = compare_fingerprints(
            primary.fingerprint, sample.fingerprint, baseline_text=primary.text, candidate_text=sample.text
        )
    reflection = check_reflection(result.body, canary)
    record.reflected = reflection.reflected
    record.reflection_count = reflection.occurrences
    if delta is not None:
        record.deltas.append(delta)

    assessment = assess_delta(delta, baseline, control) if delta is not None else None
    if assessment is None:
        record.status = BehavioralStatus.INCONCLUSIVE
        record.notes.append("no baseline available for comparison")
    elif assessment.significant:
        record.signals.extend(assessment.signals)
        record.notes.extend(assessment.reasons)
        if confirm:
            await _confirm(client, record, baseline, control, parameter, active, normalizer)
        else:
            record.status = BehavioralStatus.BEHAVIORAL_CHANGE
    else:
        record.notes.extend(assessment.reasons)
        record.status = (
            BehavioralStatus.REFLECTION_ONLY if reflection.reflected else BehavioralStatus.NO_CHANGE
        )
        if reflection.reflected:
            record.notes.append(
                "the canary was reflected verbatim; reflection alone is not a vulnerability and was "
                "not treated as a behavioural change"
            )

    if record.status in (BehavioralStatus.NO_CHANGE, BehavioralStatus.ERROR) and reflection.reflected:
        record.status = BehavioralStatus.REFLECTION_ONLY
    record.signals = dedupe_signals(record.signals)
    outcome.outcomes[parameter] = record
    return record


async def _confirm(
    client: ParamScoutClient,
    record: ProbeOutcome,
    baseline: BaselineSet,
    control: ControlResult | None,
    parameter: str,
    active: ActiveConfig,
    normalizer: NormalizerConfig,
) -> None:
    """Re-test a promising candidate; only repeatable evidence counts."""

    from paramscout.discovery.baseline import _sample_from_result

    confirmations = max(1, active.confirmations)
    repeat_hits = 0
    for index in range(confirmations):
        canary = make_canary(active.canary_prefix)
        url = build_probe_url(baseline.url, parameter, canary, max_length=client.config.max_url_length)
        if url is None:
            record.notes.append("confirmation skipped: URL length limit")
            break
        record.probe_urls.append(redact_url(url))
        result = await client.fetch(url, FetchOptions(purpose="confirm", endpoint=baseline.endpoint))
        record.attempts += 1
        if result.error is not None:
            record.errors.append(result.error)
            record.notes.append(f"confirmation {index + 1} failed: {result.error}")
            continue
        sample = _sample_from_result(result, normalizer)
        primary = baseline.primary()
        if primary is None:
            continue
        delta = compare_fingerprints(
            primary.fingerprint, sample.fingerprint, baseline_text=primary.text, candidate_text=sample.text
        )
        record.deltas.append(delta)
        assessment = assess_delta(delta, baseline, control)
        if assessment.significant:
            repeat_hits += 1
            for signal in assessment.signals:
                if signal not in record.signals:
                    record.signals.append(signal)
        reflection = check_reflection(result.body, canary)
        record.reflected = record.reflected or reflection.reflected
        record.reflection_count = max(record.reflection_count, reflection.occurrences)

    if repeat_hits >= 1:
        record.status = BehavioralStatus.BEHAVIORAL_CHANGE
        record.notes.append(
            f"change reproduced in {repeat_hits} of {confirmations} independent confirmation requests"
        )
    else:
        record.status = BehavioralStatus.BEHAVIORAL_CHANGE_UNCONFIRMED
        record.notes.append(
            "the initial difference did not reproduce; treated as unconfirmed rather than a finding"
        )


async def _probe_in_batches(
    client: ParamScoutClient,
    outcome: EndpointOutcome,
    baseline: BaselineSet,
    control: ControlResult | None,
    candidates: list[Candidate],
    active: ActiveConfig,
    normalizer: NormalizerConfig,
) -> None:
    """Batch probing: many parameters per request, then individual validation.

    Limitations, also recorded in the report:

    * a change observed in a batch **cannot be attributed** to a specific
      parameter - every member has to be re-probed alone;
    * interactions between parameters are invisible (one parameter can mask
      another);
    * the URL length limit silently reduces the batch size;
    * a batch that shows no change can still hide a parameter whose effect is
      cancelled out by another member.
    """

    from paramscout.discovery.baseline import _sample_from_result

    size = max(2, active.batch_size)
    outcome.notes.append(
        f"batch mode (batch size {size}): batch results are never reported as findings on their own; "
        "every candidate is re-probed individually"
    )
    remaining = list(candidates)
    while remaining:
        chunk = remaining[:size]
        remaining = remaining[size:]
        assignments = [(candidate.name, make_canary(active.canary_prefix)) for candidate in chunk]
        url, included = build_batch_probe_url(
            baseline.url, assignments, max_length=client.config.max_url_length
        )
        dropped = {name for name, _ in assignments} - {name for name, _ in included}
        for name in dropped:
            outcome.skipped.append((name, "dropped from batch: URL length limit"))
        if url is None:
            for candidate in chunk:
                await _probe_single(client, outcome, baseline, control, candidate.name, active, normalizer, confirm=True)
            continue

        result = await client.fetch(url, FetchOptions(purpose="batch-probe", endpoint=baseline.endpoint))
        if result.error is not None:
            for candidate in chunk:
                outcome.outcomes.setdefault(candidate.name, ProbeOutcome(parameter=candidate.name))
                outcome.outcomes[candidate.name].errors.append(result.error)
                outcome.outcomes[candidate.name].status = BehavioralStatus.ERROR
            continue

        sample = _sample_from_result(result, normalizer)
        primary = baseline.primary()
        batch_delta = None
        if primary is not None:
            batch_delta = compare_fingerprints(
                primary.fingerprint,
                sample.fingerprint,
                baseline_text=primary.text,
                candidate_text=sample.text,
            )
        assessment = assess_delta(batch_delta, baseline, control) if batch_delta else None
        reflected_names = {
            name
            for name, canary in included
            if check_reflection(result.body, canary).reflected
        }

        # A quiet batch still needs individual probes for reflected members and
        # for anything the batch may have masked; the budget decides how far we
        # get, and skipped work is reported rather than silently dropped.
        interesting = [candidate for candidate in chunk if (assessment and assessment.significant)]
        if not interesting:
            for candidate in chunk:
                record = outcome.outcomes.get(candidate.name) or ProbeOutcome(parameter=candidate.name)
                record.notes.append(
                    "batch probe showed no difference beyond baseline/control noise; "
                    "batch results cannot rule out an effect masked by another parameter"
                )
                if candidate.name in reflected_names:
                    record.reflected = True
                    record.notes.append("canary reflected in the batch response; re-probing individually")
                    outcome.outcomes[candidate.name] = record
                    await _probe_single(client, outcome, baseline, control, candidate.name, active, normalizer, confirm=True)
                    continue
                record.status = BehavioralStatus.NO_CHANGE
                record.attempts += 1
                outcome.outcomes[candidate.name] = record
            continue

        outcome.notes.append(
            f"batch of {len(included)} parameters changed the response; attributing the change by "
            "re-probing each parameter individually"
        )
        for candidate in chunk:
            if candidate.name in reflected_names:
                record = outcome.outcomes.get(candidate.name) or ProbeOutcome(parameter=candidate.name)
                record.reflected = True
                outcome.outcomes[candidate.name] = record
            await _probe_single(client, outcome, baseline, control, candidate.name, active, normalizer, confirm=True)
