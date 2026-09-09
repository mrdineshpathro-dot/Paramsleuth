"""Explainable scoring.

Three numbers are produced for every finding and they answer three different
questions.  They are never collapsed into a "severity".

``discovery_confidence`` (0..1)
    Does this parameter really exist on this endpoint?  Purely provenance.

``behavioral_confidence`` (0..1)
    Does setting it measurably change the response, repeatably, beyond what an
    unrelated dummy parameter achieves?  Purely measurement.

``review_priority`` (0..100)
    Where should a human look first?  A weighted, fully explained ordering.

Every score ships with the list of reasons that produced it, so a reviewer can
agree or disagree with the arithmetic rather than trusting a number.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from paramscout.analysis.categories import CATEGORY_REVIEW_WEIGHT, Category, classify_parameter
from paramscout.models import BehavioralResult, BehavioralStatus, Candidate, SourceKind

#: Maximum weight each provenance class can contribute.
SOURCE_WEIGHTS: dict[SourceKind, float] = {
    SourceKind.URL_QUERY: 0.50,
    SourceKind.HTML_FORM_FIELD: 0.45,
    SourceKind.ARCHIVE: 0.40,
    SourceKind.HTML_LINK: 0.40,
    SourceKind.SITEMAP: 0.30,
    SourceKind.ROBOTS: 0.28,
    SourceKind.JS_INLINE: 0.32,
    SourceKind.JS_EXTERNAL: 0.32,
    SourceKind.JSON_BLOB: 0.28,
    SourceKind.HTML_ATTRIBUTE: 0.22,
    SourceKind.PAGE_DERIVED: 0.18,
    SourceKind.WORDLIST: 0.06,
    SourceKind.CONTROL: 0.0,
}

#: Diminishing return for every additional distinct source.
_EXTRA_SOURCE_DECAY = 0.5

#: Weights used to combine the priority score.  They sum to 1.0.
PRIORITY_WEIGHTS = {
    "discovery": 0.28,
    "behavioral": 0.34,
    "rarity": 0.18,
    "naming": 0.12,
    "reflection": 0.08,
}


@dataclass
class Score:
    """A score plus the reasons that produced it."""

    value: float
    reasons: list[str] = field(default_factory=list)


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def discovery_confidence(candidate: Candidate) -> Score:
    """Score how confident we are that the parameter exists."""

    reasons: list[str] = []
    weights: list[float] = []
    kinds = set(candidate.sources)

    if SourceKind.URL_QUERY in kinds:
        reasons.append("parameter observed in a real query string on this endpoint")
    if SourceKind.HTML_FORM_FIELD in kinds:
        methods = ",".join(candidate.form_methods) or "GET"
        reasons.append(f"declared as a form field (method {methods}) on this endpoint")
    if SourceKind.HTML_LINK in kinds:
        reasons.append("present in a hyperlink on this target")
    if SourceKind.ARCHIVE in kinds:
        reasons.append("present in a user-supplied URL archive")
    if SourceKind.JS_INLINE in kinds or SourceKind.JS_EXTERNAL in kinds:
        reasons.append("referenced in target JavaScript (heuristic)")
    if SourceKind.JSON_BLOB in kinds:
        reasons.append("referenced in an embedded JSON/configuration object (heuristic)")
    if SourceKind.ROBOTS in kinds or SourceKind.SITEMAP in kinds:
        reasons.append("listed in robots.txt/sitemap.xml")
    if SourceKind.HTML_ATTRIBUTE in kinds:
        reasons.append("found in a data-* attribute query string")
    if kinds == {SourceKind.WORDLIST}:
        reasons.append("wordlist guess only - no target-specific evidence")
    if not kinds:
        reasons.append("no provenance recorded")

    for kind in sorted(kinds, key=lambda item: SOURCE_WEIGHTS.get(item, 0.0), reverse=True):
        weights.append(SOURCE_WEIGHTS.get(kind, 0.05))

    if not weights:
        return Score(0.0, reasons or ["no evidence"])

    # Best source dominates; each additional independent source adds a
    # geometrically decaying bonus, so five weak sources cannot outvote one
    # real observation.
    total = weights[0]
    decay = _EXTRA_SOURCE_DECAY
    for extra in weights[1:]:
        total += extra * decay
        decay *= 0.6
    total = clamp(total, 0.0, 0.97)
    reasons.append(
        "combined provenance weight "
        + " + ".join(f"{weight:.2f}" for weight in weights[:4])
        + f" = {total:.2f}"
    )
    if len(candidate.evidence) > 1:
        reasons.append(f"{len(candidate.evidence)} independent observations")
    return Score(total, reasons)


def behavioral_confidence(result: BehavioralResult | None) -> Score:
    """Score the repeatability and size of an observed behavioural change."""

    if result is None:
        return Score(0.0, ["not actively tested (passive mode)"])

    status = result.status
    if status is BehavioralStatus.BEHAVIORAL_CHANGE:
        base = 0.75
        reasons = ["response changed repeatably across independent validation attempts"]
    elif status is BehavioralStatus.BEHAVIORAL_CHANGE_UNCONFIRMED:
        base = 0.4
        reasons = ["response changed on one attempt but the change did not repeat"]
    elif status is BehavioralStatus.REFLECTION_ONLY:
        base = 0.1
        reasons = ["parameter value reflected verbatim, no other response change"]
    elif status is BehavioralStatus.NO_CHANGE:
        base = 0.0
        reasons = ["no response difference beyond baseline noise and the control parameter"]
    elif status is BehavioralStatus.INCONCLUSIVE:
        base = 0.05
        reasons = ["endpoint responses too unstable to reach a conclusion"]
    elif status is BehavioralStatus.ERROR:
        base = 0.0
        reasons = ["probe failed with an error"]
    elif status is BehavioralStatus.SKIPPED:
        base = 0.0
        reasons = ["probe skipped (budget, exclusion or throttling)"]
    else:
        base = 0.0
        reasons = [f"status {status.value}"]

    reasons.extend(result.notes)
    if result.attempts > 1 and status is BehavioralStatus.BEHAVIORAL_CHANGE:
        base += min(0.15, 0.05 * (result.attempts - 1))
        reasons.append(f"{result.attempts} validation attempts all agreed")
    if result.reflection and result.reflection.reflected and status is BehavioralStatus.BEHAVIORAL_CHANGE:
        base += 0.05
        reasons.append("canary reflected in addition to the behavioural change")
    return Score(clamp(base), reasons)


def rarity_score(parameter: str, frequency: dict[str, int], endpoint_count: int) -> Score:
    """Rarer parameters are more interesting: they are less likely to be noise."""

    if endpoint_count <= 0:
        return Score(0.0, ["no endpoint population to compare against"])
    seen = frequency.get(parameter, 0)
    value = clamp(1.0 - (seen / max(1, endpoint_count)))
    if seen <= 1:
        reason = f"'{parameter}' appears on {seen} of {endpoint_count} endpoints (rare)"
    else:
        reason = f"'{parameter}' appears on {seen} of {endpoint_count} endpoints (common)"
    return Score(value, [reason])


def review_priority(
    candidate: Candidate,
    *,
    discovery: Score,
    behavioral: Score,
    rarity: Score,
    reflected: bool = False,
) -> tuple[int, list[str], Category]:
    """Combine the components into a 0..100 manual-review ordering."""

    classification = classify_parameter(candidate.name)
    naming = CATEGORY_REVIEW_WEIGHT.get(classification.category, 0.2)
    reflection_value = 1.0 if reflected else 0.0

    weighted = (
        PRIORITY_WEIGHTS["discovery"] * discovery.value
        + PRIORITY_WEIGHTS["behavioral"] * behavioral.value
        + PRIORITY_WEIGHTS["rarity"] * rarity.value
        + PRIORITY_WEIGHTS["naming"] * naming
        + PRIORITY_WEIGHTS["reflection"] * reflection_value
    )
    priority = int(round(clamp(weighted) * 100))

    reasons = [
        f"discovery confidence {discovery.value:.2f} x weight {PRIORITY_WEIGHTS['discovery']}",
        f"behavioral confidence {behavioral.value:.2f} x weight {PRIORITY_WEIGHTS['behavioral']}",
        f"rarity {rarity.value:.2f} x weight {PRIORITY_WEIGHTS['rarity']}",
        f"category '{classification.label}' naming weight {naming:.2f} x weight {PRIORITY_WEIGHTS['naming']}",
        f"canary reflection {'yes' if reflected else 'no'} x weight {PRIORITY_WEIGHTS['reflection']}",
    ]
    if behavioral.value == 0.0:
        reasons.append("no repeatable behavioural change observed - this is a discovery, not a vulnerability")
    if classification.category is Category.UNKNOWN:
        reasons.append("parameter name carries no known intent signal")
    reasons.append("priority is a triage ordering only; it is not a vulnerability severity")
    return priority, reasons, classification.category
