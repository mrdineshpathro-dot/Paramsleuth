"""Flatten findings into stable, report-ready rows.

All report formats (JSON, CSV, HTML) share one row shape so the outputs stay
consistent. Every dynamic value is redacted by the caller-provided Redactor
before it reaches a row.
"""

from __future__ import annotations

import time
from typing import Any

from .. import __about__
from ..models import Candidate, DiscoverySourceKind, Endpoint, Finding, SourceRef
from ..redaction import Redactor

_KIND_LABELS = {
    DiscoverySourceKind.QUERY: "URL query string",
    DiscoverySourceKind.HTML_LINK: "HTML link URL",
    DiscoverySourceKind.FORM: "form field",
    DiscoverySourceKind.JS: "JavaScript",
    DiscoverySourceKind.JSON: "embedded JSON/config",
    DiscoverySourceKind.ROBOTS: "robots.txt",
    DiscoverySourceKind.SITEMAP: "sitemap.xml",
    DiscoverySourceKind.USER_FILE: "user-supplied URL archive",
    DiscoverySourceKind.BUILTIN_WORDLIST: "built-in wordlist",
    DiscoverySourceKind.USER_WORDLIST: "user wordlist",
    DiscoverySourceKind.UNKNOWN: "unknown",
}


def _sources_text(sources: list[SourceRef]) -> str:
    seen: list[str] = []
    for source in sources:
        label = _KIND_LABELS.get(source.kind, source.kind.value)
        if label not in seen:
            seen.append(label)
    return ", ".join(seen[:6]) or "unknown"


def _source_contexts(sources: list[SourceRef], redactor: Redactor, limit: int = 3) -> list[str]:
    out: list[str] = []
    for source in sources:
        ctx = source.context or source.location or ""
        ctx = redactor.redact(str(ctx))[:300]
        if ctx not in out:
            out.append(ctx)
        if len(out) >= limit:
            break
    return out


def _endpoint_label(endpoint: Endpoint, redactor: Redactor) -> str:
    return redactor.redact_url(endpoint.url)


def _reproduction_request(endpoint: Endpoint, param: str, redactor: Redactor, canary: str = "<canary>") -> str:
    from ..urlutils import append_params

    url = endpoint.url
    if param:
        url = append_params(url, [(param, canary)])
    return f"GET {redactor.redact_url(url)}"


def row_from_finding(finding: Finding, redactor: Redactor) -> dict[str, Any]:
    probe = finding.probe
    differences: list[str] = []
    if probe:
        for diff in probe.observed_diffs:
            differences.append(f"{diff.kind}: {redactor.redact(diff.detail)}")
    reflection = "not-tested"
    if probe is not None:
        if probe.reflected:
            reflection = "yes (" + ", ".join(probe.reflect_contexts or ["body"]) + ")"
            if probe.control_similar and any("reflect" in n for n in probe.notes):
                reflection += "; note: control also reflected"
        else:
            reflection = "no"
    status_note = ""
    if probe is not None and probe.error:
        status_note = redactor.redact(probe.error)
    elif finding.inconclusive:
        status_note = "inconclusive"
    row = {
        "endpoint": _endpoint_label(finding.endpoint, redactor),
        "parameter": finding.param,
        "category": finding.category,
        "source": _sources_text(finding.source_summary),
        "source_context": " | ".join(_source_contexts(finding.source_summary, redactor)),
        "discovery_confidence": finding.discovery_label,
        "discovery_score": round(finding.discovery_score, 3),
        "behavior_confidence": finding.behavior_label if finding.behavior_label is not None else "not-tested",
        "behavior_score": (
            round(finding.behavior_score, 3) if finding.behavior_score is not None else ""
        ),
        "manual_review_priority": finding.priority,
        "priority_reasons": " | ".join(redactor.redact(r) for r in finding.priority_reasons),
        "observed_differences": " | ".join(differences),
        "reflection_status": reflection,
        "validation_attempts": probe.attempts if probe else 0,
        "inconclusive": bool(finding.inconclusive) or (
            probe is not None and bool(probe.error)
        ),
        "status_note": status_note,
        "reproduction_request": _reproduction_request(
            finding.endpoint, finding.param, redactor,
            probe.canary if probe and probe.canary else "<canary>",
        ),
        "limitations": " | ".join(finding.limitations),
    }
    return row


def row_from_passive(endpoint: Endpoint, candidate: Candidate, redactor: Redactor) -> dict[str, Any]:
    """Row for a candidate discovered offline (no behavioral testing)."""
    reasons: list[str] = []
    priority = "low"
    if candidate.discovery_score >= 0.75:
        reasons.append("high-confidence discovery (real URL / form / strong script evidence)")
    if candidate.security_relevant:
        reasons.append(
            f"name matches security-relevant category {candidate.category!r} "
            "(naming hint only, never a vulnerability claim)"
        )
    if candidate.rarity >= 0.8:
        reasons.append(f"rare across collected set (rarity {candidate.rarity:.2f})")
    if len(candidate.sources) > 1:
        reasons.append(f"corroborated by {len(candidate.sources)} independent sources")
    if candidate.security_relevant and candidate.discovery_score >= 0.4:
        priority = "high"
    elif candidate.discovery_score >= 0.75 or candidate.security_relevant:
        priority = "medium"
    return {
        "endpoint": _endpoint_label(endpoint, redactor),
        "parameter": candidate.name,
        "category": candidate.category,
        "source": _sources_text(candidate.sources),
        "source_context": " | ".join(_source_contexts(candidate.sources, redactor)),
        "discovery_confidence": _score_label(candidate.discovery_score),
        "discovery_score": round(candidate.discovery_score, 3),
        "behavior_confidence": "not-tested",
        "behavior_score": "",
        "manual_review_priority": priority,
        "priority_reasons": " | ".join(reasons),
        "observed_differences": "",
        "reflection_status": "not-tested",
        "validation_attempts": 0,
        "inconclusive": False,
        "status_note": "offline extraction only; no network requests were made",
        "reproduction_request": "",
        "limitations": "",
    }


def _score_label(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def metadata_block(
    *,
    command: str,
    mode: str,
    status: str,
    status_detail: str,
    args: dict[str, Any],
    scope_lines: list[str],
    totals: dict[str, Any],
    limitations: list[str],
) -> dict[str, Any]:
    return {
        "tool": __about__.__title__,
        "version": __about__.__version__,
        "author": __about__.__author__,
        "contact": __about__.__author_email__,
        "support": __about__.__support_url__,
        "authorized_use": (
            "Authorized use only: run ParamScout only against systems you own "
            "or have explicit permission to test."
        ),
        "command": command,
        "mode": mode,
        "status": status,
        "status_detail": status_detail,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "scan_configuration": args,
        "scope": scope_lines,
        "totals": totals,
        "limitations": limitations,
    }
