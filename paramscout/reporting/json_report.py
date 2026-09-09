"""JSON report assembly and writing."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from paramscout import __version__
from paramscout.config import ScanConfig
from paramscout.models import Finding, ScanStats
from paramscout.redaction import redact_url

LIMITATIONS = (
    "ParamScout is a reconnaissance aid, not a vulnerability scanner: no finding in this "
    "report is a vulnerability, and no severity is assigned.",
    "Parameter categories are inferred from names only. A name never proves behaviour.",
    "JavaScript and JSON extraction is heuristic; every such candidate carries the source "
    "context it was derived from so it can be confirmed or discarded by hand.",
    "Passive discovery only sees parameters the target already exposes. Parameters that "
    "exist but are never referenced anywhere will be missed unless a wordlist probe finds them.",
    "Active discovery uses GET requests only. Endpoints that accept parameters exclusively "
    "via POST/PUT/DELETE bodies are out of reach by design.",
    "Active results are differential. If an endpoint's responses vary more than the measured "
    "baseline noise, results are reported as inconclusive rather than guessed at.",
    "Reflection is reported separately from behavioural change. Reflection alone is not XSS "
    "and no injection testing is performed.",
    "Endpoint grouping is configurable; folding paths (case or trailing slash) can merge "
    "endpoints that the application treats as distinct.",
    "URLs differing only in percent-encoding or parameter order are treated as different "
    "inputs and are not de-duplicated.",
)


def build_report(
    *,
    mode: str,
    config: ScanConfig,
    stats: ScanStats,
    findings: list[Finding],
    endpoints: list[dict[str, Any]],
    limitations: list[str] | None = None,
    warnings: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the canonical report document."""

    ordered = sorted(
        findings,
        key=lambda item: (-item.review_priority, -item.behavioral_confidence, item.endpoint, item.parameter),
    )
    report: dict[str, Any] = {
        "tool": "ParamScout",
        "version": __version__,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "mode": mode,
        "authorized_scope": config.scope.to_dict(),
        "settings": {
            "request": config.request.__dict__ | {"headers": "[redacted]", "cookies": "[redacted]"},
            "crawl": config.crawl.__dict__,
            "active": config.active.__dict__,
            "endpoint_grouping": config.output.endpoint_grouping.value,
            "dry_run": config.dry_run,
        },
        "stats": stats.to_dict(),
        "summary": summarise(ordered),
        "endpoints": endpoints,
        "findings": [finding.to_dict() for finding in ordered],
        "limitations": list(limitations or LIMITATIONS),
        "warnings": list(warnings or []),
    }
    if extra:
        report.update(extra)
    return report


def summarise(findings: list[Finding]) -> dict[str, Any]:
    """Aggregate counters for the report header."""

    categories: dict[str, int] = {}
    statuses: dict[str, int] = {}
    reflected = 0
    inconclusive = 0
    for finding in findings:
        categories[finding.category] = categories.get(finding.category, 0) + 1
        status = finding.behavioral.status.value if finding.behavioral else "not_tested"
        statuses[status] = statuses.get(status, 0) + 1
        if finding.behavioral and finding.behavioral.reflection and finding.behavioral.reflection.reflected:
            reflected += 1
        if finding.inconclusive:
            inconclusive += 1
    return {
        "findings_total": len(findings),
        "endpoints_total": len({finding.endpoint for finding in findings}),
        "by_category": dict(sorted(categories.items(), key=lambda item: -item[1])),
        "by_behavioral_status": dict(sorted(statuses.items(), key=lambda item: -item[1])),
        "reflected_canaries": reflected,
        "inconclusive": inconclusive,
        "top_priority": [
            {
                "endpoint": finding.endpoint,
                "parameter": finding.parameter,
                "priority": finding.review_priority,
            }
            for finding in sorted(findings, key=lambda item: -item.review_priority)[:10]
        ],
    }


def write_json(report: dict[str, Any], path: str | Path) -> Path:
    """Write the report as UTF-8 JSON."""

    target = Path(path)
    if str(target.parent) and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return target


def findings_from_dicts(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Re-order previously stored findings (used when resuming)."""

    return sorted(items, key=lambda item: -int(item.get("review_priority", 0)))


def redacted_endpoint_list(urls: list[str]) -> list[str]:
    return [redact_url(url) for url in urls]
