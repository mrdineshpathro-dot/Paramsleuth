"""CSV report writer (one row per finding)."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

COLUMNS = (
    "endpoint",
    "parameter",
    "category",
    "sources",
    "discovery_confidence",
    "behavioral_status",
    "behavioral_confidence",
    "observed_differences",
    "reflection",
    "reflection_occurrences",
    "validation_attempts",
    "review_priority",
    "inconclusive",
    "priority_reasons",
    "discovery_reasons",
    "form_methods",
    "errors",
    "reproduction",
)


def _row(finding: dict[str, Any]) -> dict[str, Any]:
    behavioral = finding.get("behavioral") or {}
    reflection = behavioral.get("reflection") or {}
    return {
        "endpoint": finding.get("endpoint", ""),
        "parameter": finding.get("parameter", ""),
        "category": finding.get("category", ""),
        "sources": ";".join(finding.get("sources", [])),
        "discovery_confidence": finding.get("discovery_confidence", 0),
        "behavioral_status": behavioral.get("status", "not_tested"),
        "behavioral_confidence": finding.get("behavioral_confidence", 0),
        "observed_differences": " | ".join(behavioral.get("signals", [])),
        "reflection": "yes" if reflection.get("reflected") else "no",
        "reflection_occurrences": reflection.get("occurrences", 0),
        "validation_attempts": behavioral.get("attempts", 0),
        "review_priority": finding.get("review_priority", 0),
        "inconclusive": "yes" if finding.get("inconclusive") else "no",
        "priority_reasons": " | ".join(finding.get("priority_reasons", [])),
        "discovery_reasons": " | ".join(finding.get("discovery_reasons", [])),
        "form_methods": ";".join(finding.get("form_methods", [])),
        "errors": " | ".join(finding.get("errors", [])),
        "reproduction": (finding.get("reproduction") or "").replace("\n", " \\n "),
    }


def write_csv(report: dict[str, Any], path: str | Path) -> Path:
    """Write ``report['findings']`` as CSV."""

    target = Path(path)
    if str(target.parent) and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(COLUMNS), extrasaction="ignore")
        writer.writeheader()
        for finding in report.get("findings", []):
            writer.writerow(_row(finding))
    return target
