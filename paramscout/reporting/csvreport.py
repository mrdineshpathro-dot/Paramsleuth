"""CSV report writer with spreadsheet-formula-injection mitigation.

CSV exports may be opened in spreadsheet applications, so untrusted values
starting with ``=``, ``+``, ``-``, ``@``, tab or carriage-return are prefixed
with a single quote (the standard safe-encoding practice). All fields are
quoted through Python's :mod:`csv` module.
"""

from __future__ import annotations

import csv
import io
from typing import Any, Iterable

_DANGEROUS_STARTS = ("=", "+", "-", "@", "\t", "\r")

# Columns shared by JSON/CSV/HTML so artifacts line up.
COLUMNS = [
    "endpoint",
    "parameter",
    "category",
    "source",
    "source_context",
    "discovery_confidence",
    "discovery_score",
    "behavior_confidence",
    "behavior_score",
    "manual_review_priority",
    "priority_reasons",
    "observed_differences",
    "reflection_status",
    "validation_attempts",
    "inconclusive",
    "status_note",
    "reproduction_request",
    "limitations",
]


def sanitize_csv_value(value: Any) -> str:
    """Neutralize spreadsheet formula injection and coerce to text."""
    text = "" if value is None else str(value)
    if text.startswith(_DANGEROUS_STARTS):
        return "'" + text
    return text


def render_csv_report(rows: Iterable[dict[str, Any]]) -> str:
    """Render findings rows as CSV text (header + data)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(COLUMNS)
    for row in rows:
        writer.writerow([sanitize_csv_value(row.get(col, "")) for col in COLUMNS])
    return buffer.getvalue()
