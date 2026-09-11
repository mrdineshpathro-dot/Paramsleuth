"""File writers for JSON/CSV/HTML reports."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ..redaction import Redactor
from .csvreport import render_csv_report
from .htmlreport import render_html_report
from .jsonreport import render_json_report

log = logging.getLogger("paramscout.report")


def write_reports(
    *,
    json_path: str | None,
    csv_path: str | None,
    html_path: str | None,
    metadata: dict[str, Any],
    rows: list[dict[str, Any]],
    redactor: Redactor,
) -> list[str]:
    """Write the requested report files; returns the list of written paths."""
    written: list[str] = []
    if json_path:
        Path(json_path).parent.mkdir(parents=True, exist_ok=True)
        Path(json_path).write_text(render_json_report(metadata, rows), encoding="utf-8")
        written.append(json_path)
    if csv_path:
        Path(csv_path).parent.mkdir(parents=True, exist_ok=True)
        Path(csv_path).write_text(render_csv_report(rows), encoding="utf-8")
        written.append(csv_path)
    if html_path:
        Path(html_path).parent.mkdir(parents=True, exist_ok=True)
        Path(html_path).write_text(render_html_report(metadata, rows), encoding="utf-8")
        written.append(html_path)
    return written
