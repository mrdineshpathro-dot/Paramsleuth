"""Report rendering: JSON, CSV and HTML escaping."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from paramscout.config import ScanConfig
from paramscout.models import (
    BehavioralResult,
    BehavioralStatus,
    CandidateStatus,
    Evidence,
    Finding,
    ReflectionInfo,
    ScanStats,
    SourceKind,
)
from paramscout.reporting import build_report, render_html, write_csv, write_html, write_json
from paramscout.scope import Scope

HOSTILE = "<script>alert('xss')</script>"
HOSTILE_ATTR = '" onload="alert(1)'


def hostile_finding() -> Finding:
    return Finding(
        endpoint=f"https://app.example.test/{HOSTILE}",
        parameter=f"p{HOSTILE}",
        category="redirect_navigation",
        category_reason=f"exact name match '{HOSTILE}'",
        sources=["js_inline", "url_query"],
        evidence=[
            Evidence(
                kind=SourceKind.JS_INLINE,
                origin=f"https://app.example.test/{HOSTILE}",
                detail=f"fetch('{HOSTILE}')",
                context=f"var x = '{HOSTILE}'; // {HOSTILE_ATTR}",
                line=7,
            )
        ],
        discovery_confidence=0.62,
        discovery_reasons=[f"referenced in JavaScript containing {HOSTILE}"],
        behavioral=BehavioralResult(
            status=BehavioralStatus.BEHAVIORAL_CHANGE,
            confidence=0.8,
            attempts=3,
            signals=[f"title changed to {HOSTILE}"],
            notes=[f"observed {HOSTILE_ATTR} in the response"],
            reflection=ReflectionInfo(reflected=True, occurrences=2, locations=["response body"]),
        ),
        behavioral_confidence=0.8,
        review_priority=77,
        priority_reasons=[f"reflected {HOSTILE}", "priority is a triage ordering only; it is not a vulnerability severity"],
        status=CandidateStatus.CONFIRMED,
        observed_values=[HOSTILE],
        form_methods=["GET"],
        reproduction=f"GET /{HOSTILE}?p=[[CANARY]] HTTP/1.1\nHost: app.example.test",
    )


def _report() -> dict:
    config = ScanConfig()
    config.scope = Scope.from_hosts(["app.example.test"])
    return build_report(
        mode="active",
        config=config,
        stats=ScanStats(requests_total=42, skipped_off_scope=["https://evil.test/x :: not in allowlist"]),
        findings=[hostile_finding()],
        endpoints=[{"endpoint": HOSTILE, "example_url": HOSTILE, "candidates": 1, "active_status": "probed"}],
        warnings=[HOSTILE],
        limitations=[HOSTILE],
    )


def test_html_report_escapes_every_untrusted_value() -> None:
    document = render_html(_report())
    assert HOSTILE not in document
    assert HOSTILE_ATTR not in document
    assert "<script>alert" not in document
    # the escaped forms are present, so the data survived - inertly
    assert "&lt;script&gt;" in document
    assert "&quot; onload=&quot;alert(1)" in document
    # nothing may break out of an attribute context
    assert 'onload="alert(1)' not in document
    assert "<script>" not in document.split("<style>", 1)[-1].split("</style>", 1)[-1]


def test_html_report_loads_no_external_resources() -> None:
    document = render_html(_report())
    lowered = document.lower()
    assert "http://" not in lowered.split("<body")[0]
    assert 'src="http' not in lowered
    assert "<link" not in lowered
    assert 'name="referrer" content="no-referrer"' in lowered


def test_json_report_round_trips() -> None:
    report = _report()
    payload = json.loads(json.dumps(report, default=str))
    finding = payload["findings"][0]
    assert finding["parameter"].startswith("p<script>")
    assert finding["behavioral"]["status"] == "behavioral_change"
    assert finding["behavioral"]["reflection"]["reflected"] is True
    assert payload["summary"]["findings_total"] == 1
    assert payload["summary"]["reflected_canaries"] == 1
    assert payload["stats"]["requests_total"] == 42
    assert payload["authorized_scope"]["hosts"][0]["host"] == "app.example.test"
    assert payload["limitations"], "limitations must always be present"


def test_json_report_hides_credentials_in_settings() -> None:
    config = ScanConfig()
    config.request.cookies = {"session": "secret"}
    config.request.headers = {"Authorization": "Bearer secret"}
    report = build_report(
        mode="passive",
        config=config,
        stats=ScanStats(),
        findings=[],
        endpoints=[],
    )
    text = json.dumps(report, default=str)
    assert "Bearer secret" not in text
    assert '"cookies": "[redacted]"' in text


def test_csv_report_columns(tmp_path: Path) -> None:
    target = write_csv(_report(), tmp_path / "out.csv")
    with target.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    row = rows[0]
    assert row["parameter"].startswith("p<script>")
    assert row["behavioral_status"] == "behavioral_change"
    assert row["reflection"] == "yes"
    assert row["reflection_occurrences"] == "2"
    assert row["validation_attempts"] == "3"
    assert row["review_priority"] == "77"
    assert "not a vulnerability severity" in row["priority_reasons"]


def test_writers_create_parent_directories(tmp_path: Path) -> None:
    report = _report()
    nested = tmp_path / "a" / "b"
    assert write_json(report, nested / "r.json").exists()
    assert write_csv(report, nested / "r.csv").exists()
    assert write_html(report, nested / "r.html").exists()
    assert json.loads((nested / "r.json").read_text())["tool"] == "ParamScout"


def test_report_includes_required_operational_counters() -> None:
    stats = ScanStats(
        requests_total=10,
        retries=2,
        skipped_off_scope=["https://evil.test/ :: not in the allowlist"],
        skipped_budget=3,
        truncated_responses=1,
        elapsed_seconds=1.5,
    )
    report = build_report(
        mode="passive", config=ScanConfig(), stats=stats, findings=[], endpoints=[]
    )
    payload = report["stats"]
    assert payload["requests_total"] == 10
    assert payload["retries"] == 2
    assert len(payload["skipped_off_scope"]) == 1
    assert payload["skipped_budget"] == 3
    assert payload["truncated_responses"] == 1
    assert payload["elapsed_seconds"] == 1.5
    assert report["limitations"]


def test_empty_report_is_still_valid_html() -> None:
    document = render_html(
        build_report(mode="extract-offline", config=ScanConfig(), stats=ScanStats(), findings=[], endpoints=[])
    )
    assert document.startswith("<!DOCTYPE html>")
    assert "No parameter candidates were discovered." in document
