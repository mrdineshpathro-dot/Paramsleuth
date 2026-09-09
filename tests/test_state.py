"""State store, interrupted scans and resumption."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import fast_config
from mockapp import MockApp

from paramscout import engine
from paramscout.config import ScanConfig
from paramscout.models import CandidateStatus, Finding
from paramscout.scope import Scope
from paramscout.state import StateStore


def _finding(endpoint: str, parameter: str) -> Finding:
    return Finding(
        endpoint=endpoint,
        parameter=parameter,
        category="search_filtering",
        category_reason="test",
        sources=["url_query"],
        evidence=[],
        discovery_confidence=0.9,
        discovery_reasons=["seen in a real query string"],
        behavioral=None,
        behavioral_confidence=0.0,
        review_priority=50,
        priority_reasons=["test"],
        status=CandidateStatus.DISCOVERED,
    )


def test_state_store_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "scan.sqlite"
    with StateStore(path) as store:
        config = ScanConfig()
        config.urls = ["https://app.example.test/"]
        config.scope = Scope.from_hosts(["app.example.test"])
        config.request.cookies = {"session": "super-secret"}
        config.request.headers = {"Authorization": "Bearer super-secret"}
        store.save_config(config)
        store.upsert_endpoint("https://app.example.test/a", "https://app.example.test/a?x=1")
        store.mark_endpoint("https://app.example.test/a", "done")
        store.upsert_endpoint("https://app.example.test/b", "https://app.example.test/b")
        store.save_finding(_finding("https://app.example.test/a", "x"))
        store.save_stats({"requests_total": 12})

        assert store.counts() == {"endpoints": 2, "candidates": 0, "findings": 1}
        assert [item["endpoint"] for item in store.pending_endpoints()] == ["https://app.example.test/b"]
        assert store.load_stats()["requests_total"] == 12
        assert store.load_findings()[0]["parameter"] == "x"

    # secrets must never reach the file on disk
    raw = path.read_bytes()
    assert b"super-secret" not in raw
    assert b"[REDACTED]" in raw


def test_state_store_survives_reopening(tmp_path: Path) -> None:
    path = tmp_path / "scan.sqlite"
    store = StateStore(path)
    store.upsert_endpoint("https://h.test/a", "https://h.test/a")
    store.close()
    reopened = StateStore(path)
    assert reopened.counts()["endpoints"] == 1
    reopened.close()


def test_interrupted_scan_saves_partial_results(app: MockApp, tmp_path: Path, monkeypatch) -> None:
    state_path = tmp_path / "interrupted.sqlite"
    config = fast_config()
    config.urls = [app.base + "/"]
    config.active.enabled = True
    config.active.excluded_paths.append(r"^/checkout")
    config.request.max_requests = 900
    config.output.state_path = str(state_path)

    calls = {"n": 0}
    original = engine.prepare_endpoint

    async def interrupting_prepare(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] >= 3:
            raise KeyboardInterrupt
        return await original(*args, **kwargs)

    monkeypatch.setattr(engine, "prepare_endpoint", interrupting_prepare)
    ctx = engine.run_scan(config)

    assert ctx.interrupted is True
    assert ctx.stats.interrupted is True
    assert any("interrupted" in warning for warning in ctx.warnings)
    assert state_path.exists()

    with StateStore(state_path) as store:
        stored = store.load_config()
        assert stored, "the resume configuration must be saved"
        assert stored["request"]["cookies"] == {}
        assert store.load_stats()["interrupted"] is True
        assert store.counts()["endpoints"] > 0


def test_resume_completes_the_pending_endpoints(app: MockApp, tmp_path: Path) -> None:
    state_path = tmp_path / "resume.sqlite"

    # First run: a tiny budget is spent before anything can be probed.
    config = fast_config()
    config.urls = [app.base + "/search"]
    config.active.enabled = True
    config.crawl.depth = -1
    config.request.max_requests = 4
    config.output.state_path = str(state_path)
    first = engine.run_scan(config)
    assert first.stats.requests_total <= 4
    assert first.findings == []

    with StateStore(state_path) as store:
        pending_before = len(store.pending_endpoints())
        assert pending_before >= 1

    # Second run: resume with a real budget.
    overrides = ScanConfig()
    overrides.request.max_requests = 400
    resumed = engine.run_resume(str(state_path), overrides=overrides)

    assert resumed.stats.requests_total > 0
    with StateStore(state_path) as store:
        assert len(store.pending_endpoints()) == 0
        assert store.counts()["findings"] >= 1
    assert any("resumed scan" in warning for warning in resumed.warnings)
    # the resumed run still reaches a real conclusion on /search
    assert any(
        finding.parameter == "q" and finding.behavioral is not None for finding in resumed.findings
    )


def test_resume_does_not_restore_secrets(app: MockApp, tmp_path: Path) -> None:
    state_path = tmp_path / "secrets.sqlite"
    config = fast_config()
    config.urls = [app.base + "/static-page"]
    config.crawl.depth = -1
    config.request.max_requests = 2
    config.request.cookies = {"session": "cookie-secret"}
    config.request.headers = {"Authorization": "Bearer header-secret"}
    config.output.state_path = str(state_path)
    engine.run_scan(config)

    resumed = engine.run_resume(str(state_path), overrides=ScanConfig())
    assert resumed.config.request.cookies == {}
    assert "Authorization" not in resumed.config.request.headers
    assert any("re-supply" in warning for warning in resumed.warnings)


def test_resume_rejects_an_unknown_state_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty.sqlite"
    StateStore(empty).close()
    with pytest.raises(ValueError):
        engine.run_resume(str(empty))
