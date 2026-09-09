"""Integration tests against the local mock application (scan engine)."""

import pytest

from paramscout.config import Config
from paramscout.discovery.engine import ScanEngine, run_resume
from paramscout.redaction import Redactor
from paramscout.scope import Scope


def base_cfg(urls, host, *, active=False, wordlist=None, crawl=False, depth=0,
             max_pages=10, max_requests=0, per_endpoint=0, retries=1,
             baseline_requests=3, validation_retests=1, state=None,
             exclude_paths=None, batch_size=1, throttle_stop_after=6):
    cfg = Config()
    cfg.seed_urls = urls
    cfg.scope_hosts = [host]
    cfg.active = active
    cfg.wordlist = wordlist
    cfg.use_builtin_wordlist = False
    cfg.crawl = crawl
    cfg.depth = depth
    cfg.max_pages = max_pages
    cfg.rate = 0.0
    cfg.concurrency = 4
    cfg.delay_between_probes = 0.0
    cfg.max_requests = max_requests
    cfg.max_requests_per_endpoint = per_endpoint
    cfg.retries = retries
    cfg.baseline_requests = baseline_requests
    cfg.validation_retests = validation_retests
    cfg.batch_size = batch_size
    cfg.timeout = 5.0
    cfg.throttle_stop_after = throttle_stop_after
    cfg.state_file = state
    cfg.exclude_paths = exclude_paths or []
    cfg.derive()
    return cfg


def host_of(live):
    return live.base.removeprefix("http://")


def scope_for(host):
    scope = Scope.from_hosts([host])
    return scope


async def test_passive_crawl_requests_only_existing_urls(server_a):
    live = server_a
    cfg = base_cfg([live.url("/")], host_of(live), crawl=True, depth=2, max_pages=20)
    scope = scope_for(host_of(live))
    engine = ScanEngine(cfg, scope, Redactor())
    report = await engine.run_scan()
    assert report.status == "ok"
    assert report.crawl is not None and report.crawl.pages_fetched >= 1

    requested = [f"{r['method']} {r['path']}?{r['query']}".rstrip("?") for r in live.app.requests]
    assert all(r.startswith("GET ") for r in requested)
    # no guessed parameters, no POST, no state-changing endpoints
    assert not any(r.startswith("POST ") for r in requested)
    assert not any("/checkout" in r for r in requested)
    assert not any("evil" in r for r in requested)

    names = {f.param for f in report.findings}
    # from link URLs
    assert "q" in names and "id" in names
    # form fields (hidden included) recorded passively
    assert "filter" in names and "item_id" in names
    # inline JS heuristics (URLSearchParams / fetch)
    assert "preview" in names
    # embedded JSON config under a params key
    assert "order" in names or "theme" in names


async def test_active_detects_behavioral_parameter(server_a, tmp_path):
    live = server_a
    wl = tmp_path / "wl.txt"
    wl.write_text("q\nzzz\n")
    cfg = base_cfg(
        [live.url("/search")], host_of(live), active=True, wordlist=str(wl),
        max_requests=200, per_endpoint=60, retries=1,
    )
    engine = ScanEngine(cfg, scope_for(host_of(live)), Redactor())
    report = await engine.run_scan()
    by_param = {f.param: f for f in report.findings}
    q = by_param.get("q")
    assert q is not None, "q should have been probed"
    assert q.probe is not None
    assert any(d.kind in ("text", "title") for d in q.probe.observed_diffs)
    assert q.behavior_score is not None and q.behavior_score >= 0.8
    assert q.priority == "high"
    zzz = by_param.get("zzz")
    assert zzz is not None and (zzz.probe is None or not zzz.probe.observed_diffs)
    # only GET requests were sent, none state-changing
    assert all(r["method"] == "GET" for r in live.app.requests)
    assert not any("/checkout" in r["path"] for r in live.app.requests)


async def test_reflection_reported_but_not_claimed_vulnerable(server_a, tmp_path):
    live = server_a
    wl = tmp_path / "wl.txt"
    wl.write_text("echo\n")
    cfg = base_cfg(
        [live.url("/reflect")], host_of(live), active=True, wordlist=str(wl),
        max_requests=200, per_endpoint=60, retries=1,
    )
    engine = ScanEngine(cfg, scope_for(host_of(live)), Redactor())
    report = await engine.run_scan()
    finding = next(f for f in report.findings if f.param == "echo")
    assert finding.probe is not None and finding.probe.reflected is True
    assert finding.probe.reflect_contexts
    reasons = " ".join(finding.priority_reasons).lower()
    assert "not a vulnerability" in reasons or "never" in reasons
    assert "xss" not in reasons


async def test_ignores_endpoint_no_false_positive(server_a, tmp_path):
    live = server_a
    wl = tmp_path / "wl.txt"
    wl.write_text("unused_alpha\nunused_beta\n")
    cfg = base_cfg(
        [live.url("/ignores")], host_of(live), active=True, wordlist=str(wl),
        max_requests=200, per_endpoint=60, retries=1,
    )
    engine = ScanEngine(cfg, scope_for(host_of(live)), Redactor())
    report = await engine.run_scan()
    for f in report.findings:
        assert f.param.startswith("unused_")
        assert f.probe is not None
        assert f.probe.reflected is False
        assert f.probe.observed_diffs == []


async def test_dynamic_timestamps_do_not_create_false_positive(server_a, tmp_path):
    live = server_a
    wl = tmp_path / "wl.txt"
    wl.write_text("ping\n")
    cfg = base_cfg(
        [live.url("/dynamic")], host_of(live), active=True, wordlist=str(wl),
        max_requests=200, per_endpoint=60, retries=1, validation_retests=0,
    )
    engine = ScanEngine(cfg, scope_for(host_of(live)), Redactor())
    report = await engine.run_scan()
    finding = next(f for f in report.findings if f.param == "ping")
    assert finding.inconclusive is False
    assert finding.probe is not None
    assert finding.probe.observed_diffs == []  # timestamps normalized away
    # the endpoint's baselines were considered stable
    assert not any("unstable" in l for l in report.limitations)


async def test_global_budget_enforced(server_a, tmp_path):
    live = server_a
    wl = tmp_path / "wl.txt"
    wl.write_text("\n".join(f"param{i}" for i in range(20)))
    cfg = base_cfg(
        [live.url("/ignores")], host_of(live), active=True, wordlist=str(wl),
        max_requests=5, per_endpoint=0, retries=0, validation_retests=0,
    )
    engine = ScanEngine(cfg, scope_for(host_of(live)), Redactor())
    report = await engine.run_scan()
    assert report.status == "budget"
    # 3 baselines + 1 control + 1 probe = 5 requests actually sent
    assert report.stats.attempts_total == 5
    assert len(live.app.requests) == 5


async def test_throttling_stops_scan(server_a, tmp_path):
    live = server_a
    wl = tmp_path / "wl.txt"
    wl.write_text("x\n")
    cfg = base_cfg(
        [live.url("/rate-limit")], host_of(live), active=True, wordlist=str(wl),
        max_requests=200, per_endpoint=60, retries=0, throttle_stop_after=1,
    )
    engine = ScanEngine(cfg, scope_for(host_of(live)), Redactor())
    report = await engine.run_scan()
    assert report.status == "throttled"
    assert report.stats.throttles >= 1


async def test_off_scope_redirect_never_followed(server_a, tmp_path):
    live = server_a
    wl = tmp_path / "wl.txt"
    wl.write_text("x\n")
    cfg = base_cfg(
        [live.url("/redirect-offscope")], host_of(live), active=True, wordlist=str(wl),
        max_requests=50, per_endpoint=20, retries=0,
    )
    engine = ScanEngine(cfg, scope_for(host_of(live)), Redactor())
    report = await engine.run_scan()
    assert report.stats.skipped_off_scope >= 1
    assert report.status == "ok"
    # the off-scope host was never contacted (it never received any request)
    assert not any("evil" in (r["path"] + "?" + r["query"]) for r in live.app.requests)


async def test_excluded_endpoints_never_contacted(server_a):
    live = server_a
    cfg = base_cfg(
        [live.url("/")], host_of(live), crawl=True, depth=1, max_pages=20,
        exclude_paths=["/checkout"],
    )
    engine = ScanEngine(cfg, scope_for(host_of(live)), Redactor())
    await engine.run_scan()
    assert not any("/checkout" in r["path"] for r in live.app.requests)


async def test_interrupted_scan_resumes_from_state(server_a, tmp_path):
    live = server_a
    state_file = str(tmp_path / "scan.sqlite")
    wl = tmp_path / "wl.txt"
    wl.write_text("\n".join(f"param{i:02d}" for i in range(12)))
    host = host_of(live)
    cfg = base_cfg(
        [live.url("/ignores")], host, active=True, wordlist=str(wl),
        max_requests=6, per_endpoint=0, retries=0, state=state_file,
        validation_retests=0, throttle_stop_after=20,
    )
    engine = ScanEngine(cfg, scope_for(host), Redactor())
    first = await engine.run_scan()
    assert first.status == "budget"
    hits_after_first = len(live.app.requests)

    # Resume with a fresh, larger budget; scope must be re-supplied.
    cfg2 = base_cfg(
        [], host, active=True, max_requests=500, per_endpoint=0, retries=0,
        state=state_file, validation_retests=0,
    )
    report2 = await run_resume(cfg2, scope_for(host), Redactor())
    assert report2.status != "budget"
    assert len(live.app.requests) > hits_after_first
    assert report2.stats.candidates_probed >= 1

    # Resuming again reports nothing pending.
    report3 = await run_resume(cfg2, scope_for(host), Redactor())
    assert report3.status == "nothing-pending"


async def test_resume_revalidates_scope(server_a, tmp_path):
    live = server_a
    state_file = str(tmp_path / "scan.sqlite")
    wl = tmp_path / "wl.txt"
    wl.write_text("\n".join(f"k{i}" for i in range(15)))
    host = host_of(live)
    cfg = base_cfg(
        [live.url("/ignores")], host, active=True, wordlist=str(wl),
        max_requests=6, per_endpoint=0, retries=0, state=state_file,
        validation_retests=0,
    )
    engine = ScanEngine(cfg, scope_for(host), Redactor())
    await engine.run_scan()
    hits = len(live.app.requests)
    # Resume with a scope that no longer authorizes the target host.
    other = Scope.from_hosts(["somewhere-else.example.test"])
    cfg2 = base_cfg([], host, active=True, max_requests=500, state=state_file)
    report = await run_resume(cfg2, other, Redactor())
    assert report.stats.skipped_off_scope >= 1
    assert len(live.app.requests) == hits  # nothing further was requested
