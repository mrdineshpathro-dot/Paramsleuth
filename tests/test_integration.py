"""End-to-end tests against the local mock application."""

from __future__ import annotations

import asyncio

from conftest import fast_config
from mockapp import MockApp

from paramscout.engine import run_extract, run_scan
from paramscout.http_client import FetchOptions, ParamScoutClient
from paramscout.models import BehavioralStatus, ScanStats
from paramscout.scope import Scope


def _finding(ctx, parameter: str, endpoint_suffix: str):
    for finding in ctx.findings:
        if finding.parameter == parameter and finding.endpoint.endswith(endpoint_suffix):
            return finding
    return None


def test_passive_scan_never_sends_a_guessed_parameter(app: MockApp) -> None:
    config = fast_config()
    config.urls = [app.base + "/"]
    ctx = run_scan(config)

    purposes = ctx.stats.requests_by_purpose
    assert "probe" not in purposes
    assert "control" not in purposes
    assert "baseline" not in purposes

    names = {finding.parameter for finding in ctx.findings}
    # parameters the target actually told us about
    assert {"q", "sort", "note", "id", "source", "filter"} <= names
    # ...and no wordlist guesses
    assert "redirect_url" not in names
    assert all("wordlist" not in finding.sources for finding in ctx.findings)


def test_active_scan_separates_change_from_reflection(app: MockApp) -> None:
    config = fast_config()
    config.urls = [app.base + "/"]
    config.active.enabled = True
    config.active.excluded_paths.append(r"^/checkout")
    config.request.max_requests = 900
    ctx = run_scan(config)

    search_q = _finding(ctx, "q", "/search")
    assert search_q is not None
    assert search_q.behavioral.status is BehavioralStatus.BEHAVIORAL_CHANGE
    assert search_q.behavioral.attempts >= 2

    profile_note = _finding(ctx, "note", "/profile")
    assert profile_note is not None
    assert profile_note.behavioral.status is BehavioralStatus.REFLECTION_ONLY
    assert profile_note.behavioral.reflection.reflected is True
    # reflection must never be scored like a behavioural change
    assert profile_note.behavioral_confidence < search_q.behavioral_confidence

    static = _finding(ctx, "anything", "/static-page")
    assert static is not None
    assert static.behavioral.status is BehavioralStatus.NO_CHANGE


def test_state_changing_endpoint_is_never_probed(app: MockApp) -> None:
    config = fast_config()
    config.urls = [app.base + "/"]
    config.active.enabled = True
    config.active.excluded_paths.append(r"^/checkout")
    config.request.max_requests = 900
    ctx = run_scan(config)

    assert app.state.canary_requests("/checkout") == []
    assert app.state.counts.get("POST", 0) == 0
    excluded = [outcome for outcome in ctx.outcomes if outcome.endpoint.endswith("/checkout")]
    assert excluded and excluded[0].excluded


def test_forms_are_recorded_but_never_submitted(app: MockApp) -> None:
    config = fast_config()
    config.urls = [app.base + "/"]
    ctx = run_scan(config)

    assert app.state.counts.get("POST", 0) == 0
    assert ctx.passive.forms, "forms must be captured as passive evidence"
    methods = {(form.action.rstrip("/").split("/")[-1], form.method) for form in ctx.passive.forms}
    assert ("search", "GET") in methods
    assert ("checkout", "POST") in methods
    # the POST form's fields are known, but the form itself was never submitted
    checkout = [form for form in ctx.passive.forms if form.method == "POST"][0]
    assert "order_id" in checkout.fields


def test_off_scope_redirect_is_never_followed(apps: tuple[MockApp, MockApp]) -> None:
    app, secondary = apps
    config = fast_config()  # scope is 127.0.0.1 only
    config.urls = [app.base + "/leave"]
    ctx = run_scan(config)

    assert secondary.state.counts == {}, "the off-scope host must never be contacted"
    assert secondary.state.requests == []
    assert ctx.stats.skipped_off_scope, "the blocked redirect must be reported"
    assert any("redirect blocked" in entry for entry in ctx.stats.skipped_off_scope)


def test_off_scope_scripts_are_never_fetched(apps: tuple[MockApp, MockApp]) -> None:
    app, secondary = apps
    config = fast_config()
    config.urls = [app.base + "/"]
    ctx = run_scan(config)

    assert secondary.state.counts == {}
    assert any("localhost" in entry for entry in ctx.stats.skipped_off_scope)


def test_in_scope_redirect_is_followed_and_validated(app: MockApp) -> None:
    config = fast_config()
    config.urls = [app.base + "/redir-inscope"]
    ctx = run_scan(config)
    pages = ctx.crawl_result.pages if ctx.crawl_result else []
    assert any("/redir-inscope" in page.url for page in pages)
    assert any("/product?id=9" in page.final_url for page in pages)


def test_credentials_are_not_forwarded_across_origins(apps: tuple[MockApp, MockApp]) -> None:
    app, secondary = apps

    async def scenario() -> None:
        # Both hosts are authorized here, so the redirect *is* followed - which
        # is exactly the situation where credential leakage would happen.
        scope = Scope.from_hosts(["127.0.0.1", "localhost"], allow_private_networks=True)
        config = fast_config(scope_hosts=["127.0.0.1", "localhost"])
        config.request.headers = {"Authorization": "Bearer top-secret-value"}
        config.request.cookies = {"session": "cookie-secret-value"}
        async with ParamScoutClient(
            scope=scope, request_config=config.request, stats=ScanStats()
        ) as client:
            direct = await client.fetch(app.base + "/echoauth", FetchOptions(purpose="test"))
            assert b"true" in direct.body
            redirected = await client.fetch(app.base + "/leave", FetchOptions(purpose="test"))
            assert redirected.status == 200
            assert redirected.final_url.startswith(secondary.base)

    asyncio.run(scenario())

    on_secondary = [item for item in secondary.state.requests if item["path"] == "/elsewhere"]
    assert on_secondary, "the in-scope redirect should have been followed"
    assert all(item["authorization"] is False for item in on_secondary)
    assert all(item["cookie"] is False for item in on_secondary)


def test_cookies_are_scoped_to_the_configured_origin(app: MockApp) -> None:
    async def scenario() -> bytes:
        config = fast_config()
        config.request.cookies = {"session": "cookie-secret-value"}
        async with ParamScoutClient(
            scope=config.scope, request_config=config.request, stats=ScanStats()
        ) as client:
            result = await client.fetch(app.base + "/echoauth", FetchOptions(purpose="test"))
            return result.body

    body = asyncio.run(scenario())
    assert b'"cookie_present": true' in body


def test_server_cookies_do_not_leak_to_other_hosts(apps: tuple[MockApp, MockApp]) -> None:
    app, secondary = apps

    async def scenario() -> None:
        config = fast_config(scope_hosts=["127.0.0.1", "localhost"])
        async with ParamScoutClient(
            scope=config.scope, request_config=config.request, stats=ScanStats()
        ) as client:
            await client.fetch(app.base + "/setcookie", FetchOptions(purpose="test"))
            await client.fetch(secondary.base + "/elsewhere", FetchOptions(purpose="test"))

    asyncio.run(scenario())
    assert all(item["cookie"] is False for item in secondary.state.requests)


def test_private_targets_require_an_explicit_opt_in(app: MockApp) -> None:
    config = fast_config()
    config.scope.allow_private_networks = False
    config.urls = [app.base + "/"]
    ctx = run_scan(config)
    assert ctx.stats.requests_total == 0
    assert ctx.warnings


def test_dry_run_sends_nothing(app: MockApp) -> None:
    config = fast_config()
    config.urls = [app.base + "/"]
    config.active.enabled = True
    config.dry_run = True
    ctx = run_scan(config)

    assert app.state.counts == {}
    assert ctx.stats.requests_total == 0
    assert ctx.plan["stages"]
    assert "estimated total" in ctx.plan["budget"]
    assert ctx.plan["endpoints"]


def test_offline_extract_makes_no_requests(app: MockApp, tmp_path) -> None:
    collected = tmp_path / "collected.txt"
    collected.write_text(
        "\n".join(
            [
                f"{app.base}/search?q=widgets&sort=asc",
                f"{app.base}/profile?note=hi&note=",
                f"{app.base}/product?id=1&id=2",
                "https://outside.example.test/x?a=1",
            ]
        ),
        encoding="utf-8",
    )
    config = fast_config()
    config.input_files = [str(collected)]
    ctx = run_extract(config)

    assert app.state.counts == {}, "extract must never touch the network"
    assert ctx.stats.requests_total == 0
    names = {(finding.parameter, finding.endpoint) for finding in ctx.findings}
    assert ("q", app.base + "/search") in names
    assert ("note", app.base + "/profile") in names
    assert ("id", app.base + "/product") in names
    # out-of-scope input is excluded from analysis and reported
    assert any("outside.example.test" in warning for warning in ctx.warnings)


def test_repeated_and_blank_parameters_survive_offline_extract(app: MockApp, tmp_path) -> None:
    collected = tmp_path / "collected.txt"
    collected.write_text(f"{app.base}/product?id=1&id=&id=3\n", encoding="utf-8")
    config = fast_config()
    config.input_files = [str(collected)]
    ctx = run_extract(config)

    candidates = ctx.passive.candidates_for(app.base + "/product")
    identifier = [item for item in candidates if item.name == "id"]
    assert len(identifier) == 1, "repeats collapse into one candidate ..."
    evidence = identifier[0].evidence[0]
    assert "id=1" in evidence.detail
    # ... but the evidence records that the parameter was seen more than once
    assert len(identifier[0].evidence) == 3


def test_dump_metadata_columns_are_not_treated_as_urls(tmp_path) -> None:
    """``URL<TAB>date<TAB>type<TAB>status`` lines must yield exactly one URL."""

    from paramscout import engine

    collected = tmp_path / "dump.txt"
    collected.write_text(
        "https://app.example.test/a?x=1\t2024-03-11\ttext/html\t200\n"
        '{"url": "https://app.example.test/b?y=2", "status": 200}\n',
        encoding="utf-8",
    )
    config = fast_config()
    config.input_files = [str(collected)]
    seeds, _archives = engine.load_inputs(config)
    assert seeds == ["https://app.example.test/a?x=1", "https://app.example.test/b?y=2"]


def test_wordlist_candidates_are_labelled_as_guesses(app: MockApp) -> None:
    config = fast_config()
    config.urls = [app.base + "/static-page"]
    config.active.enabled = True
    config.active.wordlists = []
    config.active.max_candidates_per_endpoint = 5
    config.crawl.depth = -1
    ctx = run_scan(config)

    guesses = [
        finding
        for finding in ctx.findings
        if finding.sources == ["wordlist"]
    ]
    for finding in guesses:
        assert any("wordlist" in reason.lower() for reason in finding.discovery_reasons)
        assert finding.discovery_confidence < 0.2


def test_findings_always_explain_their_scores(app: MockApp) -> None:
    config = fast_config()
    config.urls = [app.base + "/"]
    config.active.enabled = True
    config.active.excluded_paths.append(r"^/checkout")
    config.request.max_requests = 900
    ctx = run_scan(config)

    assert ctx.findings
    for finding in ctx.findings:
        assert finding.discovery_reasons, finding.parameter
        assert finding.priority_reasons, finding.parameter
        assert any("not a vulnerability severity" in reason for reason in finding.priority_reasons)
        assert finding.reproduction.startswith("GET ")
        assert "Host:" in finding.reproduction
