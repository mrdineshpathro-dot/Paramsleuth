"""CLI behaviour: argument handling, guard rails and exit codes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import fast_config
from mockapp import MockApp

from paramscout import cli
from paramscout.cli import build_config, build_parser, main
from paramscout.urls import EndpointGrouping


def test_parser_supports_the_documented_invocations() -> None:
    parser = build_parser()
    namespace = parser.parse_args(
        [
            "scan",
            "--url", "https://app.example.test/search",
            "--scope-host", "app.example.test",
            "--active",
            "--wordlist", "parameters.txt",
            "--rate", "1",
            "--concurrency", "2",
            "--max-requests", "300",
            "--output", "findings.json",
        ]
    )
    assert namespace.command == "scan"
    assert namespace.active is True
    assert namespace.rate == 1.0
    assert namespace.concurrency == 2
    assert namespace.max_requests == 300
    assert namespace.wordlists == ["parameters.txt"]

    namespace = parser.parse_args(
        ["scan", "--input", "targets.txt", "--scope-file", "scope.txt", "--active", "--dry-run"]
    )
    assert namespace.dry_run is True and namespace.scope_file == "scope.txt"

    namespace = parser.parse_args(["extract", "--input", "collected_urls.txt", "--output", "passive.json"])
    assert namespace.command == "extract"

    namespace = parser.parse_args(["resume", "--state", "scan.sqlite"])
    assert namespace.state_path == "scan.sqlite"

    namespace = parser.parse_args(
        ["scan", "--url", "https://a.test", "--scope-host", "a.test", "--extract-js", "--output", "js.json"]
    )
    assert namespace.extract_js is True
    namespace = parser.parse_args(
        ["scan", "--url", "https://a.test", "--scope-host", "a.test", "--no-extract-js"]
    )
    assert namespace.extract_js is False


def test_unspecified_flags_do_not_override_the_config_file(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[scope]
hosts = ["from-file.example.test"]
include_subdomains = true

[request]
rate = 7.5
timeout = 33.0

[crawl]
depth = 4

[active]
baselines = 5
""",
        encoding="utf-8",
    )
    parser = build_parser()
    namespace = parser.parse_args(
        ["scan", "--url", "https://from-file.example.test/", "--config", str(config_file), "--rate", "1.5"]
    )
    config = build_config(namespace)
    assert config.request.rate == 1.5, "an explicit flag wins"
    assert config.request.timeout == 33.0, "unspecified values come from the file"
    assert config.crawl.depth == 4
    assert config.active.baselines == 5
    assert config.scope.hosts[0].host == "from-file.example.test"
    assert config.scope.include_subdomains is True


def test_scope_file_and_repeated_hosts(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("# comment\napp.example.test\n.example2.test\n", encoding="utf-8")
    parser = build_parser()
    namespace = parser.parse_args(
        [
            "scan",
            "--url", "https://app.example.test/",
            "--scope-host", "extra.example.test",
            "--scope-file", str(scope_file),
            "--allow-path", "/app/",
            "--exclude-path", "re:^/admin/",
        ]
    )
    config = build_config(namespace)
    hosts = {rule.host for rule in config.scope.hosts}
    assert hosts == {"extra.example.test", "app.example.test", "example2.test"}
    assert [rule.include_subdomains for rule in config.scope.hosts if rule.host == "example2.test"] == [True]
    assert config.scope.allow_paths[0].pattern == "^/app/"
    assert config.scope.deny_paths[0].pattern == "^/admin/"


def test_headers_and_cookies_are_parsed(tmp_path: Path) -> None:
    parser = build_parser()
    namespace = parser.parse_args(
        [
            "scan",
            "--url", "https://app.example.test/",
            "--scope-host", "app.example.test",
            "--header", "X-Tenant: acme",
            "--cookie", "session=abc; theme=dark",
        ]
    )
    config = build_config(namespace)
    assert config.request.headers == {"X-Tenant": "acme"}
    assert config.request.cookies == {"session": "abc", "theme": "dark"}


def test_malformed_header_is_rejected() -> None:
    parser = build_parser()
    namespace = parser.parse_args(
        ["scan", "--url", "https://a.test/", "--scope-host", "a.test", "--header", "nonsense"]
    )
    with pytest.raises(ValueError):
        build_config(namespace)


def test_endpoint_grouping_flag() -> None:
    parser = build_parser()
    namespace = parser.parse_args(
        ["scan", "--url", "https://a.test/", "--scope-host", "a.test", "--endpoint-grouping", "origin-only"]
    )
    assert build_config(namespace).output.endpoint_grouping is EndpointGrouping.ORIGIN_ONLY


def test_scan_refuses_to_run_without_scope(app: MockApp) -> None:
    assert app.state.counts == {}
    code = main(["scan", "--url", app.base + "/", "--quiet"])
    assert code == cli.EXIT_USAGE
    assert app.state.counts == {}, "no request may be sent without a scope"


def test_scan_requires_a_target() -> None:
    assert main(["scan", "--scope-host", "app.example.test", "--quiet"]) == cli.EXIT_USAGE
    assert main(["extract", "--quiet"]) == cli.EXIT_USAGE


def test_extract_offline_writes_reports(tmp_path: Path, app: MockApp) -> None:
    collected = tmp_path / "collected.txt"
    collected.write_text(
        "\n".join(
            [
                f"{app.base}/search?q=widgets&sort=asc",
                f"{app.base}/profile?note=hi",
            ]
        ),
        encoding="utf-8",
    )
    out = tmp_path / "passive.json"
    csv_out = tmp_path / "passive.csv"
    html_out = tmp_path / "passive.html"
    code = main(
        [
            "extract",
            "--input", str(collected),
            "--scope-host", "127.0.0.1",
            "--allow-private-networks",
            "--output", str(out),
            "--csv", str(csv_out),
            "--html-report", str(html_out),
            "--quiet",
        ]
    )
    assert code == cli.EXIT_OK
    assert app.state.counts == {}, "extract must never touch the network"
    report = json.loads(out.read_text())
    assert report["mode"] == "extract-offline"
    assert report["stats"]["requests_total"] == 0
    parameters = {finding["parameter"] for finding in report["findings"]}
    assert {"q", "sort", "note"} <= parameters
    assert csv_out.exists() and html_out.exists()


def test_dry_run_sends_nothing_and_reports_a_plan(tmp_path: Path, app: MockApp) -> None:
    collected = tmp_path / "targets.txt"
    collected.write_text(f"{app.base}/search?q=widgets\n", encoding="utf-8")
    out = tmp_path / "plan.json"
    code = main(
        [
            "scan",
            "--input", str(collected),
            "--scope-host", "127.0.0.1",
            "--allow-private-networks",
            "--active",
            "--batch", "3",
            "--dry-run",
            "--output", str(out),
            "--quiet",
        ]
    )
    assert code == cli.EXIT_OK
    assert app.state.counts == {}
    document = json.loads(out.read_text())
    plan = document["plan"]
    assert plan["budget"]["configured --max-requests"] == 500
    assert plan["budget"]["estimated total"] > 0
    assert any(stage[0] == "active/batch caveat" for stage in plan["stages"])
    # A dry run never reaches the probe phase, so the standing caveats have to
    # be recorded by the planner or they would be missing from the report.
    joined = " ".join(document["warnings"])
    assert "GET requests only" in joined
    assert "batch size 3" in joined
    assert joined.count("GET requests only") == 1


def test_full_scan_via_cli_produces_findings(tmp_path: Path, app: MockApp) -> None:
    out = tmp_path / "findings.json"
    code = main(
        [
            "scan",
            "--url", app.base + "/",
            "--scope-host", "127.0.0.1",
            "--allow-private-networks",
            "--active",
            "--exclude-endpoint", "^/checkout",
            "--depth", "1",
            "--max-requests", "900",
            "--rate", "500",
            "--global-rate", "900",
            "--state", str(tmp_path / "state.sqlite"),
            "--output", str(out),
            "--csv", str(tmp_path / "findings.csv"),
            "--html-report", str(tmp_path / "findings.html"),
            "--quiet",
        ]
    )
    assert code == cli.EXIT_OK
    report = json.loads(out.read_text())
    assert report["mode"] == "active"
    by_parameter = {(finding["parameter"], finding["endpoint"]) for finding in report["findings"]}
    assert ("q", app.base + "/search") in by_parameter
    statuses = {finding["behavioral"]["status"] for finding in report["findings"] if finding["behavioral"]}
    assert "behavioral_change" in statuses
    assert "reflection_only" in statuses
    assert app.state.counts.get("POST", 0) == 0
    assert (tmp_path / "state.sqlite").exists()


def test_resume_command_via_cli(tmp_path: Path, app: MockApp) -> None:
    state = tmp_path / "state.sqlite"
    main(
        [
            "scan",
            "--url", app.base + "/static-page",
            "--scope-host", "127.0.0.1",
            "--allow-private-networks",
            "--active",
            "--depth", "-1",
            "--max-requests", "3",
            "--rate", "500",
            "--state", str(state),
            "--quiet",
        ]
    )
    out = tmp_path / "resumed.json"
    code = main(
        [
            "resume",
            "--state", str(state),
            "--max-requests", "200",
            "--output", str(out),
            "--quiet",
        ]
    )
    assert code == cli.EXIT_OK
    report = json.loads(out.read_text())
    assert report["mode"] == "resumed"
    assert any("resumed scan" in warning for warning in report["warnings"])


def test_resume_requires_an_existing_state_file(tmp_path: Path) -> None:
    assert main(["resume", "--state", str(tmp_path / "missing.sqlite"), "--quiet"]) == cli.EXIT_USAGE


def test_wordlist_command() -> None:
    assert main(["wordlist"]) == cli.EXIT_OK
    assert main(["wordlist", "--count"]) == cli.EXIT_OK


def test_tls_verification_is_on_by_default() -> None:
    parser = build_parser()
    namespace = parser.parse_args(["scan", "--url", "https://a.test/", "--scope-host", "a.test"])
    assert build_config(namespace).request.verify_tls is True
    namespace = parser.parse_args(
        ["scan", "--url", "https://a.test/", "--scope-host", "a.test", "--insecure-skip-tls-verify"]
    )
    assert build_config(namespace).request.verify_tls is False


def test_every_overridable_flag_reaches_the_config() -> None:
    """Guard against a CLI dest silently failing to map onto a config field."""

    parser = build_parser()
    namespace = parser.parse_args(
        [
            "scan",
            "--url", "https://a.test/",
            "--scope-host", "a.test",
            "--active",
            "--baselines", "7",
            "--confirmations", "4",
            "--batch", "5",
            "--max-candidates-per-endpoint", "11",
            "--max-active-endpoints", "13",
            "--no-builtin-wordlist",
            "--wordlist", "w.txt",
            "--depth", "3",
            "--max-pages", "77",
            "--max-js-files", "9",
            "--no-external-js",
            "--no-robots",
            "--no-sitemap",
            "--rate", "4",
            "--concurrency", "6",
            "--timeout", "21",
            "--retries", "1",
            "--max-redirects", "2",
            "--max-response-bytes", "1234",
            "--max-requests", "88",
            "--max-requests-per-endpoint", "9",
            "--max-url-length", "1500",
            "--proxy", "http://127.0.0.1:8080",
            "--user-agent", "UA/1",
            "--insecure-skip-tls-verify",
            "--state", "s.sqlite",
        ]
    )
    config = build_config(namespace)
    assert config.active.enabled is True
    assert config.active.baselines == 7
    assert config.active.confirmations == 4
    assert config.active.batch_size == 5
    assert config.active.max_candidates_per_endpoint == 11
    assert config.active.max_active_endpoints == 13
    assert config.active.use_builtin_wordlist is False
    assert config.active.wordlists == ["w.txt"]
    assert config.crawl.depth == 3
    assert config.crawl.max_pages == 77
    assert config.crawl.max_js_files == 9
    assert config.crawl.fetch_external_js is False
    assert config.crawl.fetch_robots is False
    assert config.crawl.fetch_sitemap is False
    assert config.request.rate == 4.0
    assert config.request.concurrency == 6
    assert config.request.timeout == 21.0
    assert config.request.retries == 1
    assert config.request.max_redirects == 2
    assert config.request.max_response_bytes == 1234
    assert config.request.max_requests == 88
    assert config.request.max_requests_per_endpoint == 9
    assert config.request.max_url_length == 1500
    assert config.request.proxy == "http://127.0.0.1:8080"
    assert config.request.user_agent == "UA/1"
    assert config.request.verify_tls is False
    assert config.output.state_path == "s.sqlite"


def test_rate_and_concurrency_scopes_are_explicit() -> None:
    parser = build_parser()
    namespace = parser.parse_args(
        [
            "scan",
            "--url", "https://a.test/",
            "--scope-host", "a.test",
            "--rate", "3",
            "--rate-scope", "global",
            "--concurrency", "5",
            "--concurrency-scope", "global",
        ]
    )
    config = build_config(namespace)
    assert config.request.rate == 3.0 and config.request.rate_scope == "global"
    assert config.request.concurrency == 5 and config.request.concurrency_scope == "global"


def test_default_configuration_is_conservative() -> None:
    config = fast_config()
    defaults = type(config)()
    assert defaults.request.rate <= 2.0
    assert defaults.request.concurrency <= 2
    assert defaults.request.verify_tls is True
    assert defaults.request.max_requests == 500
    assert defaults.request.max_redirects == 5
    assert defaults.active.enabled is False
    assert defaults.active.batch_size == 1
    assert defaults.crawl.max_pages == 100
    assert any("/logout" in pattern for pattern in defaults.active.excluded_paths)
