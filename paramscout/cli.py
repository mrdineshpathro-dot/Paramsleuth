"""Command line interface.

Sub-commands
------------

``extract``
    Analyse local URL collections / saved HTML **without any network access**.

``scan``
    Crawl an explicitly authorized scope (passive by default), optionally with
    ``--active`` controlled parameter probing.

``resume``
    Continue an interrupted scan from its SQLite state file.

``wordlist``
    Print the built-in candidate list.

Every overridable option defaults to ``None`` so that "not passed" is
distinguishable from "passed with the default value"; values from ``--config``
are only replaced by flags the operator actually typed.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from rich.console import Console

from paramscout import __version__
from paramscout.config import (
    ScanConfig,
    apply_toml,
    load_toml_config,
    parse_cookie_header,
    parse_header,
)
from paramscout.engine import run_extract, run_resume, run_scan
from paramscout.reporting import build_report, render_plan, render_summary, write_csv, write_html, write_json
from paramscout.scope import Scope, compile_path_rule, parse_host_rule
from paramscout.urls import EndpointGrouping
from paramscout.wordlists import builtin_wordlist

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="paramscout",
        description=(
            "ParamScout - passive-first URL parameter discovery, validation and prioritisation "
            "for explicitly authorized targets. It does not exploit anything and never labels a "
            "parameter as vulnerable."
        ),
        epilog=(
            "Network activity requires explicit scope configuration. "
            "Use --dry-run to preview a scan without sending a single request."
        ),
    )
    parser.add_argument("--version", action="version", version=f"ParamScout {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    _add_extract(subparsers)
    _add_scan(subparsers)
    _add_resume(subparsers)
    _add_wordlist(subparsers)
    return parser


def _add_output_options(parser: argparse.ArgumentParser, *, include_state: bool = True) -> None:
    parser.add_argument("--output", "-o", dest="json_path", default=None, help="write the JSON report here")
    parser.add_argument("--csv", dest="csv_path", default=None, help="write a CSV report here")
    parser.add_argument("--html-report", dest="html_path", default=None, help="write a standalone HTML report here")
    if include_state:
        parser.add_argument("--state", dest="state_path", default=None, help="SQLite state file for resumable scans")
    parser.add_argument(
        "--endpoint-grouping",
        dest="endpoint_grouping",
        default=None,
        choices=[item.value for item in EndpointGrouping],
        help="how aggressively to fold URLs into endpoints (default: strict)",
    )
    parser.add_argument("--quiet", "-q", action="store_true", default=False, help="suppress the terminal summary")


def _add_scope_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--scope-host",
        dest="scope_hosts",
        action="append",
        default=None,
        metavar="HOST[:PORT]",
        help="allowlisted host; prefix with '.' or '*.' to include subdomains (repeatable)",
    )
    parser.add_argument(
        "--scope-file",
        dest="scope_file",
        default=None,
        help="file with one scope host per line ('#' comments allowed)",
    )
    parser.add_argument(
        "--allow-path",
        dest="allow_paths",
        action="append",
        default=None,
        help="only request paths matching this prefix or 're:<regex>' (repeatable)",
    )
    parser.add_argument(
        "--exclude-path",
        dest="deny_paths",
        action="append",
        default=None,
        help="never request paths matching this prefix or 're:<regex>' (repeatable)",
    )
    parser.add_argument(
        "--include-subdomains",
        dest="include_subdomains",
        action="store_true",
        default=None,
        help="treat scope hosts as covering their subdomains",
    )
    parser.add_argument(
        "--allow-private-networks",
        dest="allow_private_networks",
        action="store_true",
        default=None,
        help="permit loopback/private/link-local targets (needed for local test apps)",
    )
    parser.add_argument(
        "--resolve-hosts",
        dest="resolve_hosts",
        action="store_true",
        default=None,
        help="also reject hostnames that resolve to private/loopback addresses",
    )


def _add_request_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--rate",
        dest="rate",
        type=float,
        default=None,
        help="requests per second (default 2.0); applies per host unless --rate-scope global",
    )
    parser.add_argument(
        "--rate-scope",
        dest="rate_scope",
        default=None,
        choices=["host", "global"],
        help="whether --rate is a per-host or a global limit (a global cap is always enforced too)",
    )
    parser.add_argument(
        "--concurrency",
        dest="concurrency",
        type=int,
        default=None,
        help="concurrent requests (default 2); per host unless --concurrency-scope global",
    )
    parser.add_argument(
        "--concurrency-scope",
        dest="concurrency_scope",
        default=None,
        choices=["host", "global"],
        help="whether --concurrency is a per-host or a global limit",
    )
    parser.add_argument("--global-rate", dest="global_rate", type=float, default=None, help="aggregate requests/second cap")
    parser.add_argument(
        "--global-concurrency", dest="global_concurrency", type=int, default=None, help="aggregate in-flight request cap"
    )
    parser.add_argument("--timeout", dest="timeout", type=float, default=None, help="per-request timeout in seconds")
    parser.add_argument("--retries", dest="retries", type=int, default=None, help="retries per request (default 2)")
    parser.add_argument("--max-redirects", dest="max_redirects", type=int, default=None, help="maximum redirect hops")
    parser.add_argument(
        "--max-response-bytes", dest="max_response_bytes", type=int, default=None, help="response body size cap"
    )
    parser.add_argument(
        "--max-requests", dest="max_requests", type=int, default=None, help="global request budget (default 500)"
    )
    parser.add_argument(
        "--max-requests-per-endpoint",
        dest="max_requests_per_endpoint",
        type=int,
        default=None,
        help="per-endpoint request budget (default 40)",
    )
    parser.add_argument("--max-url-length", dest="max_url_length", type=int, default=None, help="refuse probe URLs longer than this")
    parser.add_argument("--proxy", dest="proxy", default=None, help="HTTP(S) proxy for authorized inspection")
    parser.add_argument("--user-agent", dest="user_agent", default=None, help="override the User-Agent header")
    parser.add_argument(
        "--header",
        dest="headers",
        action="append",
        default=None,
        metavar="'Name: value'",
        help="extra request header (repeatable); values are redacted from logs and reports",
    )
    parser.add_argument(
        "--cookie",
        dest="cookies",
        action="append",
        default=None,
        metavar="'name=value; name2=value2'",
        help="cookies for authorized authenticated testing (repeatable); never written to reports or state",
    )
    parser.add_argument(
        "--insecure-skip-tls-verify",
        dest="verify_tls",
        action="store_false",
        default=None,
        help="disable TLS verification (authorized internal targets only)",
    )


def _add_crawl_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--depth", dest="depth", type=int, default=None, help="crawl depth (default 2, -1 disables crawling)")
    parser.add_argument("--max-pages", dest="max_pages", type=int, default=None, help="maximum pages to fetch (default 100)")
    parser.add_argument("--max-js-files", dest="max_js_files", type=int, default=None, help="maximum external JS files to fetch")
    parser.add_argument("--max-js-bytes", dest="max_js_bytes", type=int, default=None, help="per-file JS size cap")
    parser.add_argument(
        "--extract-js",
        dest="extract_js",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="extract parameter candidates from JavaScript (default: on)",
    )
    parser.add_argument(
        "--external-js",
        dest="fetch_external_js",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="fetch in-scope external JavaScript files (default: on)",
    )
    parser.add_argument(
        "--robots",
        dest="fetch_robots",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="read robots.txt for endpoints (default: on)",
    )
    parser.add_argument(
        "--sitemap",
        dest="fetch_sitemap",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="read sitemap.xml for endpoints (default: on)",
    )


def _add_active_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--active",
        dest="active",
        action="store_true",
        default=None,
        help="enable controlled active parameter discovery (GET only, alphanumeric canaries)",
    )
    parser.add_argument(
        "--wordlist",
        dest="wordlists",
        action="append",
        default=None,
        help="parameter wordlist file (repeatable)",
    )
    parser.add_argument(
        "--no-builtin-wordlist",
        dest="use_builtin_wordlist",
        action="store_false",
        default=None,
        help="do not use the conservative built-in parameter list",
    )
    parser.add_argument("--baselines", dest="baselines", type=int, default=None, help="baseline responses per endpoint (default 3)")
    parser.add_argument(
        "--confirmations", dest="confirmations", type=int, default=None, help="re-tests per promising candidate (default 2)"
    )
    parser.add_argument(
        "--batch",
        dest="batch_size",
        type=int,
        default=None,
        help="probe N parameters per request (default 1); batch hits are always re-probed individually",
    )
    parser.add_argument(
        "--max-candidates-per-endpoint",
        dest="max_candidates_per_endpoint",
        type=int,
        default=None,
        help="cap on candidates probed per endpoint",
    )
    parser.add_argument(
        "--max-active-endpoints",
        dest="max_active_endpoints",
        type=int,
        default=None,
        help="cap on endpoints probed in active mode",
    )
    parser.add_argument(
        "--exclude-endpoint",
        dest="excluded_paths",
        action="append",
        default=None,
        help="regex for endpoints that must never be probed (repeatable, added to the defaults)",
    )


def _add_extract(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "extract",
        help="analyse collected URLs / saved HTML without making network requests",
        description="Offline analysis. No HTTP requests are made by this command.",
    )
    parser.add_argument("--url", dest="urls", action="append", default=None, help="a URL to analyse (repeatable)")
    parser.add_argument(
        "--input",
        "-i",
        dest="input_files",
        action="append",
        default=None,
        help="file of collected URLs, or a saved .html document (repeatable)",
    )
    parser.add_argument("--config", dest="config", default=None, help="TOML configuration file")
    _add_scope_options(parser)
    _add_output_options(parser)


def _add_scan(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "scan",
        help="crawl an authorized scope (passive) and optionally probe parameters (--active)",
    )
    parser.add_argument("--url", dest="urls", action="append", default=None, help="seed URL (repeatable)")
    parser.add_argument("--input", "-i", dest="input_files", action="append", default=None, help="file of URLs (repeatable)")
    parser.add_argument("--config", dest="config", default=None, help="TOML configuration file")
    parser.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        default=False,
        help="print scope, planned actions and a request-budget estimate; sends nothing",
    )
    _add_scope_options(parser)
    _add_request_options(parser)
    _add_crawl_options(parser)
    _add_active_options(parser)
    _add_output_options(parser)


def _add_resume(subparsers: Any) -> None:
    parser = subparsers.add_parser("resume", help="resume an interrupted scan from its state file")
    parser.add_argument("--state", dest="state_path", required=True, help="SQLite state file written by a previous scan")
    parser.add_argument(
        "--cookie",
        dest="cookies",
        action="append",
        default=None,
        help="re-supply cookies for authenticated resumption (they are never stored in the state file)",
    )
    parser.add_argument(
        "--header",
        dest="headers",
        action="append",
        default=None,
        help="re-supply a request header for authenticated resumption",
    )
    parser.add_argument("--max-requests", dest="max_requests", type=int, default=None, help="request budget for this run")
    _add_output_options(parser, include_state=False)


def _add_wordlist(subparsers: Any) -> None:
    parser = subparsers.add_parser("wordlist", help="print the built-in conservative parameter list")
    parser.add_argument("--count", action="store_true", help="print only the number of entries")


# ---------------------------------------------------------------------------
# config assembly
# ---------------------------------------------------------------------------


def _load_scope_file(path: str) -> list[str]:
    hosts: list[str] = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        entry = line.strip()
        if entry and not entry.startswith("#"):
            hosts.append(entry)
    return hosts


def build_config(args: argparse.Namespace) -> ScanConfig:
    """Build a :class:`ScanConfig` from defaults + TOML + explicit CLI flags."""

    config = ScanConfig()
    if getattr(args, "config", None):
        apply_toml(config, load_toml_config(args.config))

    if getattr(args, "urls", None):
        config.urls.extend(args.urls)
    if getattr(args, "input_files", None):
        config.input_files.extend(args.input_files)

    scope_hosts: list[str] = []
    if getattr(args, "scope_hosts", None):
        scope_hosts.extend(args.scope_hosts)
    if getattr(args, "scope_file", None):
        scope_hosts.extend(_load_scope_file(args.scope_file))
    include_subdomains = getattr(args, "include_subdomains", None)
    if scope_hosts:
        config.scope = Scope.from_hosts(
            scope_hosts,
            include_subdomains=bool(include_subdomains or config.scope.include_subdomains),
            allow_paths=[rule.pattern for rule in config.scope.allow_paths],
            deny_paths=[rule.pattern for rule in config.scope.deny_paths],
            allow_private_networks=config.scope.allow_private_networks,
            resolve_hosts=config.scope.resolve_hosts,
        )
    if include_subdomains is not None:
        config.scope.include_subdomains = include_subdomains
        config.scope.hosts = [
            parse_host_rule(rule.host, include_subdomains) for rule in config.scope.hosts
        ]
    if getattr(args, "allow_private_networks", None) is not None:
        config.scope.allow_private_networks = bool(args.allow_private_networks)
    if getattr(args, "resolve_hosts", None) is not None:
        config.scope.resolve_hosts = bool(args.resolve_hosts)
    for pattern in getattr(args, "allow_paths", None) or []:
        config.scope.allow_paths.append(compile_path_rule(pattern))
    for pattern in getattr(args, "deny_paths", None) or []:
        config.scope.deny_paths.append(compile_path_rule(pattern))

    _apply(config.request, args, _REQUEST_FIELDS)
    _apply(config.crawl, args, _CRAWL_FIELDS)
    _apply(config.active, args, _ACTIVE_FIELDS)
    _apply(config.output, args, _OUTPUT_FIELDS)
    if getattr(args, "active", None) is not None:
        config.active.enabled = bool(args.active)

    if getattr(args, "endpoint_grouping", None):
        config.output.endpoint_grouping = EndpointGrouping(args.endpoint_grouping)
    if getattr(args, "headers", None):
        for raw in args.headers:
            name, value = parse_header(raw)
            config.request.headers[name] = value
    if getattr(args, "cookies", None):
        for raw in args.cookies:
            config.request.cookies.update(parse_cookie_header(raw))
    if getattr(args, "excluded_paths", None):
        config.active.excluded_paths.extend(args.excluded_paths)
    if getattr(args, "dry_run", False):
        config.dry_run = True
    return config


_REQUEST_FIELDS = (
    "rate",
    "rate_scope",
    "concurrency",
    "concurrency_scope",
    "global_rate",
    "global_concurrency",
    "timeout",
    "retries",
    "max_redirects",
    "max_response_bytes",
    "max_requests",
    "max_requests_per_endpoint",
    "max_url_length",
    "proxy",
    "user_agent",
    "verify_tls",
)
_CRAWL_FIELDS = (
    "depth",
    "max_pages",
    "max_js_files",
    "max_js_bytes",
    "extract_js",
    "fetch_external_js",
    "fetch_robots",
    "fetch_sitemap",
)
#: ``--active`` maps to ``ActiveConfig.enabled``; everything else matches by name.
_ACTIVE_FIELDS = (
    "wordlists",
    "use_builtin_wordlist",
    "baselines",
    "confirmations",
    "batch_size",
    "max_candidates_per_endpoint",
    "max_active_endpoints",
)
_OUTPUT_FIELDS = ("json_path", "csv_path", "html_path", "state_path", "quiet")


def _apply(target: Any, args: argparse.Namespace, names: Sequence[str]) -> None:
    for name in names:
        value = getattr(args, name, None)
        if value is None:
            continue
        if not hasattr(target, name):
            continue
        setattr(target, name, value)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def _write_reports(config: ScanConfig, report: dict[str, Any], console: Console) -> None:
    if config.output.json_path:
        path = write_json(report, config.output.json_path)
        console.print(f"[green]wrote[/green] JSON report -> {path}")
    if config.output.csv_path:
        path = write_csv(report, config.output.csv_path)
        console.print(f"[green]wrote[/green] CSV report -> {path}")
    if config.output.html_path:
        path = write_html(report, config.output.html_path)
        console.print(f"[green]wrote[/green] HTML report -> {path}")


def _report_for(ctx: Any, mode: str) -> dict[str, Any]:
    endpoints = []
    outcomes = {item.endpoint: item for item in ctx.outcomes}
    for endpoint, url in ctx.passive.endpoint_examples.items():
        outcome = outcomes.get(endpoint)
        if outcome is None:
            active_status = "not tested"
        elif outcome.baseline is None:
            active_status = "excluded"
        elif not outcome.baseline.stable:
            active_status = "inconclusive (unstable baseline)"
        else:
            active_status = f"{len(outcome.outcomes)} candidates probed"
        endpoints.append(
            {
                "endpoint": endpoint,
                "example_url": url,
                "candidates": len(ctx.passive.candidates_for(endpoint)),
                "active_status": active_status,
                "active": outcome.to_dict() if outcome else None,
            }
        )
    extra: dict[str, Any] = {}
    if ctx.plan:
        extra["plan"] = ctx.plan
    if ctx.client_description:
        extra["client"] = ctx.client_description
    if ctx.crawl_result is not None:
        extra["crawl"] = ctx.crawl_result.to_dict()
    extra["passive"] = ctx.passive.to_dict()
    return build_report(
        mode=mode,
        config=ctx.config,
        stats=ctx.stats,
        findings=ctx.findings,
        endpoints=endpoints,
        warnings=ctx.warnings,
        limitations=ctx.limitations,
        extra=extra,
    )


def _cmd_extract(args: argparse.Namespace, console: Console) -> int:
    config = build_config(args)
    if not config.urls and not config.input_files:
        console.print("[red]error:[/red] extract needs --url or --input")
        return EXIT_USAGE
    ctx = run_extract(config)
    report = _report_for(ctx, "extract-offline")
    _write_reports(config, report, console)
    if not config.output.quiet:
        render_summary(report, console=console)
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace, console: Console) -> int:
    config = build_config(args)
    if not config.urls and not config.input_files:
        console.print("[red]error:[/red] scan needs --url or --input")
        return EXIT_USAGE
    if not config.dry_run and not config.scope.hosts:
        console.print(
            "[red]error:[/red] refusing to make network requests without explicit scope configuration.\n"
            "       Pass --scope-host <host> (or --scope-file) for every host you are authorized to test,\n"
            "       or use --dry-run to preview the plan without sending anything."
        )
        return EXIT_USAGE
    if not config.dry_run and not config.scope.allow_private_networks:
        console.print(
            "[dim]note: loopback/private targets are rejected unless --allow-private-networks is given.[/dim]"
        )
    if config.request.verify_tls is False:
        console.print("[yellow]warning:[/yellow] TLS verification is disabled for this scan")
    if (
        config.active.enabled
        and config.active.batch_size
        and config.active.batch_size > 1
        and not config.dry_run
    ):
        # Pre-flight notice: printed before a single request leaves. A dry run
        # gets the same caveat from the plan itself, so it is not repeated here.
        console.print(
            "[yellow]batch mode:[/yellow] a change observed in a batch cannot be attributed to a single "
            "parameter. Every batch hit is re-probed individually before it is reported."
        )

    ctx = run_scan(config)
    if config.dry_run:
        report = _report_for(ctx, "dry-run")
        _write_reports(config, report, console)
        if not config.output.quiet:
            render_plan(report, console=console)
        return EXIT_OK

    report = _report_for(ctx, "active" if config.active.enabled else "passive")
    _write_reports(config, report, console)
    if not config.output.quiet:
        render_summary(report, console=console)
    if ctx.store is not None:
        console.print(f"[dim]state file: {config.output.state_path} "
                      f"(counts: {ctx.store.counts()}); resume with: paramscout resume --state {config.output.state_path}[/dim]")
        ctx.store.close()
    return EXIT_INTERRUPTED if ctx.interrupted else EXIT_OK


def _cmd_resume(args: argparse.Namespace, console: Console) -> int:
    if not Path(args.state_path).exists():
        console.print(f"[red]error:[/red] state file not found: {args.state_path}")
        return EXIT_USAGE
    overrides = ScanConfig()
    if getattr(args, "cookies", None):
        for raw in args.cookies:
            overrides.request.cookies.update(parse_cookie_header(raw))
    if getattr(args, "headers", None):
        for raw in args.headers:
            name, value = parse_header(raw)
            overrides.request.headers[name] = value
    if getattr(args, "max_requests", None) is not None:
        overrides.request.max_requests = args.max_requests
    for name in ("json_path", "csv_path", "html_path"):
        path_value = getattr(args, name, None)
        if path_value:
            setattr(overrides.output, name, path_value)

    ctx = run_resume(args.state_path, overrides=overrides)
    report = _report_for(ctx, "resumed")
    _write_reports(ctx.config, report, console)
    if not ctx.config.output.quiet:
        render_summary(report, console=console)
    if ctx.store is not None:
        ctx.store.close()
    return EXIT_INTERRUPTED if ctx.interrupted else EXIT_OK


def _cmd_wordlist(args: argparse.Namespace, console: Console) -> int:
    names = builtin_wordlist()
    if getattr(args, "count", False):
        console.print(str(len(names)))
        return EXIT_OK
    for name in names:
        console.print(name)
    return EXIT_OK


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point (also used by ``python -m paramscout``)."""

    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console(quiet=bool(getattr(args, "quiet", False)))
    handlers = {
        "extract": _cmd_extract,
        "scan": _cmd_scan,
        "resume": _cmd_resume,
        "wordlist": _cmd_wordlist,
    }
    handler = handlers.get(args.command)
    if handler is None:  # pragma: no cover - argparse enforces the subcommand
        parser.error(f"unknown command: {args.command}")
        return EXIT_USAGE
    try:
        return handler(args, console)
    except KeyboardInterrupt:  # pragma: no cover - interactive
        console.print("\n[yellow]interrupted[/yellow] - partial results were saved where a state file was configured")
        return EXIT_INTERRUPTED
    except FileNotFoundError as exc:
        console.print(f"[red]error:[/red] {exc}")
        return EXIT_ERROR
    except ValueError as exc:
        console.print(f"[red]error:[/red] {exc}")
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
