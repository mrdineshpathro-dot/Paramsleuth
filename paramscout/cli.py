"""Command-line interface for ParamScout.

Command structure::

    paramscout --version
    paramscout --about
    paramscout extract --input collected.txt --output passive.json
    paramscout scan  --url URL --scope-host H [--active --wordlist wl ...] [--dry-run]
    paramscout resume --state scan.sqlite [--scope-file scope.txt] [--cookie ...]

Branding goes to stderr (suppressed with ``--quiet``); machine-readable output
(JSON/CSV) is written only to files and never mixed with banner text.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Any, Sequence

from . import __about__
from .config import Config
from .extractors.builtin import builtin_parameter_names
from .logsetup import configure_logging
from .redaction import Redactor
from .scope import Scope

log = logging.getLogger("paramscout.cli")

_EXIT_OK = 0
_EXIT_ERROR = 1
_EXIT_USAGE = 2
_EXIT_INTERRUPTED = 130


# ---------------------------------------------------------------------------
# Parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="paramscout",
        description=__about__.__description__,
        epilog="Authorized use only: test only systems you own or have explicit "
        "permission to test.",
    )
    parser.add_argument(
        "--version", action="store_true", help="print the ParamScout version and exit"
    )
    parser.add_argument(
        "--about",
        action="store_true",
        help="print author, contact, support and authorized-use information",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="suppress branding and progress output"
    )
    parser.add_argument(
        "--verbose", action="count", default=0, help="increase log verbosity (-v/-vv)"
    )
    sub = parser.add_subparsers(dest="command", metavar="{extract,scan,resume}")

    # --quiet / --verbose also work after the subcommand name without
    # overriding a value given before it (default=SUPPRESS keeps main defaults).
    def _sub_quiet_verbose(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--quiet", action="store_true", default=argparse.SUPPRESS,
            help="suppress branding and progress output",
        )
        p.add_argument(
            "--verbose", action="count", default=argparse.SUPPRESS,
            help="increase log verbosity (-v/-vv)",
        )

    # ---- extract ----------------------------------------------------------
    ex = sub.add_parser(
        "extract",
        help="analyze collected URLs / local files with no network requests",
        description="Offline extraction: analyze collected URLs and local HTML/JS "
        "files without making any network request.",
    )
    _sub_quiet_verbose(ex)
    ex.add_argument(
        "--input",
        "-i",
        action="append",
        default=[],
        metavar="PATH",
        help="local file or directory (URL list, HTML, JS, JSON/HAR). Repeatable.",
    )
    ex.add_argument("--output", "-o", metavar="FILE", help="write JSON report to FILE")
    ex.add_argument("--output-csv", metavar="FILE", help="write CSV report to FILE")
    ex.add_argument("--output-html", metavar="FILE", help="write self-contained HTML report")
    ex.add_argument(
        "--wordlist", metavar="FILE", help="attach additional parameter names (as low-confidence candidates)"
    )
    ex.add_argument(
        "--endpoint-grouping",
        choices=["path", "host"],
        default="path",
        help="group URLs into endpoints by path or by host (default: path)",
    )
    ex.add_argument(
        "--include-inconclusive",
        action="store_true",
        help="include low-signal candidates in the output",
    )
    ex.set_defaults(func=cmd_extract)

    # ---- scan -------------------------------------------------------------
    sc = sub.add_parser(
        "scan",
        help="passive/active discovery on an explicitly authorized target",
        description="Scan an explicitly authorized scope. Passive mode crawls "
        "existing in-scope resources and extracts candidates. --active enables "
        "controlled, conservative GET-only probing with safe canaries.",
    )
    _sub_quiet_verbose(sc)
    _add_common_scan_args(sc)
    sc.set_defaults(func=cmd_scan)

    # ---- resume -------------------------------------------------------------
    rs = sub.add_parser(
        "resume",
        help="resume an interrupted scan from its SQLite state file",
        description="Resume a scan: re-validates scope, restores request-budget "
        "accounting, and continues pending candidates. Credentials (--cookie/"
        "--header) must be supplied again; they are never persisted.",
    )
    _sub_quiet_verbose(rs)
    rs.add_argument("--state", required=True, metavar="FILE", help="SQLite state file to resume")
    rs.add_argument("--scope-host", action="append", default=[], metavar="HOST", help="authorized host (repeatable)")
    rs.add_argument("--scope-file", metavar="FILE", help="scope file; defaults to the persisted scope")
    rs.add_argument("--wordlist", metavar="FILE", help="wordlist for new candidate batches (optional)")
    rs.add_argument("--cookie", action="append", default=[], metavar="N=V;...", help="cookies for authenticated testing (re-supply)")
    rs.add_argument("--header", action="append", default=[], metavar="'Name: value'", help="custom header (re-supply)")
    rs.add_argument("--rate", type=float, metavar="SECONDS", help="per-host minimum interval between requests")
    rs.add_argument("--concurrency", type=int, metavar="N", help="per-host concurrency")
    rs.add_argument("--max-requests", type=int, metavar="N", help="override global request budget")
    rs.add_argument("--max-requests-per-endpoint", type=int, metavar="N", help="override per-endpoint budget")
    rs.add_argument("--output", "-o", metavar="FILE", help="write JSON report to FILE")
    rs.add_argument("--output-csv", metavar="FILE", help="write CSV report to FILE")
    rs.add_argument("--output-html", metavar="FILE", help="write self-contained HTML report")
    rs.add_argument("--timeout", type=float, metavar="SECONDS", help="per-request timeout")
    rs.add_argument("--retries", type=int, metavar="N", help="retries per request")
    rs.add_argument("--max-redirects", type=int, metavar="N", help="max redirects followed in-scope")
    rs.set_defaults(func=cmd_resume)

    _add_output_and_http_options(sc)
    return parser


def _add_common_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--url", action="append", default=[], metavar="URL", help="seed URL (repeatable)")
    parser.add_argument("--input", "-i", action="append", default=[], metavar="PATH", help="file with seed URLs (repeatable)")
    parser.add_argument("--scope-host", action="append", default=[], metavar="HOST", help="authorized hostname (repeatable)")
    parser.add_argument("--scope-file", metavar="FILE", help="scope rules file")
    parser.add_argument("--exclude-path", action="append", default=[], metavar="PREFIX", help="path prefix excluded from scope (repeatable)")
    parser.add_argument("--active", action="store_true", help="enable controlled active parameter discovery")
    parser.add_argument("--wordlist", metavar="FILE", help="parameter wordlist for active discovery")
    parser.add_argument("--no-builtin-wordlist", action="store_true", help="disable the conservative built-in wordlist")
    parser.add_argument("--crawl", action="store_true", help="crawl in-scope pages (default when depth/pages/robots/js flags used)")
    parser.add_argument("--depth", type=int, default=None, metavar="N", help="crawl depth (implies --crawl)")
    parser.add_argument("--max-pages", type=int, default=None, metavar="N", help="maximum pages to fetch (implies --crawl)")
    parser.add_argument("--extract-js", action="store_true", help="fetch and parse in-scope external JavaScript")
    parser.add_argument("--robots", action="store_true", help="fetch robots.txt (in scope)")
    parser.add_argument("--sitemap", action="store_true", help="fetch sitemap.xml (in scope)")
    parser.add_argument("--batch-size", type=int, default=None, metavar="N", help="candidates per probe batch (default 1)")
    parser.add_argument("--baseline-requests", type=int, default=None, metavar="N", help="baseline responses per endpoint (default 3)")
    parser.add_argument("--validation-retests", type=int, default=None, metavar="N", help="individual re-tests per promising candidate (default 1)")
    parser.add_argument("--endpoint-grouping", choices=["path", "host"], default=None, help="group URLs by path or host (default: path)")
    parser.add_argument("--rate", type=float, metavar="SECONDS", help="per-host minimum interval between requests (default 0.1)")
    parser.add_argument("--concurrency", type=int, metavar="N", help="per-host max in-flight requests (default 3)")
    parser.add_argument("--max-requests", type=int, metavar="N", help="global request budget including retries/redirects (default 300)")
    parser.add_argument("--max-requests-per-endpoint", type=int, metavar="N", help="per-endpoint budget (default: derived from the global budget, min 25)")
    parser.add_argument("--max-candidates-per-endpoint", type=int, metavar="N", help="probe at most N candidates per endpoint")
    parser.add_argument("--dry-run", action="store_true", help="print the scan plan and exit without any network activity")
    parser.add_argument("--state", metavar="FILE", help="SQLite state file for resumable scans")


def _add_output_and_http_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", "-o", metavar="FILE", help="write JSON report to FILE")
    parser.add_argument("--output-csv", metavar="FILE", help="write CSV report to FILE")
    parser.add_argument("--output-html", metavar="FILE", help="write self-contained HTML report")
    parser.add_argument("--cookie", action="append", default=[], metavar="N=V;...", help="cookies (repeatable). Sent only to scope hosts.")
    parser.add_argument("--header", action="append", default=[], metavar="'Name: value'", help="custom header (repeatable). Sent only to scope hosts.")
    parser.add_argument("--timeout", type=float, metavar="SECONDS", help="per-request timeout (default 15)")
    parser.add_argument("--retries", type=int, metavar="N", help="retries per request (default 2)")
    parser.add_argument("--max-redirects", type=int, metavar="N", help="max redirects followed in-scope (default 5)")
    parser.add_argument("--max-response-size", metavar="SIZE", help="max response body size, e.g. 1m/2m/512k (default 2m)")
    parser.add_argument("--proxy", metavar="URL", help="HTTP(S) proxy for authorized inspection")
    parser.add_argument("--no-verify-tls", action="store_true", help="disable TLS certificate verification (discouraged)")
    parser.add_argument("--config", metavar="FILE", help="TOML config file with defaults")
    parser.add_argument("--include-inconclusive", action="store_true", help="include inconclusive/error rows in reports")


# ---------------------------------------------------------------------------
# Argument helpers


def _apply_config_file(cfg: Config, path: str) -> None:
    """Merge a TOML config file over the defaults (CLI values still win)."""
    import tomllib

    with open(path, "rb") as handle:
        data = tomllib.load(handle)
    section = data.get("paramscout", data)
    if not isinstance(section, dict):
        raise ValueError(f"config file {path}: expected a [paramscout] table")
    valid = {name for name in Config.__dataclass_fields__}  # type: ignore[attr-defined]
    for key, value in section.items():
        if key in valid:
            setattr(cfg, key, value)
        else:
            log.warning("config file %s: unknown option %r ignored", path, key)


def _parse_size(text: str) -> int:
    text = text.strip().lower()
    multiplier = 1
    if text.endswith("k"):
        multiplier = 1024
        text = text[:-1]
    elif text.endswith("kb"):
        multiplier = 1024
        text = text[:-2]
    elif text.endswith("m"):
        multiplier = 1024 * 1024
        text = text[:-1]
    elif text.endswith("mb"):
        multiplier = 1024 * 1024
        text = text[:-2]
    return int(float(text) * multiplier)


def _parse_cookies(specs: list[str]) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for spec in specs:
        for chunk in spec.split(";"):
            chunk = chunk.strip()
            if not chunk:
                continue
            name, _, value = chunk.partition("=")
            if not name:
                continue
            cookies[name.strip()] = value
    return cookies


def _parse_headers(specs: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for spec in specs:
        name, _, value = spec.partition(":")
        if not name:
            continue
        headers[name.strip()] = value.strip()
    return headers


def _seed_urls(args: argparse.Namespace) -> list[str]:
    urls: list[str] = []
    if getattr(args, "url", None):
        urls.extend(args.url)
    if getattr(args, "input", None):
        from .discovery.wordlists import urls_from_files

        for path in args.input:
            found = urls_from_files([path])
            urls.extend(found)
            if not found:
                log.warning("no seed URLs found in %s", path)
    return urls


def _cookies_cfg(args: argparse.Namespace) -> dict[str, str]:
    return _parse_cookies(getattr(args, "cookie", []) or [])


def _headers_cfg(args: argparse.Namespace) -> dict[str, str]:
    return _parse_headers(getattr(args, "header", []) or [])


def _config_from_scan_args(args: argparse.Namespace) -> Config:
    cfg = Config()
    if getattr(args, "config", None):
        _apply_config_file(cfg, args.config)
    # Scope
    if args.scope_host:
        cfg.scope_hosts = list(args.scope_host)
    if args.scope_file:
        cfg.scope_file = args.scope_file
    if args.exclude_path:
        cfg.exclude_paths = list(args.exclude_path)
    # Crawl flags: crawl is implied by depth/max-pages/robots/sitemap/extract-js
    crawl_flags = [getattr(args, f, None) for f in ("crawl", "extract_js", "robots", "sitemap")]
    explicit_crawl = any(bool(x) for x in crawl_flags)
    depth = args.depth if args.depth is not None else 0
    max_pages = args.max_pages if args.max_pages is not None else 50
    cfg.crawl = bool(args.crawl) or depth > 0 or args.max_pages is not None or explicit_crawl
    cfg.depth = max(0, depth)
    cfg.max_pages = max(1, max_pages)
    cfg.extract_js = bool(args.extract_js)
    cfg.fetch_robots = bool(args.robots)
    cfg.fetch_sitemap = bool(args.sitemap)
    # Active probing
    cfg.active = bool(args.active)
    cfg.wordlist = args.wordlist
    cfg.use_builtin_wordlist = not args.no_builtin_wordlist
    cfg.endpoint_grouping = args.endpoint_grouping or "path"
    if args.batch_size is not None:
        cfg.batch_size = max(1, args.batch_size)
    if args.baseline_requests is not None:
        cfg.baseline_requests = max(2, args.baseline_requests)
    if args.validation_retests is not None:
        cfg.validation_retests = max(0, args.validation_retests)
    if args.max_candidates_per_endpoint is not None:
        cfg.max_candidates_per_endpoint = max(1, args.max_candidates_per_endpoint)
    # Request controls (per host)
    if args.rate is not None:
        cfg.rate = max(0.0, args.rate)
    if args.concurrency is not None:
        cfg.concurrency = max(1, args.concurrency)
    if args.max_requests is not None:
        cfg.max_requests = max(0, args.max_requests)
    if args.max_requests_per_endpoint is not None:
        cfg.max_requests_per_endpoint = max(1, args.max_requests_per_endpoint)
    if args.timeout is not None:
        cfg.timeout = max(0.5, args.timeout)
    if args.retries is not None:
        cfg.retries = max(0, args.retries)
    if args.max_redirects is not None:
        cfg.max_redirects = max(0, args.max_redirects)
    if args.max_response_size:
        cfg.max_response_bytes = _parse_size(args.max_response_size)
    if args.proxy:
        cfg.proxy = args.proxy
    cfg.verify_tls = not args.no_verify_tls
    # Auth (memory only)
    cfg.cookies = _cookies_cfg(args)
    cfg.headers = _headers_cfg(args)
    # Output / state
    cfg.state_file = args.state
    cfg.output_json = args.output
    cfg.output_csv = args.output_csv
    cfg.output_html = args.output_html
    cfg.include_inconclusive = bool(args.include_inconclusive)
    cfg.quiet = bool(args.quiet)
    cfg.seed_urls = _seed_urls(args)
    cfg.derive()
    return cfg


def _scope_from_args(args: argparse.Namespace, cfg: Config) -> Scope:
    """Build the scope; raises ValueError when no network activity is authorized."""
    scope = Scope.from_hosts(list(args.scope_host or cfg.scope_hosts))
    if args.scope_file or cfg.scope_file:
        file_scope = Scope.from_file(args.scope_file or cfg.scope_file)
        if not scope.host_rules:
            scope = file_scope
        else:
            scope.host_rules.extend(file_scope.host_rules)
            scope.path_include_prefixes.extend(file_scope.path_include_prefixes)
            scope.path_exclude_prefixes.extend(file_scope.path_exclude_prefixes)
            scope.deny_hosts.update(file_scope.deny_hosts)
    for prefix in cfg.exclude_paths:
        if not prefix.startswith("/"):
            prefix = "/" + prefix
        scope.path_exclude_prefixes.append(prefix)
    return scope


def _auth_hosts_from_scope(scope: Scope) -> list[str]:
    """Hostnames that may receive credentials (exact + wildcard rule hosts)."""
    hosts: list[str] = []
    for rule in scope.host_rules:
        if rule.host not in hosts:
            hosts.append(rule.host)
    return hosts


# ---------------------------------------------------------------------------
# Report assembly (shared by scan/extract/resume)


def _rows_from_findings(findings: list, redactor: Redactor, include_inconclusive: bool) -> list[dict]:
    from .reporting.models import row_from_finding
    from .models import priority_rank

    rows = []
    for finding in findings:
        if finding.inconclusive and not include_inconclusive:
            continue
        rows.append(row_from_finding(finding, redactor))
    rows.sort(key=lambda r: (-priority_rank(r["manual_review_priority"]), -float(r["discovery_score"] or 0)))
    return rows


def _totals_from_report(report, args: argparse.Namespace) -> dict[str, Any]:
    stats = report.stats
    totals: dict[str, Any] = {
        "requests": stats.attempts_total,
        "requests by purpose": dict(stats.requests_by_purpose),
        "skipped off-scope URLs": stats.skipped_off_scope,
        "throttling events": stats.throttles,
        "elapsed seconds": round(report.elapsed, 2),
        "endpoints discovered": stats.endpoints_discovered,
        "candidates discovered": stats.candidates_discovered,
        "endpoints probed": stats.endpoints_probed,
        "candidates probed": stats.candidates_probed,
    }
    if stats.throttle_events:
        totals["throttling events detail"] = list(stats.throttle_events)
    if stats.skipped_reasons:
        totals["skipped off-scope URLs detail"] = list(stats.skipped_reasons)
    if report.crawl is not None:
        totals["pages fetched"] = report.crawl.pages_fetched
        totals["external JS fetched"] = report.crawl.external_js_fetched
        totals["robots fetched"] = report.crawl.robots_fetched
        totals["sitemap fetched"] = report.crawl.sitemap_fetched
    return totals


def _emit(
    *,
    command: str,
    mode: str,
    report,
    rows: list[dict],
    args: argparse.Namespace,
    cfg: Config | None = None,
    scope_lines: list[str] | None = None,
    extra_limitations: list[str] | None = None,
) -> int:
    from .reporting import write_reports
    from .reporting.models import metadata_block
    from .reporting.terminal import print_terminal_summary

    limitations = list(getattr(report, "limitations", []) or [])
    limitations.extend(extra_limitations or [])
    scope_lines = scope_lines or []
    if cfg is not None and getattr(report, "mode", "scan"):
        limits_note = (
            f"rate={cfg.rate}s/host; concurrency={cfg.concurrency}/host; "
            f"global budget={cfg.max_requests}; "
            f"per-endpoint budget={cfg.max_requests_per_endpoint}"
        )
        limitations.insert(0, limits_note)
    redactor = Redactor()
    metadata = metadata_block(
        command=command,
        mode=mode,
        status=getattr(report, "status", "ok"),
        status_detail=getattr(report, "status_detail", ""),
        args=(cfg.redacted_dict() if cfg is not None else {"grouping": "path"}),
        scope_lines=scope_lines,
        totals=_totals_from_report(report, args),
        limitations=limitations,
    )
    redacted_rows = [_deep_redact_row(r, redactor) for r in rows]
    written = write_reports(
        json_path=cfg.output_json if cfg else getattr(args, "output", None),
        csv_path=cfg.output_csv if cfg else getattr(args, "output_csv", None),
        html_path=cfg.output_html if cfg else getattr(args, "output_html", None),
        metadata=metadata,
        rows=redacted_rows,
        redactor=redactor,
    )
    if getattr(args, "dry_run", False):
        return _EXIT_OK
    print_terminal_summary(metadata, redacted_rows, quiet=bool(getattr(args, "quiet", False)))
    if written:
        log.info("reports written: %s", ", ".join(written))
    return _EXIT_OK


def _deep_redact_row(row: dict, redactor: Redactor) -> dict:
    out: dict[str, Any] = {}
    for key, value in row.items():
        if key in ("endpoint", "reproduction_request"):
            out[key] = redactor.redact_url(str(value))
        else:
            out[key] = redactor.redact(str(value) if value is not None else "")
    return out


def _brand(quiet: bool, console_out=None) -> None:
    """Optional branding line, always on stderr, suppressed by --quiet."""
    if quiet:
        return
    print(f"ParamScout v{__about__.__version__} - authorized testing only", file=sys.stderr)


# ---------------------------------------------------------------------------
# Commands


def cmd_extract(args: argparse.Namespace) -> int:
    from .discovery.offline import OfflineAnalyzer
    from .reporting.models import metadata_block, row_from_passive

    configure_logging(quiet=args.quiet, verbosity=args.verbose)
    redactor = Redactor()
    analyzer = OfflineAnalyzer(redactor=redactor, grouping=args.endpoint_grouping)
    if not args.input:
        raise ValueError("extract requires at least one --input path")
    result = analyzer.run(args.input)

    rows: list[dict] = []
    from .models import priority_rank

    endpoints = {e.id: e for e in result.endpoints}
    for candidate in result.candidates:
        endpoint = endpoints.get(candidate.endpoint_id)
        if endpoint is None:
            continue
        rows.append(row_from_passive(endpoint, candidate, redactor))
    rows.sort(key=lambda r: (-priority_rank(r["manual_review_priority"]), -float(r["discovery_score"])))

    # Optional wordlist expansion (offline, low confidence)
    if args.wordlist:
        from .discovery.wordlists import load_wordlist_file
        from .extractors.base import classify_hint
        from .models import Candidate, DiscoverySourceKind, SourceRef

        names = load_wordlist_file(args.wordlist)
        existing = {(c.endpoint_id, c.name) for c in result.candidates}
        for endpoint in result.endpoints:
            if endpoint.virtual:
                continue
            for name in names:
                if (endpoint.id, name) in existing:
                    continue
                cand = Candidate(endpoint_id=endpoint.id, name=name)
                cand.sources.append(
                    SourceRef(
                        kind=DiscoverySourceKind.USER_WORDLIST,
                        location=f"wordlist {args.wordlist}",
                        context="user-supplied wordlist (offline)",
                        weight=0.3,
                    )
                )
                cand.category, cand.security_relevant = classify_hint(name)
                cand.discovery_score = 0.3
                result.candidates.append(cand)
                rows.append(row_from_passive(endpoint, cand, redactor))
        rows.sort(key=lambda r: (-priority_rank(r["manual_review_priority"]), -float(r["discovery_score"])))

    scope_lines: list[str] = ["(none - offline analysis makes no network requests)"]
    metadata = metadata_block(
        command="extract",
        mode="offline",
        status="ok",
        status_detail="offline extraction; zero network requests were made",
        args={"grouping": args.endpoint_grouping, "wordlist": args.wordlist or None},
        scope_lines=scope_lines,
        totals={
            "requests": 0,
            "files scanned": result.files_scanned,
            "endpoints found": len(result.endpoints),
            "candidates found": len(rows),
            "skipped off-scope URLs": 0,
            "throttling events": 0,
            "elapsed seconds": 0,
        },
        limitations=[
            "offline extraction only: parameters are candidate hints, not validated",
            "no network requests are performed in extract mode",
        ],
    )
    redacted_rows = [_deep_redact_row(r, redactor) for r in rows]
    from .reporting import write_reports

    written = write_reports(
        json_path=args.output,
        csv_path=args.output_csv,
        html_path=args.output_html,
        metadata=metadata,
        rows=redacted_rows,
        redactor=redactor,
    )
    from .reporting.terminal import print_terminal_summary

    print_terminal_summary(metadata, redacted_rows, quiet=args.quiet)
    if written:
        log.info("reports written: %s", ", ".join(written))
    return _EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    from .discovery.engine import ScanEngine, ScanReport
    from .discovery.engine import ScanStats  # noqa: F401

    configure_logging(quiet=args.quiet, verbosity=args.verbose)
    _brand(args.quiet)
    cfg = _config_from_scan_args(args)
    redactor = Redactor()
    scope = _scope_from_args(args, cfg)

    if not cfg.seed_urls:
        raise ValueError("scan requires at least one --url or an --input file with URLs")

    # Network activity always requires explicit scope configuration.
    if scope.is_empty:
        raise ValueError(
            "no scope configured; refusing network activity. Provide --scope-host "
            "and/or --scope-file."
        )
    for url in cfg.seed_urls:
        if not scope.check(url).allowed:
            raise ValueError(
                f"seed URL is outside the configured scope: {redactor.redact_url(url)} "
                "(refusing to start)"
            )
    cfg.auth_hosts = _auth_hosts_from_scope(scope)

    if args.dry_run:
        _print_dry_run(cfg, scope, args)
        return _EXIT_OK

    async def _run() -> ScanReport:
        engine = ScanEngine(cfg, scope, redactor)
        return await engine.run_scan()

    try:
        report = asyncio.run(_run())
    except KeyboardInterrupt:
        print(
            "\ninterrupted (Ctrl+C). Partial progress was saved when --state was "
            "used; run 'paramscout resume --state <file>' to continue.",
            file=sys.stderr,
        )
        return _EXIT_INTERRUPTED

    rows = _rows_from_findings(report.findings, redactor, cfg.include_inconclusive)
    return _emit(
        command="scan",
        mode="active" if cfg.active else "passive",
        report=report,
        rows=rows,
        args=args,
        cfg=cfg,
        scope_lines=scope.summary_lines(),
    )


def cmd_resume(args: argparse.Namespace) -> int:
    from .discovery.engine import run_resume, ScanReport

    configure_logging(quiet=args.quiet, verbosity=args.verbose)
    _brand(args.quiet)
    redactor = Redactor()
    cfg = Config()
    cfg.state_file = args.state
    cfg.active = True
    cfg.wordlist = args.wordlist
    cfg.quiet = args.quiet
    cfg.output_json = args.output
    cfg.output_csv = args.output_csv
    cfg.output_html = args.output_html
    cfg.include_inconclusive = bool(getattr(args, "include_inconclusive", False))
    if args.rate is not None:
        cfg.rate = max(0.0, args.rate)
    if args.concurrency is not None:
        cfg.concurrency = max(1, args.concurrency)
    if args.max_requests is not None:
        cfg.max_requests = max(0, args.max_requests)
    if args.max_requests_per_endpoint is not None:
        cfg.max_requests_per_endpoint = max(1, args.max_requests_per_endpoint)
    if args.timeout is not None:
        cfg.timeout = max(0.5, args.timeout)
    if getattr(args, "retries", None) is not None:
        cfg.retries = max(0, args.retries)
    if getattr(args, "max_redirects", None) is not None:
        cfg.max_redirects = max(0, args.max_redirects)
    cfg.cookies = _parse_cookies(args.cookie)
    cfg.headers = _parse_headers(args.header)
    if args.scope_host:
        cfg.scope_hosts = list(args.scope_host)
    cfg.scope_file = args.scope_file
    cfg.derive()

    scope = _scope_from_args(args, cfg)
    if scope.is_empty:
        # Fall back to the persisted scope snapshot from the state file.
        from .state import StateStore

        store = StateStore(args.state)
        try:
            persisted = store.get_meta("scope") or {}
        finally:
            store.close()
        hosts = [h.get("host", "") for h in persisted.get("hosts", [])]
        scope = Scope.from_hosts(hosts)
        for prefix in persisted.get("path_exclude_prefixes", []):
            scope.path_exclude_prefixes.append(prefix)
        for prefix in persisted.get("path_include_prefixes", []):
            scope.path_include_prefixes.append(prefix)
        for host in persisted.get("deny_hosts", []):
            scope.deny_hosts.add(host)
        if scope.is_empty:
            raise ValueError(
                "resume needs --scope-host/--scope-file (or a persisted scope in the state file)"
            )
    cfg.auth_hosts = _auth_hosts_from_scope(scope)

    try:
        report = asyncio.run(run_resume(cfg, scope, redactor))
    except KeyboardInterrupt:
        print(
            "\ninterrupted (Ctrl+C). Progress continues to be saved; resume again "
            "with the same --state file.",
            file=sys.stderr,
        )
        return _EXIT_INTERRUPTED
    rows = _rows_from_findings(report.findings, redactor, cfg.include_inconclusive)
    return _emit(
        command="resume",
        mode="active",
        report=report,
        rows=rows,
        args=args,
        cfg=cfg,
        scope_lines=scope.summary_lines(),
    )


# ---------------------------------------------------------------------------
# Dry run


def _print_dry_run(cfg: Config, scope: Scope, args: argparse.Namespace) -> None:
    """Print the scan plan with request-budget estimates; no network activity."""
    from rich.console import Console
    from rich.table import Table

    console = Console(stderr=True)
    console.print("[bold]ParamScout dry run[/bold] - no requests will be sent\n")
    scope_table = Table(title="Scope")
    scope_table.add_column("Rule")
    for line in scope.summary_lines():
        scope_table.add_row(line)
    console.print(scope_table)

    plan_table = Table(title="Planned actions")
    plan_table.add_column("Action")
    plan_table.add_column("Estimate", overflow="fold")
    seeds = len(cfg.seed_urls)
    plan_table.add_row("Seeds", str(seeds))
    candidate_names: list[str] = []
    if cfg.wordlist:
        from .discovery.wordlists import load_wordlist_file

        candidate_names.extend(load_wordlist_file(cfg.wordlist))
    if cfg.use_builtin_wordlist:
        candidate_names.extend(builtin_parameter_names())
    unique_names = len(set(candidate_names))
    if cfg.crawl:
        plan_table.add_row(
            "Crawl in-scope pages",
            f"depth={cfg.depth}, max {cfg.max_pages} pages"
            + (" (estimate depends on links discovered; exact count unknown until crawl)" if cfg.depth else ""),
        )
    if cfg.fetch_robots:
        plan_table.add_row("robots.txt", f"1 request per seed host (in scope)")
    if cfg.fetch_sitemap:
        plan_table.add_row("sitemap.xml", "1 request per seed host (in scope)")
    plan_table.add_row("Passive extraction", "forms/links/JS on fetched pages (no requests on its own)")
    if cfg.active:
        est_baseline = max(2, cfg.baseline_requests)
        est_control = 1
        est_probes_per_ep = unique_names + 5 if unique_names else 10
        est_per_ep = est_baseline + est_control + est_probes_per_ep
        plan_table.add_row(
            "Active probes (GET only, safe canaries)",
            f"{seeds} seed endpoint(s) x ~{est_per_ep} requests/endpoint "
            f"(baselines={est_baseline}, control={est_control}, "
            f"probes<={est_probes_per_ep}); clamped by global budget "
            f"{cfg.max_requests} and per-endpoint budget "
            f"{cfg.max_requests_per_endpoint}",
        )
        plan_table.add_row(
            "Probe method",
            "GET only; one candidate per probe (batch-size=%d); "
            "individual validation of findings" % cfg.batch_size,
        )
    console.print(plan_table)

    budget_table = Table(title="Request controls (per host unless stated)")
    budget_table.add_column("Setting")
    budget_table.add_column("Value")
    for row in [
        ("minimum interval", f"{cfg.rate} s"),
        ("concurrency", str(cfg.concurrency)),
        ("global budget", str(cfg.max_requests)),
        ("per-endpoint budget", str(cfg.max_requests_per_endpoint)),
        ("timeout", f"{cfg.timeout} s"),
        ("retries", str(cfg.retries)),
        ("max redirects", str(cfg.max_redirects)),
        ("max response body", str(cfg.max_response_bytes)),
        ("verify TLS", str(cfg.verify_tls)),
        ("endpoint grouping", cfg.endpoint_grouping),
    ]:
        budget_table.add_row(row[0], row[1])
    console.print(budget_table)
    console.print(
        "\n[dim]Dry-run made no network requests. Wordlist names are not "
        "automatically probed off-scope.[/dim]"
    )


# ---------------------------------------------------------------------------
# Entry point


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"ParamScout {__about__.__version__}")
        return _EXIT_OK
    if args.about:
        _print_about()
        return _EXIT_OK
    if not getattr(args, "command", None):
        parser.print_help(sys.stderr)
        return _EXIT_USAGE
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return _EXIT_INTERRUPTED
    except ValueError as exc:
        log.error("%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_ERROR
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_ERROR
    except Exception as exc:  # keep the CLI predictable
        log.exception("unexpected error")
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_ERROR


def _print_about() -> None:
    print(f"{__about__.__title__} {__about__.__version__}")
    print(f"Author: {__about__.__author__}")
    print(f"Contact: {__about__.__author_email__}")
    print(f"Support: {__about__.__support_url__}")
    print()
    print(__about__.__description__)
    print()
    print(__about__.AUTHORIZED_USE_NOTICE)
    print()
    print(
        "Privacy: the email and support link above are for contact and voluntary "
        "support only. ParamScout sends no telemetry, scan results, target URLs, "
        "credentials, or error reports anywhere, and never opens the support "
        "website automatically."
    )


if __name__ == "__main__":
    sys.exit(main())
