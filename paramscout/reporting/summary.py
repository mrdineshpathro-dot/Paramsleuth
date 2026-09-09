"""Rich terminal summary."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from paramscout import __version__

_STATUS_STYLE = {
    "behavioral_change": "bold red",
    "behavioral_change_unconfirmed": "yellow",
    "reflection_only": "cyan",
    "inconclusive": "magenta",
    "no_change": "dim",
    "not_tested": "dim",
    "error": "yellow",
    "skipped": "dim",
}


def _status_text(status: str) -> Text:
    return Text(status.replace("_", " "), style=_STATUS_STYLE.get(status, "white"))


def render_summary(report: dict[str, Any], *, console: Console | None = None, top: int = 20) -> Console:
    """Print the terminal summary for a completed (or interrupted) scan."""

    console = console or Console()
    stats = report.get("stats", {})
    summary = report.get("summary", {})
    scope = report.get("authorized_scope", {})

    hosts = ", ".join(item.get("host", "?") for item in scope.get("hosts", [])) or "none"
    header = Text.assemble(
        ("ParamScout ", "bold cyan"),
        (f"v{__version__}", "dim"),
        ("  mode: ", "dim"),
        (str(report.get("mode")), "bold"),
        ("  scope: ", "dim"),
        (hosts, "bold"),
    )
    console.print(Panel(header, title="authorized parameter discovery", border_style="cyan"))

    stats_table = Table(title="Scan statistics", show_header=False, box=None, pad_edge=False)
    stats_table.add_column("metric", style="dim")
    stats_table.add_column("value")
    stats_table.add_row("requests sent", str(stats.get("requests_total", 0)))
    purposes = ", ".join(f"{key}={value}" for key, value in (stats.get("requests_by_purpose") or {}).items())
    stats_table.add_row("by purpose", purposes or "-")
    statuses = ", ".join(f"{key}={value}" for key, value in (stats.get("requests_by_status") or {}).items())
    stats_table.add_row("by status", statuses or "-")
    stats_table.add_row("retries", str(stats.get("retries", 0)))
    stats_table.add_row("throttling events", str(len(stats.get("throttle_events", []))))
    console_off_scope = stats.get("skipped_off_scope", [])
    stats_table.add_row("off-scope URLs skipped", str(len(console_off_scope)))
    stats_table.add_row("skipped (budget/throttle)", str(stats.get("skipped_budget", 0)))
    stats_table.add_row("transport errors", str(stats.get("transport_errors", 0)))
    stats_table.add_row("truncated responses", str(stats.get("truncated_responses", 0)))
    stats_table.add_row("elapsed", f"{stats.get('elapsed_seconds', 0)}s")
    if stats.get("interrupted"):
        stats_table.add_row("interrupted", "yes - these are partial results")
    console.print(stats_table)

    findings = report.get("findings", [])
    table = Table(
        title=f"Top findings ({summary.get('findings_total', 0)} total)", show_lines=False, expand=True
    )
    table.add_column("pri", justify="right", style="bold", no_wrap=True)
    table.add_column("parameter", style="cyan", overflow="fold", ratio=2)
    table.add_column("endpoint", overflow="fold", ratio=4)
    table.add_column("category", overflow="fold", ratio=2)
    table.add_column("sources", overflow="fold", ratio=2)
    table.add_column("disc", justify="right", no_wrap=True)
    table.add_column("behaviour", overflow="fold", ratio=2)
    table.add_column("beh", justify="right", no_wrap=True)
    table.add_column("refl", no_wrap=True)
    table.add_column("n", justify="right", no_wrap=True)

    for finding in findings[:top]:
        behavioral = finding.get("behavioral") or {}
        status = behavioral.get("status", "not_tested")
        reflection = behavioral.get("reflection") or {}
        table.add_row(
            str(finding.get("review_priority", 0)),
            finding.get("parameter", ""),
            finding.get("endpoint", ""),
            finding.get("category", ""),
            ",".join(finding.get("sources", [])),
            f"{finding.get('discovery_confidence', 0):.2f}",
            _status_text(status),
            f"{finding.get('behavioral_confidence', 0):.2f}",
            "yes" if reflection.get("reflected") else "-",
            str(behavioral.get("attempts", 0)),
        )
    if not findings:
        table.add_row("-", "no candidates discovered", "-", "-", "-", "-", _status_text("not_tested"), "-", "-", "-")
    console.print(table)

    for warning in report.get("warnings", []):
        console.print(f"[yellow]warning:[/yellow] {warning}")

    console.print(
        Panel(
            "Priority is a triage ordering, not a severity. No finding in this report is a "
            "confirmed vulnerability: parameter categories come from names, behavioural change "
            "is differential evidence, and reflection alone is never treated as XSS.",
            title="read this before you act",
            border_style="yellow",
        )
    )
    return console


def render_plan(report: dict[str, Any], *, console: Console | None = None) -> Console:
    """Print the dry-run plan (no requests were made)."""

    console = console or Console()
    plan = report.get("plan", {})
    scope = report.get("authorized_scope", {})

    scope_table = Table(title="Authorized scope", show_header=True)
    scope_table.add_column("host")
    scope_table.add_column("port")
    scope_table.add_column("subdomains")
    for item in scope.get("hosts", []):
        scope_table.add_row(
            str(item.get("host")), str(item.get("port") or "any"), "yes" if item.get("include_subdomains") else "no"
        )
    console.print(scope_table)

    actions = Table(title="Planned actions (no requests were sent)")
    actions.add_column("stage")
    actions.add_column("detail", overflow="fold")
    for stage, detail in plan.get("stages", []):
        actions.add_row(stage, str(detail))
    console.print(actions)

    budget = Table(title="Request budget estimate")
    budget.add_column("item")
    budget.add_column("estimate", justify="right")
    for key, value in (plan.get("budget") or {}).items():
        budget.add_row(str(key), str(value))
    console.print(budget)

    endpoints = plan.get("endpoints") or []
    if endpoints:
        endpoint_table = Table(title=f"Endpoints in the plan ({len(endpoints)})", expand=True)
        endpoint_table.add_column("endpoint", overflow="fold", ratio=3)
        endpoint_table.add_column("from evidence", justify="right", ratio=1)
        endpoint_table.add_column("from wordlist", justify="right", ratio=1)
        endpoint_table.add_column("probed (cap)", justify="right", ratio=1)
        for item in endpoints[:50]:
            endpoint_table.add_row(
                str(item.get("endpoint")),
                str(item.get("candidates_from_evidence", item.get("candidates"))),
                str(item.get("candidates_from_wordlist", 0)),
                str(item.get("candidates")),
            )
        if len(endpoints) > 50:
            endpoint_table.add_row(f"... and {len(endpoints) - 50} more", "", "")
        console.print(endpoint_table)

    for warning in report.get("warnings", []):
        console.print(f"[yellow]warning:[/yellow] {warning}")
    return console
