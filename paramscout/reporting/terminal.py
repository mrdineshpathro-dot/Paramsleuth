"""Rich terminal summaries (human-readable only; never on machine output)."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


def print_terminal_summary(
    metadata: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    quiet: bool = False,
    console: Console | None = None,
) -> None:
    """Print the scan summary to *console* (default: stdout)."""
    if quiet:
        return
    console = console or Console()
    totals = metadata.get("totals") or {}
    status = metadata.get("status", "")
    console.print()
    title = f"[bold]{metadata.get('tool', 'ParamScout')}[/bold] "
    title += f"v{metadata.get('version', '')} - {metadata.get('command', '')} "
    title += f"({metadata.get('mode', '')})"
    if status and status not in ("ok", "nothing-pending"):
        title += f"  [bold red]status: {status}[/bold red]"
    console.print(Panel(title, border_style="blue"))
    detail = metadata.get("status_detail")
    if detail:
        console.print(f"[dim]{detail}[/dim]")

    table = Table(title="Findings", title_justify="left")
    table.add_column("Endpoint", style="cyan", overflow="fold", max_width=46)
    table.add_column("Parameter", style="bold")
    table.add_column("Category")
    table.add_column("Priority", justify="center")
    table.add_column("Reflection")
    table.add_column("Behavior", justify="center")
    table.add_column("Diff kinds", overflow="fold", max_width=24)
    for row in rows:
        diffs = row.get("observed_differences") or ""
        kinds = ", ".join(
            sorted({part.split(":", 1)[0].strip() for part in diffs.split("|") if part.strip()})
        )
        priority = row.get("manual_review_priority") or "low"
        color = {"high": "red", "medium": "yellow", "low": "green"}.get(priority, "white")
        table.add_row(
            str(row.get("endpoint", ""))[:120],
            str(row.get("parameter", "")),
            str(row.get("category", "")),
            f"[{color}]{priority}[/{color}]",
            str(row.get("reflection_status", ""))[:40],
            str(row.get("behavior_confidence", ""))[:12],
            kinds,
        )
    if rows:
        console.print(table)
    else:
        console.print("[dim]No findings to display.[/dim]")

    totals_table = Table(title="Totals", title_justify="left", show_header=False)
    for key, value in (totals or {}).items():
        label = key.replace("_", " ")
        totals_table.add_row(f"[bold]{label}[/bold]", str(value))
    if metadata.get("scope"):
        scope_text = ", ".join(str(x) for x in metadata["scope"])
        totals_table.add_row("[bold]scope[/bold]", scope_text[:200])
    console.print(totals_table)

    limitations = metadata.get("limitations") or []
    if limitations:
        console.print("\n[bold yellow]Limitations[/bold yellow]")
        for item in limitations[:25]:
            console.print(f"  - {item}")
    if (totals or {}).get("skipped off-scope URLs", 0):
        console.print("\n[bold]Skipped off-scope URLs[/bold]")
        skipped = totals.get("skipped off-scope URLs detail") or []
        for item in list(skipped)[:10]:
            console.print(f"  - {item}")
