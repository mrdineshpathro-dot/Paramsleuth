"""Standalone HTML report.

Every value interpolated into this document is passed through
:func:`html.escape`.  Findings contain attacker-influenced text (parameter
names, reflected canaries, page titles, extraction snippets), so the report is
treated as an untrusted-content renderer: no value is ever inserted raw, no
value is inserted into a script context, and no external resources are loaded.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

_CSS = """
:root { color-scheme: light dark; }
body { font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
       margin: 0; padding: 2rem; background: #f7f8fa; color: #14181f; line-height: 1.5; }
h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
h2 { font-size: 1.1rem; margin: 2rem 0 .5rem; border-bottom: 1px solid #d6dae1; padding-bottom: .25rem; }
.sub { color: #5b6472; font-size: .9rem; margin-bottom: 1.5rem; }
.card { background: #fff; border: 1px solid #e1e5eb; border-radius: 8px; padding: 1rem 1.25rem;
        margin-bottom: 1rem; }
table { border-collapse: collapse; width: 100%; font-size: .875rem; }
th, td { text-align: left; padding: .4rem .5rem; border-bottom: 1px solid #e8ebf0; vertical-align: top; }
th { background: #f0f2f6; font-weight: 600; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .8rem; }
pre { background: #0f1420; color: #e6e9ef; padding: .75rem; border-radius: 6px; overflow-x: auto;
      white-space: pre-wrap; word-break: break-word; }
.pill { display: inline-block; padding: .1rem .45rem; border-radius: 999px; font-size: .75rem;
        border: 1px solid #cfd5de; background: #eef1f6; }
.pill-high { background: #fdecec; border-color: #f3b6b6; }
.pill-med { background: #fff5e5; border-color: #f0d3a1; }
.pill-low { background: #eef4ff; border-color: #c3d5f7; }
ul { margin: .35rem 0 .35rem 1.1rem; padding: 0; }
details { margin-top: .5rem; }
summary { cursor: pointer; color: #2a5bd7; font-size: .85rem; }
.warn { background: #fff8e6; border-color: #ecd9a4; }
.note { color: #5b6472; font-size: .85rem; }
"""

_STATUS_PILL = {
    "behavioral_change": "pill pill-high",
    "behavioral_change_unconfirmed": "pill pill-med",
    "reflection_only": "pill pill-low",
    "inconclusive": "pill pill-med",
    "no_change": "pill",
    "not_tested": "pill",
    "error": "pill pill-med",
    "skipped": "pill",
}


def escape(value: Any) -> str:
    """Escape anything for safe insertion into HTML text or attributes."""

    return html.escape("" if value is None else str(value), quote=True)


def _pill(status: str) -> str:
    css = _STATUS_PILL.get(status, "pill")
    return f'<span class="{css}">{escape(status)}</span>'


def _finding_row(index: int, finding: dict[str, Any]) -> str:
    behavioral = finding.get("behavioral") or {}
    reflection = behavioral.get("reflection") or {}
    status = behavioral.get("status", "not_tested")
    reasons = "".join(f"<li>{escape(item)}</li>" for item in finding.get("priority_reasons", []))
    discovery_reasons = "".join(f"<li>{escape(item)}</li>" for item in finding.get("discovery_reasons", []))
    notes = "".join(f"<li>{escape(item)}</li>" for item in behavioral.get("notes", []))
    deltas = behavioral.get("deltas") or []
    delta_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            escape(item.get("status_changed")),
            escape(item.get("text_similarity")),
            escape(item.get("length_delta")),
            escape(", ".join(item.get("signals", [])[:6])),
        )
        for item in deltas[:6]
    )
    evidence_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>".format(
            escape(item.get("kind")),
            escape(item.get("origin")),
            escape(item.get("detail")),
            escape(item.get("context")),
        )
        for item in (finding.get("evidence") or [])[:8]
    )
    return f"""
    <tr>
      <td>{index}</td>
      <td><code>{escape(finding.get('parameter'))}</code><br>
          <span class="note">{escape(finding.get('endpoint'))}</span></td>
      <td>{escape(finding.get('category'))}</td>
      <td>{escape(", ".join(finding.get('sources', [])))}</td>
      <td>{escape(round(float(finding.get('discovery_confidence', 0)), 2))}</td>
      <td>{_pill(status)}</td>
      <td>{escape(round(float(finding.get('behavioral_confidence', 0)), 2))}</td>
      <td>{escape(finding.get('review_priority'))}</td>
      <td>{'yes (' + escape(reflection.get('occurrences')) + ')' if reflection.get('reflected') else 'no'}</td>
      <td>{escape(behavioral.get('attempts', 0))}</td>
    </tr>
    <tr class="detail">
      <td></td>
      <td colspan="9">
        <details>
          <summary>observed differences, evidence and reproduction</summary>
          <p><strong>Observed differences:</strong></p>
          <ul>{''.join(f'<li>{escape(item)}</li>' for item in behavioral.get('signals', [])) or '<li>none</li>'}</ul>
          <p><strong>Why this priority:</strong></p><ul>{reasons}</ul>
          <p><strong>Discovery reasoning:</strong></p><ul>{discovery_reasons}</ul>
          <p><strong>Measurement notes:</strong></p><ul>{notes or '<li>none</li>'}</ul>
          {'<p><strong>Probe deltas:</strong></p><table><tr><th>status changed</th><th>text similarity</th><th>length delta</th><th>signals</th></tr>' + delta_rows + '</table>' if delta_rows else ''}
          <p><strong>Provenance:</strong></p>
          <table><tr><th>kind</th><th>origin</th><th>detail</th><th>context</th></tr>{evidence_rows}</table>
          <p><strong>Sanitized reproduction request</strong>
             <span class="note">(credentials removed; canary shown as a placeholder)</span></p>
          <pre>{escape(finding.get('reproduction'))}</pre>
        </details>
      </td>
    </tr>"""


def _endpoint_rows(endpoints: list[dict[str, Any]]) -> str:
    rows = []
    for endpoint in endpoints:
        rows.append(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                escape(endpoint.get("endpoint")),
                escape(endpoint.get("example_url")),
                escape(endpoint.get("candidates")),
                escape(endpoint.get("active_status", "not tested")),
            )
        )
    return "".join(rows)


def render_html(report: dict[str, Any]) -> str:
    """Render the full standalone HTML document."""

    stats = report.get("stats", {})
    summary = report.get("summary", {})
    scope = report.get("authorized_scope", {})
    hosts = ", ".join(
        f"{item.get('host')}{':' + str(item.get('port')) if item.get('port') else ''}"
        f"{' (and subdomains)' if item.get('include_subdomains') else ''}"
        for item in scope.get("hosts", [])
    )
    warnings = "".join(
        f'<div class="card warn"><strong>Warning:</strong> {escape(item)}</div>'
        for item in report.get("warnings", [])
    )
    limitations = "".join(f"<li>{escape(item)}</li>" for item in report.get("limitations", []))
    findings = report.get("findings", [])
    rows = "".join(_finding_row(index, finding) for index, finding in enumerate(findings, start=1))
    status_counts = "".join(
        f"<tr><td>{escape(key)}</td><td>{escape(value)}</td></tr>"
        for key, value in (summary.get("by_behavioral_status") or {}).items()
    )
    category_counts = "".join(
        f"<tr><td>{escape(key)}</td><td>{escape(value)}</td></tr>"
        for key, value in (summary.get("by_category") or {}).items()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>ParamScout report - {escape(report.get('generated_at'))}</title>
<style>{_CSS}</style>
</head>
<body>
<h1>ParamScout parameter discovery report</h1>
<div class="sub">
  Mode: <strong>{escape(report.get('mode'))}</strong> &middot;
  Generated: {escape(report.get('generated_at'))} &middot;
  Version {escape(report.get('version'))}
</div>

<div class="card warn">
  <strong>Authorized use only.</strong> This report describes <em>observed parameter behaviour</em>.
  Nothing here is a confirmed vulnerability and no severity is assigned. Verify every item
  manually, inside the scope you are authorized to test.
</div>
{warnings}

<h2>Scope</h2>
<div class="card">
  <p><strong>Allowed hosts:</strong> {escape(hosts) or '<em>none - no network requests were permitted</em>'}</p>
  <p><strong>Allowed paths:</strong> {escape(", ".join(scope.get('allow_paths', [])) or 'all')}</p>
  <p><strong>Excluded paths:</strong> {escape(", ".join(scope.get('deny_paths', [])) or 'none')}</p>
</div>

<h2>Scan statistics</h2>
<div class="card">
  <table>
    <tr><th>Requests sent</th><td>{escape(stats.get('requests_total'))}</td></tr>
    <tr><th>By purpose</th><td>{escape(stats.get('requests_by_purpose'))}</td></tr>
    <tr><th>By status</th><td>{escape(stats.get('requests_by_status'))}</td></tr>
    <tr><th>Retries</th><td>{escape(stats.get('retries'))}</td></tr>
    <tr><th>Throttling events</th><td>{escape(len(stats.get('throttle_events', [])))}</td></tr>
    <tr><th>Off-scope URLs skipped</th><td>{escape(len(stats.get('skipped_off_scope', [])))}</td></tr>
    <tr><th>Requests skipped (budget/throttle)</th><td>{escape(stats.get('skipped_budget'))}</td></tr>
    <tr><th>Transport errors</th><td>{escape(stats.get('transport_errors'))}</td></tr>
    <tr><th>Truncated responses</th><td>{escape(stats.get('truncated_responses'))}</td></tr>
    <tr><th>Elapsed seconds</th><td>{escape(stats.get('elapsed_seconds'))}</td></tr>
    <tr><th>Interrupted</th><td>{escape('yes - partial results' if stats.get('interrupted') else 'no')}</td></tr>
  </table>
</div>

<h2>Results at a glance</h2>
<div class="card">
  <p><strong>{escape(summary.get('findings_total'))}</strong> parameter findings across
     <strong>{escape(summary.get('endpoints_total'))}</strong> endpoints &middot;
     <strong>{escape(summary.get('reflected_canaries'))}</strong> reflected canaries &middot;
     <strong>{escape(summary.get('inconclusive'))}</strong> inconclusive</p>
  <table style="width:auto"><tr><th>Behavioural status</th><th>Count</th></tr>{status_counts}</table>
  <table style="width:auto"><tr><th>Category</th><th>Count</th></tr>{category_counts}</table>
</div>

<h2>Findings</h2>
<div class="card">
  <table>
    <tr>
      <th>#</th><th>Parameter / endpoint</th><th>Category</th><th>Sources</th>
      <th>Discovery</th><th>Behavioural status</th><th>Behavioural</th>
      <th>Priority</th><th>Reflected</th><th>Attempts</th>
    </tr>
    {rows or '<tr><td colspan="10">No parameter candidates were discovered.</td></tr>'}
  </table>
</div>

<h2>Endpoints examined</h2>
<div class="card">
  <table>
    <tr><th>Endpoint</th><th>Example URL</th><th>Candidates</th><th>Active validation</th></tr>
    {_endpoint_rows(report.get('endpoints', [])) or '<tr><td colspan="4">none</td></tr>'}
  </table>
</div>

<h2>Limitations</h2>
<div class="card"><ul>{limitations}</ul></div>

</body>
</html>
"""


def write_html(report: dict[str, Any], path: str | Path) -> Path:
    """Render and write the standalone HTML report."""

    target = Path(path)
    if str(target.parent) and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_html(report), encoding="utf-8")
    return target
