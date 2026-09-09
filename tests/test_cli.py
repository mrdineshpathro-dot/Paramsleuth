"""End-to-end CLI tests: version/about, offline extraction, scans, resume.

Subprocess calls run via ``asyncio.to_thread`` so the local mock server's
event loop keeps serving while the child process runs.
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest

VENV = Path(sys.executable)

HTML_DOC = """<!DOCTYPE html>
<html><head><title>x</title></head><body>
<form method="GET" action="/search"><input name="q"><input type="hidden" name="csrf"></form>
<a href="/list?page=2&sort=asc">next</a>
</body></html>
"""


async def run_cli(*argv: str) -> subprocess.CompletedProcess:
    return await asyncio.to_thread(
        subprocess.run,
        [str(VENV), "-m", "paramscout", *argv],
        capture_output=True,
        text=True,
        timeout=180,
    )


async def test_version_output():
    proc = await run_cli("--version")
    assert proc.returncode == 0
    assert "ParamScout 0.1.0" in proc.stdout


async def test_about_output():
    proc = await run_cli("--about")
    assert proc.returncode == 0
    out = proc.stdout
    assert "Mrdineshpathro" in out
    assert "mrdineshpathro@gmail.com" in out
    assert "https://buymeacoffee.com/mrdineshpathro" in out
    assert "Authorized use only" in out


async def test_extract_offline_no_network(server_a, tmp_path):
    urls_file = tmp_path / "collected.txt"
    urls_file.write_text(server_a.url("/search?q=a&debug=true\n"))
    proc = await run_cli(
        "extract", "--input", str(urls_file), "--output", str(tmp_path / "out.json"),
        "--quiet",
    )
    assert proc.returncode == 0, proc.stderr
    assert server_a.app.requests == []  # zero network requests
    data = json.loads((tmp_path / "out.json").read_text())
    params = {r["parameter"] for r in data["findings"]}
    assert {"q", "debug"}.issubset(params)
    assert data["metadata"]["tool"] == "ParamScout"
    assert data["metadata"]["totals"]["requests"] == 0


async def test_extract_html_file_form_and_links(tmp_path):
    html_file = tmp_path / "page.html"
    html_file.write_text(HTML_DOC)
    proc = await run_cli(
        "extract", "--input", str(html_file), "--output", str(tmp_path / "out.json"),
        "--quiet",
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads((tmp_path / "out.json").read_text())
    params = {r["parameter"] for r in data["findings"]}
    assert {"q", "csrf", "page", "sort"}.issubset(params)


async def test_dry_run_makes_no_requests(server_a):
    host = server_a.base.removeprefix("http://")
    proc = await run_cli(
        "scan",
        "--url", server_a.url("/"),
        "--scope-host", host,
        "--active",
        "--dry-run",
        "--quiet",
    )
    assert proc.returncode == 0, proc.stderr
    assert server_a.app.requests == []
    assert "no requests will be sent" in (proc.stdout + proc.stderr)


async def test_scan_cli_active_and_machine_output_clean(server_a, tmp_path):
    host = server_a.base.removeprefix("http://")
    wl = tmp_path / "wl.txt"
    wl.write_text("q\nn\n")
    out_json = tmp_path / "findings.json"
    proc = await run_cli(
        "scan",
        "--url", server_a.url("/search"),
        "--scope-host", host,
        "--active",
        "--wordlist", str(wl),
        "--rate", "0",
        "--max-requests", "60",
        "--output", str(out_json),
        "--quiet",
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out_json.read_text())
    assert data["metadata"]["tool"] == "ParamScout"
    raw = out_json.read_text()
    # machine-readable output must be free of banner text
    assert not raw.startswith("ParamScout v")
    assert "authorized testing only" not in raw
    q_rows = [r for r in data["findings"] if r["parameter"] == "q"]
    assert q_rows, "q finding expected"
    assert q_rows[0]["observed_differences"]
    assert all(r["method"] == "GET" for r in server_a.app.requests)


async def test_scan_requires_scope(server_a):
    proc = await run_cli("scan", "--url", server_a.url("/"))
    assert proc.returncode == 1
    assert "scope" in proc.stderr.lower()


async def test_scan_rejects_off_scope_seed(server_a):
    host = server_a.base.removeprefix("http://")
    proc = await run_cli(
        "scan", "--url", "http://not-in-scope.example.test/", "--scope-host", host,
    )
    assert proc.returncode == 1
    assert "outside the configured scope" in proc.stderr


async def test_cli_scan_and_resume_roundtrip(server_a, tmp_path):
    host = server_a.base.removeprefix("http://")
    wl = tmp_path / "wl.txt"
    wl.write_text("\n".join(f"p{i:02d}" for i in range(10)))
    state_file = tmp_path / "scan.sqlite"
    out1 = tmp_path / "first.json"
    proc = await run_cli(
        "scan",
        "--url", server_a.url("/ignores"),
        "--scope-host", host,
        "--active",
        "--wordlist", str(wl),
        "--rate", "0",
        "--retries", "0",
        "--max-requests", "5",
        "--state", str(state_file),
        "--output", str(out1),
        "--quiet",
    )
    assert proc.returncode == 0, proc.stderr
    hits_before = len(server_a.app.requests)
    out2 = tmp_path / "resume.json"
    proc2 = await run_cli(
        "resume",
        "--state", str(state_file),
        "--scope-host", host,
        "--rate", "0",
        "--retries", "0",
        "--max-requests", "500",
        "--output", str(out2),
        "--quiet",
    )
    assert proc2.returncode == 0, proc2.stderr
    assert len(server_a.app.requests) > hits_before
    data = json.loads(out2.read_text())
    assert data["metadata"]["command"] == "resume"


async def test_offline_extract_wordlist_option(tmp_path):
    urls_file = tmp_path / "u.txt"
    urls_file.write_text("https://app.example.test/thing\n")
    wl = tmp_path / "extra.txt"
    wl.write_text("# comment\nnext\npage_size\n")
    out = tmp_path / "out.json"
    proc = await run_cli(
        "extract", "--input", str(urls_file), "--wordlist", str(wl),
        "--output", str(out), "--quiet",
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text())
    params = {r["parameter"] for r in data["findings"]}
    assert "next" in params and "page_size" in params
