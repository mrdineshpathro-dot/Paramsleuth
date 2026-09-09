"""Privacy guarantees: no telemetry, no external contacts, machine output clean."""

import asyncio
import json
import subprocess
import sys
from pathlib import Path

VENV = Path(sys.executable)


async def _run(*argv: str) -> subprocess.CompletedProcess:
    return await asyncio.to_thread(
        subprocess.run,
        [str(VENV), "-m", "paramscout", *argv],
        capture_output=True,
        text=True,
        timeout=180,
    )


async def test_support_website_never_contacted(server_a, tmp_path):
    """A full scan only ever talks to the scoped target, never the author."""
    host = server_a.base.removeprefix("http://")
    wl = tmp_path / "wl.txt"
    wl.write_text("q\n")
    out = tmp_path / "r.json"
    proc = await _run(
        "scan",
        "--url", server_a.url("/search"),
        "--scope-host", host,
        "--active", "--wordlist", str(wl),
        "--rate", "0", "--retries", "0",
        "--output", str(out), "--quiet",
    )
    assert proc.returncode == 0, proc.stderr
    # every request the mock received had a local Host header
    assert server_a.app.requests, "expected the mock to receive requests"
    for request in server_a.app.requests:
        assert request["host"].startswith("127.0.0.1:"), request["host"]
    # and the mock never saw a request for the support domain
    assert not any("buymeacoffee" in (r["path"] + r["query"]) for r in server_a.app.requests)


def test_no_hidden_outbound_code_paths():
    """No source file should open the support website or send telemetry."""
    import paramscout
    from pathlib import Path as P

    pkg_root = P(paramscout.__file__).parent
    forbidden_imports = ("requests.get(", "urllib.request.urlopen", "webbrowser.open")
    hits = []
    for source in pkg_root.rglob("*.py"):
        text = source.read_text(encoding="utf-8")
        for token in forbidden_imports:
            if token in text:
                hits.append((source.name, token))
    assert hits == []
    # the support URL must appear only in static metadata modules
    found = set()
    for source in pkg_root.rglob("*.py"):
        if "buymeacoffee.com" in source.read_text(encoding="utf-8"):
            found.add(source.name)
    assert found <= {"__about__.py", "cli.py", "models.py"}, found


def test_user_agent_identifies_tool_and_version():
    from paramscout.__about__ import user_agent

    ua = user_agent()
    assert ua.startswith("ParamScout/0.1.0")


async def test_quiet_mode_suppresses_branding(server_a, tmp_path):
    """Branding is sent to stderr and suppressed by --quiet."""
    host = server_a.base.removeprefix("http://")
    out = tmp_path / "o.json"
    proc = await _run(
        "scan",
        "--url", server_a.url("/ignores?x=1"),
        "--scope-host", host,
        "--rate", "0", "--retries", "0",
        "--output", str(out), "--quiet",
    )
    assert proc.returncode == 0, proc.stderr
    assert "ParamScout v" not in proc.stderr
    assert json.loads(out.read_text())["metadata"]["tool"] == "ParamScout"
