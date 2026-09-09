#!/usr/bin/env python3
"""Run ParamScout end-to-end against the bundled local mock application.

This is the safe way to see the tool work without pointing it at anything real:

    python examples/local_demo.py

It starts the same mock web application the test-suite uses (a plain
``http.server`` on 127.0.0.1 plus a second one on ``localhost``), runs a full
passive + active scan, and prints the Rich summary.  Reports are written to a
temporary directory and the servers are shut down afterwards.

Nothing leaves the machine.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests"))

from mockapp import make_pair  # noqa: E402

from paramscout.config import ScanConfig  # noqa: E402
from paramscout.engine import run_scan  # noqa: E402
from paramscout.reporting import build_report, render_summary, write_csv, write_html, write_json  # noqa: E402
from paramscout.scope import Scope  # noqa: E402


def main() -> int:
    primary, secondary = make_pair()
    print(f"mock target      : {primary.base}")
    print(f"off-scope target : {secondary.base}  (must never be contacted)\n")

    with tempfile.TemporaryDirectory(prefix="paramscout-demo-") as tmp:
        output = Path(tmp)
        config = ScanConfig()
        config.urls = [primary.base + "/"]
        # 127.0.0.1 is a loopback address, so the private-network guard needs an
        # explicit opt-in even for a local demo.
        config.scope = Scope.from_hosts(["127.0.0.1"], allow_private_networks=True)
        config.crawl.depth = 2
        config.crawl.max_pages = 30
        config.active.enabled = True
        config.active.excluded_paths.append(r"^/checkout")  # fake state-changing endpoint
        config.request.rate = 200.0          # fast for a demo; real scans stay slow
        config.request.global_rate = 400.0
        config.request.concurrency = 4
        config.request.max_requests = 900
        config.request.max_requests_per_endpoint = 80

        ctx = run_scan(config)

        endpoints = []
        outcomes = {item.endpoint: item for item in ctx.outcomes}
        for endpoint, url in ctx.passive.endpoint_examples.items():
            outcome = outcomes.get(endpoint)
            endpoints.append(
                {
                    "endpoint": endpoint,
                    "example_url": url,
                    "candidates": len(ctx.passive.candidates_for(endpoint)),
                    "active_status": (
                        "not tested"
                        if outcome is None
                        else ("excluded" if outcome.excluded else f"{len(outcome.outcomes)} probed")
                    ),
                    "active": outcome.to_dict() if outcome else None,
                }
            )
        report = build_report(
            mode="active",
            config=config,
            stats=ctx.stats,
            findings=ctx.findings,
            endpoints=endpoints,
            warnings=ctx.warnings,
            limitations=ctx.limitations,
        )
        write_json(report, output / "findings.json")
        write_csv(report, output / "findings.csv")
        write_html(report, output / "report.html")
        render_summary(report)

        print(f"\nreports written to: {output}")
        print(f"off-scope host requests : {dict(secondary.state.counts) or 'none (correct)'}")
        print(f"POST requests sent      : {primary.state.counts.get('POST', 0)} (must be 0)")
        print(f"probes against /checkout: {len(primary.state.canary_requests('/checkout'))} (must be 0)")

    primary.stop()
    secondary.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
