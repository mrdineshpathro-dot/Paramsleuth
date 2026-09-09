"""Configuration model for ParamScout runs.

Defaults are deliberately conservative. All request controls are configurable
through the CLI or a TOML config file (``--config``). Rate and concurrency
options are defined **per host**: every host gets at most ``concurrency``
in-flight requests, spaced at least ``rate`` seconds apart, so N targets do not
multiply the load by N.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from . import __about__


@dataclass
class Config:
    # ---- identity / scope -------------------------------------------
    tool_name: str = "ParamScout"
    scope_hosts: list[str] = field(default_factory=list)
    scope_file: str | None = None
    exclude_paths: list[str] = field(default_factory=list)

    # ---- request controls (all per host unless stated) --------------
    rate: float = 0.1  # minimum seconds between requests to the same host
    concurrency: int = 3  # max in-flight requests per host
    max_requests: int = 300  # global budget (scan). 0 = unlimited with warning
    max_requests_per_endpoint: int = 0  # per-endpoint budget; 0 = global-derived
    timeout: float = 15.0  # per-request timeout, seconds
    retries: int = 2  # limited retries per request attempt chain
    backoff_base: float = 1.0
    backoff_max: float = 30.0
    jitter: float = 0.25
    max_redirects: int = 5
    max_response_bytes: int = 2 * 1024 * 1024  # 2 MiB per response body
    proxy: str | None = None  # optional proxy URL for authorized inspection
    verify_tls: bool = True
    user_agent: str = field(default_factory=__about__.user_agent)
    # slowdown/stop on repeated throttling (429/503)
    throttle_stop_after: int = 6  # consecutive 429/503 -> pause scan
    throttle_slowdown: float = 3.0  # seconds added per consecutive throttle

    # ---- crawl -------------------------------------------------------
    crawl: bool = False
    depth: int = 1
    max_pages: int = 50
    extract_js: bool = False  # fetch in-scope external JavaScript
    fetch_robots: bool = False
    fetch_sitemap: bool = False
    content_type_filters: list[str] = field(default_factory=list)  # e.g. ["text/html"]

    # ---- active probing ----------------------------------------------
    active: bool = False
    wordlist: str | None = None
    use_builtin_wordlist: bool = True
    endpoint_grouping: str = "path"  # "path" or "host"
    batch_size: int = 1  # candidates per probe batch; 1 = one candidate/probe
    baseline_requests: int = 3  # baselines collected before probing
    max_baseline_spread: float = 0.35  # max relative size spread considered stable
    similarity_threshold: float = 0.95  # above this -> "similar" normalized text
    min_size_diff_bytes: int = 150  # size differences below this are ignored
    min_size_diff_ratio: float = 0.10
    validation_retests: int = 1  # individual re-tests per promising candidate
    delay_between_probes: float = 0.2

    # ---- extraction ---------------------------------------------------
    max_candidates_per_endpoint: int = 200

    # ---- auth (never persisted to resume files) ----------------------
    cookies: dict[str, str] = field(default_factory=dict)  # per original host
    headers: dict[str, str] = field(default_factory=dict)
    auth_hosts: list[str] = field(default_factory=list)  # hosts that may see them

    # ---- state / reporting -------------------------------------------
    state_file: str | None = None
    output_json: str | None = None
    output_csv: str | None = None
    output_html: str | None = None
    include_inconclusive: bool = False
    quiet: bool = False
    no_color: bool = False

    # ---- misc ----------------------------------------------------------
    seed_urls: list[str] = field(default_factory=list)
    offline_inputs: list[str] = field(default_factory=list)
    scan_label: str = ""

    # ------------------------------------------------------------------
    def derive(self) -> None:
        """Fill derived values after construction."""
        if self.max_requests_per_endpoint <= 0:
            # Default per-endpoint budget: a practical floor of 25 probes plus
            # room derived from the global budget.
            self.max_requests_per_endpoint = max(25, self.max_requests // 10)
        # auth hosts default to the scope hosts when not provided
        if not self.auth_hosts and self.scope_hosts:
            self.auth_hosts = [_plain_hostname(h) for h in self.scope_hosts if h]


    def redacted_dict(self) -> dict[str, Any]:
        """Config as a dict safe for persistence/reports (no credentials)."""
        data = dataclasses.asdict(self)
        data["cookies"] = {k: "<redacted>" for k in self.cookies}
        data["headers"] = {k: "<redacted>" for k in self.headers}
        return data

    def describe(self) -> str:
        out = [
            f"mode={self.scan_label or '?'}",
            f"rate={self.rate}s",
            f"concurrency/host={self.concurrency}",
            f"global_budget={self.max_requests}",
            f"per_endpoint_budget={self.max_requests_per_endpoint}",
            f"crawl={self.crawl}",
            f"active={self.active}",
            f"batch_size={self.batch_size}",
        ]
        return ", ".join(out)
def _plain_hostname(expression: str) -> str:
    """Strip scheme and port from a host expression (used for credential scope)."""
    expr = expression.strip()
    if "://" not in expr:
        expr = "//" + expr
    try:
        return (urlsplit(expr).hostname or "").strip("[]").lower()
    except ValueError:
        return expression.strip().lower().split(":", 1)[0].strip("[]")
