"""Configuration objects, defaults and TOML loading.

Precedence is: built-in defaults < TOML config file < CLI flags.  The CLI only
overrides keys the user actually passed (tracked by comparing against the
argparse default), so a config file remains useful for the verbose options.
"""

from __future__ import annotations

import tomllib
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from paramscout import USER_AGENT
from paramscout.scope import Scope
from paramscout.urls import EndpointGrouping

#: Endpoints that are excluded from active probing by default.  Even a GET
#: request to one of these can have side effects on a badly designed app, so we
#: stay away unless the operator explicitly opts back in.
DEFAULT_EXCLUDED_PATHS: tuple[str, ...] = (
    r"^/logout",
    r"^/logoff",
    r"^/signout",
    r"^/sign-out",
    r"^/delete",
    r"^/remove",
    r"^/unsubscribe",
    r"^/cancel",
    r"^/confirm",
    r"^/verify-email",
    r"^/reset-password",
    r"^/password/reset",
    r"^/account/close",
    r"^/admin/",
    r"/delete$",
    r"/logout$",
    r"/unsubscribe$",
)


@dataclass
class RequestConfig:
    """Network behaviour knobs.

    ``rate`` and ``concurrency`` are **per host** unless the matching
    ``*_scope`` field is set to ``"global"``.  Both scopes are always enforced:
    the global limiter caps aggregate traffic, the per-host limiter caps
    pressure on any single origin.
    """

    rate: float = 2.0
    rate_scope: str = "host"  # "host" | "global"
    concurrency: int = 2
    concurrency_scope: str = "host"  # "host" | "global"
    global_rate: float = 5.0
    global_concurrency: int = 4
    timeout: float = 15.0
    connect_timeout: float = 8.0
    retries: int = 2
    backoff_base: float = 0.8
    backoff_max: float = 20.0
    max_redirects: int = 5
    max_response_bytes: int = 2_000_000
    max_url_length: int = 2000
    max_requests: int = 500
    max_requests_per_endpoint: int = 40
    throttle_status: tuple[int, ...] = (429, 503)
    throttle_slowdown_factor: float = 2.0
    throttle_slowdown_after: int = 2
    throttle_stop_after: int = 6
    proxy: str | None = None
    verify_tls: bool = True
    user_agent: str = USER_AGENT
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass
class CrawlConfig:
    """Passive crawling limits."""

    depth: int = 2
    max_pages: int = 100
    max_js_files: int = 20
    max_js_bytes: int = 500_000
    extract_js: bool = True
    fetch_external_js: bool = True
    fetch_robots: bool = True
    fetch_sitemap: bool = True
    allowed_content_types: tuple[str, ...] = ("text/html", "application/xhtml+xml")
    follow_query_variants: bool = False


@dataclass
class ActiveConfig:
    """Advanced (opt-in) active discovery settings."""

    enabled: bool = False
    wordlists: list[str] = field(default_factory=list)
    use_builtin_wordlist: bool = True
    baselines: int = 3
    confirmations: int = 2
    batch_size: int = 1
    max_candidates_per_endpoint: int = 60
    max_active_endpoints: int = 25
    canary_prefix: str = "psc"
    excluded_paths: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDED_PATHS))
    similarity_min_chars: int = 32
    similarity_max_chars: int = 20_000


@dataclass
class OutputConfig:
    """Report destinations."""

    json_path: str | None = None
    csv_path: str | None = None
    html_path: str | None = None
    state_path: str | None = None
    quiet: bool = False
    endpoint_grouping: EndpointGrouping = EndpointGrouping.STRICT


@dataclass
class ScanConfig:
    """Everything one scan run needs, independent of how it was supplied."""

    urls: list[str] = field(default_factory=list)
    input_files: list[str] = field(default_factory=list)
    scope: Scope = field(default_factory=Scope)
    request: RequestConfig = field(default_factory=RequestConfig)
    crawl: CrawlConfig = field(default_factory=CrawlConfig)
    active: ActiveConfig = field(default_factory=ActiveConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    dry_run: bool = False
    network_allowed: bool = False

    def to_dict(self, *, include_secrets: bool = False) -> dict[str, Any]:
        """Serialize for the resume store.

        Secrets (cookies, ``Authorization`` headers) are **never** written to
        the state file; that is not optional and not configurable.
        """

        data: dict[str, Any] = {
            "urls": list(self.urls),
            "input_files": list(self.input_files),
            "scope": self.scope.to_dict(),
            "request": asdict(self.request),
            "crawl": asdict(self.crawl),
            "active": asdict(self.active),
            "output": asdict(self.output),
            "dry_run": self.dry_run,
        }
        if not include_secrets:
            data["request"]["headers"] = {
                name: "[REDACTED]"
                for name in self.request.headers
                if name.lower() in {"authorization", "cookie", "proxy-authorization", "x-api-key"}
            } | {
                name: value
                for name, value in self.request.headers.items()
                if name.lower() not in {"authorization", "cookie", "proxy-authorization", "x-api-key"}
            }
            data["request"]["cookies"] = {name: "[REDACTED]" for name in self.request.cookies}
        data["output"]["endpoint_grouping"] = self.output.endpoint_grouping.value
        return data


def load_toml_config(path: str | Path) -> dict[str, Any]:
    """Load a TOML configuration file, tolerating an absent file."""

    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"config file not found: {config_path}")
    with config_path.open("rb") as handle:
        return tomllib.load(handle)


def apply_toml(config: ScanConfig, raw: dict[str, Any]) -> ScanConfig:
    """Overlay a TOML mapping onto *config* (CLI flags are applied after)."""

    def overlay(target: Any, section: dict[str, Any]) -> None:
        known = {item.name for item in fields(target)}
        for key, value in section.items():
            if key not in known:
                continue
            if isinstance(value, (list, tuple)) and isinstance(getattr(target, key), tuple):
                value = tuple(value)
            setattr(target, key, value)

    if "scope" in raw:
        section = raw["scope"]
        for entry in section.get("hosts", []):
            config.scope.add_host(str(entry))
        config.scope.include_subdomains = bool(
            section.get("include_subdomains", config.scope.include_subdomains)
        )
        config.scope.allow_private_networks = bool(
            section.get("allow_private_networks", config.scope.allow_private_networks)
        )
        for key, attr in (("allow_paths", "allow_paths"), ("deny_paths", "deny_paths")):
            from paramscout.scope import compile_path_rule

            for entry in section.get(key, []):
                getattr(config.scope, attr).append(compile_path_rule(str(entry)))
    for section_name, target in (
        ("request", config.request),
        ("crawl", config.crawl),
        ("active", config.active),
        ("output", config.output),
    ):
        if section_name in raw:
            overlay(target, raw[section_name])
    if "output" in raw and "endpoint_grouping" in raw["output"]:
        config.output.endpoint_grouping = EndpointGrouping(str(raw["output"]["endpoint_grouping"]))
    if "scan" in raw:
        config.urls.extend(str(item) for item in raw["scan"].get("urls", []))
        config.input_files.extend(str(item) for item in raw["scan"].get("input_files", []))
    return config


def parse_cookie_header(value: str) -> dict[str, str]:
    """Parse ``name=value; name2=value2`` into a dict."""

    cookies: dict[str, str] = {}
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        name, _, cookie_value = chunk.partition("=")
        name = name.strip()
        if name:
            cookies[name] = cookie_value.strip()
    return cookies


def parse_header(value: str) -> tuple[str, str]:
    """Parse ``Name: value`` into a tuple."""

    name, sep, header_value = value.partition(":")
    if not sep:
        raise ValueError(f"header must be in 'Name: value' form, got: {value!r}")
    return name.strip(), header_value.strip()
