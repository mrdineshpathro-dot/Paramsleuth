"""Explicit scope management.

Scope rules are host-centric. Hostnames are matched exactly or through an
explicit wildcard (``*.example.com``) -- never by fragile substring matching,
so ``example.com`` can never authorize ``notexample.com``.

Scope file format (one rule per line, ``#`` comments allowed)::

    # host only (http and https, any port unless a port is written)
    app.example.test
    # host with a required path prefix
    app.example.test/api
    # wildcard subdomains (does not include the bare apex)
    *.example.test
    # a port is part of the host rule when written
    app.example.test:8443
    # path prefix requirement applied to every URL on this host
    +path /public
    # global path exclusion prefix
    -path /admin
    # explicit host denial (wins over allow rules)
    -host internal.example.test
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .urlutils import normalize_url

DEFAULT_SCOPE_FILE_HEADER = (
    "# ParamScout scope file: one host rule per line. Comments start with '#'.\n"
)


def _valid_hostname(host: str) -> bool:
    """Conservative hostname syntax check (no spaces/slashes/junk symbols)."""
    import re

    if not host or " " in host or "/" in host or "@" in host or "://" in host:
        return False
    return bool(re.fullmatch(r"[a-z0-9_.\-]+", host))


def _host_and_port(hostport: str) -> tuple[str, int | None]:
    hostport = hostport.strip().rstrip("/")
    if hostport.startswith("["):  # IPv6 literal
        end = hostport.find("]")
        if end == -1:
            return hostport.lower(), None
        host = hostport[: end + 1]
        rest = hostport[end + 1 :]
        port = None
        if rest.startswith(":"):
            try:
                port = int(rest[1:])
            except ValueError:
                port = None
        return host.lower(), port
    if ":" in hostport:
        host, _, port_s = hostport.rpartition(":")
        try:
            return host.lower(), int(port_s)
        except ValueError:
            return hostport.lower(), None
    return hostport.lower(), None


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str = ""


@dataclass
class HostRule:
    """One host allow rule (from CLI --scope-host or a scope file)."""

    host: str  # lowercase hostname; may contain a leading "*." wildcard
    port: int | None
    path_prefix: str = ""
    wildcard: bool = False

    def matches_host(self, host: str, port: int | None) -> bool:
        if self.port is not None:
            if port is None:
                return False
            if port != self.port:
                return False
        if not self.wildcard:
            return host == self.host
        # self.host is stored without the "*." prefix for wildcard rules.
        return host.endswith("." + self.host) and host != self.host


@dataclass
class Scope:
    """Allowlist-based scope. Empty scope denies everything."""

    host_rules: list[HostRule] = field(default_factory=list)
    path_include_prefixes: list[str] = field(default_factory=list)
    path_exclude_prefixes: list[str] = field(default_factory=list)
    deny_hosts: set[str] = field(default_factory=set)

    @property
    def is_empty(self) -> bool:
        return not self.host_rules

    # -- construction -------------------------------------------------
    @classmethod
    def from_hosts(cls, hosts: list[str]) -> "Scope":
        """Build a scope from CLI ``--scope-host`` values."""
        scope = cls()
        for host in hosts:
            scope.add_host_rule(host)
        return scope

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        """Parse a scope file. Raises ValueError on malformed rules."""
        scope = cls()
        with open(path, "r", encoding="utf-8") as handle:
            for lineno, raw in enumerate(handle, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                scope._apply_line(line, str(path), lineno)
        return scope

    def add_host_rule(self, expression: str) -> None:
        self._apply_line(expression, "<--scope-host>", 0)

    def _apply_line(self, line: str, source: str, lineno: int) -> None:
        if line.startswith("-path"):
            prefix = line[len("-path"):].strip()
            if not prefix.startswith("/"):
                prefix = "/" + prefix
            self.path_exclude_prefixes.append(prefix)
        elif line.startswith("+path"):
            prefix = line[len("+path"):].strip()
            if not prefix.startswith("/"):
                prefix = "/" + prefix
            self.path_include_prefixes.append(prefix)
        elif line.startswith("-host"):
            hostname = line[len("-host"):].strip().lower()
            if not hostname:
                raise ValueError(f"{source}:{lineno}: empty -host rule")
            self.deny_hosts.add(hostname)
        elif line.startswith("-"):
            # Unknown directive (e.g. "-p ...") - reject rather than guess.
            raise ValueError(
                f"{source}:{lineno}: unknown scope directive {line.split()[0]!r} "
                "(supported: -path, +path, -host)"
            )
        else:
            # host [with optional path prefix or :port]
            expr = line.strip()
            hostport, _, path_prefix = expr.partition("/")
            if not hostport:
                raise ValueError(f"{source}:{lineno}: empty host rule")
            host, port = _host_and_port(hostport)
            wildcard = host.startswith("*.")
            bare_host = host[2:] if wildcard else host
            if not _valid_hostname(bare_host):
                raise ValueError(f"{source}:{lineno}: malformed host rule: {expr!r}")
            self.host_rules.append(
                HostRule(host=bare_host, port=port, path_prefix="/" + path_prefix if path_prefix else "", wildcard=wildcard)
            )

    # -- evaluation ----------------------------------------------------
    def check(self, url: str) -> ScopeDecision:
        """Validate *url* against the scope.

        Returns a decision; ``allowed`` is True only when every component is
        in scope. Callers must check every URL (including redirect targets and
        discovered links) with this method *before* requesting it.
        """
        normalized = normalize_url(url)
        if not normalized:
            return ScopeDecision(False, f"not an absolute http(s) URL: {url!r}")
        if self.is_empty:
            return ScopeDecision(False, "no scope configured; refusing network activity")
        try:
            parts = urlsplit(normalized)
        except ValueError as exc:
            return ScopeDecision(False, f"malformed URL: {exc}")
        host = (parts.hostname or "").lower()
        port = parts.port
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            return ScopeDecision(False, f"non-http(s) scheme not allowed: {scheme}")
        if not host:
            return ScopeDecision(False, "URL has no hostname")

        if host in self.deny_hosts:
            return ScopeDecision(False, f"host {host} is explicitly denied")

        matching = [r for r in self.host_rules if r.matches_host(host, port)]
        if not matching:
            return ScopeDecision(
                False,
                f"host {host}:{port or ''} is not in the scope allowlist",
            )
        path = parts.path or "/"
        # A host rule may carry a required path prefix; any matching rule may
        # authorize the path (OR semantics across rules for the same host).
        if not any(
            (rule.path_prefix and path.startswith(rule.path_prefix))
            or not rule.path_prefix
            for rule in matching
        ):
            return ScopeDecision(
                False,
                f"path {path!r} is outside every allowed prefix for host {host}",
            )
        if self.path_include_prefixes and not any(
            path.startswith(prefix) for prefix in self.path_include_prefixes
        ):
            return ScopeDecision(
                False,
                f"path {path!r} does not match any required +path prefix",
            )
        for prefix in self.path_exclude_prefixes:
            if path.startswith(prefix):
                return ScopeDecision(
                    False, f"path {path!r} is excluded by -path {prefix!r}"
                )
        return ScopeDecision(True, "in scope")

    def check_redirect(self, url: str) -> ScopeDecision:
        """Validate a redirect destination before following it."""
        return self.check(url)

    def authorizes_hostname(self, host: str) -> bool:
        """True when *host* (hostname only, no port) is an authorized host.

        Used for credential origin checks: credentials may follow a host even
        when the URL's port differs from the rule's port (still same hostname),
        but never a different hostname.
        """
        host = (host or "").lower().strip().rstrip(".")
        if host in self.deny_hosts:
            return False
        for rule in self.host_rules:
            if rule.wildcard:
                suffix = rule.host
                if host.endswith("." + suffix):
                    return True
            elif host == rule.host:
                return True
        return False

    # -- misc -----------------------------------------------------------
    def summary_lines(self) -> list[str]:
        lines: list[str] = []
        for rule in self.host_rules:
            label = f"*.{rule.host}" if rule.wildcard else rule.host
            if rule.port is not None:
                label = f"{label}:{rule.port}"
            if rule.path_prefix:
                label = f"{label}{rule.path_prefix}"
            lines.append(label)
        if self.path_include_prefixes:
            lines.append("+path " + ", ".join(self.path_include_prefixes))
        if self.path_exclude_prefixes:
            lines.append("-path " + ", ".join(self.path_exclude_prefixes))
        if self.deny_hosts:
            lines.append("-host " + ", ".join(sorted(self.deny_hosts)))
        return lines

    def as_dict(self) -> dict:
        return {
            "hosts": [
                {
                    "host": r.host,
                    "port": r.port,
                    "path_prefix": r.path_prefix,
                    "wildcard": r.wildcard,
                }
                for r in self.host_rules
            ],
            "path_include_prefixes": self.path_include_prefixes,
            "path_exclude_prefixes": self.path_exclude_prefixes,
            "deny_hosts": sorted(self.deny_hosts),
        }
