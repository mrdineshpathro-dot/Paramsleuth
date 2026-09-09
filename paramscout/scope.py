"""Scope enforcement: the single gate every outbound URL must pass through.

No part of ParamScout performs a network request without calling
:meth:`Scope.check` first - not the crawler, not a redirect hop, not an
``<script src>`` discovered in HTML, not an active probe.

Host matching is *exact or dot-boundary suffix* - never substring.  A rule of
``example.test`` therefore matches ``example.test`` and (only with
``include_subdomains``) ``www.example.test``; it never matches
``notexample.test`` or ``example.test.evil.test``.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from paramscout.urls import DEFAULT_PORTS

ALLOWED_SCHEMES = frozenset({"http", "https"})

_PRIVATE_SUFFIXES = (".local", ".internal", ".localhost", ".invalid", ".lan")
_RESERVED_HOSTNAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"})


@dataclass(frozen=True)
class ScopeDecision:
    """Result of a scope check."""

    allowed: bool
    reason: str

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.allowed


@dataclass(frozen=True)
class HostRule:
    """One allow-listed host, optionally pinned to a port."""

    host: str
    port: int | None = None
    include_subdomains: bool = False

    def matches(self, host: str, port: int | None) -> bool:
        if self.port is not None and port is not None and self.port != port:
            return False
        if self.port is not None and port is None:
            # Rule pins a non-default port; the URL omitted it.
            if DEFAULT_PORTS.get("https") != self.port and DEFAULT_PORTS.get("http") != self.port:
                return False
        if host == self.host:
            return True
        return self.include_subdomains and host.endswith("." + self.host)


@dataclass
class Scope:
    """Explicit authorization boundary for one scan."""

    hosts: list[HostRule] = field(default_factory=list)
    allow_paths: list[re.Pattern[str]] = field(default_factory=list)
    deny_paths: list[re.Pattern[str]] = field(default_factory=list)
    include_subdomains: bool = False
    allow_private_networks: bool = False
    resolve_hosts: bool = False
    require_scope: bool = True

    # -- construction ----------------------------------------------------

    @classmethod
    def from_hosts(
        cls,
        hosts: list[str],
        *,
        include_subdomains: bool = False,
        allow_paths: list[str] | None = None,
        deny_paths: list[str] | None = None,
        allow_private_networks: bool = False,
        resolve_hosts: bool = False,
    ) -> Scope:
        rules = [parse_host_rule(entry, include_subdomains) for entry in hosts if entry.strip()]
        return cls(
            hosts=rules,
            allow_paths=[compile_path_rule(item) for item in (allow_paths or [])],
            deny_paths=[compile_path_rule(item) for item in (deny_paths or [])],
            include_subdomains=include_subdomains,
            allow_private_networks=allow_private_networks,
            resolve_hosts=resolve_hosts,
        )

    def add_host(self, entry: str, *, include_subdomains: bool | None = None) -> None:
        rule = parse_host_rule(
            entry, self.include_subdomains if include_subdomains is None else include_subdomains
        )
        if rule not in self.hosts:
            self.hosts.append(rule)

    @property
    def is_empty(self) -> bool:
        return not self.hosts

    # -- checks ----------------------------------------------------------

    def host_allowed(self, host: str, port: int | None = None) -> bool:
        host = host.rstrip(".").lower()
        if not host:
            return False
        return any(rule.matches(host, port) for rule in self.hosts)

    def check(self, url: str) -> ScopeDecision:
        """Validate a full URL.  This is the only authorization decision point."""

        if not url or not url.strip():
            return ScopeDecision(False, "empty URL")
        try:
            parts = urlsplit(url.strip())
        except ValueError as exc:
            return ScopeDecision(False, f"unparseable URL: {exc}")

        scheme = parts.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            return ScopeDecision(False, f"scheme '{scheme or 'none'}' not permitted (http/https only)")

        host = (parts.hostname or "").rstrip(".").lower()
        if not host:
            return ScopeDecision(False, "URL has no host component")

        if "@" in parts.netloc:
            return ScopeDecision(False, "URL embeds credentials in the authority component")

        if not self.allow_private_networks:
            private_reason = private_network_reason(host, resolve=self.resolve_hosts)
            if private_reason:
                return ScopeDecision(False, private_reason)

        if self.require_scope:
            if not self.hosts:
                return ScopeDecision(False, "no scope configured - refusing to make network requests")
            if not self.host_allowed(host, parts.port):
                return ScopeDecision(False, f"host '{host}' is not in the allowlist")

        path = parts.path or "/"
        if self.deny_paths and any(pattern.search(path) for pattern in self.deny_paths):
            return ScopeDecision(False, f"path '{path}' matches an exclusion rule")
        if self.allow_paths and not any(pattern.search(path) for pattern in self.allow_paths):
            return ScopeDecision(False, f"path '{path}' is outside the allowed path rules")

        return ScopeDecision(True, "in scope")

    def filter(self, urls: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
        """Split *urls* into ``(allowed, rejected)``."""

        allowed: list[str] = []
        rejected: list[tuple[str, str]] = []
        for url in urls:
            decision = self.check(url)
            if decision.allowed:
                allowed.append(url)
            else:
                rejected.append((url, decision.reason))
        return allowed, rejected

    def to_dict(self) -> dict[str, object]:
        return {
            "hosts": [
                {"host": rule.host, "port": rule.port, "include_subdomains": rule.include_subdomains}
                for rule in self.hosts
            ],
            # 're:' keeps the rule exactly as compiled, so a resumed scan
            # re-applies the same matcher instead of escaping it as a prefix.
            "allow_paths": [f"re:{pattern.pattern}" for pattern in self.allow_paths],
            "deny_paths": [f"re:{pattern.pattern}" for pattern in self.deny_paths],
            "include_subdomains": self.include_subdomains,
            "allow_private_networks": self.allow_private_networks,
            "require_scope": self.require_scope,
        }


def parse_host_rule(entry: str, include_subdomains: bool = False) -> HostRule:
    """Parse ``host``, ``.host`` (implies subdomains) or ``host:port``."""

    raw = entry.strip().lower()
    if raw.startswith("*."):
        raw = raw[1:]
        include_subdomains = True
    if raw.startswith("."):
        include_subdomains = True
        raw = raw[1:]
    # Strip any accidental scheme/path from a pasted value.
    if "://" in raw:
        raw = urlsplit(raw).hostname or raw
    raw = raw.split("/", 1)[0].rstrip(".")
    port: int | None = None
    if raw.startswith("["):  # IPv6 literal, optionally with :port
        host, _, rest = raw.partition("]")
        host = host[1:]
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
    elif ":" in raw:
        host, _, maybe_port = raw.partition(":")
        if maybe_port.isdigit():
            port = int(maybe_port)
        else:
            host = raw
    else:
        host = raw
    return HostRule(host=host, port=port, include_subdomains=include_subdomains)


def compile_path_rule(entry: str) -> re.Pattern[str]:
    """Compile a path rule: ``re:`` prefix means regex, otherwise prefix match."""

    entry = entry.strip()
    if entry.startswith("re:"):
        return re.compile(entry[3:])
    return re.compile("^" + re.escape(entry))


def is_private_literal(host: str) -> bool:
    """True for loopback/private/link-local/reserved *literal* addresses."""

    if host in _RESERVED_HOSTNAMES or host.endswith(_PRIVATE_SUFFIXES):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def private_network_reason(host: str, *, resolve: bool = False) -> str | None:
    """Explain why *host* looks internal, or ``None`` when it does not."""

    if is_private_literal(host):
        return f"host '{host}' resolves to a private/loopback address"
    if not resolve:
        return None
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return None
    for info in infos:
        candidate = str(info[4][0])
        if is_private_literal(candidate):
            return f"host '{host}' resolves to private/loopback address {candidate}"
    return None
