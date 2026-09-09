"""Scope enforcement tests: matching rules, redirects and URL validation."""

from __future__ import annotations

import pytest

from paramscout.scope import Scope, is_private_literal, parse_host_rule


def test_host_matching_is_not_substring_matching() -> None:
    scope = Scope.from_hosts(["example.test"])
    assert scope.host_allowed("example.test")
    assert not scope.host_allowed("notexample.test")
    assert not scope.host_allowed("example.test.evil.test")
    assert not scope.host_allowed("evilexample.test")
    # a rule does not implicitly cover subdomains
    assert not scope.host_allowed("www.example.test")


def test_subdomain_rules_require_a_dot_boundary() -> None:
    scope = Scope.from_hosts([".example.test"])
    assert scope.host_allowed("www.example.test")
    assert scope.host_allowed("a.b.example.test")
    assert scope.host_allowed("example.test")
    assert not scope.host_allowed("notexample.test")


def test_wildcard_prefix_is_treated_as_subdomain_rule() -> None:
    rule = parse_host_rule("*.example.test")
    assert rule.host == "example.test"
    assert rule.include_subdomains is True


def test_port_rules() -> None:
    scope = Scope.from_hosts(["example.test:8443"])
    assert scope.check("https://example.test:8443/a").allowed
    # a URL that omits the pinned port is not the same endpoint
    assert not scope.check("https://example.test/a").allowed


def test_only_http_and_https_are_permitted() -> None:
    scope = Scope.from_hosts(["example.test"])
    assert scope.check("https://example.test/").allowed
    assert scope.check("http://example.test/").allowed
    for url in ("file:///etc/passwd", "ftp://example.test/x", "gopher://example.test/", "javascript:alert(1)"):
        decision = scope.check(url)
        assert not decision.allowed
        assert "scheme" in decision.reason


def test_credentials_in_the_authority_are_rejected() -> None:
    scope = Scope.from_hosts(["example.test"])
    decision = scope.check("https://user:pass@example.test/")
    assert not decision.allowed
    assert "credentials" in decision.reason


def test_private_networks_are_rejected_by_default() -> None:
    scope = Scope.from_hosts(["127.0.0.1"])
    assert not scope.check("http://127.0.0.1/").allowed
    allowed = Scope.from_hosts(["127.0.0.1"], allow_private_networks=True)
    assert allowed.check("http://127.0.0.1/").allowed
    assert is_private_literal("localhost")
    assert is_private_literal("10.1.2.3")
    assert is_private_literal("192.168.0.1")
    assert is_private_literal("169.254.1.1")
    assert not is_private_literal("93.184.216.34")


def test_path_allowlists_and_exclusions() -> None:
    scope = Scope.from_hosts(
        ["example.test"],
        allow_paths=["/app/"],
        deny_paths=["/app/logout", r"re:^/app/admin/"],
    )
    assert scope.check("https://example.test/app/dashboard").allowed
    assert not scope.check("https://example.test/app/logout").allowed
    assert not scope.check("https://example.test/app/admin/users").allowed
    assert not scope.check("https://example.test/public").allowed


def test_network_activity_requires_explicit_scope() -> None:
    empty = Scope()
    decision = empty.check("https://example.test/")
    assert not decision.allowed
    assert "no scope configured" in decision.reason


def test_filter_splits_allowed_and_rejected() -> None:
    scope = Scope.from_hosts(["example.test"])
    allowed, rejected = scope.filter(
        ["https://example.test/a", "https://evil.test/b", "ftp://example.test/c"]
    )
    assert allowed == ["https://example.test/a"]
    assert len(rejected) == 2


def test_empty_and_malformed_urls_are_rejected() -> None:
    scope = Scope.from_hosts(["example.test"])
    assert not scope.check("").allowed
    assert not scope.check("   ").allowed
    assert not scope.check("http://").allowed


def test_scope_serialises_without_secrets() -> None:
    scope = Scope.from_hosts(["example.test"], deny_paths=["/x"])
    data = scope.to_dict()
    assert data["hosts"][0]["host"] == "example.test"
    assert data["deny_paths"] == ["re:^/x"]


def test_path_rules_survive_a_serialisation_round_trip() -> None:
    scope = Scope.from_hosts(["example.test"], allow_paths=["/app/"], deny_paths=[r"re:^/admin/"])
    data = scope.to_dict()
    restored = Scope.from_hosts(
        ["example.test"], allow_paths=data["allow_paths"], deny_paths=data["deny_paths"]
    )
    assert restored.check("https://example.test/app/dashboard").allowed
    assert not restored.check("https://example.test/admin/users").allowed
    assert not restored.check("https://example.test/other").allowed


def test_allow_paths_regex_prefix_is_supported() -> None:
    scope = Scope.from_hosts(["example.test"], allow_paths=[r"re:^/api/v[0-9]+/"])
    assert scope.check("https://example.test/api/v2/items").allowed
    assert not scope.check("https://example.test/api/items").allowed


@pytest.mark.parametrize(
    "rule,host,port,expected",
    [
        ("example.test", "example.test", 443, True),
        ("example.test", "sub.example.test", 443, False),
        (".example.test", "sub.example.test", 443, True),
        ("example.test:8443", "example.test", 8443, True),
        ("example.test:8443", "example.test", 443, False),
    ],
)
def test_host_rule_matrix(rule: str, host: str, port: int, expected: bool) -> None:
    assert parse_host_rule(rule).matches(host, port) is expected
