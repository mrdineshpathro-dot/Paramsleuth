"""Scope matching: exact hosts, no substring matches, path rules, redirects."""

import pytest

from paramscout.scope import Scope


def test_exact_host_matching_not_substring():
    scope = Scope.from_hosts(["app.example.test"])
    assert scope.check("https://app.example.test/x").allowed
    assert scope.check("http://app.example.test/x").allowed
    # substring-style matches must never be allowed
    assert not scope.check("https://notapp.example.test/x").allowed
    assert not scope.check("https://app.example.test.evil.net/x").allowed
    assert not scope.check("https://evilexample.test/x").allowed


def test_wildcard_subdomains():
    scope = Scope.from_hosts(["*.example.test"])
    assert scope.check("https://a.example.test/").allowed
    assert scope.check("https://deep.a.example.test/").allowed
    assert not scope.check("https://example.test/").allowed  # apex not included
    assert not scope.check("https://other.test/").allowed


def test_empty_scope_denies_everything():
    scope = Scope()
    assert scope.is_empty
    assert not scope.check("https://anywhere.test/").allowed


def test_path_prefix_and_port_rules():
    scope = Scope.from_hosts(["app.example.test/api", "app.example.test:8443"])
    assert scope.check("https://app.example.test/api/users").allowed
    assert not scope.check("https://app.example.test/other").allowed
    assert scope.check("https://app.example.test:8443/x").allowed
    assert not scope.check("https://app.example.test/x").allowed  # no port rule matches
    assert not scope.check("http://app.example.test:80/x").allowed


def test_include_and_exclude_path_rules():
    scope = Scope.from_hosts(["app.example.test"])
    scope.path_include_prefixes.append("/public")
    scope.path_exclude_prefixes.append("/admin")
    assert scope.check("https://app.example.test/public/x").allowed
    assert not scope.check("https://app.example.test/other").allowed
    scope2 = Scope.from_hosts(["app.example.test"])
    scope2.path_exclude_prefixes.append("/admin")
    assert scope2.check("https://app.example.test/admin/config").allowed is False


def test_deny_host_wins():
    scope = Scope.from_hosts(["example.test", "-host internal.example.test"])
    assert scope.check("https://internal.example.test/x").allowed is False
    assert scope.check("https://example.test/x").allowed


def test_scope_file_parsing():
    path = "/tmp/scope_test_ps.txt"
    with open(path, "w") as handle:
        handle.write(
            "# comment\n"
            "app.example.test\n"
            "*.sub.example.test\n"
            "-path /admin\n"
            "+path /app\n"
            "-host old.example.test\n"
            "ignored invalid line !!!\n"
        )
    with pytest.raises(ValueError):
        Scope.from_file(path)
    with open(path, "w") as handle:
        handle.write("app.example.test\n-p /admin\n")
    with pytest.raises(ValueError):
        Scope.from_file(path)


def test_redirect_destination_validated():
    scope = Scope.from_hosts(["app.example.test"])
    assert scope.check_redirect("https://app.example.test/ok").allowed
    assert not scope.check_redirect("https://evil.example.net/x").allowed


def test_non_http_denied():
    scope = Scope.from_hosts(["app.example.test"])
    assert not scope.check("ftp://app.example.test/x").allowed
    assert not scope.check("gopher://app.example.test/x").allowed
