"""URL parsing, normalization and endpoint-key tests."""

from __future__ import annotations

from paramscout.urls import (
    EndpointGrouping,
    build_url,
    endpoint_key,
    normalize_url,
    parse_query,
    query_names,
    relative_url,
    split_url,
)


def test_parse_query_preserves_order_repeats_and_blanks() -> None:
    pairs = parse_query("b=2&a=1&a=2&c=&d")
    assert [(item.name, item.value) for item in pairs] == [
        ("b", "2"),
        ("a", "1"),
        ("a", "2"),
        ("c", ""),
        ("d", ""),
    ]
    # repeated parameters survive, in order
    assert query_names("a=1&b=2&a=3") == ["a", "b", "a"]
    # blank values are distinguishable from absent values
    assert pairs[3].has_value is True
    assert pairs[4].has_value is False


def test_parse_query_keeps_raw_encoding() -> None:
    pair = parse_query("path=%2Fa%2Fb&sp=a+b")[0]
    assert pair.raw == "path=%2Fa%2Fb"
    assert pair.raw_value == "%2Fa%2Fb"
    assert pair.value == "/a/b"
    space = parse_query("sp=a+b")[0]
    assert space.raw_value == "a+b"
    assert space.value == "a b"


def test_names_and_paths_are_never_lowercased() -> None:
    parts = split_url("https://Example.test/Mixed/Case?CamelCase=Value")
    assert parts.path == "/Mixed/Case"
    assert parts.pairs[0].name == "CamelCase"
    assert parts.pairs[0].value == "Value"
    # the host is the only component that is case-insensitive
    assert parts.host == "example.test"


def test_normalize_url_drops_only_the_fragment() -> None:
    assert normalize_url("https://h.test/a%2Fb?x=1&x=2#frag") == "https://h.test/a%2Fb?x=1&x=2"
    # parameter order is preserved, so reordering is *not* deduplicated
    assert normalize_url("https://h.test/p?a=1&b=2") != normalize_url("https://h.test/p?b=2&a=1")
    # differently encoded paths are not assumed equivalent
    assert normalize_url("https://h.test/a%2Fb") != normalize_url("https://h.test/a/b")


def test_endpoint_key_grouping_modes() -> None:
    url = "https://h.test/Path/To/?a=1"
    assert endpoint_key(url) == "https://h.test/Path/To/"
    assert (
        endpoint_key(url, EndpointGrouping.IGNORE_TRAILING_SLASH) == "https://h.test/Path/To"
    )
    assert endpoint_key(url, EndpointGrouping.CASE_FOLDED_PATH) == "https://h.test/path/to"
    assert endpoint_key(url, EndpointGrouping.ORIGIN_ONLY) == "https://h.test/"
    # the query is never part of the endpoint identity
    assert endpoint_key("https://h.test/p?a=1") == endpoint_key("https://h.test/p?b=2")


def test_endpoint_key_keeps_non_default_ports() -> None:
    assert endpoint_key("https://h.test:8443/p") == "https://h.test:8443/p"
    assert endpoint_key("https://h.test/p") == "https://h.test/p"


def test_build_url_replaces_the_query() -> None:
    built = build_url("https://h.test/p?keep=1", [("keep", "1"), ("new", "a b")])
    assert built == "https://h.test/p?keep=1&new=a%20b"


def test_relative_url_rejects_non_http_schemes() -> None:
    base = "https://h.test/a/b"
    assert relative_url(base, "c?x=1") == "https://h.test/a/c?x=1"
    assert relative_url(base, "/d?x=1") == "https://h.test/d?x=1"
    assert relative_url(base, "javascript:alert(1)") is None
    assert relative_url(base, "data:text/html,x") is None
    assert relative_url(base, "mailto:a@b.c") is None
    assert relative_url(base, "") is None
