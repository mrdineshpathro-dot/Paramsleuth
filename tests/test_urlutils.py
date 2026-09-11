"""URL/query parsing: blank values, repeats, encoding preservation."""

from paramscout.urlutils import (
    append_params,
    endpoint_key,
    host_of,
    normalize_url,
    resolve_link,
    serialize_query,
    split_query,
)


def test_split_query_preserves_repeats_and_blanks():
    assert split_query("a=1&a=2&b=&c&a=3") == [
        ("a", "1"),
        ("a", "2"),
        ("b", ""),
        ("c", ""),
        ("a", "3"),
    ]


def test_split_query_decodes_plus_and_percent():
    assert split_query("q=hello+world&path=%2Fetc%2Fpasswd&sp=%20") == [
        ("q", "hello world"),
        ("path", "/etc/passwd"),
        ("sp", " "),
    ]


def test_serialize_round_trip_preserves_semantics():
    params = split_query("a=1&a=2&b=&path=%2Ftmp%2Fx&plus=a+b&enc=%26%3D")
    rebuilt = serialize_query(params)
    assert split_query(rebuilt) == params


def test_empty_query_and_segments():
    assert split_query("") == []
    assert split_query("a&&b=1") == [("a", ""), ("b", "1")]


def test_append_params_keeps_existing_query():
    url = append_params("http://h/p?x=1&x=2", [("y", "z z")])
    parsed = split_query(url.split("?", 1)[1])
    assert parsed[:2] == [("x", "1"), ("x", "2")]
    assert parsed[2] == ("y", "z z")


def test_normalize_url_keeps_path_case_and_encoding():
    a = "HTTPS://EXAMPLE.com/A%2FB?q=1"
    b = normalize_url("https://example.com/a%2fb?q=1")
    # scheme/host lowercased; path case & encoding preserved (not equivalent)
    assert normalize_url(a).startswith("https://example.com/A%2FB?q=1")
    assert normalize_url(a) != b


def test_normalize_url_strips_default_port_and_fragment():
    assert normalize_url("http://h:80/x#frag") == "http://h/x"
    assert normalize_url("https://h:443/x?q=1#f") == "https://h/x?q=1"


def test_host_of_and_endpoint_key():
    assert host_of("http://Sub.Example.com:8080/x") == "sub.example.com"
    assert endpoint_key("http://h/a?q=1", grouping="path") == "http://h/a"
    assert endpoint_key("http://h/a", grouping="host") == "http://h"
    assert endpoint_key("http://h/b", grouping="path") != endpoint_key("http://h/a", grouping="path")


def test_reject_non_http_schemes():
    assert normalize_url("ftp://h/x") == ""
    assert normalize_url("javascript:alert(1)") == ""
    assert normalize_url("/relative") == ""


def test_resolve_link_skips_non_http():
    assert resolve_link("http://h/a", "javascript:void(0)") == ""
    assert resolve_link("http://h/a", "mailto:x@y.z") == ""
    assert resolve_link("http://h/a/b", "../c?d=1") == "http://h/c?d=1"
    assert resolve_link("http://h/a", "//other.test/x") == "http://other.test/x"
