"""Credential and secret redaction tests."""

from __future__ import annotations

from paramscout.config import ScanConfig
from paramscout.engine import sanitize_request
from paramscout.redaction import (
    REDACTED,
    contains_secret_header,
    is_sensitive_key,
    is_sensitive_value,
    redact_headers,
    redact_query_string,
    redact_text,
    redact_url,
)


def test_sensitive_key_detection() -> None:
    for key in (
        "password",
        "passwd",
        "pwd",
        "token",
        "access_token",
        "accessToken",
        "api_key",
        "apiKey",
        "secret",
        "client_secret",
        "session",
        "sessionid",
        "sid",
        "csrf",
        "xsrf_token",
        "Authorization",
        "signature",
        "otp",
        "code",
        "refresh-token",
        "private_key",
    ):
        assert is_sensitive_key(key), key
    for key in ("q", "page", "sort", "id", "redirect", "category", "username"):
        assert not is_sensitive_key(key), key


def test_sensitive_value_detection() -> None:
    assert is_sensitive_value("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc")
    assert is_sensitive_value("Bearer abcdef123456")
    assert is_sensitive_value("user:hunter2")
    assert is_sensitive_value("0" * 40)
    assert not is_sensitive_value("widgets")
    assert not is_sensitive_value("3")
    assert not is_sensitive_value("")


def test_query_string_redaction_preserves_structure() -> None:
    redacted = redact_query_string("q=widgets&token=abcdef&empty=&page=2")
    assert redacted == f"q=widgets&token={REDACTED}&empty=&page=2"
    # parameter order, blanks and repeats survive
    assert redact_query_string("a=1&a=2&b=") == "a=1&a=2&b="


def test_url_redaction_strips_userinfo_and_secrets() -> None:
    url = "https://user:secret@app.example.test/path?token=abc&q=widgets#frag"
    result = redact_url(url)
    assert "user" not in result and "secret" not in result
    assert "abc" not in result
    assert "q=widgets" in result
    assert result.startswith("https://app.example.test/path")


def test_header_redaction() -> None:
    headers = {
        "Authorization": "Bearer supersecret",
        "Cookie": "session=abc; other=1",
        "X-CSRF-Token": "zzz",
        "Accept": "text/html",
        "User-Agent": "ParamScout",
    }
    result = redact_headers(headers)
    assert result["Authorization"] == REDACTED
    assert result["Cookie"] == REDACTED
    assert result["X-CSRF-Token"] == REDACTED
    assert result["Accept"] == "text/html"
    assert contains_secret_header(headers)
    assert not contains_secret_header({"Accept": "*/*"})


def test_free_text_redaction() -> None:
    text = 'const apiKey = "abcdef1234567890"; Authorization: Bearer zzz.yyy'
    scrubbed = redact_text(text)
    assert "abcdef1234567890" not in scrubbed
    assert "zzz.yyy" not in scrubbed


def test_reproduction_requests_never_contain_credentials() -> None:
    config = ScanConfig()
    config.request.headers = {"Authorization": "Bearer secret-value", "X-Tenant": "acme"}
    config.request.cookies = {"session": "cookie-secret"}
    text = sanitize_request(
        "https://app.example.test/search?q=widgets&token=abc", config, canary=None
    )
    assert "secret-value" not in text
    assert "cookie-secret" not in text
    assert REDACTED in text
    assert "X-Tenant: acme" in text
    assert text.startswith("GET /search?q=widgets&token=abc HTTP/1.1")


def test_reproduction_requests_placeholder_the_canary() -> None:
    config = ScanConfig()
    text = sanitize_request("https://app.example.test/p?note=psc0123456789", config, canary="psc0123456789")
    assert "psc0123456789" not in text
    assert "[[CANARY]]" in text


def test_state_file_config_strips_secrets() -> None:
    config = ScanConfig()
    config.request.cookies = {"session": "abc"}
    config.request.headers = {"Authorization": "Bearer xyz", "X-Tenant": "acme"}
    data = config.to_dict(include_secrets=False)
    assert data["request"]["cookies"] == {"session": "[REDACTED]"}
    assert data["request"]["headers"]["Authorization"] == "[REDACTED]"
    assert data["request"]["headers"]["X-Tenant"] == "acme"
