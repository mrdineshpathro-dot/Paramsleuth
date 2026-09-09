"""Redaction of credentials and sensitive query values.

Redaction in ParamScout is *always on* and cannot be disabled from the CLI.
Anything that could end up in a log line, a report, a CSV cell or the SQLite
resume file is passed through this module first.

Two independent surfaces are covered:

* **Headers** - ``Authorization``, ``Cookie``, ``Proxy-Authorization`` and
  friends are replaced wholesale.
* **URL query values** - a value is redacted when its *key* looks sensitive
  (``token``, ``api_key``, ``sid`` ...) or when the value itself looks like a
  credential (JWT, long base64 blob, ``user:pass`` userinfo).

The module is intentionally conservative in the "redact" direction: a false
positive (redacting a harmless ``?sort=token``) costs a little readability,
while a false negative leaks a session.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

REDACTED = "[REDACTED]"

#: Headers whose *values* are always secrets.
SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "cookie2",
        "set-cookie",
        "set-cookie2",
        "x-api-key",
        "x-apikey",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-session-id",
    }
)

_SEPARATORS = re.compile(r"[-_\s.]+")

#: Lowercased, separator-stripped key names that are always sensitive.
_SENSITIVE_EXACT: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "pwd",
        "pw",
        "secret",
        "clientsecret",
        "appsecret",
        "token",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "idtokenhint",
        "apikey",
        "auth",
        "authorization",
        "authheader",
        "bearer",
        "jwt",
        "session",
        "sessionid",
        "sid",
        "ssid",
        "jsessionid",
        "phpsessid",
        "csrf",
        "csrftoken",
        "xsrf",
        "xsrftoken",
        "nonce",
        "otp",
        "otpcode",
        "pin",
        "cvv",
        "cvc",
        "ssn",
        "signature",
        "sig",
        "credential",
        "credentials",
        "privatekey",
        "key",
        "apikeyid",
        "assertion",
        "samlresponse",
        "code",  # OAuth authorization codes are single-use credentials.
        "accesscode",
        "refresh",
        "userpassword",
        "userpass",
        "apikeysecret",
        "authkey",
        "masterkey",
        "encryptionkey",
        "signingkey",
        "wallet",
        "seedphrase",
    }
)

#: Substrings that make a key sensitive regardless of surrounding words.
_SENSITIVE_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "apikey",
    "api_key",
    "token",
    "credential",
    "privatekey",
    "sessionid",
    "csrf",
    "xsrf",
    "signature",
    "bearer",
    "authorization",
)

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{4,}(?:\.[A-Za-z0-9_\-]{4,})?")
_LONG_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{32,}={0,2}$")
_LONG_HEX_RE = re.compile(r"^[0-9a-fA-F]{32,}$")
_USERINFO_RE = re.compile(r"^[^:/@\s]{1,64}:[^@\s]{1,128}$")


def normalize_key(key: str) -> str:
    """Lowercase a parameter name and strip separators for matching."""

    return _SEPARATORS.sub("", key.strip()).lower()


def is_sensitive_key(key: str) -> bool:
    """Return ``True`` when a query-parameter *name* implies a secret value."""

    normalized = normalize_key(key)
    if not normalized:
        return False
    if normalized in _SENSITIVE_EXACT:
        return True
    return any(needle in normalized for needle in _SENSITIVE_SUBSTRINGS)


def is_sensitive_value(value: str) -> bool:
    """Return ``True`` when a value *looks like* a credential on its own."""

    candidate = value.strip()
    if not candidate:
        return False
    if _JWT_RE.match(candidate):
        return True
    if _LONG_BASE64_RE.match(candidate) or _LONG_HEX_RE.match(candidate):
        return True
    if _USERINFO_RE.match(candidate):
        return True
    lowered = candidate.lower()
    return lowered.startswith(("bearer ", "basic ", "token ", "apikey "))


def redact_pairs(pairs: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    """Redact the values of sensitive ``(name, value)`` query pairs."""

    return [
        (name, REDACTED if (is_sensitive_key(name) or is_sensitive_value(value)) else value)
        for name, value in pairs
    ]


def redact_query_string(query: str) -> str:
    """Redact a raw query string while preserving parameter order and blanks."""

    if not query:
        return query
    out: list[str] = []
    for part in query.split("&"):
        if not part:
            continue
        name, sep, value = part.partition("=")
        if not sep:
            out.append(part)
            continue
        from urllib.parse import unquote_plus

        decoded_name = unquote_plus(name)
        decoded_value = unquote_plus(value)
        if is_sensitive_key(decoded_name) or is_sensitive_value(decoded_value):
            out.append(f"{name}={REDACTED}")
        else:
            out.append(part)
    return "&".join(out)


def redact_url(url: str) -> str:
    """Return *url* with userinfo removed and sensitive query values masked."""

    try:
        parts = urlsplit(url)
    except ValueError:
        return REDACTED
    netloc = parts.netloc
    if "@" in netloc:
        # Drop the userinfo component entirely rather than partially masking it.
        netloc = netloc.rsplit("@", 1)[1]
    return urlunsplit(
        (parts.scheme, netloc, parts.path, redact_query_string(parts.query), "")
    )


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Return a copy of *headers* with secret values replaced."""

    return {
        name: (REDACTED if name.lower() in SENSITIVE_HEADERS else value)
        for name, value in headers.items()
    }


def redact_text(text: str) -> str:
    """Best-effort scrub of credential-shaped strings inside free text.

    Used for JS/HTML extraction context snippets, where a hard-coded token in
    the page source would otherwise be copied into a report verbatim.
    """

    if not text:
        return text
    result = _JWT_RE.sub(REDACTED, text)
    result = re.sub(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/\-]{6,}={0,2}", f"\\1 {REDACTED}", result)
    result = re.sub(
        r"(?i)\b((?:api[_-]?key|secret|password|passwd|token|access[_-]?key)\s*[:=]\s*)(['\"]?)([^\s'\"]{6,})\2",
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}{match.group(2)}",
        result,
    )
    return result


def contains_secret_header(headers: Mapping[str, str]) -> bool:
    """True when any header in *headers* carries a credential value."""

    return any(name.lower() in SENSITIVE_HEADERS for name in headers)
