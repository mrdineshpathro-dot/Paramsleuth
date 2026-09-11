"""Secret redaction helpers.

Everything that can end up in logs, reports, terminal output, or saved state
is routed through :class:`Redactor` so credentials and sensitive query values
never leak. Redaction applies to URLs, free-text context, extraction snippets,
and sanitized reproduction requests -- not only to endpoint URLs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

# Sensitive query parameter names whose values are replaced when they appear in
# query strings (covers both "documented" auth cookies/params and common ones).
_SENSITIVE_PARAM_RE = re.compile(
    r"(?i)^(?:"
    r"access_token|auth|authtoken|authorization|aws_access_key_id|"
    r"aws_secret_access_key|api[_-]?key|apikey|bearer|client_secret|"
    r"connectionstring|cookie|credentials|csrf|csrftoken|jwt|key|"
    r"passwd|password|password2|pwd|secret|session|sessionid|session_key|"
    r"sid|signature|sso|state|token|token_id|userpass|x[_-]?api[_-]?key|"
    r"xsrf|x[_-]?auth[_-]?token"
    r")$"
)

# Redaction performed only for entire "secrets" registered at runtime
# (e.g. Cookie/Authorization header values), since removing those from a URL
# query string would needlessly corrupt harmless names such as ?key=.
_HEADER_VALUE_NAME_RE = re.compile(r"(?i)^(?:cookie|authorization|proxy-authorization)$")

_CREDENTIAL_CHARS_RE = re.compile(r"(?:[^/?#:@]+):(?:[^/?#:@]+)@")


@dataclass
class Redactor:
    """Stateful redactor.

    Values registered with :meth:`add_secret` are replaced by ``<redacted>``
    anywhere they appear. On top of that, URL userinfo and sensitive query
    parameter values are always scrubbed structurally.
    """

    secrets: set[str] = field(default_factory=set)

    @classmethod
    def empty(cls) -> "Redactor":
        return cls()

    def add_secret(self, value: str | None) -> None:
        """Register a secret (cookie value, header value) for redaction."""
        if value and len(value) >= 4:
            self.secrets.add(value)

    def add_secrets(self, values: Any) -> None:
        """Register many secrets from an iterable or mapping of values."""
        if values is None:
            return
        if isinstance(values, dict):
            values = values.values()
        for value in values:
            if isinstance(value, str):
                self.add_secret(value)

    def _mask_value(self, value: str) -> str:
        if value in self.secrets:
            return "<redacted>"
        return value

    def redact(self, text: str | None) -> str:
        """Redact registered secrets anywhere they occur in *text*."""
        if not text:
            return text or ""
        masked = text
        # Longest first avoids partial masking of overlapping secrets.
        for secret in sorted(self.secrets, key=len, reverse=True):
            masked = masked.replace(secret, "<redacted>")
        return masked

    def redact_url(self, url: str | None) -> str:
        """Redact a URL: registered secrets, userinfo, and sensitive query values."""
        if not url:
            return url or ""
        # Whole-secret replacement first (covers tokens embedded raw in the URL).
        url = self.redact(url)
        parts = urlsplit(url)
        netloc = parts.netloc
        if "@" in netloc:
            netloc = netloc.rsplit("@", 1)[1]
        # Scrub sensitive query parameter values structurally.
        query = self._redact_query(parts.query)
        return urlunsplit((parts.scheme, netloc, parts.path, query, ""))

    def redact_query(self, query: str | None) -> str:
        return self._redact_query(query or "")

    def _redact_query(self, query: str) -> str:
        if not query:
            return query
        kept: list[str] = []
        for chunk in query.split("&"):
            name, _, value = chunk.partition("=")
            if not value:
                kept.append(chunk)
                continue
            unquoted = _unquote_plus_safe(name)
            if _SENSITIVE_PARAM_RE.match(unquoted) and not _HEADER_VALUE_NAME_RE.match(
                unquoted
            ):
                kept.append(f"{name}=<redacted>")
            else:
                kept.append(chunk)
        return "&".join(kept)

    def scrub_credentials_from_text(self, text: str | None) -> str:
        """Remove ``user:pass@`` credential patterns from free text (e.g. errors)."""
        if not text:
            return text or ""
        return _CREDENTIAL_CHARS_RE.sub("<redacted>@", text)


def _unquote_plus_safe(name: str) -> str:
    """Minimal percent/plus decoding used only for name matching."""
    from urllib.parse import unquote_plus

    try:
        return unquote_plus(name)
    except Exception:
        return name


# Default sensitive-name matcher reused by scope-free sanitizers.
def is_sensitive_param_name(name: str) -> bool:
    """True when a decoded parameter name conventionally carries a secret."""
    return bool(_SENSITIVE_PARAM_RE.match(name or ""))
