"""Interesting-parameter classification.

Parameters are categorized by their *likely purpose* using conservative naming
hints. A category is never a vulnerability claim: names like ``next`` or
``token`` only tell a human reviewer where to look. Parameter names are case
sensitive in HTTP, so matching here lowercases only for the hint lookup.
"""

from __future__ import annotations

import re

CAT_REDIRECT = "redirect/navigation"
CAT_REMOTE = "remote-resource reference"
CAT_FILE = "file/path reference"
CAT_SEARCH = "search/filtering"
CAT_RESOURCE = "resource identifier"
CAT_DEBUG = "debug/configuration"
CAT_PAGINATION = "pagination"
CAT_AUTH = "authentication/session"
CAT_UNKNOWN = "unknown/general-purpose"

# Security-relevant *hint* categories (manual-review signal only).
_SECURITY_CATEGORIES = {CAT_REDIRECT, CAT_REMOTE, CAT_AUTH, CAT_FILE}

# Order matters: first matching category wins for overlapping names.
_CATEGORY_RULES: list[tuple[str, set[str]]] = [
    (
        CAT_AUTH,
        {
            "token", "session", "sessionid", "session_id", "sid", "csrf",
            "csrftoken", "xsrf", "jwt", "oauth", "auth", "authorization",
            "login", "password", "passwd", "pwd", "apikey", "api_key",
            "access_token", "refresh_token", "secret", "nonce", "code",
            "state", "assertion", "id_token",
        },
    ),
    (
        CAT_REDIRECT,
        {
            "next", "redirect", "redirecturl", "redirect_uri", "return",
            "returnurl", "return_uri", "return_to", "continue", "dest",
            "destination", "target", "rurl", "go", "back", "forward",
        },
    ),
    (
        CAT_REMOTE,
        {"url", "uri", "host", "endpoint", "callback", "cb", "webhook", "link"},
    ),
    (
        CAT_FILE,
        {
            "file", "filename", "path", "template", "dir", "directory",
            "folder", "download", "upload", "view", "page_template",
        },
    ),
    (
        CAT_RESOURCE,
        {
            "id", "uid", "gid", "guid", "account", "order", "document",
            "user", "username", "email", "item", "product", "post",
            "article", "msg", "message",
        },
    ),
    (
        CAT_PAGINATION,
        {
            "page", "offset", "limit", "cursor", "per_page", "perpage",
            "page_size", "pagesize", "start", "max_results",
        },
    ),
    (
        CAT_DEBUG,
        {"debug", "trace", "mode", "env", "environment", "config", "verbose", "test", "dryrun", "dry_run"},
    ),
    (
        CAT_SEARCH,
        {"q", "search", "query", "filter", "sort", "keyword", "keywords", "term", "text", "qry"},
    ),
]

_TOKEN_SPLIT_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|_+|\.+|[\-\s]+")


def _tokens(name: str) -> set[str]:
    lowered = name.lower()
    tokens: set[str] = set()
    for chunk in _TOKEN_SPLIT_RE.split(lowered):
        if chunk:
            tokens.add(chunk)
    tokens.add(lowered)  # allow exact-name matching (e.g. single-letter "q")
    return tokens


def classify_parameter(name: str) -> tuple[str, bool]:
    """Return ``(category_label, security_relevant_hint)`` for a parameter name."""
    tokens = _tokens(name)
    for category, keywords in _CATEGORY_RULES:
        if tokens & keywords:
            return category, category in _SECURITY_CATEGORIES
    return CAT_UNKNOWN, False


def is_resource_id_name(name: str) -> bool:
    """True when a name looks like an identifier reference (``id``-ish)."""
    lowered = name.lower()
    tokens = _tokens(lowered)
    return bool(tokens & {"id", "uid", "guid"}) or lowered.endswith("_id")
