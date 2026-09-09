"""Wordlist handling.

The built-in list is deliberately conservative: it contains parameter names
that appear constantly across real web applications, not an exploit dictionary.
A wordlist hit is the *weakest* form of evidence ParamScout records - it is
labelled a guess everywhere it appears, and it only becomes interesting if the
target measurably reacts to it.
"""

from __future__ import annotations

from pathlib import Path

#: Conservative built-in list of common parameter names.
BUILTIN_PARAMETERS: tuple[str, ...] = (
    # redirect / navigation
    "next",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return",
    "returnUrl",
    "returnTo",
    "continue",
    "goto",
    "destination",
    "target",
    "forward",
    # resource identifiers
    "id",
    "uid",
    "user_id",
    "userId",
    "account",
    "account_id",
    "order",
    "order_id",
    "item",
    "item_id",
    "product_id",
    "document",
    "doc_id",
    "ref",
    "uuid",
    "slug",
    # file / path
    "file",
    "filename",
    "path",
    "filepath",
    "template",
    "view",
    "dir",
    "include",
    "attachment",
    "download",
    "image",
    "layout",
    "theme",
    # search / filtering
    "q",
    "s",
    "search",
    "query",
    "keyword",
    "term",
    "filter",
    "sort",
    "sort_by",
    "order_by",
    "category",
    "tag",
    "group",
    # remote resources
    "url",
    "uri",
    "link",
    "host",
    "endpoint",
    "callback",
    "webhook",
    "proxy",
    "feed",
    "image_url",
    "domain",
    "service",
    # debug / configuration
    "debug",
    "trace",
    "mode",
    "env",
    "environment",
    "verbose",
    "test",
    "preview",
    "draft",
    "profile",
    "log",
    "config",
    "settings",
    "feature",
    "flag",
    "beta",
    # pagination
    "page",
    "offset",
    "limit",
    "per_page",
    "size",
    "cursor",
    "start",
    "rows",
    "count",
    "from",
    "to",
    # auth / session
    "token",
    "session",
    "session_id",
    "code",
    "state",
    "auth",
    "access_token",
    "refresh_token",
    "jwt",
    "ticket",
    "otp",
    "signature",
    "api_key",
    "csrf",
    "nonce",
)


def builtin_wordlist() -> list[str]:
    """The built-in candidate names, as a list."""

    return list(BUILTIN_PARAMETERS)


def load_wordlist(path: str | Path) -> list[str]:
    """Load a wordlist file: one parameter name per line, ``#`` comments allowed."""

    names: list[str] = []
    seen: set[str] = set()
    for raw_line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line in seen:
            continue
        seen.add(line)
        names.append(line)
    return names


def merge_wordlists(*lists: list[str]) -> list[str]:
    """Merge wordlists, preserving first-seen order and de-duplicating."""

    merged: list[str] = []
    seen: set[str] = set()
    for names in lists:
        for name in names:
            if name and name not in seen:
                seen.add(name)
                merged.append(name)
    return merged
