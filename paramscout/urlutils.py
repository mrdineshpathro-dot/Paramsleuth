"""Careful URL and query-string helpers.

Encoding policy
---------------
ParamScout never lowercases paths or parameter names, never discards repeated
parameters, and never drops blank values. Query parsing decodes names/values
once (``+`` and ``%XX``) and serialization re-encodes them with
:func:`urllib.parse.quote`, which preserves the server-visible semantics of
characters such as ``/``, ``?``, ``&`` and ``=``. The byte-for-byte wire form
may change (``+`` may become ``%20``); this is documented as a limitation.

Endpoint identity / grouping
----------------------------
Two URLs that differ only in encoding of the *same* semantic characters are
still treated as distinct endpoint keys unless they produce identical parsed
paths after a single decode. This is deliberately conservative: we never
assume differently encoded paths are equivalent.
"""

from __future__ import annotations

import re
from urllib.parse import (
    quote,
    unquote,
    unquote_plus,
    urljoin,
    urlsplit,
    urlunsplit,
)

# A parameter that already exists on an endpoint URL when we baseline it can
# legitimately "name" the page. Probe parameters are appended after it.
ParamList = list[tuple[str, str]]

_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
_IPV6_HOST_RE = re.compile(r"^\[[0-9a-fA-F:.]+\]$")


def normalize_url(url: str) -> str:
    """Normalize a URL for *safe* comparisons.

    - scheme and hostname are lowercased (hostnames are case-insensitive).
    - an explicit default port is removed.
    - fragments are dropped (they never reach the server).
    - the path and query are preserved byte-for-byte (case, encoding, order).
    - IDN hosts are converted to punycode when possible.

    Returns an empty string when *url* is not an absolute http(s) URL.
    """
    if not url:
        return ""
    url = url.strip()
    if not _SCHEME_RE.match(url):
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return ""
    host = parts.hostname or ""
    try:
        host = host.encode("idna").decode("ascii") if host else ""
    except UnicodeError:
        pass
    port = parts.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    netloc = host
    if port is not None:
        netloc = f"{host}:{port}"
    if "@" in parts.netloc:  # credentials are never part of the identity
        userinfo = parts.netloc.rsplit("@", 1)[0]
        netloc = f"{userinfo}@{netloc}" if userinfo else netloc
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def host_of(url: str) -> str:
    """Return the lowercase hostname (without port) of an absolute URL."""
    try:
        host = urlsplit(url.strip()).hostname
    except ValueError:
        return ""
    return (host or "").lower()


def scheme_of(url: str) -> str:
    """Return the lowercase scheme of an absolute URL."""
    try:
        return urlsplit(url.strip()).scheme.lower()
    except ValueError:
        return ""


def netloc_of(url: str) -> str:
    """Return ``host[:port]`` with the default port dropped, lowercased."""
    parts = urlsplit(normalize_url(url) or url)
    host = (parts.hostname or "").lower()
    if not host:
        return ""
    port = parts.port
    if (parts.scheme == "http" and port == 80) or (parts.scheme == "https" and port == 443):
        return host
    return f"{host}:{port}" if port is not None else host


def path_of(url: str) -> str:
    """Return the raw path of an absolute URL (never lowercased)."""
    parts = urlsplit(url.strip())
    return parts.path or "/"


def endpoint_key(url: str, grouping: str = "path") -> str:
    """Return a stable key used to group URLs into endpoints.

    grouping="path" -> ``scheme://host[:port]/path`` (query ignored).
    grouping="host" -> ``scheme://host[:port]`` (whole host is one endpoint).

    The path is kept exactly as it appears (case and percent-encoding
    preserved) so differently encoded paths are *not* merged. See the module
    docstring for the tradeoff.
    """
    norm = normalize_url(url)
    if not norm:
        return ""
    parts = urlsplit(norm)
    base = f"{parts.scheme}://{parts.netloc}"
    if grouping == "host":
        return base
    return f"{base}{parts.path or '/'}"


def split_query(query: str) -> ParamList:
    """Parse a query string preserving order, repeats, and blank values.

    ``?a=1&a=2&b=&c`` -> ``[("a","1"), ("a","2"), ("b",""), ("c","")]``.
    Names and values are percent-decoded exactly once.
    """
    if not query:
        return []
    result: ParamList = []
    for segment in query.split("&"):
        if not segment:
            continue
        name, sep, value = segment.partition("=")
        try:
            decoded_name = unquote_plus(name)
        except Exception:
            decoded_name = name
        if sep:
            try:
                decoded_value = unquote_plus(value)
            except Exception:
                decoded_value = value
        else:
            decoded_value = ""
        result.append((decoded_name, decoded_value))
    return result


def serialize_query(params: ParamList) -> str:
    """Serialize parsed params back into a query string (order preserved)."""
    encoded: list[str] = []
    for name, value in params:
        encoded.append(f"{quote(name, safe='')}={quote(value, safe='')}")
    return "&".join(encoded)


def append_params(url: str, params: ParamList) -> str:
    """Append *params* to *url*, preserving the existing query verbatim."""
    url = url.strip()
    parts = urlsplit(url)
    existing = parts.query
    additions = serialize_query(params)
    if not existing:
        new_query = additions
    else:
        new_query = existing + ("&" if existing and additions else "") + additions
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, ""))


def set_query_params(url: str, params: ParamList) -> str:
    """Return *url* with its query replaced by *params* (existing params removed)."""
    parts = urlsplit(url.strip())
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, serialize_query(params), "")
    )


def remove_param_from_query(query: str, names_to_remove: set[str]) -> str:
    """Remove params whose decoded name is in *names_to_remove* (case-sensitive)."""
    kept: list[str] = []
    for segment in query.split("&"):
        if not segment:
            continue
        name, _, _ = segment.partition("=")
        decoded = _try_unquote_plus(name)
        if decoded in names_to_remove:
            continue
        kept.append(segment)
    return "&".join(kept)


def _try_unquote_plus(value: str) -> str:
    try:
        return unquote_plus(value)
    except Exception:
        return value


def resolve_link(base_url: str, raw_href: str) -> str:
    """Resolve a possibly-relative link against *base_url* (URL-join semantics)."""
    if not raw_href:
        return ""
    href = raw_href.strip()
    if href.lower().startswith(("javascript:", "data:", "mailto:", "tel:", "vbscript:")):
        return ""
    try:
        joined = urljoin(base_url, href)
    except ValueError:
        return ""
    # Strip fragments; do not touch anything else.
    parts = urlsplit(joined)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def is_absolute_http_url(url: str) -> bool:
    return bool(normalize_url(url))


def unquote_once(value: str) -> str:
    """Decode percent escapes once; used before reflecting content comparisons."""
    try:
        return unquote(value)
    except Exception:
        return value
