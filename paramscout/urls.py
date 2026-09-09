"""URL parsing, endpoint keys and de-duplication keys.

Design rules enforced here (see README "Normalization" for the reasoning):

* Paths and parameter names are **never** lower-cased.
* Repeated parameters are preserved, in order.
* Percent-encoding is preserved verbatim - ``/a%2Fb`` and ``/a/b`` are treated
  as different paths because servers routinely disagree about them.
* Fragments are dropped for de-duplication (they are client side only).
* Parameter order is preserved, therefore ``?a=1&b=2`` and ``?b=2&a=1`` are
  *not* deduplicated.  That is a deliberate, documented limitation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import unquote_plus, urlsplit, urlunsplit

DEFAULT_PORTS = {"http": 80, "https": 443}


class EndpointGrouping(StrEnum):
    """How aggressively distinct URLs are folded into one endpoint."""

    STRICT = "strict"
    IGNORE_TRAILING_SLASH = "ignore-trailing-slash"
    CASE_FOLDED_PATH = "case-folded-path"
    ORIGIN_ONLY = "origin-only"


@dataclass(frozen=True)
class QueryPair:
    """One ``name=value`` occurrence inside a query string.

    Both the raw (still percent-encoded) and decoded forms are kept: the raw
    form is what has to be replayed byte-for-byte, the decoded form is what
    humans and heuristics read.
    """

    raw: str
    name: str
    value: str
    raw_name: str
    raw_value: str

    @classmethod
    def from_raw(cls, raw: str) -> QueryPair:
        raw_name, sep, raw_value = raw.partition("=")
        return cls(
            raw=raw,
            name=unquote_plus(raw_name),
            value=unquote_plus(raw_value) if sep else "",
            raw_name=raw_name,
            raw_value=raw_value if sep else "",
        )

    @property
    def has_value(self) -> bool:
        return "=" in self.raw


def parse_query(query: str) -> list[QueryPair]:
    """Split a query string into ordered pairs.

    Blank values (``?a=``), value-less keys (``?a``) and repeats (``?a=1&a=2``)
    all survive.  A leading ``?`` is tolerated.
    """

    if not query:
        return []
    query = query.removeprefix("?")
    if not query:
        return []
    return [QueryPair.from_raw(part) for part in query.split("&") if part != ""]


def query_names(query: str) -> list[str]:
    """Decoded parameter names in appearance order, repeats preserved."""

    return [pair.name for pair in parse_query(query)]


@dataclass(frozen=True)
class UrlParts:
    """Structural breakdown of a URL, preserving the original spelling."""

    url: str
    scheme: str
    host: str
    port: int | None
    netloc: str
    path: str
    query: str
    pairs: tuple[QueryPair, ...]
    fragment: str

    @property
    def origin(self) -> str:
        port = "" if self.port is None else f":{self.port}"
        return f"{self.scheme}://{self.host}{port}"

    @property
    def authority(self) -> str:
        """Host (plus port when it is not the scheme default)."""

        if self.port is None or DEFAULT_PORTS.get(self.scheme) == self.port:
            return self.host
        return f"{self.host}:{self.port}"


def split_url(url: str) -> UrlParts:
    """Parse *url* defensively; malformed input yields empty components."""

    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return UrlParts(url, "", "", None, "", "", "", (), "")
    host = (parts.hostname or "").rstrip(".").lower()
    port = parts.port
    return UrlParts(
        url=url,
        scheme=parts.scheme.lower(),
        host=host,
        port=port,
        netloc=parts.netloc,
        path=parts.path or "/",
        query=parts.query,
        pairs=tuple(parse_query(parts.query)),
        fragment=parts.fragment,
    )


def normalize_url(url: str) -> str:
    """Canonical form used for crawl de-duplication.

    Only the fragment is removed.  Everything else - including percent
    encoding, parameter order and repeated parameters - is preserved.
    """

    parts = split_url(url)
    if not parts.scheme or not parts.host:
        return url.strip()
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def endpoint_key(url: str, grouping: EndpointGrouping = EndpointGrouping.STRICT) -> str:
    """Return the endpoint identity (origin + path, query removed)."""

    parts = split_url(url)
    if not parts.scheme or not parts.host:
        return url.strip()
    path = parts.path or "/"
    if grouping is EndpointGrouping.ORIGIN_ONLY:
        return parts.origin + "/"
    if grouping is EndpointGrouping.CASE_FOLDED_PATH:
        path = path.lower()
    if grouping in (EndpointGrouping.IGNORE_TRAILING_SLASH, EndpointGrouping.CASE_FOLDED_PATH):
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/") or "/"
    return f"{parts.origin}{path}"


def build_url(base: str, pairs: list[tuple[str, str]]) -> str:
    """Replace the query string of *base* with ``pairs``.

    Names and values are percent-encoded with ``quote(..., safe="")`` so the
    result is unambiguous; callers that need byte-exact replay of an observed
    query should build the string themselves from :class:`QueryPair.raw`.
    """

    from urllib.parse import quote

    parts = split_url(base)
    encoded = "&".join(
        f"{quote(name, safe='')}={quote(value, safe='') if value is not None else ''}"
        for name, value in pairs
    )
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", encoded, ""))


def build_url_raw(base: str, raw_pairs: list[str]) -> str:
    """Replace the query string of *base* with pre-encoded ``raw_pairs``."""

    parts = split_url(base)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "&".join(raw_pairs), ""))


def relative_url(base: str, target: str) -> str | None:
    """Resolve *target* against *base*; returns ``None`` for unusable targets."""

    from urllib.parse import urljoin

    target = target.strip()
    if not target:
        return None
    if target.startswith(("javascript:", "data:", "mailto:", "blob:", "tel:", "about:")):
        return None
    try:
        return urljoin(base, target)
    except ValueError:
        return None


def strip_fragment(url: str) -> str:
    parts = split_url(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def looks_like_html(content_type: str | None) -> bool:
    if not content_type:
        return False
    ctype = content_type.split(";", 1)[0].strip().lower()
    return ctype in {"text/html", "application/xhtml+xml"}


def looks_like_javascript(content_type: str | None) -> bool:
    if not content_type:
        return False
    ctype = content_type.split(";", 1)[0].strip().lower()
    return ctype in {
        "application/javascript",
        "text/javascript",
        "application/x-javascript",
        "application/ecmascript",
        "text/ecmascript",
    }


def looks_like_json(content_type: str | None) -> bool:
    if not content_type:
        return False
    ctype = content_type.split(";", 1)[0].strip().lower()
    return ctype == "application/json" or ctype.endswith("+json")
