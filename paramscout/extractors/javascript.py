"""Heuristic parameter extraction from JavaScript source.

Everything here is a heuristic and every hit keeps the source context it came
from, so a human can confirm or discard it in seconds.  Nothing in this module
executes JavaScript; it only reads it.

Patterns covered:

* ``URLSearchParams`` construction and mutation
  (``new URLSearchParams({a: 1})``, ``sp.set('b', ...)``)
* literal query strings inside ``fetch`` / ``axios`` / ``XHR`` calls
* object literals passed as ``params``/``data``/``query``
* server-side accessors that leak parameter names into bundles
  (``req.query.x``, ``$_GET['x']``, ``request.GET['x']``, ``params[:x]``)
* ``location.search`` parsing helpers
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from paramscout.extractors.base import (
    ExtractionResult,
    context_snippet,
    is_plausible_param_name,
    line_of,
    params_from_query,
)
from paramscout.models import Evidence, SourceKind

_OBJECT_KEYS_RE = re.compile(r"([A-Za-z_$][\w$.\-]*)\s*:")
_BARE_KEYS_RE = re.compile(r"[{,]\s*([A-Za-z_$][\w$]*)\s*[,}]")

#: Identifiers that conventionally hold a URLSearchParams instance.
_SEARCH_PARAMS_NAMES = ("searchParams", "urlSearchParams", "params", "query", "qs", "search", "parameters")

#: ``const sp = new URLSearchParams(...)`` - lets us recognise non-conventional
#: variable names such as ``sp`` without matching every ``map.set('x')``.
_SEARCH_PARAMS_ASSIGN_RE = re.compile(
    r"""(?:const|let|var|,)\s*([A-Za-z_$][\w$]*)\s*=\s*new\s+URLSearchParams""", re.IGNORECASE
)


def _search_params_regex(source: str) -> re.Pattern[str]:
    """Build the accessor pattern using names actually used in this source."""

    names = set(_SEARCH_PARAMS_NAMES)
    names.update(_SEARCH_PARAMS_ASSIGN_RE.findall(source))
    alternation = "|".join(re.escape(name) for name in sorted(names))
    return re.compile(
        rf"""(?:{alternation})\s*\.\s*(?:set|append|get|delete|has|getAll)\s*\(\s*['"`]"""
        r"""([\w$.\-[\]]{1,64})['"`]""",
        re.IGNORECASE,
    )

#: ``new URLSearchParams({ a: 1, b: 2 })`` and ``URLSearchParams("a=1&b=2")``
_URL_SEARCH_PARAMS_CTOR_RE = re.compile(
    r"""URLSearchParams\s*\(\s*(?P<body>\{[^}]{0,400}\}|['"][^'"]{0,400}['"])""",
)

#: ``{ params: { a: 1 } }`` / ``data: { ... }`` / ``query: { ... }``
_PARAMS_OBJECT_RE = re.compile(
    r"""\b(?:params|query|data|queryString|searchParams)\s*:\s*\{(?P<body>[^{}]{0,400})\}""",
)

#: ``fetch('/x?a=1')``, ``axios.get('/x?a=1')``, ``xhr.open('GET', '/x?a=1')``
_URL_LITERAL_RE = re.compile(
    r"""(?:fetch|get|post|put|open|url|href|src|action|to|path|endpoint)\s*[\(:=]\s*"""
    r"""['"`](?P<url>[^'"`\s]{0,300}\?[^'"`\s]{0,300})['"`]""",
    re.IGNORECASE,
)

#: A bare ``'&name='`` fragment used for string concatenation.
_AMP_FRAGMENT_RE = re.compile(r"""['"`][^'"`\s]{0,80}&([A-Za-z_$][\w$.\-]{0,63})=""")

#: Server-side accessors that end up in a shipped bundle.
_SERVER_ACCESSOR_RE = re.compile(
    r"""(?:req(?:uest)?\s*\.\s*query\s*[\.\[]\s*['"]?([\w$.\-]{1,64})['"]?]?)"""
    r"""|(?:\$_GET\s*\[\s*['"]([\w$.\-]{1,64})['"]\s*\])"""
    r"""|(?:request\.(?:GET|args|query_params)\s*[\[\(]\s*['"]([\w$.\-]{1,64})['"])"""
    r"""|(?:params\s*\[\s*:([\w$.\-]{1,64})\s*\])"""
)

#: ``location.search``-style parsing helpers: ``getQueryVar('name')``
_HELPER_CALL_RE = re.compile(
    r"""(?:get|read|fetch)?\s*(?:query|url|search|get|request)?\s*param(?:eter)?s?"""
    r"""\s*\(\s*['"`]([\w$.\-]{1,64})['"`]""",
    re.IGNORECASE,
)

#: Full literal query strings anywhere in the source (captures the whole literal).
_BARE_QUERY_RE = re.compile(r"""['"`]([^'"`\s]{0,200}\?[A-Za-z_$][\w$.\-]{0,63}=[^'"`\s]{0,300})['"`]""")


def _keys_from_object(body: str) -> list[str]:
    """Extract plausible keys from a JS object-literal fragment."""

    keys = list(_OBJECT_KEYS_RE.findall(body))
    keys.extend(_BARE_KEYS_RE.findall(body))
    return [key for key in keys if is_plausible_param_name(key, allow_stopwords=False)]


def extract_from_javascript(
    source: str,
    *,
    origin: str,
    kind: SourceKind = SourceKind.JS_INLINE,
    max_hits: int = 400,
) -> ExtractionResult:
    """Extract parameter candidates from a JavaScript document."""

    result = ExtractionResult()
    if not source:
        return result

    def add(
        name: str,
        position: int,
        detail: str,
        confidence: float | None = None,
        target: str = "",
    ) -> None:
        if len(result.params) >= max_hits:
            return
        if not is_plausible_param_name(name):
            return
        result.params.append(
            (
                name,
                Evidence(
                    kind=kind,
                    origin=origin,
                    detail=detail,
                    context=context_snippet(source, position),
                    line=line_of(source, position),
                    confidence=confidence,
                    target=target,
                ),
            )
        )

    for match in _search_params_regex(source).finditer(source):
        add(match.group(1), match.start(), f"URLSearchParams-style accessor .{match.group(1)}")

    for match in _URL_SEARCH_PARAMS_CTOR_RE.finditer(source):
        body = match.group("body")
        if body.startswith("{"):
            for key in _keys_from_object(body):
                add(key, match.start(), "URLSearchParams object literal", confidence=0.55)
        else:
            for name, _evidence in params_from_query(
                body.strip("'\""),
                kind=kind,
                origin=origin,
                detail="URLSearchParams string literal",
                context=context_snippet(source, match.start()),
            ):
                add(name, match.start(), "URLSearchParams string literal")

    for match in _PARAMS_OBJECT_RE.finditer(source):
        for key in _keys_from_object(match.group("body")):
            add(key, match.start(), "params/data/query object literal", confidence=0.5)

    for match in _URL_LITERAL_RE.finditer(source):
        url = match.group("url")
        query = url.split("?", 1)[1] if "?" in url else ""
        from paramscout.urls import relative_url

        target = relative_url(origin, url.split("?", 1)[0]) or origin
        for name, evidence in params_from_query(
            query,
            kind=kind,
            origin=origin,
            detail=f"query string in JS URL literal: {url[:120]}",
            context=context_snippet(source, match.start()),
            target=target,
        ):
            add(name, match.start(), evidence.detail, confidence=0.65, target=target)
        if url.startswith(("/", "http://", "https://")):
            result.urls.append(url)

    for match in _AMP_FRAGMENT_RE.finditer(source):
        add(match.group(1), match.start(), "'&name=' string fragment", confidence=0.45)

    for match in _SERVER_ACCESSOR_RE.finditer(source):
        accessor = next((group for group in match.groups() if group), None)
        if accessor:
            add(accessor, match.start(), "server-side query accessor", confidence=0.6)

    for match in _HELPER_CALL_RE.finditer(source):
        add(match.group(1), match.start(), "query-param helper call", confidence=0.4)

    for match in _BARE_QUERY_RE.finditer(source):
        from paramscout.urls import relative_url

        literal = match.group(1)
        query = literal.split("?", 1)[1]
        target = relative_url(origin, literal.split("?", 1)[0]) or origin
        for name, evidence in params_from_query(
            query,
            kind=kind,
            origin=origin,
            detail=f"bare query-string literal: {literal[:120]}",
            context=context_snippet(source, match.start()),
            target=target,
        ):
            add(name, match.start(), evidence.detail, confidence=0.5, target=target)

    return result


def extract_param_names(source: str) -> list[str]:
    """Convenience: just the names, de-duplicated, order preserved."""

    seen: list[str] = []
    for name, _evidence in extract_from_javascript(source, origin="<source>").params:
        if name not in seen:
            seen.append(name)
    return seen


def summarise_kinds(evidence: Iterable[Evidence]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in evidence:
        counts[item.kind.value] = counts[item.kind.value] + 1
    return counts
