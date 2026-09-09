"""Heuristic JavaScript parameter extraction.

JavaScript extraction is inherently heuristic. Every finding produced here is
flagged as such and retains its source context; names found this way are never
treated as proof that an endpoint accepts the parameter.

Patterns recognized (in order of decreasing confidence):

1. ``URLSearchParams`` / ``url.searchParams`` calls: ``.get("name")``,
   ``.getAll``, ``.has``, ``.append``, ``.set`` - the *string* argument is the
   parameter name. High confidence.
2. Fetch / Axios / XHR query construction: ``fetch("/x?name=" + value)``.
   High confidence for the first ``name=`` fragment.
3. Axios-style options objects: ``{ params: { name: value } }``. Medium-high.
4. String literals near ``param``/``query``/``search`` keywords. Low
   confidence; filtered to identifier-looking tokens.

Reserved words and obvious non-parameters (``http``, ``url``, ``query``, ...)
are filtered out. The returned evidence weight encodes confidence.
"""

from __future__ import annotations

import logging
import re

from ..models import DiscoverySourceKind, SourceRef
from ..redaction import Redactor
from .base import SourceEvidence, param_context_snippet

log = logging.getLogger("paramscout.extract.js")

_IDENT = r"[A-Za-z_$][A-Za-z0-9_$\-\.\[\]]{0,79}"
_QUOTE = r"[\"'`]"

_RESERVED = {
    "and", "async", "await", "break", "case", "catch", "class", "const",
    "continue", "debugger", "default", "delete", "do", "document", "else",
    "export", "extends", "false", "finally", "for", "from", "function",
    "get", "global", "history", "if", "import", "in", "instanceof", "let",
    "location", "module", "name", "navigator", "new", "null", "of", "or",
    "params", "query", "querystring", "return", "search", "self", "static",
    "super", "switch", "this", "throw", "true", "try", "typeof", "undefined",
    "url", "uri", "var", "void", "while", "window", "with", "yield", "http",
    "https", "target", "window", "top", "parent", "length", "value", "type",
    "method", "headers", "body", "data", "json", "string", "number", "array",
    "element", "object", "status", "index", "src", "href", "action", "key",
    "keys", "values", "map", "set", "prototype", "constructor", "append",
    "push", "pop", "shift", "unshift", "forEach", "filter", "reduce", "then",
    "catch", "finally", "done", "fail", "success", "error", "read", "write",
    "open", "close", "load", "ready", "click", "submit", "change", "input",
    "output", "result", "response", "request", "offset", "scroll", "inner",
    "outer", "client", "server", "local", "global", "current", "previous",
    "next", "last", "first", "list", "item", "items", "total", "count", "num",
    "min", "max", "raw", "text", "html", "css", "class", "style", "color",
    "width", "height", "size", "top", "bottom", "left", "right", "middle",
    "center", "start", "end", "begin", "stop", "pause", "play", "speed",
    "level", "state", "status", "config", "conf", "settings", "opt",
    "options", "option", "flag", "flags", "title", "heading", "header",
    "footer", "body", "main", "content", "contents", "meta", "desc",
    "description", "label", "labels", "icon", "image", "images", "photo",
    "photos", "video", "audio", "file", "files", "folder", "dir", "link",
    "links", "path", "paths", "dirs", "name", "names", "id", "ids", "uid",
    "guid", "uuid", "seq", "order", "orders", "product", "products", "user",
    "users", "account", "accounts", "email", "phone", "address", "url",
    "host", "hostname", "port", "domain", "origin", "protocol", "scheme",
    "args", "arg", "argument", "arguments", "attribute", "attributes",
}

# SearchParams references (e.g. URLSearchParams, location.search params usage).
_PREFIX_RE = re.compile(
    r"(?:URLSearchParams|searchParams|\bparams\b|\bquery\b|\bquerystring\b|\bqs\b)",
    re.IGNORECASE,
)
# Literal parameter name passed to a query-parameter accessor call.
_CALL_RE = re.compile(
    rf"\.(get|getAll|has|append|set|delete)\s*\(\s*"
    rf"{_QUOTE}([A-Za-z0-9_\-\.]{{1,80}}){_QUOTE}",
    re.DOTALL,
)

# URL building for fetch/axios/XHR: "path?name=" + ...  or  `?name=${...}`
_FETCH_RE = re.compile(
    rf"(?:fetch|axios(?:\.\w+)*|XMLHttpRequest|\.open\s*\(|new\s+Request|"
    rf"\.get\s*\(|\.post\s*\(|\.put\s*\(|\.delete\s*\(|\.patch\s*\(|\.head\s*\()"
    rf"[^;]{{0,300}}?"
    rf"{_QUOTE}[^\"'`]*[?&]([A-Za-z0-9_\-]{{1,80}})=",
    re.DOTALL,
)

# Axios-style options: params: { a: 1, "b": 2 }
_PARAMS_OBJ_RE = re.compile(r"params\s*[:=]\s*\{([^}]{0,500})\}", re.DOTALL)
_OBJ_KEY_RE = re.compile(
    rf"(?:{_QUOTE}([A-Za-z0-9_\-\.]{{1,80}}){_QUOTE}|([A-Za-z_$][\w$]{{0,79}}))\s*:"
)

# Weak: string literal near the words param/parameter/query/search
_WEAK_RE = re.compile(
    rf"(?:param(?:eter)?s?|query|querystring|search)\b[^;]{{0,90}}?"
    rf"{_QUOTE}([A-Za-z0-9_\-\.]{{1,80}}){_QUOTE}",
    re.IGNORECASE,
)


def _plausible(name: str) -> bool:
    if not name or len(name) < 2 or len(name) > 80:
        return False
    lowered = name.lower()
    if lowered in _RESERVED:
        return False
    if lowered.startswith(("http", "www.", "//", "javascript:", "data:")):
        return False
    # must look like an identifier or dotted/bracket-ish param reference
    if not re.match(r"^[A-Za-z0-9_\-\.\[\]]+$", name):
        return False
    return True


def _dedupe(evidences: list[tuple[str, float, str]]) -> list[tuple[str, float, str]]:
    """Merge duplicate (name, weight) pairs keeping the highest weight."""
    best: dict[str, tuple[float, str]] = {}
    for name, weight, snippet in evidences:
        current = best.get(name)
        if current is None or weight > current[0]:
            best[name] = (weight, snippet)
    return [(name, w, s) for name, (w, s) in best.items()]


def extract_from_js_text(
    js_text: str,
    *,
    location: str,
    redactor: Redactor,
) -> list[SourceEvidence]:
    """Return candidate evidence for parameter names found in *js_text*."""
    evidences: list[tuple[str, float, str]] = []

    # URLSearchParams-style access: find every reference, then scan a bounded
    # window after it for .get/.set/.append(...) calls with literal names.
    window_end = -1
    for match in _PREFIX_RE.finditer(js_text):
        start = match.start()
        if start < window_end:
            continue  # overlapping prefixes only need one scan window
        window = js_text[start : start + 500]
        window_end = start + len(window)
        for call in _CALL_RE.finditer(window):
            name = call.group(2)
            if _plausible(name):
                evidences.append(
                    (name, 0.8, param_context_snippet(js_text, call.group(0)[:40], 50))
                )

    for match in _FETCH_RE.finditer(js_text):
        name = match.group(1)
        if _plausible(name):
            evidences.append((name, 0.7, param_context_snippet(js_text, match.group(0)[:80], 40)))

    for obj_match in _PARAMS_OBJ_RE.finditer(js_text):
        for key_match in _OBJ_KEY_RE.finditer(obj_match.group(1)):
            name = key_match.group(1) or key_match.group(2)
            if _plausible(name):
                evidences.append((name, 0.6, param_context_snippet(obj_match.group(0), name, 40)))

    for match in _WEAK_RE.finditer(js_text):
        name = match.group(1)
        if _plausible(name):
            evidences.append((name, 0.35, param_context_snippet(js_text, match.group(0)[:60], 40)))

    refs: list[SourceEvidence] = []
    for name, weight, snippet in _dedupe(evidences):
        source = SourceRef(
            kind=DiscoverySourceKind.JS,
            location=location,
            context=(
                f"JavaScript heuristic match for {name!r}: "
                f"{redactor.redact(param_context_snippet(snippet, name, 60))}"
            ),
            weight=weight,
        )
        refs.append(SourceEvidence(param=name, endpoint_id="", source=source))
    return refs
