"""Parameter extraction from embedded JSON / configuration objects.

Single-page applications routinely ship their API surface as a JSON blob in a
``<script type="application/json">`` tag or as an object literal in a bundle.
We only treat a JSON document as evidence when it *plausibly references URL
parameters*: a key that is itself a query string, an endpoint string containing
a query, or a nested object under a key such as ``query``/``params``.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from paramscout.extractors.base import ExtractionResult, context_snippet, is_plausible_param_name
from paramscout.models import Evidence, SourceKind

_PARAM_CONTAINER_KEYS = frozenset({"query", "params", "parameters", "querystring", "searchparams", "filters"})
_URLISH_KEYS = frozenset({"url", "uri", "href", "endpoint", "path", "api", "apiurl", "link", "action", "src"})
_QUERY_VALUE_RE = re.compile(r"[?&][A-Za-z_$][\w$.\-]{0,63}=")


def _walk(node: object, path: str, out: list[tuple[str, str, str]]) -> None:
    """Collect ``(param_name, json_path, reason)`` triples from a JSON tree."""

    if isinstance(node, dict):
        for key, value in node.items():
            key_path = f"{path}.{key}" if path else str(key)
            lowered = str(key).lower()
            if _QUERY_VALUE_RE.search(str(key)):
                for match in _QUERY_VALUE_RE.finditer(str(key)):
                    out.append((match.group(0)[1:].rstrip("="), key_path, "parameter named inside a JSON key"))
            if lowered in _PARAM_CONTAINER_KEYS and isinstance(value, dict):
                for sub_key in value:
                    if is_plausible_param_name(str(sub_key)):
                        out.append((str(sub_key), key_path, f"key inside JSON '{key}' object"))
            if lowered in _URLISH_KEYS and isinstance(value, str):
                query = urlsplit(value).query
                if query:
                    for pair in query.split("&"):
                        name = pair.split("=", 1)[0]
                        if is_plausible_param_name(name):
                            out.append((name, key_path, f"query string in JSON '{key}' value"))
            if lowered in _URLISH_KEYS and isinstance(value, str) and _QUERY_VALUE_RE.search(value):
                pass  # already handled above via urlsplit
            _walk(value, key_path, out)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _walk(item, f"{path}[{index}]", out)
    elif isinstance(node, str):
        if "?" in node and _QUERY_VALUE_RE.search(node):
            query = urlsplit(node).query or node.split("?", 1)[1]
            for pair in query.split("&"):
                name = pair.split("=", 1)[0]
                if is_plausible_param_name(name):
                    out.append((name, path, "query string inside a JSON string value"))


def extract_from_json_text(text: str, *, origin: str, max_hits: int = 200) -> ExtractionResult:
    """Extract parameter candidates from a JSON (or JSON-like) document."""

    result = ExtractionResult()
    if not text or not text.strip():
        return result
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return result
    hits: list[tuple[str, str, str]] = []
    _walk(document, "", hits)
    for name, path, reason in hits[:max_hits]:
        result.params.append(
            (
                name,
                Evidence(
                    kind=SourceKind.JSON_BLOB,
                    origin=origin,
                    detail=f"{reason} at {path}",
                    context=context_snippet(text, text.find(name)) if name in text else "",
                    confidence=0.55,
                ),
            )
        )
    return result


def extract_json_blobs_from_javascript(source: str, *, origin: str) -> ExtractionResult:
    """Find JSON-ish object literals inside JavaScript and mine them.

    Heuristic: locate balanced ``{...}`` blocks that parse as JSON after quoting
    bare keys.  Failures are ignored silently - this is best-effort.
    """

    result = ExtractionResult()
    if not source:
        return result
    candidates = re.finditer(r"\{[^{}]{2,600}\}", source)
    for match in candidates:
        block = match.group(0)
        if ":" not in block:
            continue
        quoted = re.sub(r"([{,]\s*)([A-Za-z_$][\w$]*)\s*:", r'\1"\2":', block)
        try:
            parsed = json.loads(quoted)
        except (json.JSONDecodeError, ValueError):
            continue
        result.merge(extract_from_json_text(json.dumps(parsed), origin=origin))
    return result
