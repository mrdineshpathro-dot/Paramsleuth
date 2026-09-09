"""Dynamic-response normalization.

Live pages carry timestamps, rotating tokens, counters, ads and personalized
content. Before comparing responses we normalize away the classes of noise we
can recognize, and we additionally measure ordinary baseline variation so a
single changed response is never treated as evidence on its own.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter

from bs4 import BeautifulSoup

# ---- dynamic token patterns ------------------------------------------------
_ISO_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}|\d{2}[/-]\d{2}[/-]\d{2,4}")
_TIME_RE = re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?(?:\s?[APap][Mm])?\b")
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_HEX_TOKEN_RE = re.compile(r"\b[0-9a-fA-F]{24,}\b")
_LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-\.]{32,}\b")
_NUMBER_RE = re.compile(r"\b\d{2,}\b")
_EPOCH_RE = re.compile(r"\b1[0-9]{9,10}\b")
_WHITESPACE_RE = re.compile(r"\s+")

_VISIBLE_TEXT_CAP = 80_000  # similarity inputs are capped for speed


def normalize_dynamic_text(text: str) -> str:
    """Replace recognizable volatile content with stable placeholders."""
    out = text
    out = _ISO_TS_RE.sub("<DATETIME>", out)
    out = _EPOCH_RE.sub("<EPOCH>", out)
    out = _UUID_RE.sub("<UUID>", out)
    out = _HEX_TOKEN_RE.sub("<HEXTOKEN>", out)
    out = _LONG_TOKEN_RE.sub("<LONGTOKEN>", out)
    out = _DATE_RE.sub("<DATE>", out)
    out = _TIME_RE.sub("<TIME>", out)
    out = _NUMBER_RE.sub("<NUM>", out)
    out = _WHITESPACE_RE.sub(" ", out)
    return out.strip()


def visible_text(html: str) -> str:
    """Extract collapsed visible text from an HTML document."""
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return _WHITESPACE_RE.sub(" ", re.sub(r"<[^>]+>", " ", html)).strip()
    for node in soup.find_all(["script", "style", "noscript", "template"]):
        node.decompose()
    return _WHITESPACE_RE.sub(" ", soup.get_text(" ")).strip()


def text_similarity(a: str, b: str) -> float:
    """Character-level similarity in [0,1] on normalized, capped text."""
    import difflib

    na = normalize_dynamic_text(a)[:_VISIBLE_TEXT_CAP]
    nb = normalize_dynamic_text(b)[:_VISIBLE_TEXT_CAP]
    if not na and not nb:
        return 1.0
    if not na or not nb:
        return 0.0
    return difflib.SequenceMatcher(None, na, nb, autojunk=False).ratio()


def page_title(html: str) -> str:
    try:
        soup = BeautifulSoup(html, "html.parser")
        title = soup.title
        if title is not None and title.string:
            return _WHITESPACE_RE.sub(" ", title.string).strip()
    except Exception:
        pass
    return ""


def structure_digest(html: str) -> str:
    """Digest of tag-count structure (structural-change detector)."""
    try:
        soup = BeautifulSoup(html, "html.parser")
        counts = Counter(tag.name for tag in soup.find_all())
        top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:40]
        return "|".join(f"{k}:{v}" for k, v in top)
    except Exception:
        return ""


def json_structure_digest(payload: str | bytes) -> str | None:
    """Digest of a JSON document's shape (keys + leaf types), ignoring values."""
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", "replace")
    try:
        data = json.loads(payload)
    except (ValueError, TypeError):
        return None

    def shape(node: object) -> object:
        if isinstance(node, dict):
            return {
                "obj": sorted((k, shape(v)) for k, v in node.items())
            }
        if isinstance(node, list):
            inner = [shape(v) for v in node[:50]]
            return {"arr": inner[:1] if inner else []}
        if node is None:
            return "null"
        return type(node).__name__

    try:
        digest = json.dumps(shape(data), sort_keys=True)
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(digest.encode()).hexdigest()


def quick_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
