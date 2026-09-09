"""Canary-reflection detection.

Reflection is tracked separately from behavioral changes and is never equated
with a vulnerability (e.g. XSS). We simply report where and how the exact
canary value came back, plus whether an unrelated control parameter reflected
too (general query-string reflection), which strongly reduces the signal.
"""

from __future__ import annotations

import html as html_lib
import json
import re
from dataclasses import dataclass, field


@dataclass
class ReflectionInfo:
    reflected: bool = False
    contexts: list[str] = field(default_factory=list)
    control_also_reflected: bool = False
    # contexts in which the *control* canary appeared (general reflection)
    control_contexts: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "reflected": self.reflected,
            "contexts": self.contexts,
            "control_also_reflected": self.control_also_reflected,
            "control_contexts": self.control_contexts,
        }


def _find_in_html(body: str, canary: str) -> list[str]:
    """Locate reflection contexts in an HTML-ish body (heuristic)."""
    contexts: list[str] = []
    if canary in body:
        contexts.append("raw-body")
    unescaped = html_lib.unescape(body)
    if canary in unescaped:
        if "raw-body" not in contexts:
            contexts.append("html-unescaped")
    # inside <script> body
    if re.search(rf"<script\b[^>]*>[^<]*{re.escape(canary)}", unescaped, re.IGNORECASE | re.DOTALL):
        contexts.append("in-script")
    # inside a quoted or unquoted attribute value
    if re.search(
        rf"<[^>]*[\w:\-]+\s*=\s*[\"'][^\"']*{re.escape(canary)}[^\"']*[\"']",
        unescaped,
        re.IGNORECASE,
    ):
        contexts.append("in-quoted-attribute")
    if re.search(
        rf"<[^>]*[\w:\-]+\s*=\s*[^\"'>\s]*{re.escape(canary)}[^\"'>\s]*",
        unescaped,
        re.IGNORECASE,
    ):
        contexts.append("in-attribute-value")
    # URL-encoded echo (e.g. the browser's address bar or a form action)
    from urllib.parse import quote

    if quote(canary, safe="") in body or quote(canary, safe="-._~") in body:
        contexts.append("url-encoded")
    return list(dict.fromkeys(contexts))


def _find_in_json(body: str, canary: str) -> list[str]:
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return []

    hits: list[str] = []

    def walk(node: object, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for i, item in enumerate(node[:200]):
                walk(item, f"{path}[{i}]")
        elif isinstance(node, str) and canary in node:
            hits.append(f"json-string@{path}")

    walk(data, "$")
    return hits[:10]


def detect_reflection(body: str, canary: str, *, content_type: str = "") -> ReflectionInfo:
    """Detect exact reflection of *canary* in *body* and its contexts."""
    info = ReflectionInfo()
    if not canary or not body:
        return info
    lowered_ct = content_type.lower()
    contexts: list[str] = []
    if "json" in lowered_ct:
        contexts = _find_in_json(body, canary)
        # JSON bodies may still be served with an HTML content type.
        if not contexts:
            contexts = _find_in_html(body, canary)
    else:
        contexts = _find_in_html(body, canary)
        if not contexts:
            contexts = _find_in_json(body, canary)
    info.contexts = contexts
    info.reflected = bool(contexts)
    return info


def compare_control_reflection(
    candidate_info: ReflectionInfo, control_info: ReflectionInfo
) -> None:
    """Mark candidate reflection as less distinctive when control reflected too."""
    if control_info.reflected:
        candidate_info.control_also_reflected = True
        candidate_info.control_contexts = list(control_info.contexts)
