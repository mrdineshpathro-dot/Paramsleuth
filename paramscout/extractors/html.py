"""HTML extraction: links, forms, media references and inline scripts.

Forms are recorded as *evidence only*.  ParamScout never submits a form - not
in passive mode, not in active mode.  A form's method and field names are
strong signals about which parameters an endpoint accepts, and capturing them
costs nothing.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from paramscout.extractors.base import (
    ExtractionResult,
    FormInfo,
    context_snippet,
    is_plausible_param_name,
    params_from_query,
)
from paramscout.extractors.javascript import extract_from_javascript
from paramscout.models import Evidence, SourceKind
from paramscout.redaction import redact_text
from paramscout.urls import looks_like_html, relative_url

_LINK_ATTRS: tuple[tuple[str, str], ...] = (
    ("a", "href"),
    ("area", "href"),
    ("link", "href"),
    ("img", "src"),
    ("iframe", "src"),
    ("frame", "src"),
    ("script", "src"),
    ("source", "src"),
    ("video", "src"),
    ("audio", "src"),
    ("embed", "src"),
    ("track", "src"),
    ("form", "action"),
    ("button", "formaction"),
    ("input", "formaction"),
)

_QUERYISH_ATTR_RE = re.compile(r"([?&])([A-Za-z_$][\w$.\-]{0,63})=")
_DATA_URL_ATTRS = ("data-url", "data-href", "data-src", "data-endpoint", "data-api", "data-action", "data-uri")


def _attr(tag: Any, name: str) -> str:
    """Return an element attribute as a single string.

    BeautifulSoup types multi-valued attributes (``class``, and any attribute it
    decides is a list) as ``list[str]``, so a plain ``tag.get(name)`` is not
    usable as text without a join.
    """

    raw = tag.get(name)
    if raw is None:
        return ""
    if isinstance(raw, list):
        return " ".join(part for part in raw if isinstance(part, str))
    return str(raw)


def extract_from_html(
    html: str,
    *,
    origin: str,
    extract_js: bool = True,
) -> ExtractionResult:
    """Extract parameters, URLs, script sources and forms from an HTML document."""

    result = ExtractionResult()
    if not html:
        return result
    soup = BeautifulSoup(html, "html.parser")

    # -- links, media and form targets ----------------------------------
    for tag_name, attr in _LINK_ATTRS:
        for tag in soup.find_all(tag_name):
            raw = tag.get(attr)
            if not raw or not isinstance(raw, str):
                continue
            raw = raw.strip()
            if not raw:
                continue
            resolved = relative_url(origin, raw)
            if resolved:
                result.urls.append(resolved)
                if tag_name == "script":
                    result.scripts.append(resolved)
                query = urlsplit(resolved).query
                if query:
                    kind = SourceKind.HTML_FORM_FIELD if tag_name == "form" else SourceKind.HTML_LINK
                    detail = f"{tag_name}[{attr}] -> {redact_text(resolved)[:160]}"
                    for name, evidence in params_from_query(
                        query, kind=kind, origin=origin, detail=detail, target=resolved
                    ):
                        result.params.append((name, evidence))

    # -- meta refresh ----------------------------------------------------
    for tag in soup.find_all("meta"):
        content = tag.get("content")
        if not isinstance(content, str):
            continue
        match = re.search(r"url\s*=\s*([^;]+)", content, re.IGNORECASE)
        if match:
            resolved = relative_url(origin, match.group(1).strip())
            if resolved:
                result.urls.append(resolved)

    # -- forms (recorded, never submitted) -------------------------------
    for form in soup.find_all("form"):
        action_raw = _attr(form, "action").strip()
        action = relative_url(origin, action_raw) or origin
        method = (_attr(form, "method") or "GET").upper()
        enctype = _attr(form, "enctype").strip()
        fields: list[str] = []
        for field in form.find_all(["input", "select", "textarea", "button"]):
            raw_name = field.get("name")
            if not isinstance(raw_name, str) or not raw_name.strip():
                continue
            name = raw_name.strip()
            if not is_plausible_param_name(name):
                continue
            fields.append(name)
            field_type = (_attr(field, "type") or field.name or "").lower()
            hidden = " (hidden)" if field_type == "hidden" else ""
            form_action = (_attr(field, "formaction") or action_raw).strip()
            action_url = relative_url(origin, form_action) or action
            detail = f"{method}: {redact_text(form_action or action)[:120]} field '{name}'{hidden}"
            evidence = Evidence(
                kind=SourceKind.HTML_FORM_FIELD,
                origin=origin,
                detail=detail,
                context=f"form method={method} fields={','.join(fields[:12])}",
                confidence=0.9 if field_type == "hidden" else None,
                target=action_url,
            )
            result.params.append((name, evidence))
        if fields or action_raw:
            result.forms.append(
                FormInfo(
                    action=action,
                    method=method,
                    fields=fields,
                    origin=origin,
                    enctype=enctype,
                    context=f"<form method='{method}' action='{redact_text(action_raw)}'>",
                )
            )

    # -- query strings embedded in data-* attributes ---------------------
    for tag in soup.find_all(True):
        for attr in list(tag.attrs):
            if attr not in _DATA_URL_ATTRS and not attr.startswith("data-"):
                continue
            value = tag.attrs[attr]
            if not isinstance(value, str) or ("=" not in value):
                continue
            if "?" not in value and "&" not in value:
                continue
            attr_target = relative_url(origin, value.split("?", 1)[0] if "?" in value else value) or origin
            for name, evidence in params_from_query(
                value.split("?", 1)[1] if "?" in value else value.lstrip("&"),
                kind=SourceKind.HTML_ATTRIBUTE,
                origin=origin,
                detail=f"{tag.name}[{attr}]",
                context=context_snippet(str(value), 0),
                target=attr_target,
            ):
                result.params.append((name, evidence))

    # -- inline JavaScript ------------------------------------------------
    if extract_js:
        for script in soup.find_all("script"):
            if script.get("src"):
                continue
            body = script.string or script.get_text() or ""
            if not body.strip():
                continue
            js_result = extract_from_javascript(body, origin=origin, kind=SourceKind.JS_INLINE)
            result.merge(js_result)

    # -- embedded JSON configuration blobs --------------------------------
    from paramscout.extractors.jsonblobs import extract_from_json_text

    for script in soup.find_all("script"):
        script_type = _attr(script, "type").lower()
        if script.get("src"):
            continue
        if script_type in {"application/json", "application/ld+json", "importmap"}:
            body = script.string or script.get_text() or ""
            result.merge(extract_from_json_text(body, origin=origin))

    return result


def html_title(html: str) -> str:
    """The ``<title>`` text, or an empty string."""

    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    tag = soup.find("title")
    if tag is None:
        return ""
    return re.sub(r"\s+", " ", tag.get_text(" ", strip=True))[:300]


def is_html_content_type(content_type: str | None) -> bool:
    return looks_like_html(content_type)
