"""Response normalization, fingerprinting and comparison.

The whole point of this module is to make "the page changed" mean something.
Naive comparison of raw bytes reports a difference on almost every dynamic
site: timestamps, CSRF tokens, cache nonces, rotating ad slots and
personalized widgets all change between two identical requests.

The pipeline is:

1. strip noise containers (configurable CSS selectors)
2. mask dynamic values (timestamps, UUIDs, hex/base64/JWT blobs, long numbers)
3. collapse whitespace
4. hash the normalized visible text and the tag sequence separately
5. compare fingerprints field by field, and score the difference

Comparison is *relative to a measured baseline*, not to an absolute threshold.
"""

from __future__ import annotations

import hashlib
import json
import re
import warnings
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any

from bs4 import BeautifulSoup, Comment

try:  # BeautifulSoup warns when an XML document meets the HTML parser.
    from bs4 import XMLParsedAsHTMLWarning

    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
except ImportError:  # pragma: no cover - older beautifulsoup4
    pass

from paramscout.models import PageFingerprint, ReflectionInfo, ResponseDelta
from paramscout.urls import looks_like_json

#: Elements removed before comparison.  These are the usual sources of
#: "changed" false positives and carry no parameter-behaviour signal.
DEFAULT_NOISE_SELECTORS: tuple[str, ...] = (
    "script[src*='ad']",
    "script[src*='analytics']",
    "iframe[src*='ad']",
    "[data-ad]",
    "[data-ad-slot]",
    "[data-adunit]",
    ".ad",
    ".ads",
    ".advert",
    ".advertisement",
    "#ad",
    "#ads",
    "[data-personalized]",
    "[data-recommendations]",
)

_STRIP_TAGS = ("script", "style", "noscript", "template", "svg")

#: ``(pattern, replacement)`` applied to visible text.  Order matters.
_DYNAMIC_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "[[TS]]"),
    (re.compile(r"\d{4}-\d{2}-\d{2}"), "[[DATE]]"),
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b"), "[[TS]]"),
    (
        re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
        "[[UUID]]",
    ),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{2,}(?:\.[A-Za-z0-9_\-]{2,})?"), "[[JWT]]"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "[[HEX]]"),
    (re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b"), "[[B64]]"),
    (re.compile(r"\b\d{10,13}\b"), "[[EPOCH]]"),
    (re.compile(r"\b\d{5,}\b"), "[[NUM]]"),
)

#: ``<input name="csrf_token" value="...">`` - the value rotates every response.
_SENSITIVE_INPUT_RE = re.compile(
    r"""(?is)(<input\b[^>]*?\bname\s*=\s*["']?[\w\-]*(?:token|csrf|xsrf|nonce|secret|password|signature)"""
    r"""[\w\-]*["']?[^>]*?\bvalue\s*=\s*)(["']?)([^"'<>\s]{4,})\2"""
)

#: Attribute values that rotate on every response.
_DYNAMIC_ATTR_RE = re.compile(
    r"(?i)\b(nonce|csrf|xsrf|_token|authenticity_token|request[_-]?id|trace[_-]?id|"
    r"cache[_-]?bust(?:er)?|t|_t|timestamp|ts)\s*=\s*[\"']?([\w.\-+/=]{6,})"
)


@dataclass
class NormalizerConfig:
    """Knobs for the normalization pipeline."""

    noise_selectors: tuple[str, ...] = DEFAULT_NOISE_SELECTORS
    similarity_max_chars: int = 20_000
    similarity_min_chars: int = 32
    max_structure_tags: int = 800
    mask_dynamic_values: bool = True


@dataclass
class NormalizedDocument:
    """Normalized view of one HTML/JSON/text response."""

    text: str
    title: str
    structure_hash: str
    text_hash: str
    json_keys: tuple[str, ...] = field(default_factory=tuple)
    tag_count: int = 0


def mask_dynamic_values(text: str) -> str:
    """Replace rotating values with stable placeholders."""

    result = text
    for pattern, replacement in _DYNAMIC_PATTERNS:
        result = pattern.sub(replacement, result)
    result = _DYNAMIC_ATTR_RE.sub(r"\1=[[DYN]]", result)
    result = _SENSITIVE_INPUT_RE.sub(r"\1\2[[DYN]]\2", result)
    return result


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


def normalize_document(
    body: str,
    *,
    content_type: str = "",
    config: NormalizerConfig | None = None,
) -> NormalizedDocument:
    """Produce the comparable form of a response body."""

    config = config or NormalizerConfig()
    if looks_like_json(content_type):
        keys = json_key_paths(body)
        text = json.dumps(sorted(keys)) if keys else body.strip()
        text_hash = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        return NormalizedDocument(
            text=text,
            title="",
            structure_hash=hashlib.sha256(",".join(keys).encode()).hexdigest(),
            text_hash=text_hash,
            json_keys=keys,
            tag_count=0,
        )

    if "<" not in body:
        text = re.sub(r"\s+", " ", body.strip())
        if config.mask_dynamic_values:
            text = mask_dynamic_values(text)
        text = text[: config.similarity_max_chars]
        return NormalizedDocument(
            text=text,
            title="",
            structure_hash="text",
            text_hash=hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
            json_keys=(),
            tag_count=0,
        )

    soup = _soup(body)
    for comment in soup.find_all(string=lambda item: isinstance(item, Comment)):
        comment.extract()
    for selector in config.noise_selectors:
        try:
            for tag in soup.select(selector):
                tag.decompose()
        except Exception:  # noqa: BLE001 - a bad selector must not break a scan
            continue
    title_tag = soup.find("title")
    title = re.sub(r"\s+", " ", title_tag.get_text(" ", strip=True)) if title_tag else ""
    if config.mask_dynamic_values:
        title = mask_dynamic_values(title)

    for tag_name in _STRIP_TAGS:
        for tag in soup.find_all(tag_name):
            tag.decompose()

    tags = [tag.name for tag in soup.find_all() if tag.name][: config.max_structure_tags]
    text = soup.get_text(" ", strip=True)
    text = re.sub(r"\s+", " ", text).strip()
    if config.mask_dynamic_values:
        text = mask_dynamic_values(text)
    text = text[: config.similarity_max_chars]

    return NormalizedDocument(
        text=text,
        title=title,
        structure_hash=hashlib.sha256(",".join(tags).encode()).hexdigest(),
        text_hash=hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
        json_keys=(),
        tag_count=len(tags),
    )


def json_key_paths(body: str, *, max_depth: int = 5, max_paths: int = 400) -> tuple[str, ...]:
    """Sorted set of key paths in a JSON document (structure, not values)."""

    try:
        document: Any = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return ()
    paths: list[str] = []

    def walk(node: Any, prefix: str, depth: int) -> None:
        if len(paths) >= max_paths or depth > max_depth:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                paths.append(path)
                walk(value, path, depth + 1)
        elif isinstance(node, list):
            for item in node[:5]:
                walk(item, f"{prefix}[]", depth + 1)

    walk(document, "", 0)
    return tuple(sorted(set(paths)))


def fingerprint_response(
    *,
    status: int,
    headers: dict[str, str],
    body: bytes,
    content_type: str = "",
    truncated: bool = False,
    elapsed_ms: float = 0.0,
    config: NormalizerConfig | None = None,
) -> PageFingerprint:
    """Build a :class:`PageFingerprint` from a raw HTTP response."""

    config = config or NormalizerConfig()
    ctype = content_type or headers.get("content-type", "")
    lower_headers = {name.lower(): value for name, value in headers.items()}
    text_body = body.decode("utf-8", errors="replace")
    document = normalize_document(text_body, content_type=ctype, config=config)
    return PageFingerprint(
        status=status,
        content_type=ctype.split(";", 1)[0].strip().lower(),
        length=len(body),
        title=document.title,
        text_hash=document.text_hash,
        structure_hash=document.structure_hash,
        json_keys_hash=hashlib.sha256(",".join(document.json_keys).encode()).hexdigest()
        if document.json_keys
        else "",
        location=lower_headers.get("location", ""),
        elapsed_ms=elapsed_ms,
        truncated=truncated,
    )


def text_similarity(left: str, right: str, *, min_chars: int = 32) -> float:
    """Similarity ratio of two normalized texts (1.0 == identical)."""

    if left == right:
        return 1.0
    if len(left) < min_chars and len(right) < min_chars:
        return 1.0 if left == right else 0.0
    return round(SequenceMatcher(None, left, right, autojunk=False).ratio(), 4)


def compare_fingerprints(
    baseline: PageFingerprint,
    candidate: PageFingerprint,
    *,
    baseline_text: str = "",
    candidate_text: str = "",
    similarity_floor: float = 0.0,
) -> ResponseDelta:
    """Compare two fingerprints and describe the difference.

    ``baseline_text`` / ``candidate_text`` are the normalized texts; when they
    are unavailable the comparison falls back to hash equality.
    """

    delta = ResponseDelta(
        status_changed=baseline.status != candidate.status,
        content_type_changed=baseline.content_type != candidate.content_type,
        location_changed=baseline.location != candidate.location,
        title_changed=baseline.title != candidate.title,
        structure_changed=baseline.structure_hash != candidate.structure_hash,
        json_changed=bool(baseline.json_keys_hash and candidate.json_keys_hash)
        and baseline.json_keys_hash != candidate.json_keys_hash,
        length_delta=candidate.length - baseline.length,
        length_ratio=round(abs(candidate.length - baseline.length) / max(1, baseline.length), 4),
    )
    if baseline_text or candidate_text:
        delta.text_similarity = text_similarity(baseline_text, candidate_text)
    else:
        delta.text_similarity = 1.0 if baseline.text_hash == candidate.text_hash else similarity_floor

    if delta.status_changed:
        delta.details["status"] = f"{baseline.status} -> {candidate.status}"
        delta.signals.append(f"status {delta.details['status']}")
    if delta.content_type_changed:
        delta.details["content_type"] = f"{baseline.content_type or '-'} -> {candidate.content_type or '-'}"
        delta.signals.append(f"content-type {delta.details['content_type']}")
    if delta.location_changed:
        delta.details["location"] = f"{baseline.location or '-'} -> {candidate.location or '-'}"
        delta.signals.append(f"redirect Location {delta.details['location']}")
    if delta.title_changed:
        delta.details["title"] = f"{baseline.title[:80]!r} -> {candidate.title[:80]!r}"
        delta.signals.append(f"title changed ({delta.details['title']})")
    if delta.structure_changed:
        delta.signals.append("DOM structure changed")
    if delta.json_changed:
        delta.signals.append("JSON key structure changed")
    if delta.text_similarity < 0.98:
        delta.signals.append(f"normalized text similarity {delta.text_similarity}")
    if delta.length_ratio >= 0.02 and abs(delta.length_delta) >= 32:
        delta.signals.append(f"body size {delta.length_delta:+d} bytes ({delta.length_ratio:.1%})")
    delta.details["length"] = f"{delta.length_delta:+d} bytes ({delta.length_ratio:.1%})"
    delta.details["text_similarity"] = f"{delta.text_similarity:.4f}"
    return delta


def check_reflection(body: bytes, canary: str) -> ReflectionInfo:
    """Detect exact canary reflection.  Tracked separately from behaviour."""

    if not canary:
        return ReflectionInfo(reflected=False, occurrences=0)
    text = body.decode("utf-8", errors="replace")
    occurrences = text.count(canary)
    locations: list[str] = []
    if occurrences:
        lowered = text.lower()
        if canary.lower() in lowered:
            locations.append("response body")
    encoded_variant = canary in text and (
        "&#" in text or "&quot;" in text or "\\u00" in text or "%3C" in text
    )
    return ReflectionInfo(
        reflected=occurrences > 0,
        occurrences=occurrences,
        locations=locations,
        html_encoded_variant=encoded_variant,
    )


def bodies_are_error_pages(text: str, status: int) -> bool:
    """Heuristic: does this look like a generic error page?

    Used to avoid treating "our probe broke something" as a behavioural finding.
    """

    if status in (400, 401, 403, 404, 500, 502, 503):
        return True
    lowered = text.lower()[:4000]
    markers = (
        "internal server error",
        "something went wrong",
        "unexpected error",
        "stack trace",
        "traceback (most recent call last)",
        "fatal error",
        "access denied",
    )
    return any(marker in lowered for marker in markers)
