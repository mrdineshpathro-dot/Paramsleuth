"""``sitemap.xml`` extraction (standard-library XML parsing, no lxml)."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from paramscout.extractors.base import ExtractionResult, params_from_query
from paramscout.models import Evidence, SourceKind
from paramscout.urls import relative_url


def extract_from_sitemap(text: str, *, origin: str, max_urls: int = 2000) -> ExtractionResult:
    """Extract ``<loc>`` URLs from a sitemap or sitemap index."""

    result = ExtractionResult()
    if not text or "<" not in text:
        return result
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return result

    count = 0
    for element in root.iter():
        tag = element.tag.split("}", 1)[-1].lower()
        if tag != "loc" or not element.text:
            continue
        raw = element.text.strip()
        resolved = relative_url(origin, raw)
        if not resolved:
            continue
        count += 1
        if count > max_urls:
            break
        result.urls.append(resolved)
        result.endpoints.append(
            (
                resolved,
                Evidence(
                    kind=SourceKind.SITEMAP,
                    origin=origin,
                    detail=f"sitemap <loc>{raw[:160]}</loc>",
                    target=resolved,
                ),
            )
        )
        if "?" in resolved:
            for name, evidence in params_from_query(
                resolved.split("?", 1)[1],
                kind=SourceKind.SITEMAP,
                origin=origin,
                detail="sitemap <loc>",
                target=resolved,
            ):
                result.params.append((name, evidence))
    return result
