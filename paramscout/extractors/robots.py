"""``robots.txt`` extraction.

Paths listed in ``robots.txt`` are endpoints, not parameters - but they
frequently carry query strings, and they are always useful crawl seeds.  A
``Disallow`` rule is *not* treated as permission to crawl that path: ParamScout
records robots paths as candidate endpoints but does not crawl them.
"""

from __future__ import annotations

import re

from paramscout.extractors.base import ExtractionResult, params_from_query
from paramscout.models import Evidence, SourceKind
from paramscout.urls import relative_url

_DIRECTIVE_RE = re.compile(r"^\s*(Allow|Disallow|Sitemap)\s*:\s*(\S+)\s*$", re.IGNORECASE)


def extract_from_robots(text: str, *, origin: str) -> ExtractionResult:
    """Extract endpoints and any query parameters from a robots.txt body."""

    result = ExtractionResult()
    if not text:
        return result
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        match = _DIRECTIVE_RE.match(line)
        if not match:
            continue
        directive, value = match.group(1).lower(), match.group(2).strip()
        if directive == "sitemap":
            resolved = relative_url(origin, value)
            if resolved:
                result.urls.append(resolved)
            continue
        if value in {"", "/", "/*"}:
            continue
        resolved = relative_url(origin, value)
        if not resolved:
            continue
        detail = f"robots.txt {directive}: {value}"
        result.endpoints.append(
            (
                resolved,
                Evidence(
                    kind=SourceKind.ROBOTS,
                    origin=origin,
                    detail=detail,
                    context=line.strip()[:200],
                    line=line_number,
                    target=resolved,
                ),
            )
        )
        if "?" in resolved:
            for name, evidence in params_from_query(
                resolved.split("?", 1)[1],
                kind=SourceKind.ROBOTS,
                origin=origin,
                detail=detail,
                target=resolved,
            ):
                result.params.append((name, evidence))
    return result
