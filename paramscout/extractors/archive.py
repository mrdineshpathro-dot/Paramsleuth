"""User-supplied URL archives and endpoint collections.

Supported line formats (auto-detected per line):

* a bare URL
* ``URL<TAB>anything`` (proxycrawl / gau / wayback style dumps)
* a JSON object with a ``url`` key (Burp-style exports, JSON lines)
* ``#`` comments and blank lines are ignored
"""

from __future__ import annotations

import json
from pathlib import Path

from paramscout.extractors.base import ExtractionResult, params_from_query
from paramscout.models import Evidence, SourceKind

MAX_LINE_BYTES = 8192


def parse_archive_line(line: str) -> str | None:
    """Return the URL contained in one archive line, or ``None``."""

    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if len(line) > MAX_LINE_BYTES:
        return None
    if line.startswith("{"):
        try:
            document = json.loads(line)
        except json.JSONDecodeError:
            return None
        if isinstance(document, dict):
            for key in ("url", "href", "uri", "endpoint", "path"):
                value = document.get(key)
                if isinstance(value, str) and value.startswith(("http://", "https://", "/")):
                    return value
        return None
    if "\t" in line:
        candidate = line.split("\t", 1)[0].strip()
    elif " " in line:
        candidate = line.split(" ", 1)[0].strip()
    else:
        candidate = line
    return candidate or None


def extract_from_archive_text(text: str, *, source: str) -> ExtractionResult:
    """Extract URLs and query parameters from archive text."""

    result = ExtractionResult()
    for line_number, line in enumerate(text.splitlines(), start=1):
        url = parse_archive_line(line)
        if not url:
            continue
        result.urls.append(url)
        result.endpoints.append(
            (
                url,
                Evidence(
                    kind=SourceKind.ARCHIVE,
                    origin=source,
                    detail="user-supplied archive entry",
                    context=line.strip()[:200],
                    line=line_number,
                ),
            )
        )
        if "?" in url:
            for name, evidence in params_from_query(
                url.split("?", 1)[1],
                kind=SourceKind.ARCHIVE,
                origin=source,
                detail=f"query string in archived URL (line {line_number})",
                context=line.strip()[:200],
                target=url,
            ):
                result.params.append((name, evidence))
    return result


def extract_from_archive_file(path: str | Path) -> ExtractionResult:
    """Read an archive file from disk and extract from it."""

    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8", errors="replace")
    return extract_from_archive_text(text, source=str(file_path))
