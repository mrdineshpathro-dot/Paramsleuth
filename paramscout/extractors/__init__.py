"""Passive extractors.

Every extractor is pure: it takes text plus an origin URL and returns an
:class:`~paramscout.extractors.base.ExtractionResult`.  No extractor performs
network I/O and no extractor submits anything.
"""

from __future__ import annotations

from paramscout.extractors.archive import (
    extract_from_archive_file,
    extract_from_archive_text,
    parse_archive_line,
)
from paramscout.extractors.base import (
    ExtractionResult,
    FormInfo,
    is_plausible_param_name,
    params_from_query,
)
from paramscout.extractors.html import extract_from_html, html_title
from paramscout.extractors.javascript import extract_from_javascript
from paramscout.extractors.jsonblobs import (
    extract_from_json_text,
    extract_json_blobs_from_javascript,
)
from paramscout.extractors.robots import extract_from_robots
from paramscout.extractors.sitemap import extract_from_sitemap

__all__ = [
    "ExtractionResult",
    "FormInfo",
    "extract_from_archive_file",
    "extract_from_archive_text",
    "extract_from_html",
    "extract_from_javascript",
    "extract_from_json_text",
    "extract_from_robots",
    "extract_from_sitemap",
    "extract_json_blobs_from_javascript",
    "html_title",
    "is_plausible_param_name",
    "params_from_query",
    "parse_archive_line",
]
