"""Offline (zero-network) parameter discovery from local inputs.

The ``paramscout extract`` command analyzes:

- URL archive files (one URL per line, or free text containing URLs),
- HAR/JSON endpoint collections,
- saved HTML documents (links, forms, inline JavaScript/JSON),
- saved JavaScript files (heuristic name extraction).

No request is ever sent by this module, and no scope configuration is needed.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from ..extractors.base import Collector, load_urls_from_text, sniff_document_type
from ..extractors.html import extract_from_html
from ..models import DiscoverySourceKind
from ..redaction import Redactor

log = logging.getLogger("paramscout.extract")

_MAX_FILE_BYTES = 20 * 1024 * 1024
_MAX_FILES = 2_000


@dataclass
class OfflineResult:
    endpoints: list = field(default_factory=list)
    candidates: list = field(default_factory=list)
    urls_found: int = 0
    files_scanned: int = 0
    files_skipped: int = 0

    @property
    def candidate_count(self) -> int:
        return len(self.candidates)


class OfflineAnalyzer:
    """Runs the offline extraction pipeline over local inputs."""

    def __init__(self, redactor: Redactor, grouping: str = "path") -> None:
        self.redactor = redactor
        self.collector = Collector(grouping=grouping)

    def _iter_files(self, inputs: list[str]) -> list[Path]:
        files: list[Path] = []
        for raw in inputs:
            path = Path(raw)
            if path.is_dir():
                for child in sorted(path.rglob("*")):
                    if child.is_file():
                        files.append(child)
            elif path.is_file():
                files.append(path)
            else:
                log.warning("input not found: %s", raw)
        return files[:_MAX_FILES]

    def run(self, inputs: list[str]) -> OfflineResult:
        urls_found: set[str] = set()
        for path in self._iter_files(inputs):
            try:
                data = path.read_bytes()
            except OSError as exc:
                log.warning("cannot read %s: %s", path, exc)
                continue
            if len(data) > _MAX_FILE_BYTES:
                log.warning("skipping oversized file %s", path)
                continue
            self.collector.report.files_scanned += 1
            doc_type = sniff_document_type(str(path), data)
            if doc_type in ("html", "js", "json", "urls", "text"):
                try:
                    self._handle_file(str(path), doc_type, data)
                except Exception as exc:  # never let one file kill the run
                    log.warning("error analyzing %s: %s", path, exc)
        endpoints, candidates = self.collector.snapshot()
        result = OfflineResult(
            endpoints=endpoints,
            candidates=candidates,
            urls_found=self.collector.report.urls_parsed,
            files_scanned=self.collector.report.files_scanned,
        )
        return result

    # ------------------------------------------------------------------
    def _handle_file(self, label: str, doc_type: str, data: bytes) -> None:
        text = data.decode("utf-8", "replace")
        if doc_type == "html":
            extract_from_html(
                self.collector,
                text,
                page_url=None,
                label=label,
                redactor=self.redactor,
                inline_js=True,
            )
            return
        if doc_type == "js":
            from ..extractors.javascript import extract_from_js_text

            endpoint = self.collector.virtual_endpoint(label)
            for source in extract_from_js_text(
                text, location=f"(local file) {label}", redactor=self.redactor
            ):
                self.collector.add_evidence(endpoint, source.param, source.source)
            return
        if doc_type == "json":
            self._handle_json(label, text)
            return
        # urls / text
        for url in load_urls_from_text(text):
            self.collector.add_url_query(
                url,
                source_kind=DiscoverySourceKind.USER_FILE,
                location=f"(local file) {label}",
            )

    def _handle_json(self, label: str, text: str) -> None:
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            # Fall back to scanning the text for embedded URLs.
            for url in load_urls_from_text(text):
                self.collector.add_url_query(
                    url,
                    source_kind=DiscoverySourceKind.USER_FILE,
                    location=f"(local file) {label}",
                )
            return
        urls = _urls_from_json(data)
        if not urls:
            # HAR-style documents
            if isinstance(data, dict) and "log" in data and isinstance(data.get("log"), dict):
                entries = data["log"].get("entries", [])
                for entry in entries:
                    req = (entry.get("request") or {}).get("url")
                    if isinstance(req, str):
                        urls.append(req)
        for url in urls:
            self.collector.add_url_query(
                url,
                source_kind=DiscoverySourceKind.USER_FILE,
                location=f"(local file) {label}",
            )


def _urls_from_json(node: object) -> list[str]:
    found: list[str] = []

    def walk(item: object) -> None:
        if isinstance(item, dict):
            for key, value in item.items():
                if key == "url" and isinstance(value, str) and value.startswith(("http://", "https://")):
                    found.append(value)
                else:
                    walk(value)
        elif isinstance(item, list):
            for sub in item[:5000]:
                walk(sub)

    walk(node)
    return found
