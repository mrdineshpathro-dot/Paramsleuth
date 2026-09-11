"""Extractors for passive parameter discovery."""

from .base import (
    Collector,
    ExtractionReport,
    SourceEvidence,
    extract_query_params,
    param_context_snippet,
    sniff_document_type,
)
from . import html as html  # noqa: F401  (registered via Collector usage)

__all__ = [
    "Collector",
    "ExtractionReport",
    "SourceEvidence",
    "extract_query_params",
    "param_context_snippet",
    "sniff_document_type",
]
