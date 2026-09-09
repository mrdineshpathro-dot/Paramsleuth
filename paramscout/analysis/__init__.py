"""Analysis stage: normalization, categorisation, scoring and de-duplication."""

from __future__ import annotations

from paramscout.analysis.categories import (
    CATEGORY_LABELS,
    Category,
    Classification,
    classify_parameter,
    is_security_relevant_name,
)
from paramscout.analysis.dedupe import CandidateSet
from paramscout.analysis.normalization import (
    NormalizedDocument,
    NormalizerConfig,
    check_reflection,
    compare_fingerprints,
    fingerprint_response,
    json_key_paths,
    mask_dynamic_values,
    normalize_document,
    text_similarity,
)
from paramscout.analysis.scoring import (
    Score,
    behavioral_confidence,
    discovery_confidence,
    rarity_score,
    review_priority,
)

__all__ = [
    "CATEGORY_LABELS",
    "CandidateSet",
    "Category",
    "Classification",
    "NormalizedDocument",
    "NormalizerConfig",
    "Score",
    "behavioral_confidence",
    "check_reflection",
    "classify_parameter",
    "compare_fingerprints",
    "discovery_confidence",
    "fingerprint_response",
    "is_security_relevant_name",
    "json_key_paths",
    "mask_dynamic_values",
    "normalize_document",
    "rarity_score",
    "review_priority",
    "text_similarity",
]
