"""Discovery stage: passive extraction and opt-in active validation."""

from __future__ import annotations

from paramscout.discovery.active import (
    DEFAULT_GET_ONLY_WARNING,
    EndpointOutcome,
    ProbeOutcome,
    compile_exclusions,
    endpoint_is_excluded,
    has_real_provenance,
    mark_all_inconclusive,
    prepare_endpoint,
    probe_candidates,
    probe_endpoint,
    rank_candidates,
    select_candidates,
)
from paramscout.discovery.baseline import (
    BaselineSet,
    ControlResult,
    DeltaAssessment,
    assess_delta,
    build_batch_probe_url,
    build_probe_url,
    collect_baseline,
    make_canary,
    make_control_parameter,
    measure_control,
)
from paramscout.discovery.passive import PassiveResult, add_wordlist_candidates, build_passive

__all__ = [
    "DEFAULT_GET_ONLY_WARNING",
    "BaselineSet",
    "ControlResult",
    "DeltaAssessment",
    "EndpointOutcome",
    "PassiveResult",
    "ProbeOutcome",
    "add_wordlist_candidates",
    "assess_delta",
    "build_batch_probe_url",
    "build_passive",
    "build_probe_url",
    "collect_baseline",
    "compile_exclusions",
    "endpoint_is_excluded",
    "has_real_provenance",
    "make_canary",
    "make_control_parameter",
    "mark_all_inconclusive",
    "measure_control",
    "prepare_endpoint",
    "probe_candidates",
    "probe_endpoint",
    "rank_candidates",
    "select_candidates",
]
