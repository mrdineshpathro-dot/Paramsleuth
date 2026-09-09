"""Active-discovery tests: controls, reflection, batching and stability."""

from __future__ import annotations

import asyncio

from conftest import fast_config
from mockapp import MockApp

from paramscout.analysis.normalization import NormalizerConfig
from paramscout.config import ActiveConfig
from paramscout.discovery.active import (
    compile_exclusions,
    endpoint_is_excluded,
    has_real_provenance,
    probe_endpoint,
    select_candidates,
)
from paramscout.discovery.baseline import (
    assess_delta,
    build_batch_probe_url,
    build_probe_url,
    collect_baseline,
    make_canary,
    make_control_parameter,
    measure_control,
)
from paramscout.http_client import ParamScoutClient
from paramscout.models import BehavioralStatus, Candidate, Evidence, ScanStats, SourceKind

NORMALIZER = NormalizerConfig()


def candidate(name: str, *kinds: SourceKind) -> Candidate:
    return Candidate(
        endpoint="e",
        name=name,
        evidence=[Evidence(kind=kind, origin="https://h.test/e") for kind in kinds or (SourceKind.WORDLIST,)],
    )


# ---------------------------------------------------------------------------
# probe URL construction
# ---------------------------------------------------------------------------


def test_probe_url_replaces_existing_occurrences() -> None:
    url = build_probe_url("https://h.test/p?note=hello&keep=1", "note", "pscABC")
    assert url == "https://h.test/p?keep=1&note=pscABC"
    # appending would have tested nothing: the app reads the first occurrence
    assert url.count("note=") == 1
    assert "hello" not in url


def test_probe_url_preserves_blank_and_repeated_other_parameters() -> None:
    url = build_probe_url("https://h.test/p?a=1&a=2&blank=", "new", "pscXYZ")
    assert url == "https://h.test/p?a=1&a=2&blank=&new=pscXYZ"


def test_probe_url_respects_the_length_limit() -> None:
    long_base = "https://h.test/p?" + "&".join(f"k{i}=value{i}" for i in range(200))
    assert build_probe_url(long_base, "x", "psc1", max_length=200) is None
    assert build_probe_url("https://h.test/p", "x", "psc1", max_length=200) is not None


def test_batch_probe_url_drops_pairs_that_would_overflow() -> None:
    base = "https://h.test/p?" + "&".join(f"k{i}=v{i}" for i in range(40))
    assignments = [(f"param{i}", make_canary()) for i in range(10)]
    url, included = build_batch_probe_url(base, assignments, max_length=450)
    assert url is not None
    assert 0 < len(included) < len(assignments), "the URL-length limit must shrink the batch"
    assert len(url) <= 450
    # the dropped names are reported so the caller can probe them individually
    assert build_batch_probe_url(base, assignments, max_length=10) == (None, [])


def test_canaries_are_alphanumeric_only() -> None:
    for _ in range(50):
        canary = make_canary()
        assert canary.startswith("psc")
        assert canary[3:].isalnum()
        assert canary.isascii()
    control = make_control_parameter()
    assert control.startswith("psctrl") and control.isalnum()


# ---------------------------------------------------------------------------
# candidate selection and exclusions
# ---------------------------------------------------------------------------


def test_evidence_ranks_before_wordlist_guesses() -> None:
    real = candidate("q", SourceKind.HTML_LINK)
    guess = candidate("debug", SourceKind.WORDLIST)
    assert has_real_provenance(real)
    assert not has_real_provenance(guess)
    active = ActiveConfig(max_candidates_per_endpoint=1)
    selected_real, selected_guesses = select_candidates([guess, real], active)
    assert [item.name for item in selected_real] == ["q"]
    # the guess is dropped entirely: the cap is spent on real evidence
    assert selected_guesses == []


def test_endpoint_exclusions() -> None:
    exclusions = compile_exclusions([r"^/checkout", r"^/admin/"])
    assert endpoint_is_excluded("https://h.test/checkout", exclusions)
    assert endpoint_is_excluded("https://h.test/admin/users", exclusions)
    assert endpoint_is_excluded("https://h.test/checkout", [r"checkout$"])
    assert endpoint_is_excluded("https://h.test/checkout", ["checkout"])  # bad regex falls back to literal
    assert endpoint_is_excluded("https://h.test/search", exclusions) is None


# ---------------------------------------------------------------------------
# live behaviour against the mock application
# ---------------------------------------------------------------------------


def _client(config):
    return ParamScoutClient(scope=config.scope, request_config=config.request, stats=ScanStats())


def test_reflection_is_reported_separately_from_behaviour(app: MockApp) -> None:
    async def scenario():
        config = fast_config()
        active = ActiveConfig(baselines=3, confirmations=2)
        async with _client(config) as client:
            outcome = await probe_endpoint(
                client,
                endpoint=app.base + "/profile",
                url=app.base + "/profile",
                candidates=[candidate("note", SourceKind.HTML_LINK)],
                active=active,
                normalizer=NORMALIZER,
            )
        return outcome

    outcome = asyncio.run(scenario())
    record = outcome.outcomes["note"]
    assert record.reflected is True
    assert record.reflection_count >= 1
    assert record.status is BehavioralStatus.REFLECTION_ONLY
    assert record.attempts == 1, "reflection alone must not trigger confirmation runs"
    assert any("reflection alone is not a vulnerability" in note for note in record.notes)
    result = record.to_behavioral()
    assert result.reflection is not None and result.reflection.reflected


def test_behavioural_change_requires_repeatable_evidence(app: MockApp) -> None:
    async def scenario():
        config = fast_config()
        active = ActiveConfig(baselines=3, confirmations=2)
        async with _client(config) as client:
            outcome = await probe_endpoint(
                client,
                endpoint=app.base + "/search",
                url=app.base + "/search",
                candidates=[candidate("q", SourceKind.HTML_LINK)],
                active=active,
                normalizer=NORMALIZER,
            )
        return outcome

    outcome = asyncio.run(scenario())
    record = outcome.outcomes["q"]
    assert record.status is BehavioralStatus.BEHAVIORAL_CHANGE
    assert record.attempts == 3, "one probe plus two confirmations"
    assert record.signals, "the observed differences must be described"
    assert any("reproduced" in note for note in record.notes)


def test_endpoints_that_ignore_parameters_report_no_change(app: MockApp) -> None:
    async def scenario():
        config = fast_config()
        active = ActiveConfig(baselines=2, confirmations=1)
        async with _client(config) as client:
            outcome = await probe_endpoint(
                client,
                endpoint=app.base + "/static-page",
                url=app.base + "/static-page",
                candidates=[candidate("anything", SourceKind.HTML_LINK)],
                active=active,
                normalizer=NORMALIZER,
            )
        return outcome

    outcome = asyncio.run(scenario())
    record = outcome.outcomes["anything"]
    assert record.status is BehavioralStatus.NO_CHANGE
    assert record.reflected is False
    assert record.attempts == 1


def test_unknown_parameter_control_prevents_false_positives(app: MockApp) -> None:
    """/sensitive reacts to *any* parameter, including the control."""

    async def scenario():
        config = fast_config()
        active = ActiveConfig(baselines=3, confirmations=2)
        async with _client(config) as client:
            outcome = await probe_endpoint(
                client,
                endpoint=app.base + "/sensitive",
                url=app.base + "/sensitive",
                candidates=[candidate("q", SourceKind.HTML_LINK)],
                active=active,
                normalizer=NORMALIZER,
            )
        return outcome

    outcome = asyncio.run(scenario())
    assert outcome.control is not None
    assert outcome.control.reacts_to_unknown_parameters is True
    record = outcome.outcomes["q"]
    assert record.status is not BehavioralStatus.BEHAVIORAL_CHANGE
    assert any("control parameter" in note for note in record.notes)
    assert any("control parameter" in note for note in outcome.notes)


def test_unstable_endpoints_are_inconclusive_not_guesses(app: MockApp) -> None:
    async def scenario():
        config = fast_config()
        active = ActiveConfig(baselines=4, confirmations=1)
        async with _client(config) as client:
            outcome = await probe_endpoint(
                client,
                endpoint=app.base + "/chaotic",
                url=app.base + "/chaotic",
                candidates=[candidate("q", SourceKind.HTML_LINK)],
                active=active,
                normalizer=NORMALIZER,
            )
        return outcome

    outcome = asyncio.run(scenario())
    assert outcome.baseline is not None
    assert outcome.baseline.stable is False
    record = outcome.outcomes["q"]
    assert record.status is BehavioralStatus.INCONCLUSIVE
    assert record.attempts == 0, "an unstable endpoint must not be probed"


def test_dynamic_timestamps_do_not_make_an_endpoint_unstable(app: MockApp) -> None:
    async def scenario():
        config = fast_config()
        async with _client(config) as client:
            baseline = await collect_baseline(
                client, app.base + "/dynamic", app.base + "/dynamic", count=3, config=NORMALIZER
            )
        return baseline

    baseline = asyncio.run(scenario())
    assert baseline.usable
    assert baseline.stable, baseline.notes
    assert baseline.noise_magnitude < 0.30


def test_batch_hits_are_individually_validated(app: MockApp) -> None:
    async def scenario():
        config = fast_config()
        active = ActiveConfig(baselines=3, confirmations=1, batch_size=4)
        candidates = [
            candidate("q", SourceKind.HTML_LINK),
            candidate("zzunknown", SourceKind.WORDLIST),
            candidate("yyunknown", SourceKind.WORDLIST),
            candidate("xxunknown", SourceKind.WORDLIST),
        ]
        async with _client(config) as client:
            outcome = await probe_endpoint(
                client,
                endpoint=app.base + "/search",
                url=app.base + "/search",
                candidates=candidates,
                active=active,
                normalizer=NORMALIZER,
            )
        return outcome

    outcome = asyncio.run(scenario())
    assert outcome.outcomes["q"].status is BehavioralStatus.BEHAVIORAL_CHANGE
    for name in ("zzunknown", "yyunknown", "xxunknown"):
        assert outcome.outcomes[name].status is BehavioralStatus.NO_CHANGE, name
    assert any("batch" in note for note in outcome.notes)


def test_excluded_endpoints_are_never_probed(app: MockApp) -> None:
    async def scenario():
        config = fast_config()
        active = ActiveConfig(baselines=2, excluded_paths=[r"^/checkout"])
        async with _client(config) as client:
            outcome = await probe_endpoint(
                client,
                endpoint=app.base + "/checkout",
                url=app.base + "/checkout",
                candidates=[candidate("order_id", SourceKind.HTML_FORM_FIELD)],
                active=active,
                normalizer=NORMALIZER,
                exclusions=compile_exclusions(active.excluded_paths),
            )
            return outcome, client.stats

    outcome, stats = asyncio.run(scenario())
    assert outcome.excluded is not None
    assert outcome.outcomes["order_id"].status is BehavioralStatus.SKIPPED
    assert stats.requests_total == 0, "an excluded endpoint must cost zero requests"


def test_probe_marks_skipped_when_budget_is_spent(app: MockApp) -> None:
    async def scenario():
        config = fast_config()
        config.request.max_requests = 3  # spent by the baselines
        active = ActiveConfig(baselines=2, confirmations=1)
        async with _client(config) as client:
            outcome = await probe_endpoint(
                client,
                endpoint=app.base + "/static-page",
                url=app.base + "/static-page",
                candidates=[candidate("anything", SourceKind.HTML_LINK)],
                active=active,
                normalizer=NORMALIZER,
            )
            return outcome, client.stats

    outcome, stats = asyncio.run(scenario())
    record = outcome.outcomes["anything"]
    assert record.status is BehavioralStatus.SKIPPED
    assert any("budget" in note for note in record.notes)
    assert stats.requests_total <= 3


def test_assess_delta_needs_both_baseline_and_control_agreement(app: MockApp) -> None:
    async def scenario():
        config = fast_config()
        async with _client(config) as client:
            baseline = await collect_baseline(
                client, app.base + "/search", app.base + "/search", count=2, config=NORMALIZER
            )
            control = await measure_control(client, baseline, config=NORMALIZER)
            probe = build_probe_url(app.base + "/search", "q", make_canary())
            from paramscout.analysis.normalization import compare_fingerprints
            from paramscout.discovery.baseline import _sample_from_result
            from paramscout.http_client import FetchOptions

            result = await client.fetch(probe, FetchOptions(purpose="probe"))
            sample = _sample_from_result(result, NORMALIZER)
            primary = baseline.primary()
            delta = compare_fingerprints(
                primary.fingerprint, sample.fingerprint, baseline_text=primary.text, candidate_text=sample.text
            )
            return baseline, control, assess_delta(delta, baseline, control)

    baseline, control, assessment = asyncio.run(scenario())
    assert control.reacts_to_unknown_parameters is False
    assert assessment.significant is True
    assert assessment.reasons, "every verdict must be explainable"
