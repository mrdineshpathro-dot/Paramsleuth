"""Scan orchestration.

This module owns the end-to-end pipeline:

``load inputs -> (optional) crawl -> passive extraction -> candidate set ->
(optional) active validation -> scoring -> findings -> reports``

It is deliberately free of CLI concerns so it can be driven from tests, from
``python -m paramscout`` or from a library call.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from paramscout.analysis.normalization import NormalizerConfig
from paramscout.analysis.scoring import (
    behavioral_confidence,
    discovery_confidence,
    rarity_score,
    review_priority,
)
from paramscout.config import ScanConfig
from paramscout.crawler import CrawlResult, crawl
from paramscout.discovery.active import (
    DEFAULT_GET_ONLY_WARNING,
    EndpointOutcome,
    ProbeOutcome,
    compile_exclusions,
    endpoint_is_excluded,
    has_real_provenance,
    prepare_endpoint,
    probe_candidates,
    probe_endpoint,
    select_candidates,
)
from paramscout.discovery.passive import PassiveResult, add_wordlist_candidates, build_passive
from paramscout.extractors import (
    extract_from_html,
    parse_archive_line,
)
from paramscout.http_client import ParamScoutClient
from paramscout.models import (
    BehavioralStatus,
    Candidate,
    CandidateStatus,
    Evidence,
    Finding,
    ScanStats,
    SourceKind,
)
from paramscout.redaction import SENSITIVE_HEADERS, redact_url
from paramscout.state import StateStore
from paramscout.throttle import Clock, RequestBudget, ThrottleState
from paramscout.urls import EndpointGrouping, split_url
from paramscout.wordlists import builtin_wordlist, load_wordlist, merge_wordlists

#: Finding statuses that mean "we measured something worth reporting".
REPORTABLE_STATUSES = {
    BehavioralStatus.BEHAVIORAL_CHANGE,
    BehavioralStatus.BEHAVIORAL_CHANGE_UNCONFIRMED,
    BehavioralStatus.REFLECTION_ONLY,
    BehavioralStatus.INCONCLUSIVE,
    BehavioralStatus.ERROR,
}


@dataclass
class ScanContext:
    """Mutable progress for one run; survives Ctrl+C so partials can be saved."""

    config: ScanConfig
    mode: str
    stats: ScanStats = field(default_factory=ScanStats)
    budget: RequestBudget | None = None
    throttle: ThrottleState | None = None
    clock: Clock = field(default_factory=Clock)
    passive: PassiveResult = field(default_factory=PassiveResult)
    crawl_result: CrawlResult | None = None
    outcomes: list[EndpointOutcome] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    store: StateStore | None = None
    interrupted: bool = False
    client_description: dict[str, Any] = field(default_factory=dict)
    plan: dict[str, Any] = field(default_factory=dict)
    omitted_wordlist: int = 0

    def __post_init__(self) -> None:
        request = self.config.request
        self.budget = self.budget or RequestBudget(
            total=request.max_requests, per_endpoint=request.max_requests_per_endpoint
        )
        self.throttle = self.throttle or ThrottleState(
            slowdown_after=request.throttle_slowdown_after,
            stop_after=request.throttle_stop_after,
            factor=request.throttle_slowdown_factor,
        )


# ---------------------------------------------------------------------------
# inputs
# ---------------------------------------------------------------------------


def looks_like_html_text(text: str) -> bool:
    """Cheap sniff for "this file is an HTML document, not a URL list"."""

    stripped = text.lstrip()[:512].lower()
    return stripped.startswith("<!doctype html") or stripped.startswith("<html") or stripped.startswith("<!doc")


def load_inputs(config: ScanConfig) -> tuple[list[str], list[tuple[str, str]]]:
    """Return ``(seeds, archives)`` for a configuration.

    Input files are treated as URL archives.  A file whose content is clearly
    an HTML document is parsed as HTML instead, which is handy for offline
    analysis of saved pages.
    """

    seeds: list[str] = list(config.urls)
    archives: list[tuple[str, str]] = []
    for path in config.input_files:
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"input file not found: {file_path}")
        text = file_path.read_text(encoding="utf-8", errors="replace")
        if file_path.suffix.lower() in {".html", ".htm"} or looks_like_html_text(text):
            origin = seeds[0] if seeds else f"file://{file_path}"
            extracted = extract_from_html(text, origin=origin)
            seeds.extend(url for url in extracted.urls if url.startswith(("http://", "https://")))
            archive_lines = "\n".join(extracted.urls)
            archives.append((str(file_path), archive_lines))
            continue
        archives.append((str(file_path), text))
        for line in text.splitlines():
            # Use the archive parser: dump lines often carry trailing metadata
            # ("URL<TAB>date<TAB>type<TAB>status") that must not become a URL.
            candidate = parse_archive_line(line)
            if candidate is None or not candidate.startswith(("http://", "https://")):
                continue
            if candidate not in seeds:
                seeds.append(candidate)
    return seeds, archives


def sanitize_request(url: str, config: ScanConfig, *, canary: str | None = None) -> str:
    """Build a copy-pasteable, credential-free reproduction request.

    The canary value is replaced with ``[[CANARY]]`` so the report never
    encourages re-using an observed value verbatim, and no credential header
    from the scan configuration is reproduced.
    """

    parts = split_url(url)
    query = parts.query
    if canary and canary in query:
        query = query.replace(canary, "[[CANARY]]")
    target = parts.path or "/"
    if query:
        target = f"{target}?{query}"

    lines = [
        f"GET {target} HTTP/1.1",
        f"Host: {parts.netloc}",
        f"User-Agent: {config.request.user_agent}",
        "Accept: */*",
    ]
    for name, value in config.request.headers.items():
        lowered = name.lower()
        if lowered in SENSITIVE_HEADERS or lowered == "user-agent":
            continue
        lines.append(f"{name}: {value}")
    if config.request.cookies:
        lines.append("Cookie: [REDACTED]  # supplied at runtime, never stored in reports")
    if any(name.lower() in SENSITIVE_HEADERS for name in config.request.headers):
        lines.append("# Authorization/API-key headers from the scan configuration are omitted here")
    lines.append("")
    lines.append("# Replay only against targets you are authorized to test.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------


def build_finding(
    candidate: Candidate,
    *,
    outcome: ProbeOutcome | None,
    frequency: dict[str, int],
    endpoint_count: int,
    config: ScanConfig,
    probe_url: str | None = None,
) -> Finding:
    """Score one candidate and turn it into a report finding."""

    discovery = discovery_confidence(candidate)
    behavioral_result = outcome.to_behavioral() if outcome else None
    behavioral_score = behavioral_confidence(behavioral_result)
    if behavioral_result is not None:
        behavioral_result.confidence = behavioral_score.value
    rarity = rarity_score(candidate.name, frequency, endpoint_count)
    reflected = bool(outcome and outcome.reflected)
    priority, priority_reasons, category = review_priority(
        candidate,
        discovery=discovery,
        behavioral=behavioral_score,
        rarity=rarity,
        reflected=reflected,
    )
    from paramscout.analysis.categories import classify_parameter

    classification = classify_parameter(candidate.name)
    if outcome is None:
        status = CandidateStatus.DISCOVERED
    elif outcome.status is BehavioralStatus.BEHAVIORAL_CHANGE:
        status = CandidateStatus.CONFIRMED
    elif outcome.status is BehavioralStatus.ERROR:
        status = CandidateStatus.ERROR
    elif outcome.status is BehavioralStatus.SKIPPED:
        status = CandidateStatus.SKIPPED
    else:
        status = CandidateStatus.PROBED

    reproduction_url = candidate.endpoint
    if outcome is not None and outcome.probe_urls:
        reproduction_url = outcome.probe_urls[0]
    if probe_url:
        reproduction_url = probe_url
    return Finding(
        endpoint=candidate.endpoint,
        parameter=candidate.name,
        category=classification.category.value,
        category_reason=classification.reason,
        sources=[kind.value for kind in candidate.sources],
        evidence=list(candidate.evidence),
        discovery_confidence=discovery.value,
        discovery_reasons=discovery.reasons + rarity.reasons,
        behavioral=behavioral_result,
        behavioral_confidence=behavioral_score.value,
        review_priority=priority,
        priority_reasons=priority_reasons,
        status=status,
        observed_values=list(candidate.observed_values),
        form_methods=list(candidate.form_methods),
        reproduction=sanitize_request(reproduction_url, config, canary=outcome.canary if outcome else None),
        errors=list(outcome.errors) if outcome else [],
        inconclusive=bool(outcome and outcome.status is BehavioralStatus.INCONCLUSIVE),
    )


def assemble_findings(ctx: ScanContext) -> list[Finding]:
    """Build the finding list from everything the run learned."""

    frequency = ctx.passive.candidates.parameter_frequency()
    endpoint_count = max(1, len(ctx.passive.endpoint_examples))
    findings: list[Finding] = []
    outcomes_by_endpoint: dict[str, EndpointOutcome] = {item.endpoint: item for item in ctx.outcomes}

    for candidate in ctx.passive.candidates:
        endpoint_outcome = outcomes_by_endpoint.get(candidate.endpoint)
        probe: ProbeOutcome | None = None
        if endpoint_outcome is not None:
            probe = endpoint_outcome.outcomes.get(candidate.name)
        if probe is not None and probe.status is BehavioralStatus.NOT_TESTED:
            probe = None

        # Wordlist-only guesses that produced no measurable change are not
        # findings: reporting them would bury the interesting rows in noise.
        # They stay in the state file and in the candidate count.
        from_real_evidence = has_real_provenance(candidate)
        measured_something = probe is not None and probe.status in REPORTABLE_STATUSES
        if not from_real_evidence and not measured_something:
            ctx.omitted_wordlist += 1
            if ctx.store is not None:
                ctx.store.save_candidates(candidate.endpoint, [candidate])
            continue

        finding = build_finding(
            candidate,
            outcome=probe,
            frequency=frequency,
            endpoint_count=endpoint_count,
            config=ctx.config,
        )
        findings.append(finding)
        if ctx.store is not None:
            ctx.store.save_finding(finding)
            ctx.store.save_candidates(candidate.endpoint, [candidate])

    ctx.findings = sorted(
        findings,
        key=lambda item: (-item.review_priority, -item.behavioral_confidence, item.endpoint, item.parameter),
    )
    if ctx.omitted_wordlist:
        ctx.warnings.append(
            f"{ctx.omitted_wordlist} wordlist-only candidates showed no measurable change and are "
            "omitted from the findings list (they remain in the state file)"
        )
    return ctx.findings


# ---------------------------------------------------------------------------
# offline extract
# ---------------------------------------------------------------------------


def run_extract(config: ScanConfig) -> ScanContext:
    """Analyse local input without any network access."""

    ctx = ScanContext(config=config, mode="extract-offline")
    seeds, archives = load_inputs(config)
    if config.scope.hosts:
        allowed, rejected = config.scope.filter(seeds)
        for url, reason in rejected:
            ctx.warnings.append(f"input URL excluded from analysis: {redact_url(url)} ({reason})")
        seeds = allowed
    else:
        ctx.warnings.append(
            "no scope configured: running fully offline, no network requests are possible in this mode"
        )
    ctx.passive = build_passive(
        seeds=seeds,
        archives=archives,
        crawl_result=None,
        grouping=config.output.endpoint_grouping,
        scope=config.scope if config.scope.hosts else None,
    )
    ctx.passive.notes.append("offline mode: no HTTP requests were made")
    ctx.limitations.append(
        "offline mode: only parameters already present in the supplied URLs/files were considered"
    )
    assemble_findings(ctx)
    ctx.stats.elapsed_seconds = ctx.clock.elapsed()
    return ctx


# ---------------------------------------------------------------------------
# network scan
# ---------------------------------------------------------------------------


def _seeds_for_scan(config: ScanConfig) -> tuple[list[str], list[tuple[str, str]]]:
    seeds, archives = load_inputs(config)
    allowed: list[str] = []
    for url in seeds:
        if config.scope.check(url).allowed:
            allowed.append(url)
    return allowed, archives


def _warn_once(ctx: ScanContext, message: str) -> None:
    """Record a warning on the context without duplicating it.

    Planning and execution can both reach the same standing notice, and a report
    that repeats one warning four times stops being readable.
    """

    if message not in ctx.warnings:
        ctx.warnings.append(message)


async def _gather(ctx: ScanContext, coroutines: list[Any]) -> None:
    """``asyncio.gather`` that turns Ctrl+C into a clean partial-result stop.

    A real SIGINT arrives as ``KeyboardInterrupt`` inside whichever task is
    awaiting I/O.  Letting it unwind the loop prints a confusing "Task
    exception was never retrieved" traceback, so it is caught here, recorded on
    the context, and reported as an interruption instead.
    """

    try:
        await asyncio.gather(*coroutines)
    except KeyboardInterrupt:
        ctx.interrupted = True
        ctx.warnings.append("interrupted by user; partial results were saved")
    except asyncio.CancelledError:
        ctx.interrupted = True
        raise


async def _run_network(ctx: ScanContext) -> None:
    config = ctx.config
    assert ctx.budget is not None and ctx.throttle is not None
    seeds, archives = _seeds_for_scan(config)
    if not seeds:
        ctx.warnings.append("no in-scope seed URLs; nothing to crawl")
    async with ParamScoutClient(
        scope=config.scope,
        request_config=config.request,
        stats=ctx.stats,
        budget=ctx.budget,
        throttle_state=ctx.throttle,
    ) as client:
        ctx.client_description = client.describe()
        if config.crawl.depth >= 0 and seeds:
            try:
                ctx.crawl_result = await crawl(
                    client,
                    seeds,
                    config.crawl,
                    grouping=config.output.endpoint_grouping,
                )
            except KeyboardInterrupt:
                ctx.interrupted = True
                ctx.warnings.append("interrupted during crawl; partial results were saved")
        ctx.passive = build_passive(
            seeds=seeds,
            archives=archives,
            crawl_result=ctx.crawl_result,
            grouping=config.output.endpoint_grouping,
            scope=config.scope,
        )
        if config.active.enabled:
            await _run_active(ctx, client)
        else:
            ctx.limitations.append(
                "passive mode: no parameters were guessed or sent; run with --active for controlled "
                "active discovery on authorized targets"
            )


async def _run_active(ctx: ScanContext, client: ParamScoutClient) -> None:
    """Run controlled active discovery across all eligible endpoints.

    Work is ordered deliberately:

    1. every eligible endpoint is prepared first (baselines + control), so the
       budget is not consumed before we know which endpoints are even stable;
    2. candidates with target-specific evidence are probed next, round-robin
       across endpoints;
    3. wordlist guesses are probed last, also round-robin.

    Round-robin matters: without it, the first endpoint's 100-odd wordlist
    guesses would exhaust the request budget and later endpoints would never be
    examined at all.
    """

    config = ctx.config
    _warn_once(ctx, DEFAULT_GET_ONLY_WARNING)

    exclusions = compile_exclusions(config.active.excluded_paths)
    normalizer = NormalizerConfig(
        similarity_max_chars=config.active.similarity_max_chars,
        similarity_min_chars=config.active.similarity_min_chars,
    )

    targets, excluded_targets = _active_targets(ctx, exclusions)
    for endpoint, url, reason in excluded_targets:
        outcome = EndpointOutcome(endpoint=endpoint, url=url, excluded=reason)
        outcome.notes.append(f"endpoint not probed: {reason}")
        ctx.outcomes.append(outcome)
        if ctx.store is not None:
            ctx.store.mark_endpoint(endpoint, "excluded")
    if not targets:
        ctx.warnings.append("no endpoints eligible for active probing after exclusions")
        return

    names = _wordlist_names(config)
    if names:
        add_wordlist_candidates(ctx.passive, names, endpoints=[endpoint for endpoint, _url in targets])
        ctx.warnings.append(
            f"{len(names)} wordlist names are being probed against {len(targets)} endpoints; "
            "wordlist-only candidates are the weakest evidence class and are labelled as guesses"
        )

    confidence = {
        candidate.name: discovery_confidence(candidate).value
        for candidate in ctx.passive.candidates
    }
    concurrency = max(1, config.request.concurrency)
    semaphore = asyncio.Semaphore(concurrency)

    # -- phase 1: prepare every endpoint ----------------------------------
    outcomes: dict[str, EndpointOutcome] = {}

    async def prepare(endpoint: str, url: str) -> None:
        async with semaphore:
            if ctx.interrupted:
                return
            outcome = await prepare_endpoint(
                client,
                endpoint=endpoint,
                url=url,
                active=config.active,
                normalizer=normalizer,
                exclusions=exclusions,
            )
            outcomes[endpoint] = outcome
            ctx.outcomes.append(outcome)

    await _gather(ctx, [prepare(endpoint, url) for endpoint, url in targets])

    # -- phase 2/3: probe candidates, evidence first -----------------------
    real: dict[str, list[Any]] = {}
    guesses: dict[str, list[Any]] = {}
    for endpoint, _url in targets:
        endpoint_candidates = ctx.passive.candidates_for(endpoint)
        selected_real, selected_guesses = select_candidates(
            endpoint_candidates, config.active, confidence
        )
        dropped = len(endpoint_candidates) - len(selected_real) - len(selected_guesses)
        if dropped > 0:
            outcomes[endpoint].notes.append(
                f"{dropped} candidates skipped by --max-candidates-per-endpoint"
            )
        real[endpoint] = selected_real
        guesses[endpoint] = selected_guesses
        outcome = outcomes[endpoint]
        if outcome.excluded or outcome.baseline is None or not outcome.baseline.stable:
            # No probing will happen here; still record why for every candidate.
            await probe_candidates(
                client,
                outcome,
                endpoint_candidates,
                active=config.active,
                normalizer=normalizer,
                confidence=confidence,
            )
            real[endpoint] = []
            guesses[endpoint] = []

    queue: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()
    for group in (real, guesses):
        for pair in _interleave(group):
            queue.put_nowait(pair)

    async def probe_one(endpoint: str, candidate: Any) -> None:
        await probe_candidates(
            client,
            outcomes[endpoint],
            [candidate],
            active=config.active,
            normalizer=normalizer,
            confidence=confidence,
        )

    async def worker() -> None:
        while not ctx.interrupted:
            try:
                endpoint, candidate = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            async with semaphore:
                await probe_one(endpoint, candidate)

    await _gather(ctx, [worker() for _ in range(concurrency)])

    # Only mark an endpoint finished when its candidates were really all
    # examined - otherwise a resumed scan would skip the unfinished work.
    if ctx.store is not None:
        for endpoint, _url in targets:
            outcome = outcomes[endpoint]
            starved = any(
                "budget" in note
                for record in outcome.outcomes.values()
                for note in record.notes
            )
            if not ctx.interrupted and not starved:
                ctx.store.mark_endpoint(endpoint, "done")

    probed = sum(len(outcome.outcomes) for outcome in outcomes.values())
    ctx.warnings.append(f"active discovery examined {probed} (endpoint, parameter) pairs")


def _interleave(groups: dict[str, list[Any]]) -> list[tuple[str, Any]]:
    """Round-robin several per-endpoint lists into one fair work order."""

    from collections import deque

    queues = {endpoint: deque(items) for endpoint, items in groups.items() if items}
    ordered: list[tuple[str, Any]] = []
    while queues:
        for endpoint in list(queues):
            queue = queues[endpoint]
            if queue:
                ordered.append((endpoint, queue.popleft()))
            if not queue:
                del queues[endpoint]
    return ordered


def _active_targets(
    ctx: ScanContext, exclusions: list[Any]
) -> tuple[list[tuple[str, str]], list[tuple[str, str, str]]]:
    """Split eligible endpoints into ``(probe, excluded)`` lists."""

    config = ctx.config
    targets: list[tuple[str, str]] = []
    excluded: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for endpoint, url in ctx.passive.endpoint_examples.items():
        if not config.scope.check(url).allowed:
            continue
        if endpoint in seen:
            continue
        reason = endpoint_is_excluded(endpoint, exclusions)
        if reason:
            ctx.stats.skipped_excluded += 1
            ctx.warnings.append(f"endpoint excluded from active probing: {endpoint} ({reason})")
            seen.add(endpoint)
            excluded.append((endpoint, url, reason))
            if ctx.store is not None:
                ctx.store.upsert_endpoint(endpoint, url, status="pending", candidates=0)
            continue
        seen.add(endpoint)
        targets.append((endpoint, url))
        if ctx.store is not None:
            ctx.store.upsert_endpoint(
                endpoint, url, status="pending", candidates=len(ctx.passive.candidates_for(endpoint))
            )
    limit = config.active.max_active_endpoints
    if len(targets) > limit:
        ctx.warnings.append(
            f"{len(targets) - limit} eligible endpoints were not probed (--max-active-endpoints {limit})"
        )
        targets = targets[:limit]
    return targets, excluded


def _wordlist_names(config: ScanConfig) -> list[str]:
    lists: list[list[str]] = []
    for path in config.active.wordlists:
        lists.append(load_wordlist(path))
    if config.active.use_builtin_wordlist:
        lists.append(builtin_wordlist())
    return merge_wordlists(*lists)


def run_scan(config: ScanConfig) -> ScanContext:
    """Run a scan (passive or active) against the authorized scope."""

    ctx = ScanContext(config=config, mode="active" if config.active.enabled else "passive")
    if config.output.state_path:
        ctx.store = StateStore(config.output.state_path)
        ctx.store.save_config(config)
    if not config.dry_run:
        try:
            asyncio.run(_run_network(ctx))
        except KeyboardInterrupt:  # pragma: no cover - interactive
            ctx.interrupted = True
            ctx.warnings.append("interrupted by user; partial results were saved")
    else:
        ctx.plan = build_plan(ctx)
    if not config.dry_run:
        assemble_findings(ctx)
    ctx.stats.elapsed_seconds = ctx.clock.elapsed()
    ctx.stats.endpoints_seen = len(ctx.passive.endpoint_examples)
    ctx.stats.candidates_total = len(ctx.passive.candidates)
    ctx.stats.throttle_events = list(ctx.throttle.events) if ctx.throttle else []
    ctx.stats.interrupted = ctx.interrupted
    if ctx.store is not None:
        ctx.store.save_stats(ctx.stats.to_dict())
    return ctx


# ---------------------------------------------------------------------------
# dry run
# ---------------------------------------------------------------------------


def build_plan(ctx: ScanContext) -> dict[str, Any]:
    """Describe what a scan would do, without any network activity."""

    config = ctx.config
    seeds, archives = _seeds_for_scan(config)
    rejected: list[str] = []
    for url in list(config.urls):
        decision = config.scope.check(url)
        if not decision.allowed:
            rejected.append(f"{redact_url(url)} ({decision.reason})")
    offline = build_passive(
        seeds=seeds,
        archives=archives,
        crawl_result=None,
        grouping=config.output.endpoint_grouping,
        scope=config.scope,
    )
    names = _wordlist_names(config) if config.active.enabled else []
    if names:
        add_wordlist_candidates(offline, names)

    candidates_per_endpoint = {
        endpoint: min(len(offline.candidates_for(endpoint)), config.active.max_candidates_per_endpoint)
        for endpoint in offline.endpoint_examples
    }
    real_per_endpoint = {
        endpoint: len([item for item in offline.candidates_for(endpoint) if has_real_provenance(item)])
        for endpoint in offline.endpoint_examples
    }
    crawl_estimate = min(config.crawl.max_pages, 10**6) if config.crawl.depth >= 0 else 0
    active_estimate = 0
    if config.active.enabled:
        per_endpoint = (
            config.active.baselines
            + 1
            + sum(
                count * (1 + config.active.confirmations)
                for count in candidates_per_endpoint.values()
            )
        )
        active_estimate = per_endpoint
    total = crawl_estimate + config.crawl.max_js_files + 2 + active_estimate

    stages = [
        ("scope", ", ".join(rule.host for rule in config.scope.hosts) or "none configured"),
        ("seeds", f"{len(seeds)} in-scope URLs from --url/--input"),
        ("crawl", f"depth {config.crawl.depth}, max {config.crawl.max_pages} pages" if config.crawl.depth >= 0 else "disabled"),
        ("robots/sitemap", f"robots={config.crawl.fetch_robots} sitemap={config.crawl.fetch_sitemap}"),
        ("javascript", f"extract={config.crawl.extract_js} external={config.crawl.fetch_external_js}"),
        ("passive", "extract parameters from URLs, forms, JS and JSON (no guessing)"),
    ]
    if config.active.enabled:
        stages.append(
            (
                "active",
                f"GET-only probing of {len(candidates_per_endpoint)} endpoints, "
                f"batch size {config.active.batch_size}, {config.active.baselines} baselines, "
                f"{config.active.confirmations} confirmations per hit",
            )
        )
        if config.active.batch_size > 1:
            stages.append(
                (
                    "active/batch caveat",
                    "batch results cannot be attributed to a single parameter; every hit is re-probed alone",
                )
            )
            _warn_once(
                ctx,
                "batch size "
                f"{config.active.batch_size}: a change observed in a batch cannot be attributed to a single "
                "parameter, and a quiet batch does not prove that none of its members has an effect. "
                "Every batch hit is re-probed individually before it is reported.",
            )
        # A dry run never reaches _run_active, so record the standing GET-only
        # warning here too: the report must carry it even when nothing was sent.
        _warn_once(ctx, DEFAULT_GET_ONLY_WARNING)
    else:
        stages.append(("active", "disabled (passive mode)"))

    return {
        "stages": stages,
        "budget": {
            "crawl requests (worst case)": crawl_estimate,
            "javascript fetches (worst case)": config.crawl.max_js_files,
            "robots + sitemap": 2,
            "active requests (estimate)": active_estimate,
            "estimated total": total,
            "configured --max-requests": config.request.max_requests,
            "per-endpoint cap": config.request.max_requests_per_endpoint,
            "fits in budget": "yes" if total <= config.request.max_requests else "NO - raise --max-requests or narrow scope",
        },
        "endpoints": [
            {
                "endpoint": endpoint,
                "candidates": count,
                "candidates_from_evidence": real_per_endpoint.get(endpoint, 0),
                "candidates_from_wordlist": count - real_per_endpoint.get(endpoint, 0),
                "source": "supplied URL / input file",
            }
            for endpoint, count in candidates_per_endpoint.items()
        ],
        "rejected_seeds": rejected,
    }


# ---------------------------------------------------------------------------
# resume
# ---------------------------------------------------------------------------


def scan_config_from_dict(data: dict[str, Any]) -> ScanConfig:
    """Rebuild a :class:`ScanConfig` from the resume store.

    Credentials are not in the store, so the returned config has empty cookies
    and no ``Authorization`` header unless the operator supplies them again.
    """

    config = ScanConfig()
    for key, value in (data.get("request") or {}).items():
        if hasattr(config.request, key) and key not in {"headers", "cookies"}:
            setattr(config.request, key, value)
    for name, value in (data.get("request") or {}).get("headers", {}).items():
        if value != "[REDACTED]":
            config.request.headers[name] = value
    for key, value in (data.get("crawl") or {}).items():
        if hasattr(config.crawl, key):
            setattr(config.crawl, key, tuple(value) if isinstance(getattr(config.crawl, key), tuple) else value)
    for key, value in (data.get("active") or {}).items():
        if hasattr(config.active, key):
            setattr(config.active, key, value)
    scope_data = data.get("scope") or {}
    for item in scope_data.get("hosts", []):
        config.scope.add_host(
            item.get("host", ""),
            include_subdomains=bool(item.get("include_subdomains")),
        )
    config.scope.allow_private_networks = bool(scope_data.get("allow_private_networks", False))
    for pattern in scope_data.get("allow_paths", []):
        from paramscout.scope import compile_path_rule

        config.scope.allow_paths.append(compile_path_rule(pattern))
    for pattern in scope_data.get("deny_paths", []):
        from paramscout.scope import compile_path_rule

        config.scope.deny_paths.append(compile_path_rule(pattern))
    output = data.get("output") or {}
    if output.get("endpoint_grouping"):
        config.output.endpoint_grouping = EndpointGrouping(str(output["endpoint_grouping"]))
    config.urls = list(data.get("urls") or [])
    config.input_files = list(data.get("input_files") or [])
    config.active.enabled = bool(config.active.enabled)
    return config


def run_resume(state_path: str, *, overrides: ScanConfig | None = None) -> ScanContext:
    """Continue an interrupted scan from its SQLite state file."""

    store = StateStore(state_path)
    stored = store.load_config()
    if not stored:
        raise ValueError(f"state file {state_path} contains no saved scan configuration")
    config = scan_config_from_dict(stored)
    config.output.state_path = state_path
    if overrides is not None:
        config.request.cookies = overrides.request.cookies or config.request.cookies
        for name, value in overrides.request.headers.items():
            config.request.headers[name] = value
        config.request.max_requests = overrides.request.max_requests
        config.output.json_path = overrides.output.json_path or config.output.json_path
        config.output.csv_path = overrides.output.csv_path or config.output.csv_path
        config.output.html_path = overrides.output.html_path or config.output.html_path

    ctx = ScanContext(config=config, mode="resumed", store=store)
    pending = store.pending_endpoints()
    config.active.enabled = True
    ctx.warnings.append(
        "resumed scan: cookies and Authorization headers are not stored in the state file; "
        "re-supply --cookie/--header if the target needs authentication"
    )
    ctx.warnings.append(f"{len(pending)} endpoints remained pending in {state_path}")

    async def _resume() -> None:
        if not pending:
            return
        async with ParamScoutClient(
            scope=config.scope,
            request_config=config.request,
            stats=ctx.stats,
            budget=ctx.budget,
            throttle_state=ctx.throttle,
        ) as client:
            ctx.client_description = client.describe()
            normalizer = NormalizerConfig(
                similarity_max_chars=config.active.similarity_max_chars,
                similarity_min_chars=config.active.similarity_min_chars,
            )
            exclusions = compile_exclusions(config.active.excluded_paths)
            stored_candidates = store.load_candidates()
            for row in pending:
                endpoint = row["endpoint"]
                url = row["url"]
                candidates = _candidates_from_rows(endpoint, stored_candidates)
                if not candidates:
                    for name in _wordlist_names(config)[: config.active.max_candidates_per_endpoint]:
                        candidates.append(
                            Candidate(
                                endpoint=endpoint,
                                name=name,
                                evidence=[
                                    Evidence(
                                        kind=SourceKind.WORDLIST,
                                        origin=endpoint,
                                        detail="wordlist guess on resume",
                                    )
                                ],
                            )
                        )
                ctx.passive.endpoint_examples.setdefault(endpoint, url)
                for candidate in candidates:
                    ctx.passive.candidates.add(endpoint, candidate.name, candidate.evidence[0])
                outcome = await probe_endpoint(
                    client,
                    endpoint=endpoint,
                    url=url,
                    candidates=candidates,
                    active=config.active,
                    normalizer=normalizer,
                    exclusions=exclusions,
                )
                ctx.outcomes.append(outcome)
                store.mark_endpoint(endpoint, "done")

    try:
        asyncio.run(_resume())
    except KeyboardInterrupt:  # pragma: no cover - interactive
        ctx.interrupted = True
        ctx.warnings.append("interrupted again; progress saved")

    assemble_findings(ctx)
    ctx.stats.elapsed_seconds = ctx.clock.elapsed()
    ctx.stats.throttle_events = list(ctx.throttle.events) if ctx.throttle else []
    ctx.stats.interrupted = ctx.interrupted
    store.save_stats(ctx.stats.to_dict())
    return ctx


def _candidates_from_rows(endpoint: str, rows: list[dict[str, Any]]) -> list[Candidate]:
    out: list[Candidate] = []
    for row in rows:
        if row.get("endpoint") != endpoint:
            continue
        import json

        try:
            evidence_data = json.loads(row.get("evidence") or "[]")
        except json.JSONDecodeError:
            evidence_data = []
        evidence = [
            Evidence(
                kind=SourceKind(item.get("kind", SourceKind.WORDLIST.value)),
                origin=item.get("origin", endpoint),
                detail=item.get("detail", ""),
                context=item.get("context", ""),
                line=item.get("line"),
            )
            for item in evidence_data
        ] or [Evidence(kind=SourceKind.WORDLIST, origin=endpoint, detail="restored from state file")]
        out.append(Candidate(endpoint=endpoint, name=row.get("name", ""), evidence=evidence))
    return out
