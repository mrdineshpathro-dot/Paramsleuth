"""Scan engine: crawl-based discovery, active probing, budgets, and state.

Design notes / tradeoffs
------------------------
- Discovery and probing are separated. Crawling only requests existing
  in-scope resources; active probing is strictly opt-in (``--active``), GET
  only, uses safe alphanumeric canaries and never sends exploit payloads.
- Reflection is tracked separately from behavioral changes. A parameter that
  only reflects its value is reported as such -- never as a vulnerability.
- Stability gates every conclusion: multiple baselines, an unrelated
  random-parameter control per endpoint, and individual re-validation of
  promising candidates with fresh canaries. If an endpoint's ordinary
  responses vary too much, its results are marked inconclusive.
- Batching (``--batch-size > 1``) is supported but the default is one
  candidate per probe; findings from a batch are individually re-validated.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from ..analysis.probe import (
    BaselineModel,
    ResponseFeatures,
    build_baseline,
    decide_probe_difference,
    features_of_response,
)
from ..analysis.reflect import ReflectionInfo, compare_control_reflection, detect_reflection
from ..config import Config
from ..crawler import CrawlResult, Crawler
from ..extractors.base import Collector
from ..http_client import (
    BudgetExceeded,
    HttpClient,
    RequestError,
    ResponseInfo,
    ThrottleStop,
)
from ..models import (
    Candidate,
    DiffObservation,
    DiscoverySourceKind,
    Endpoint,
    Finding,
    ProbeResult,
    ScanMode,
    SourceRef,
    score_to_label,
)
from ..redaction import Redactor
from ..scope import Scope
from ..state import StateStore
from ..urlutils import append_params, normalize_url, split_query

log = logging.getLogger("paramscout.engine")

_ENDPOINT_PURPOSES = {"baseline", "control", "probe", "validation"}


# ---------------------------------------------------------------------------
# Statistics / report containers


@dataclass
class ScanStats:
    requests_by_purpose: dict[str, int] = field(default_factory=dict)
    attempts_total: int = 0
    skipped_off_scope: int = 0
    skipped_reasons: list[str] = field(default_factory=list)
    throttles: int = 0
    throttle_events: list[str] = field(default_factory=list)
    crawled_pages: int = 0
    error_responses: int = 0
    endpoints_discovered: int = 0
    candidates_discovered: int = 0
    endpoints_probed: int = 0
    candidates_probed: int = 0
    budget_truncated: bool = False

    def add_request(self, purpose: str) -> None:
        self.requests_by_purpose[purpose] = self.requests_by_purpose.get(purpose, 0) + 1
        self.attempts_total += 1


@dataclass
class ScanReport:
    mode: str = ScanMode.SCAN.value
    status: str = "ok"  # ok | budget | throttled | interrupted | error
    status_detail: str = ""
    started: float = field(default_factory=time.time)
    ended: float | None = None
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    crawl: CrawlResult | None = None
    limitations: list[str] = field(default_factory=list)
    wordlist_provenance: str | None = None

    @property
    def elapsed(self) -> float:
        end = self.ended if self.ended is not None else time.time()
        return max(0.0, end - self.started)


class _StopScan(Exception):
    def __init__(self, status: str, detail: str = ""):
        super().__init__(detail)
        self.status = status
        self.detail = detail


# ---------------------------------------------------------------------------
# Engine


class ScanEngine:
    """Executes a passive and/or active scan under strict safeguards."""

    def __init__(
        self,
        cfg: Config,
        scope: Scope,
        redactor: Redactor,
        state_store: StateStore | None = None,
    ) -> None:
        self.cfg = cfg
        self.scope = scope
        self.redactor = redactor
        self.stats = ScanStats()
        self.collector = Collector(grouping=cfg.endpoint_grouping)
        self.client: HttpClient | None = None
        self.state: StateStore | None = (
            state_store if state_store is not None else (StateStore(cfg.state_file) if cfg.state_file else None)
        )
        self.findings: list[Finding] = []
        self.limitations: list[str] = []
        self.status = "ok"
        self.status_detail = ""
        self.crawl_result: CrawlResult | None = None
        self.wordlist_provenance: str | None = None
        self._probe_priority_names: set[str] = set()
        self._seed_urls: list[str] = []
        self._current_endpoint: Endpoint | None = None
        self._endpoint_used = 0
        self._control_canary = ""

    # -- metering callbacks ------------------------------------------------
    def _meter(self, purpose: str, host: str) -> None:
        limit = self.cfg.max_requests
        if limit > 0 and self.stats.attempts_total >= limit:
            raise BudgetExceeded(
                f"global request budget of {limit} reached "
                f"({self.stats.attempts_total} attempts)"
            )
        self.stats.add_request(purpose)
        if self._current_endpoint is not None and purpose in _ENDPOINT_PURPOSES:
            self._endpoint_used += 1
        if self.state is not None:
            self.state.increment_request(purpose)

    def _on_skip(self, url: str, reason: str) -> None:
        self.stats.skipped_off_scope += 1
        entry = self.redactor.redact_url(url)
        detail = f"{entry}: {reason}"
        if len(self.stats.skipped_reasons) < 200:
            self.stats.skipped_reasons.append(detail)

    def _on_throttle(self, host: str, status: int, consecutive: int) -> None:
        self.stats.throttles += 1
        if len(self.stats.throttle_events) < 200:
            self.stats.throttle_events.append(
                f"host={host} status={status} consecutive={consecutive}"
            )
        if self.state is not None:
            self.state.add_throttle(host, status, consecutive)

    def _make_client(self) -> HttpClient:
        cookies_by_host: dict[str, dict[str, str]] = {}
        if self.cfg.cookies:
            for host in self.cfg.auth_hosts:
                cookies_by_host[host] = dict(self.cfg.cookies)
        for value in self.cfg.cookies.values():
            self.redactor.add_secret(value)
        for name, value in self.cfg.headers.items():
            if name.lower() in ("authorization", "cookie", "proxy-authorization", "x-api-key"):
                self.redactor.add_secret(value)
        return HttpClient(
            self.scope,
            self.redactor,
            rate=self.cfg.rate,
            concurrency=self.cfg.concurrency,
            timeout=self.cfg.timeout,
            retries=self.cfg.retries,
            backoff_base=self.cfg.backoff_base,
            backoff_max=self.cfg.backoff_max,
            jitter=self.cfg.jitter,
            max_redirects=self.cfg.max_redirects,
            max_response_bytes=self.cfg.max_response_bytes,
            proxy=self.cfg.proxy,
            verify_tls=self.cfg.verify_tls,
            user_agent=self.cfg.user_agent,
            cookies=cookies_by_host,
            custom_headers=self.cfg.headers,
            auth_hosts=self.cfg.auth_hosts,
            meter=self._meter,
            on_skip=self._on_skip,
            on_throttle=self._on_throttle,
            throttle_stop_after=self.cfg.throttle_stop_after,
            throttle_slowdown=self.cfg.throttle_slowdown,
        )

    # ------------------------------------------------------------------
    async def run_scan(self) -> ScanReport:
        report = ScanReport(mode=ScanMode.SCAN.value)
        self.client = self._make_client()
        self._seed_urls = list(self.cfg.seed_urls)
        report.wordlist_provenance = self.wordlist_provenance
        try:
            self._register_seeds_and_wordlists()
            self._persist_discovery_state()
            if self.cfg.crawl:
                crawler = Crawler(
                    self.client, self.scope, self.collector, self.cfg, self.redactor, self.stats
                )
                self.crawl_result = await crawler.crawl(self._seed_urls)
                report.crawl = self.crawl_result
                self.stats.crawled_pages = self.crawl_result.pages_fetched
                self._persist_discovery_state()
            if self.cfg.active:
                await self._active_phase()
            else:
                self._build_passive_findings()
        except (BudgetExceeded, ThrottleStop) as exc:
            self.status = "budget" if isinstance(exc, BudgetExceeded) else "throttled"
            self.status_detail = str(exc)
            self.stats.budget_truncated = self.status == "budget"
            log.warning("scan stopped: %s", self.status_detail)
        except _StopScan as stop:
            self.status = stop.status
            self.status_detail = stop.detail
            self.stats.budget_truncated = stop.status == "budget"
            log.warning("scan stopped: %s", stop.detail or stop.status)
        except asyncio.CancelledError:
            self.status = "interrupted"
            self.status_detail = (
                "interrupted by user; partial progress is saved in the state file "
                "when --state was used"
            )
            self._sync_save()
            report.ended = time.time()
            raise
        finally:
            if self.status != "interrupted":
                await self._shutdown(report)
        report.findings = list(self.findings)
        report.stats = self.stats
        report.status = self.status
        report.status_detail = self.status_detail
        report.limitations = list(self.limitations)
        report.wordlist_provenance = self.wordlist_provenance
        return report

    def _sync_save(self) -> None:
        """Synchronous partial-state save (usable under Ctrl+C cancellation)."""
        if self.state is not None:
            try:
                self.state.set_meta("scan_status", self.status or "interrupted")
                self.state.close()
            except Exception:
                pass
            self.state = None
        if self.client is not None:
            self.client = None  # transport closed by process exit

    async def _shutdown(self, report: ScanReport) -> None:
        report.ended = time.time()
        if self.state is not None:
            try:
                self.state.set_meta("scan_status", self.status)
                self.state.close()
            except Exception as exc:  # pragma: no cover
                log.warning("error closing state store: %s", exc)
            self.state = None
        if self.client is not None:
            try:
                await self.client.aclose()
            except Exception:
                pass
            self.client = None

    # ------------------------------------------------------------------
    def _register_seeds_and_wordlists(self) -> None:
        for url in self._seed_urls:
            normalized = normalize_url(url)
            if not normalized:
                self.stats.skipped_off_scope += 1
                self.stats.skipped_reasons.append(f"{url!r}: invalid seed URL")
                continue
            decision = self.scope.check(normalized)
            if not decision.allowed:
                self.stats.skipped_off_scope += 1
                self.stats.skipped_reasons.append(
                    self.redactor.redact_url(
                        f"{normalized}: seed off-scope -> {decision.reason}"
                    )
                )
                continue
            endpoint = self.collector.record_endpoint(normalized, "seed", is_seed=True)
            if endpoint is not None:
                query = normalized.split("?", 1)[1] if "?" in normalized else ""
                for name, _value in split_query(query):
                    if not name:
                        continue
                    self.collector.add_evidence(
                        endpoint,
                        name,
                        SourceRef(
                            kind=DiscoverySourceKind.QUERY,
                            location=self.redactor.redact_url(normalized),
                            context=f"query parameter {name!r} on the seed URL",
                            weight=0.9,
                        ),
                    )
        if self.cfg.active:
            names, provenance = self._active_names()
            self.wordlist_provenance = provenance
            # Explicit user-supplied names always probe before generated ones,
            # so a caller's wordlist is never starved out by a large built-in list.
            if self.cfg.wordlist:
                from .wordlists import load_wordlist_file

                self._probe_priority_names = set(load_wordlist_file(self.cfg.wordlist))
            else:
                self._probe_priority_names = set()
            seed_ids = [e.id for e in self.collector.endpoints.values() if e.is_seed]
            if names and seed_ids:
                kind = (
                    DiscoverySourceKind.USER_WORDLIST
                    if self.cfg.wordlist
                    else DiscoverySourceKind.BUILTIN_WORDLIST
                )
                self.collector.add_wordlist(seed_ids, names, kind)
        self.stats.endpoints_discovered = len(self.collector.endpoints)
        self.stats.candidates_discovered = len(self.collector.candidates)

    def _active_names(self) -> tuple[list[str], str | None]:
        from .wordlists import names_for_run

        return names_for_run(self.cfg.wordlist, self.cfg.use_builtin_wordlist)

    # ------------------------------------------------------------------
    def _build_passive_findings(self) -> None:
        endpoints, candidates = self.collector.snapshot()
        endpoint_map = {e.id: e for e in endpoints}
        self.stats.endpoints_discovered = len(endpoints)
        self.stats.candidates_discovered = len(candidates)
        for candidate in candidates:
            endpoint = endpoint_map.get(candidate.endpoint_id)
            if endpoint is not None:
                self.findings.append(self._passive_finding(endpoint, candidate))
        self.findings.sort(key=lambda f: (-_priority_rank(f.priority), -f.discovery_score))

    def _passive_finding(self, endpoint: Endpoint, candidate: Candidate) -> Finding:
        reasons: list[str] = []
        if candidate.discovery_score >= 0.75:
            reasons.append(
                "high-confidence discovery: observed in a real URL, form, or "
                "strongly-evidenced script"
            )
        if candidate.security_relevant:
            reasons.append(
                f"name matches security-relevant category {candidate.category!r} "
                "(naming hint only, never a vulnerability claim)"
            )
        if candidate.rarity >= 0.8 and len(self.collector.endpoints) > 3:
            reasons.append(
                f"rare within the collected endpoint set (rarity {candidate.rarity:.2f})"
            )
        if len(candidate.sources) > 1:
            reasons.append(f"corroborated by {len(candidate.sources)} independent sources")
        priority = "low"
        if candidate.security_relevant and candidate.discovery_score >= 0.4:
            priority = "high"
        elif candidate.discovery_score >= 0.75 or candidate.security_relevant:
            priority = "medium"
        return Finding(
            endpoint=endpoint,
            param=candidate.name,
            category=candidate.category,
            discovery_score=candidate.discovery_score,
            discovery_label=score_to_label(candidate.discovery_score),
            priority=priority,
            priority_reasons=reasons,
            source_summary=list(candidate.sources),
        )

    # ------------------------------------------------------------------
    # Active probing
    async def _active_phase(self) -> None:
        endpoints, candidates = self.collector.snapshot()
        endpoint_map = {e.id: e for e in endpoints}
        by_endpoint: dict[str, list[Candidate]] = {}
        for candidate in candidates:
            by_endpoint.setdefault(candidate.endpoint_id, []).append(candidate)
        ordered = sorted(
            endpoint_map.values(),
            key=lambda e: (not e.is_seed, -len(by_endpoint.get(e.id, []))),
        )
        self.stats.endpoints_discovered = len(endpoints)
        self.stats.candidates_discovered = len(candidates)
        for endpoint in ordered:
            if endpoint.virtual or not endpoint.key.startswith("http"):
                continue
            if self._global_budget_exhausted():
                self.limitations.append(
                    f"global request budget reached before endpoint {endpoint.key}"
                )
                break
            candidates_here = by_endpoint.get(endpoint.id, [])
            if not candidates_here:
                continue
            await self._probe_endpoint(endpoint, candidates_here)

    def _global_budget_exhausted(self) -> bool:
        limit = self.cfg.max_requests
        return limit > 0 and self.stats.attempts_total >= limit

    # ------------------------------------------------------------------
    async def _probe_endpoint(self, endpoint: Endpoint, candidates: list[Candidate]) -> None:
        self._current_endpoint = endpoint
        self._endpoint_used = 0
        endpoint_url = endpoint.url
        present = {
            name
            for name, _v in split_query(endpoint_url.split("?", 1)[1] if "?" in endpoint_url else "")
        }
        candidates = [c for c in candidates if c.name not in present]
        if not candidates:
            self._current_endpoint = None
            return

        # 1. Multiple baseline responses ------------------------------------
        baseline_features: list[ResponseFeatures] = []
        for index in range(max(2, self.cfg.baseline_requests)):
            if self._endpoint_budget_left() < 1:
                break
            resp = await self._safe_send(endpoint_url, purpose="baseline")
            if resp is None:
                self._endpoint_error(
                    endpoint, candidates, "baseline request failed after retries"
                )
                self._current_endpoint = None
                return
            if resp.skipped:
                self._current_endpoint = None
                return
            if resp.status_code is not None and resp.status_code >= 500:
                continue  # do not let a transient 5xx poison the baseline
            baseline_features.append(features_of_response(resp))
            if index < self.cfg.baseline_requests - 1:
                await asyncio.sleep(min(self.cfg.delay_between_probes, 0.5))

        baseline = build_baseline(baseline_features, self.cfg)
        if baseline.unstable or not baseline_features:
            reason = baseline.instability_reason or "no valid baseline samples"
            self.limitations.append(
                f"endpoint {endpoint.key}: {reason}; marking results inconclusive"
            )
            for candidate in candidates:
                finding = self._inconclusive_finding(
                    endpoint, candidate, [f"endpoint responses too unstable: {reason}"]
                )
                self.findings.append(finding)
                self._persist_candidate(candidate, finding)
            self.stats.endpoints_probed += 1
            if self.state is not None:
                self.state.mark_endpoint_probed(endpoint.id)
            self._current_endpoint = None
            return

        # 2. Unrelated random-parameter control ------------------------------
        control_features: ResponseFeatures | None = None
        if self._endpoint_budget_left() >= 1:
            control_name = "zzpsctl" + secrets.token_hex(3)
            self._control_canary = _canary()
            control_url = append_params(endpoint_url, [(control_name, self._control_canary)])
            resp = await self._safe_send(control_url, purpose="control")
            if (
                resp is not None
                and not resp.skipped
                and resp.status_code is not None
                and resp.status_code < 500
            ):
                control_features = features_of_response(resp)
        if control_features is None:
            self.limitations.append(
                f"endpoint {endpoint.key}: no control response collected; "
                "candidate differences may be less distinctive"
            )

        # 3. Probe candidates in batches -------------------------------------
        candidates.sort(
            key=lambda c: (
                c.name in self._probe_priority_names,
                c.security_relevant,
                c.discovery_score,
                c.rarity,
            ),
            reverse=True,
        )
        if len(candidates) > self.cfg.max_candidates_per_endpoint:
            self.limitations.append(
                f"endpoint {endpoint.key}: probing truncated to "
                f"{self.cfg.max_candidates_per_endpoint} candidates "
                f"(of {len(candidates)})"
            )
            candidates = candidates[: self.cfg.max_candidates_per_endpoint]
        batch_size = max(1, self.cfg.batch_size)
        self.stats.endpoints_probed += 1
        completed = True
        for start in range(0, len(candidates), batch_size):
            if self._endpoint_budget_left() < 1:
                self.limitations.append(
                    f"endpoint {endpoint.key}: per-endpoint request budget "
                    "exhausted; remaining candidates left pending"
                )
                completed = False
                break
            batch = candidates[start : start + batch_size]
            await self._probe_batch(endpoint, batch, baseline, control_features)
        # An endpoint is only marked probed when fully processed, so an
        # interrupted or budget-truncated scan remains resumable.
        if completed and self.state is not None:
            self.state.mark_endpoint_probed(endpoint.id)
        self._current_endpoint = None

    def _endpoint_error(
        self, endpoint: Endpoint, candidates: list[Candidate], message: str
    ) -> None:
        self.limitations.append(f"endpoint {endpoint.key}: {message}")
        for candidate in candidates:
            finding = self._inconclusive_finding(endpoint, candidate, [message])
            self.findings.append(finding)
            self._persist_candidate(candidate, finding)

    def _inconclusive_finding(
        self, endpoint: Endpoint, candidate: Candidate, reasons: list[str]
    ) -> Finding:
        return Finding(
            endpoint=endpoint,
            param=candidate.name,
            category=candidate.category,
            discovery_score=candidate.discovery_score,
            discovery_label=score_to_label(candidate.discovery_score),
            priority="low",
            priority_reasons=reasons,
            inconclusive=True,
            source_summary=list(candidate.sources),
        )

    # ------------------------------------------------------------------
    async def _probe_batch(
        self,
        endpoint: Endpoint,
        batch: list[Candidate],
        baseline: BaselineModel,
        control: ResponseFeatures | None,
    ) -> None:
        for candidate in batch:
            self.stats.candidates_probed += 1
            result = await self._single_probe(endpoint, candidate, baseline, control)
            if result is None:
                continue  # an error/inconclusive finding was already recorded
            diffs, dominated, feat, reflect, canary = result
            attempts = 1
            reproduced: bool | None = None
            significant = bool(diffs) or reflect.reflected
            if significant and self.cfg.validation_retests > 0:
                kinds_before = {d.kind for d in diffs}
                validated_reflects = 0
                validated_diffs = 0
                best = result  # primary observation; a retest replaces it only when it confirms a signal
                for _ in range(self.cfg.validation_retests):
                    if self._endpoint_budget_left() < 1:
                        break
                    retest = await self._single_probe(
                        endpoint, candidate, baseline, control, purpose="validation"
                    )
                    attempts += 1
                    if retest is None:
                        break
                    vdiffs, _dom, vfeat, vreflect, vcanary = retest
                    if {d.kind for d in vdiffs} & kinds_before:
                        validated_diffs += 1
                    if vreflect.reflected:
                        validated_reflects += 1
                    if vdiffs or vreflect.reflected:
                        best = retest
                diffs, dominated, feat, reflect, canary = best
                reproduced = validated_diffs > 0 or validated_reflects > 0
                if validated_diffs == 0 and validated_reflects == 0:
                    reproduced = False
            finding = self._build_finding(
                endpoint,
                candidate,
                baseline,
                diffs=diffs,
                dominated=dominated,
                reflect=reflect,
                attempts=attempts,
                reproduced=reproduced,
                status_code=feat.status,
                canary=canary,
            )
            self.findings.append(finding)
            self._persist_candidate(candidate, finding)

    async def _single_probe(
        self,
        endpoint: Endpoint,
        candidate: Candidate,
        baseline: BaselineModel,
        control: ResponseFeatures | None,
        *,
        purpose: str = "probe",
    ) -> tuple[list[DiffObservation], bool, ResponseFeatures, ReflectionInfo, str] | None:
        """Probe one candidate with a fresh canary.

        Returns (diffs, dominated, features, reflection, canary) or None after
        recording an inconclusive error finding.
        """
        canary = _canary()
        probe_url = append_params(endpoint.url, [(candidate.name, canary)])
        resp = await self._safe_send(probe_url, purpose=purpose)
        if resp is None or resp.skipped:
            self._record_probe_error(
                endpoint, candidate, canary,
                "probe request failed after retries" if resp is None else "probe skipped (off-scope)",
            )
            return None
        if resp.status_code is not None and resp.status_code >= 500:
            self._record_probe_error(
                endpoint,
                candidate,
                canary,
                f"HTTP {resp.status_code} after retries (treated as transient, not a finding)",
                status=resp.status_code,
            )
            return None
        feat = features_of_response(resp, canary)
        diffs, dominated = decide_probe_difference(baseline, feat, control, self.cfg)
        reflect = feat.reflection
        if control is not None and self._control_canary:
            control_reflect = detect_reflection(
                control.body, self._control_canary, content_type=control.content_type
            )
            compare_control_reflection(reflect, control_reflect)
        return diffs, dominated, feat, reflect, canary

    def _record_probe_error(
        self,
        endpoint: Endpoint,
        candidate: Candidate,
        canary: str,
        message: str,
        *,
        status: int | None = None,
    ) -> None:
        finding = Finding(
            endpoint=endpoint,
            param=candidate.name,
            category=candidate.category,
            discovery_score=candidate.discovery_score,
            discovery_label=score_to_label(candidate.discovery_score),
            priority="low",
            priority_reasons=[message],
            probe=ProbeResult(
                param=candidate.name,
                canary=canary,
                http_status=status,
                error=message,
                attempts=1,
            ),
            inconclusive=True,
            source_summary=list(candidate.sources),
        )
        self.findings.append(finding)
        self._persist_candidate(candidate, finding)

    # ------------------------------------------------------------------
    def _build_finding(
        self,
        endpoint: Endpoint,
        candidate: Candidate,
        baseline: BaselineModel,
        *,
        diffs: list[DiffObservation],
        dominated: bool,
        reflect: ReflectionInfo,
        attempts: int,
        reproduced: bool | None,
        status_code: int | None,
        canary: str,
    ) -> Finding:
        reasons: list[str] = []
        behavior_score: float | None = None
        priority = "low"

        if candidate.discovery_score >= 0.75:
            reasons.append(
                f"high-confidence discovery (score {candidate.discovery_score:.2f})"
            )
        if candidate.security_relevant:
            reasons.append(
                f"security-relevant name category {candidate.category!r} "
                "(naming hint only, never a vulnerability claim)"
            )
        if diffs:
            kinds = ", ".join(sorted({d.kind for d in diffs}))
            if reproduced is True:
                behavior_score = 0.85
                reasons.append(
                    f"repeatable behavioral change reproduced on individual "
                    f"re-validation (dimensions: {kinds})"
                )
            elif reproduced is False:
                behavior_score = 0.35
                reasons.append(
                    f"observed response difference ({kinds}) did NOT reproduce on "
                    "individual re-validation"
                )
            else:
                behavior_score = 0.5
                reasons.append(
                    f"observed response difference ({kinds}); single observation "
                    "(no re-validation performed)"
                )
            if dominated:
                reasons.append(
                    "caution: an unrelated control parameter produced a similar "
                    "change (possible general query-string effect)"
                )
        if reflect.reflected:
            contexts = ", ".join(reflect.contexts) or "response body"
            if reflect.control_also_reflected:
                reasons.append(
                    f"canary reflected in response ({contexts}); the control "
                    "parameter reflected too, so this may be general "
                    "query-string reflection"
                )
            else:
                reasons.append(
                    f"exact canary value reflected in response ({contexts}). "
                    "Reflection is NOT a vulnerability by itself - review how "
                    "the output is encoded"
                )
        if not diffs and not reflect.reflected:
            reasons.append("no behavioral change or reflection observed")

        # Manual-review priority (never a vulnerability severity)
        if (reflect.reflected and not reflect.control_also_reflected) or (
            behavior_score is not None and behavior_score >= 0.8
        ):
            priority = "high"
            if not reasons or "manual" not in " ".join(reasons).lower():
                pass
        elif reflect.reflected or (behavior_score is not None and behavior_score >= 0.5):
            priority = "medium"

        probe_result = ProbeResult(
            param=candidate.name,
            canary=canary,
            http_status=status_code,
            observed_diffs=diffs,
            reflected=reflect.reflected,
            reflect_contexts=reflect.contexts,
            control_similar=dominated,
            reproduced=reproduced,
            attempts=attempts,
            notes=(
                ["control parameter also reflected (general reflection)"]
                if reflect.control_also_reflected
                else []
            ),
        )
        return Finding(
            endpoint=endpoint,
            param=candidate.name,
            category=candidate.category,
            discovery_score=candidate.discovery_score,
            discovery_label=score_to_label(candidate.discovery_score),
            behavior_score=behavior_score,
            behavior_label=score_to_label(behavior_score) if behavior_score is not None else None,
            priority=priority,
            priority_reasons=reasons,
            probe=probe_result,
            source_summary=list(candidate.sources),
        )

    # ------------------------------------------------------------------
    def _endpoint_budget_left(self) -> int:
        per = self.cfg.max_requests_per_endpoint
        if per <= 0:
            return 1
        return per - self._endpoint_used

    async def _safe_send(self, url: str, *, purpose: str) -> ResponseInfo | None:
        assert self.client is not None
        try:
            return await self.client.send(url, purpose=purpose)
        except _StopScan:
            raise
        except (BudgetExceeded, ThrottleStop) as exc:
            raise _StopScan(
                "budget" if isinstance(exc, BudgetExceeded) else "throttled", str(exc)
            ) from exc
        except RequestError as exc:
            log.warning("request error (%s): %s", purpose, self.redactor.redact(str(exc)))
            return None

    # ------------------------------------------------------------------
    # State persistence
    def _persist_discovery_state(self) -> None:
        if self.state is None:
            return
        endpoints, candidates = self.collector.snapshot()
        for endpoint in endpoints:
            self.state.upsert_endpoint(endpoint)
        for candidate in candidates:
            self.state.upsert_candidate(
                candidate.endpoint_id,
                candidate.name,
                candidate.category,
                candidate.discovery_score,
                candidate.security_relevant,
                [s.as_dict() for s in candidate.sources],
            )
        self.state.set_meta("scope", self.scope.as_dict())
        self.state.set_meta("config", self.cfg.redacted_dict())
        self.state.set_meta("seed_urls", self._seed_urls)
        self.state.set_meta("mode", "scan")
        self.state.set_meta("scan_status", "running")

    def _persist_candidate(self, candidate: Candidate, finding: Finding) -> None:
        if self.state is None:
            return
        self.state.set_candidate_status(
            f"{candidate.endpoint_id}|{candidate.name}",
            "error" if finding.inconclusive else "done",
            json.dumps(finding.probe.as_dict()) if finding.probe else "{}",
        )


# ---------------------------------------------------------------------------
# Helpers


def _canary() -> str:
    """Safe alphanumeric canary value (10 hex chars, no URL metacharacters)."""
    return secrets.token_hex(5)


def _priority_rank(priority: str) -> int:
    return {"none": 0, "low": 1, "medium": 2, "high": 3}.get(priority, 0)


# ---------------------------------------------------------------------------
# Resume support


async def run_resume(cfg: Config, scope: Scope, redactor: Redactor) -> ScanReport:
    """Resume an interrupted scan from *cfg.state_file*.

    Scope is re-validated for every persisted endpoint. Credentials must be
    supplied again on the command line (they are never persisted).
    """
    if not cfg.state_file:
        raise ValueError("resume requires --state <file>")
    state = StateStore(cfg.state_file)
    report = ScanReport(mode=ScanMode.SCAN.value)
    try:
        engine = ScanEngine(cfg, scope, redactor, state_store=state)
        engine._seed_urls = list(state.get_meta("seed_urls") or [])
        report.wordlist_provenance = cfg.wordlist or "resumed"
        # Rehydrate persisted endpoints and re-validate scope. Endpoint ids are
        # kept exactly as stored so pending candidates line up.
        unprobed = state.unprobed_endpoints()
        pending_ids: set[str] = set()
        for row in unprobed:
            url = row["url"]
            if not scope.check(url).allowed:
                report.stats.skipped_off_scope += 1
                report.stats.skipped_reasons.append(
                    redactor.redact_url(f"{url}: no longer in scope on resume")
                )
                continue
            endpoint = Endpoint(
                id=row["id"],
                key=row["key"],
                url=row["url"],
                host=row["host"],
                netloc="",
                source=row["source"] or "resumed",
                is_seed=bool(row["is_seed"]),
            )
            engine.collector.endpoints[endpoint.id] = endpoint
            pending_ids.add(endpoint.id)
        pending = state.pending_candidates()
        for row in pending:
            eid = row["endpoint_id"]
            if eid not in pending_ids:
                # endpoint was probed or off-scope; skip
                continue
            try:
                sources = json.loads(row["sources_json"] or "[]")
            except (ValueError, TypeError):
                sources = []
            source_refs = [
                SourceRef(kind=DiscoverySourceKind(s.get("kind", "unknown")), location=s.get("location", ""), context=s.get("context", ""), method=s.get("method", ""))
                for s in sources
            ]
            candidate = Candidate(
                endpoint_id=eid,
                name=row["name"],
                sources=source_refs,
                category=row["category"],
                discovery_score=float(row.get("discovery_score") or 0.0),
            )
            engine.collector.candidates[(eid, row["name"])] = candidate

        # Load previously recorded results as findings too.
        for row in state.results_for(("done", "error")):
            finding = _finding_from_result_row(row)
            if finding is not None:
                report.findings.append(finding)

        if not pending_ids:
            report.status = "nothing-pending"
            report.status_detail = "no pending endpoints/candidates remain in the state file"
        else:
            engine.client = engine._make_client()
            try:
                await engine._active_phase()
            finally:
                if engine.client is not None:
                    await engine.client.aclose()
                    engine.client = None
            report.findings.extend(engine.findings)
            report.stats = engine.stats
            report.limitations = engine.limitations
            report.status = engine.status
    finally:
        state.close()
    report.ended = time.time()
    return report


def _finding_from_result_row(row: dict[str, Any]) -> Finding | None:
    """Rehydrate a finding from a stored candidate row."""
    try:
        result = json.loads(row.get("result_json") or "{}")
    except (ValueError, TypeError):
        result = {}
    endpoint = Endpoint(
        id=row["endpoint_id"],
        key=row["endpoint_key"],
        url=row["endpoint_url"],
        host=row["endpoint_host"],
        netloc="",
        source="resumed",
        is_seed=False,
    )
    probe: ProbeResult | None = None
    if result:
        probe = ProbeResult(**{k: v for k, v in result.items() if k in ProbeResult.__dataclass_fields__})
    return Finding(
        endpoint=endpoint,
        param=row["name"],
        category=row["category"],
        discovery_score=float(row.get("discovery_score") or 0.0),
        discovery_label=score_to_label(float(row.get("discovery_score") or 0.0)),
        probe=probe,
        priority="medium" if probe is not None and probe.reflected else "low",
        priority_reasons=["resumed from saved state"] if probe else [],
        inconclusive=row["status"] in ("error", "inconclusive"),
        source_summary=[],
    )
