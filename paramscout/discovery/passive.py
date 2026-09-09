"""Passive discovery: turn raw observations into a de-duplicated candidate set.

Passive discovery never sends a guessed parameter.  It only reads what the
target (or a user-supplied archive) already told us:

* query strings in supplied, crawled, archived, robots and sitemap URLs;
* HTML links and ``data-*`` attributes;
* HTML form field names, including hidden fields (recorded, never submitted);
* inline and in-scope external JavaScript (heuristic, context retained);
* embedded JSON/configuration objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from paramscout.analysis.dedupe import CandidateSet
from paramscout.crawler import CrawlResult
from paramscout.extractors import FormInfo, extract_from_archive_text, params_from_query
from paramscout.models import Candidate, Evidence, SourceKind
from paramscout.scope import Scope
from paramscout.urls import EndpointGrouping, endpoint_key, normalize_url, split_url


@dataclass
class PassiveResult:
    """Candidate set plus the endpoint index it was built from."""

    candidates: CandidateSet = field(default_factory=CandidateSet)
    endpoint_examples: dict[str, str] = field(default_factory=dict)
    forms: list[FormInfo] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def endpoints(self) -> list[str]:
        return list(self.endpoint_examples)

    def candidates_for(self, endpoint: str) -> list[Candidate]:
        return self.candidates.names_for(endpoint)

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoints": len(self.endpoint_examples),
            "candidates": len(self.candidates),
            "forms": [
                {"action": form.action, "method": form.method, "fields": form.fields}
                for form in self.forms
            ],
            "notes": list(self.notes),
        }


def _remember_endpoint(result: PassiveResult, endpoint: str, url: str, scope: Scope | None) -> None:
    if scope is not None and not scope.check(url).allowed:
        return
    result.endpoint_examples.setdefault(endpoint, url)


def _form_endpoint(forms: list[FormInfo], origin: str, field_name: str, grouping: EndpointGrouping) -> str | None:
    """Find the endpoint a form field belongs to."""

    matches = [form for form in forms if form.origin == origin and field_name in form.fields]
    if len(matches) == 1:
        return endpoint_key(matches[0].action, grouping)
    if len(matches) > 1:
        # Ambiguous (several forms on one page declare the same name): report
        # against the first form and note the ambiguity.
        return endpoint_key(matches[0].action, grouping)
    return None


def build_passive(
    *,
    seeds: list[str],
    archives: list[tuple[str, str]] | None = None,
    crawl_result: CrawlResult | None = None,
    grouping: EndpointGrouping = EndpointGrouping.STRICT,
    scope: Scope | None = None,
) -> PassiveResult:
    """Assemble the passive candidate set from every available source."""

    result = PassiveResult()
    archives = archives or []
    seed_urls = {normalize_url(url) for url in seeds}

    # 1. URLs the operator supplied directly.
    for url in seeds:
        endpoint = endpoint_key(url, grouping)
        _remember_endpoint(result, endpoint, url, scope)
        query = split_url(url).query
        if not query:
            continue
        pairs = params_from_query(
            query, kind=SourceKind.URL_QUERY, origin=url, context="supplied URL query string"
        )
        values = _values_of(url)
        result.candidates.extend(endpoint, pairs, values)

    # 2. User-supplied archives / endpoint collections.  Entries that are also
    # direct seeds are skipped so the same URL is never counted twice.
    for source, text in archives:
        extracted = extract_from_archive_text(text, source=source)
        counted = 0
        for url, _evidence in extracted.endpoints:
            if normalize_url(url) in seed_urls:
                continue
            endpoint = endpoint_key(url, grouping)
            _remember_endpoint(result, endpoint, url, scope)
        for name, evidence in extracted.params:
            if normalize_url(_endpoint_url_for(evidence)) in seed_urls:
                continue
            endpoint = endpoint_key(_endpoint_url_for(evidence), grouping)
            result.candidates.add(endpoint, name, evidence)
            counted += 1
        result.notes.append(f"archive '{source}' contributed {counted} parameter observations")

    if crawl_result is not None:
        result.forms.extend(crawl_result.forms)
        merged = crawl_result.extraction

        # 3. Endpoints the crawler or robots/sitemap saw.
        for endpoint, evidence in crawl_result.endpoints:
            # evidence.origin is the *document* (robots.txt, sitemap.xml); the
            # URL that actually represents the endpoint is evidence.target.
            result.endpoint_examples.setdefault(endpoint, evidence.target or evidence.origin or endpoint)
        for url in merged.urls:
            endpoint = endpoint_key(url, grouping)
            _remember_endpoint(result, endpoint, url, scope)

        # 4. Parameter observations, attributed to the right endpoint.
        for name, evidence in merged.params:
            owner = _endpoint_for_evidence(evidence, crawl_result.forms, grouping)
            if owner is None:
                continue
            if scope is not None and not scope.check(owner).allowed:
                continue
            result.candidates.add(owner, name, evidence)
            # A parameter observed in a link/form/fetch URL tells us about that
            # endpoint even if we never crawled it.
            if evidence.target:
                _remember_endpoint(result, owner, evidence.target, scope)

        for note in crawl_result.notes:
            result.notes.append(note)
        result.notes.append(
            f"crawled {len(crawl_result.pages)} pages, fetched {crawl_result.scripts_fetched} JavaScript files"
        )
    return result


def _values_of(url: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for pair in split_url(url).pairs:
        values.setdefault(pair.name, pair.value)
    return values


def _endpoint_url_for(evidence: Evidence) -> str:
    """Best URL to derive an endpoint from for archive evidence."""

    context = evidence.context.strip()
    if context.startswith("http://") or context.startswith("https://"):
        return context
    return evidence.origin


def _endpoint_for_evidence(
    evidence: Evidence, forms: list[FormInfo], grouping: EndpointGrouping
) -> str | None:
    """Attribute an extraction to the endpoint it actually applies to.

    ``evidence.target`` wins whenever it is known: a parameter found in a link,
    a form field or a ``fetch()`` call belongs to *that* URL, not to the page
    the snippet was read from.
    """

    if evidence.target:
        return endpoint_key(evidence.target, grouping)
    if evidence.kind is SourceKind.HTML_FORM_FIELD:
        field_name = ""
        if "field '" in evidence.detail:
            field_name = evidence.detail.split("field '", 1)[1].split("'", 1)[0]
        form_endpoint = _form_endpoint(forms, evidence.origin, field_name, grouping)
        if form_endpoint:
            return form_endpoint
        return endpoint_key(evidence.origin, grouping)
    if evidence.kind is SourceKind.ARCHIVE:
        return endpoint_key(_endpoint_url_for(evidence), grouping)
    return endpoint_key(evidence.origin, grouping)


def add_wordlist_candidates(
    result: PassiveResult,
    names: list[str],
    *,
    endpoints: list[str] | None = None,
) -> int:
    """Register wordlist guesses against endpoints (used by active mode only).

    Wordlist-only candidates carry the lowest possible discovery confidence and
    are labelled as guesses in every report.
    """

    added = 0
    targets = endpoints or list(result.endpoint_examples)
    for endpoint in targets:
        for name in names:
            if result.candidates.get(endpoint, name) is not None:
                continue
            result.candidates.add(
                endpoint,
                name,
                Evidence(
                    kind=SourceKind.WORDLIST,
                    origin=endpoint,
                    detail="wordlist guess - no target-specific evidence",
                ),
            )
            added += 1
    return added
