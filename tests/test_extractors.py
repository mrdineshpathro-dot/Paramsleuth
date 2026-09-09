"""HTML / form / JavaScript / query extraction tests."""

from paramscout.extractors.base import Collector, classify_hint
from paramscout.extractors.html import extract_from_html
from paramscout.extractors.javascript import extract_from_js_text
from paramscout.models import DiscoverySourceKind
from paramscout.redaction import Redactor

REDACTOR = Redactor()

HTML_DOC = """<!DOCTYPE html>
<html><head><title>t</title>
<script src="/assets/app.js"></script>
<script type="application/json" id="cfg">{"app":{"params":{"order":"desc"}}}</script>
</head>
<body>
<a href="/search?q=alpha&q=beta&blank=">search</a>
<a href="http://evil.example.net/x?a=1">off scope link (never fetched offline)</a>
<form method="POST" action="/login">
  <input type="hidden" name="csrf_token" value="abc">
  <input type="text" name="username">
  <select name="role"><option>a</option></select>
  <textarea name="bio"></textarea>
</form>
<script>
  const sp = new URLSearchParams(location.search);
  const a = sp.get("tab");
  const b = sp.get("preview");
  fetch("/api?page=2&callback=cb");
  axios.get("/x", { params: { sort: "asc", limit: 5 } });
  if (query.state) {}
</script>
</body></html>
"""


def _collect_html():
    collector = Collector(grouping="path")
    extract_from_html(
        collector,
        HTML_DOC,
        page_url="http://app.example.test/start",
        redactor=REDACTOR,
        inline_js=True,
    )
    endpoints, candidates = collector.snapshot()
    return collector, endpoints, candidates


def test_html_form_and_link_extraction():
    collector, endpoints, candidates = _collect_html()
    by_name = {(c.endpoint_id, c.name): c for c in candidates}
    names = {c.name for c in candidates}
    # form fields incl hidden fields
    assert {"csrf_token", "username", "role", "bio"}.issubset(names)
    # query params from in-document URLs
    assert "q" in names and "blank" in names
    # inline JS / JSON config evidence
    assert "tab" in names and "preview" in names
    assert "order" in names  # embedded JSON under params key


def test_source_provenance_kept_and_deduped():
    collector, _, candidates = _collect_html()
    q_cands = [c for c in candidates if c.name == "q"]
    assert q_cands, "expected q candidates"
    # q appears twice in the same in-document URL; dedupe should merge sources
    total_sources = sum(len(c.sources) for c in q_cands)
    # single candidate for that endpoint carrying merged evidence
    assert len(q_cands) == 1
    assert total_sources == 1  # identical evidence merged once


def test_form_method_recorded_never_submitted():
    collector, _, candidates = _collect_html()
    form = [c for c in candidates if c.name == "csrf_token"][0]
    sources = form.sources
    assert any(s.kind == DiscoverySourceKind.FORM and s.method == "POST" for s in sources)


def test_links_returned_for_crawl():
    collector = Collector()
    result = extract_from_html(
        collector,
        HTML_DOC,
        page_url="http://app.example.test/start",
        redactor=REDACTOR,
    )
    assert "/search?q=alpha&q=beta&blank=" in "".join(result.navigable_links)
    assert result.script_urls == ["http://app.example.test/assets/app.js"]


def test_javascript_heuristics_strong_and_weak():
    refs = extract_from_js_text(
        "const x=new URLSearchParams(u); x.get('mode'); x.set('debug','1');",
        location="inline",
        redactor=REDACTOR,
    )
    names = {r.param for r in refs}
    assert "mode" in names and "debug" in names
    strong = {r.param: r.source.weight for r in refs}
    assert strong["mode"] >= 0.7


def test_javascript_reserved_words_filtered():
    refs = extract_from_js_text(
        "if (params.query) { http.get('x'); } const q = url.search;",
        location="inline",
        redactor=REDACTOR,
    )
    assert all(r.param not in ("http", "query", "url", "search", "get") for r in refs)


def test_query_extractor_blank_and_repeated():
    collector = Collector()
    collector.add_url_query(
        "http://app.example.test/x?a=1&a=&b&a=3",
        source_kind=DiscoverySourceKind.QUERY,
    )
    # two more URLs that collapse onto the same endpoint but carry evidence
    # from distinct locations
    collector.add_url_query(
        "http://app.example.test/x?a=2",
        source_kind=DiscoverySourceKind.QUERY,
    )
    collector.add_url_query(
        "http://app.example.test/x?b=blank",
        source_kind=DiscoverySourceKind.QUERY,
    )
    _, candidates = collector.snapshot()
    a = [c for c in candidates if c.name == "a"][0]
    # identical in-URL occurrences merge; distinct URL evidence is preserved
    assert len(a.sources) == 2
    b = [c for c in candidates if c.name == "b"][0]
    assert len(b.sources) == 2  # "b" blank-value occurrence + b=blank URL
    assert any(s.context for s in a.sources)


def test_classification_categories():
    assert classify_hint("next")[0] == "redirect/navigation"
    assert classify_hint("redirect_url")[0] == "redirect/navigation"
    assert classify_hint("token")[0] == "authentication/session"
    assert classify_hint("q")[0] == "search/filtering"
    assert classify_hint("debug")[0] == "debug/configuration"
    assert classify_hint("user_id")[0] in ("resource identifier",)
    assert classify_hint("totally_random_name_xyz")[0] == "unknown/general-purpose"
    assert classify_hint("callback")[0] == "remote-resource reference"


def test_wordlist_candidates():
    collector = Collector()
    endpoint = collector.record_endpoint("http://app.example.test/", "test")
    collector.add_wordlist(
        [endpoint.id], ["next", "page"], DiscoverySourceKind.USER_WORDLIST
    )
    _, candidates = collector.snapshot()
    assert {c.name for c in candidates} == {"next", "page"}
    assert next(c for c in candidates if c.name == "next").discovery_score <= 0.4
