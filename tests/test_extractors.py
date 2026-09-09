"""HTML, form, JavaScript, JSON, robots, sitemap and archive extraction tests."""

from __future__ import annotations

from paramscout.extractors import (
    extract_from_archive_text,
    extract_from_html,
    extract_from_javascript,
    extract_from_json_text,
    extract_from_robots,
    extract_from_sitemap,
)
from paramscout.models import SourceKind

ORIGIN = "https://app.example.test/index"


def names(result) -> list[str]:
    return [name for name, _ in result.params]


def test_html_links_and_forms_are_extracted() -> None:
    html = """
    <html><body>
      <a href="/search?q=widgets&amp;sort=asc">search</a>
      <a href="https://other.example.test/x?a=1">off site</a>
      <form action="/apply" method="POST">
        <input type="hidden" name="csrf_token" value="abc">
        <input name="email">
        <select name="country"><option>nl</option></select>
        <button formaction="/apply-draft" name="draft_id">save</button>
      </form>
      <img src="/img/logo.png?v=3">
      <div data-url="/api/items?category=books&amp;page=2"></div>
    </body></html>
    """
    result = extract_from_html(html, origin=ORIGIN)
    found = names(result)
    for expected in ("q", "sort", "a", "csrf_token", "email", "country", "draft_id", "v", "category", "page"):
        assert expected in found, expected
    assert result.forms, "forms must be recorded as passive evidence"
    form = result.forms[0]
    assert form.method == "POST"
    assert form.action == "https://app.example.test/apply"
    assert set(form.fields) >= {"csrf_token", "email", "country", "draft_id"}


def test_form_fields_are_attributed_to_the_form_action() -> None:
    html = "<form action='/apply' method='POST'><input name='email'></form>"
    result = extract_from_html(html, origin=ORIGIN)
    email = [evidence for name, evidence in result.params if name == "email"]
    assert email, "the form field must be extracted"
    assert email[0].target == "https://app.example.test/apply"
    assert email[0].origin == ORIGIN  # provenance is the page it was found on
    assert "POST" in email[0].detail


def test_hidden_fields_are_flagged() -> None:
    html = "<form><input type='hidden' name='source' value='home'><input name='q'></form>"
    result = extract_from_html(html, origin=ORIGIN)
    by_name = {name: evidence for name, evidence in result.params}
    assert "(hidden)" in by_name["source"].detail
    assert "(hidden)" not in by_name["q"].detail


def test_inline_javascript_patterns() -> None:
    html = """
    <script>
      const sp = new URLSearchParams({ view: 'grid', theme: 'dark' });
      sp.set('layout', 'wide');
      sp.append('per_page', '25');
      fetch('/api/items?category=books&limit=10');
      axios.get('/api/orders', { params: { status: 'open', owner: 'me' } });
      const u = "/export?format=csv&columns=all";
    </script>
    """
    result = extract_from_html(html, origin=ORIGIN)
    found = names(result)
    for expected in ("view", "theme", "layout", "per_page", "category", "limit", "status", "owner", "format", "columns"):
        assert expected in found, expected


def test_javascript_url_literals_carry_their_target() -> None:
    source = "fetch('/api/items?category=books&limit=10');"
    result = extract_from_javascript(source, origin=ORIGIN)
    category = [evidence for name, evidence in result.params if name == "category"]
    assert category
    assert category[0].target == "https://app.example.test/api/items"
    assert category[0].line == 1
    assert "fetch" in category[0].context


def test_javascript_extraction_keeps_source_context() -> None:
    source = "\n\nconst x = getParam('session_token');\n"
    result = extract_from_javascript(source, origin=ORIGIN)
    assert names(result) == ["session_token"]
    evidence = result.params[0][1]
    assert evidence.line == 3
    assert "getParam" in evidence.context


def test_server_side_accessors_in_bundles() -> None:
    source = """
    const a = req.query.report_id;
    const b = $_GET['legacy'];
    const c = request.GET['django_param'];
    """
    found = names(extract_from_javascript(source, origin=ORIGIN))
    assert {"report_id", "legacy", "django_param"} <= set(found)


def test_embedded_json_configuration() -> None:
    html = """
    <script type="application/json">
      {"api": {"endpoint": "/v1/items?sort=price"}, "query": {"cursor": null, "tenant": "acme"}}
    </script>
    """
    result = extract_from_html(html, origin=ORIGIN)
    found = names(result)
    assert "sort" in found
    assert "cursor" in found
    assert "tenant" in found


def test_json_extractor_ignores_unrelated_documents() -> None:
    result = extract_from_json_text('{"title": "hello", "count": 3}', origin=ORIGIN)
    assert result.params == []


def test_robots_txt_yields_endpoints_and_parameters() -> None:
    text = "User-agent: *\nDisallow: /admin/\nDisallow: /search?sort=secret\nAllow: /p?id=1\nSitemap: https://app.example.test/sitemap.xml\n"
    result = extract_from_robots(text, origin="https://app.example.test")
    endpoints = [url for url, _ in result.endpoints]
    assert "https://app.example.test/admin/" in endpoints
    assert "https://app.example.test/p?id=1" in endpoints
    assert "https://app.example.test/sitemap.xml" in result.urls
    found = names(result)
    assert "sort" in found and "id" in found
    # provenance points at the target path, not at robots.txt
    evidence = [e for name, e in result.params if name == "sort"][0]
    assert evidence.target == "https://app.example.test/search?sort=secret"


def test_sitemap_xml_yields_endpoints() -> None:
    text = """<?xml version="1.0"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><loc>https://app.example.test/a?x=1</loc></url>
      <url><loc>https://app.example.test/b</loc></url>
    </urlset>"""
    result = extract_from_sitemap(text, origin="https://app.example.test")
    assert "https://app.example.test/a?x=1" in result.urls
    assert names(result) == ["x"]
    evidence = [e for n, e in result.params if n == "x"][0]
    assert evidence.target == "https://app.example.test/a?x=1"


def test_sitemap_handles_malformed_xml() -> None:
    result = extract_from_sitemap("<urlset><loc>", origin="https://app.example.test")
    assert result.urls == []


def test_archive_parsing_supports_common_dump_formats() -> None:
    text = "\n".join(
        [
            "# a comment",
            "",
            "https://app.example.test/a?x=1&y=",
            "https://app.example.test/b\t20230101\ttext/html",
            '{"url": "https://app.example.test/c?z=2", "status": 200}',
            "not a url at all",
        ]
    )
    result = extract_from_archive_text(text, source="dump.txt")
    assert "https://app.example.test/a?x=1&y=" in result.urls
    assert "https://app.example.test/b" in result.urls
    assert "https://app.example.test/c?z=2" in result.urls
    assert "not a url at all" not in result.urls
    assert set(names(result)) == {"x", "y", "z"}


def test_extraction_is_deterministic_and_bounded() -> None:
    source = "fetch('/x?" + "&".join(f"p{i}=1" for i in range(600)) + "');"
    result = extract_from_javascript(source, origin=ORIGIN)
    assert len(result.params) <= 400


def test_wordlist_style_kind_is_reserved_for_guesses() -> None:
    html = "<a href='/x?q=1'>x</a>"
    result = extract_from_html(html, origin=ORIGIN)
    kinds = {evidence.kind for _, evidence in result.params}
    assert SourceKind.WORDLIST not in kinds
