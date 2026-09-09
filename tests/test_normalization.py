"""Dynamic-response normalization and fingerprint comparison tests."""

from __future__ import annotations

from paramscout.analysis.normalization import (
    NormalizerConfig,
    check_reflection,
    compare_fingerprints,
    fingerprint_response,
    json_key_paths,
    mask_dynamic_values,
    normalize_document,
    text_similarity,
)

CONFIG = NormalizerConfig()


def _page(body: str) -> str:
    return f"<html><head><title>T</title></head><body>{body}</body></html>"


def test_timestamps_and_tokens_are_masked() -> None:
    text = "at 2024-01-02T03:04:05.678Z epoch 1700000000 id 3f9c1a2b4d5e6f70 jwt eyJhbGciOiJIUz.abc.def"
    masked = mask_dynamic_values(text)
    assert "2024-01-02" not in masked
    assert "1700000000" not in masked
    assert "3f9c1a2b4d5e6f70" not in masked
    assert "eyJhbGciOiJIUz" not in masked
    assert "[[TS]]" in masked and "[[EPOCH]]" in masked and "[[HEX]]" in masked and "[[JWT]]" in masked


def test_dynamic_attributes_are_masked() -> None:
    masked = mask_dynamic_values("<div nonce='abcdef123456'></div><input name=csrf_token value=zzzzzzzzzz>")
    assert "abcdef123456" not in masked
    assert "zzzzzzzzzz" not in masked


def test_identical_pages_with_different_timestamps_match() -> None:
    first = normalize_document(_page("<p>Rendered 2024-01-02T03:04:05Z</p>"), config=CONFIG)
    second = normalize_document(_page("<p>Rendered 2024-06-11T09:10:11Z</p>"), config=CONFIG)
    assert first.text_hash == second.text_hash
    assert first.structure_hash == second.structure_hash


def test_rotation_tokens_do_not_change_the_fingerprint() -> None:
    first = normalize_document(_page("<p>id 3f9c1a2b4d5e6f70 token 9a8b7c6d5e4f3a2b</p>"), config=CONFIG)
    second = normalize_document(_page("<p>id 0011223344556677 token aabbccddeeff0011</p>"), config=CONFIG)
    assert first.text_hash == second.text_hash


def test_ad_and_personalisation_blocks_are_stripped() -> None:
    first = _page("<h1>Page</h1><div class='ad'>buy things</div><p>content</p>")
    second = _page("<h1>Page</h1><div class='ad'>other things</div><p>content</p>")
    assert (
        normalize_document(first, config=CONFIG).text_hash
        == normalize_document(second, config=CONFIG).text_hash
    )


def test_real_content_changes_are_detected() -> None:
    first = normalize_document(_page("<h1>Page</h1><p>alpha</p>"), config=CONFIG)
    second = normalize_document(_page("<h1>Page</h1><p>completely different body text here</p>"), config=CONFIG)
    assert first.text_hash != second.text_hash


def test_structure_hash_tracks_tag_sequence() -> None:
    first = normalize_document(_page("<ul><li>a</li></ul>"), config=CONFIG)
    second = normalize_document(_page("<ul><li>a</li><li>b</li><li>c</li></ul>"), config=CONFIG)
    assert first.structure_hash != second.structure_hash


def test_compare_fingerprints_reports_each_difference() -> None:
    base = fingerprint_response(status=200, headers={}, body=b"<html><title>A</title>x</html>")
    other = fingerprint_response(status=404, headers={}, body=b"<html><title>B</title>y</html>")
    delta = compare_fingerprints(base, other, baseline_text="x", candidate_text="y")
    assert delta.status_changed and delta.title_changed
    assert delta.details["status"] == "200 -> 404"
    assert delta.magnitude > 0.5
    identical = compare_fingerprints(base, base, baseline_text="x", candidate_text="x")
    assert not identical.changed
    assert identical.magnitude == 0.0


def test_length_ratio_is_relative() -> None:
    base = fingerprint_response(status=200, headers={}, body=b"a" * 1000)
    other = fingerprint_response(status=200, headers={}, body=b"a" * 1010)
    delta = compare_fingerprints(base, other, baseline_text="a" * 1000, candidate_text="a" * 1010)
    assert delta.length_delta == 10
    assert abs(delta.length_ratio - 0.01) < 1e-6


def test_text_similarity_bounds() -> None:
    assert text_similarity("same", "same") == 1.0
    assert text_similarity("abcdefghij", "zyxwvutsrq") < 0.5
    # very short bodies are compared exactly, to avoid meaningless ratios
    assert text_similarity("ab", "ab", min_chars=32) == 1.0


def test_json_structure_ignores_values() -> None:
    first = json_key_paths('{"a": 1, "b": {"c": 2}, "list": [{"d": 1}]}')
    second = json_key_paths('{"a": 999, "b": {"c": 0}, "list": [{"d": 7}]}')
    assert first == second
    third = json_key_paths('{"a": 1, "extra": true}')
    assert first != third


def test_json_fingerprint_uses_key_structure() -> None:
    base = fingerprint_response(
        status=200, headers={"content-type": "application/json"}, body=b'{"a": 1, "b": 2}'
    )
    same_shape = fingerprint_response(
        status=200, headers={"content-type": "application/json"}, body=b'{"a": 5, "b": 9}'
    )
    other_shape = fingerprint_response(
        status=200, headers={"content-type": "application/json"}, body=b'{"a": 5, "c": 9}'
    )
    assert base.json_keys_hash == same_shape.json_keys_hash
    assert base.json_keys_hash != other_shape.json_keys_hash


def test_reflection_detection_is_exact() -> None:
    body = b"<html>value: psc0123456789 end</html>"
    info = check_reflection(body, "psc0123456789")
    assert info.reflected and info.occurrences == 1
    assert check_reflection(body, "psc9999999999").reflected is False
    assert check_reflection(body, "").reflected is False


def test_plain_text_responses_are_normalized() -> None:
    document = normalize_document("line one\n\n\n  line two", config=CONFIG)
    assert document.text == "line one line two"
    assert document.structure_hash == "text"
