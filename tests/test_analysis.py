"""Normalization, baseline stability, and reflection unit tests."""

from paramscout.analysis.normalize import (
    normalize_dynamic_text,
    text_similarity,
    visible_text,
)
from paramscout.analysis.reflect import detect_reflection
from paramscout.analysis.probe import build_baseline, features_of_response
from paramscout.config import Config
from paramscout.http_client import ResponseInfo


def _resp(html: str, status: int = 200, content_type: str = "text/html") -> ResponseInfo:
    return ResponseInfo(
        status_code=status,
        body=html.encode(),
        content_type=content_type,
        headers={"content-type": content_type},
        final_url="http://h/",
    )


def test_dynamic_text_normalization_removes_timestamps():
    tok_a = "0123456789abcdef0123456789abcdef01"  # 34 hex chars (session-like)
    tok_b = "fedcba9876543210fedcba9876543210fe"
    a = f"time=2026-09-09T10:00:00Z token={tok_a}  count=1234"
    b = f"time=2026-09-09T11:30:45+0530 token={tok_b}  count=99"
    assert normalize_dynamic_text(a) == normalize_dynamic_text(b)
    assert text_similarity("page time=2026-09-09 10:00:00 x", "page time=2030-01-01 00:00:00 x") > 0.95


def test_visible_text_strips_scripts():
    html = "<html><body>Hello <script>var x=1</script><style>.a{}</style> world</body></html>"
    text = visible_text(html)
    assert "Hello" in text and "world" in text
    assert "var" not in text


def test_baseline_unstable_when_text_varies():
    cfg = Config()
    samples = [
        features_of_response(_resp(f"<html><body>static {i}</body></html>"), "")
        for i in range(3)
    ]
    baseline = build_baseline(samples, cfg)
    assert baseline.unstable  # raw numbers differ without normalization...

    samples2 = [
        features_of_response(
            _resp(f"<html><body>static {100 + i} {2000 + i * 7}</body></html>"), ""
        )
        for i in range(3)
    ]
    baseline2 = build_baseline(samples2, cfg)
    # multi-digit numbers are normalized away, so this *is* stable
    assert not baseline2.unstable


def test_detect_reflection_contexts():
    body = "<html><body><p>hello CANARY123 world</p><script>const x='CANARY123'</script></body></html>"
    info = detect_reflection(body, "CANARY123", content_type="text/html")
    assert info.reflected
    assert "raw-body" in info.contexts
    assert "in-script" in info.contexts


def test_reflection_in_json_and_attribute():
    body = '{"url": "https://h/?echo=CANARY9", "ok": true}'
    info = detect_reflection(body, "CANARY9", content_type="application/json")
    assert info.reflected
    assert any(c.startswith("json-string") for c in info.contexts)

    body2 = '<a href="/go?next=CANARY8">x</a>'
    info2 = detect_reflection(body2, "CANARY8", content_type="text/html")
    assert info2.reflected
    assert "in-quoted-attribute" in info2.contexts
