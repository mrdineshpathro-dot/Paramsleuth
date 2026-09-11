"""JSON report writer."""

from __future__ import annotations

import json
from typing import Any


def render_json_report(metadata: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    """Render the full report as an indented JSON document."""
    payload = {
        "metadata": _json_safe(metadata),
        "findings": [_json_safe(row) for row in rows],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _json_safe(value: Any) -> Any:
    """Make values JSON-serializable (tuples -> lists, etc.)."""
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)
