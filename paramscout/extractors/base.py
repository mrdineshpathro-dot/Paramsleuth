"""Shared helpers for all extractors."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from paramscout.models import Evidence, SourceKind
from paramscout.redaction import is_sensitive_key, is_sensitive_value, redact_text
from paramscout.urls import QueryPair, parse_query

#: Parameter names we are willing to believe.  Deliberately permissive about
#: punctuation (``filter[]``, ``user.name`` are real) but bounded in length.
PARAM_NAME_RE = re.compile(r"^[A-Za-z_$\[][\w$.\-[\]]{0,63}$")

#: Tokens that show up in JS object literals but are never URL parameters.
#: This is deliberately a *language and framework* stoplist rather than a list
#: of "uninteresting names": ``id``, ``url``, ``type`` and ``state`` are all
#: real parameter names and must survive extraction.  The cost of a permissive
#: list is noise, which the scoring layer reports with full provenance; the
#: cost of an aggressive list is silently missing a real parameter.
JS_STOPWORDS = frozenset(
    {
        # language keywords
        "function",
        "return",
        "var",
        "let",
        "const",
        "if",
        "else",
        "for",
        "while",
        "switch",
        "case",
        "break",
        "continue",
        "new",
        "delete",
        "typeof",
        "instanceof",
        "this",
        "class",
        "extends",
        "super",
        "try",
        "catch",
        "finally",
        "throw",
        "await",
        "async",
        "yield",
        "true",
        "false",
        "null",
        "undefined",
        "import",
        "export",
        "default",
        # object plumbing
        "prototype",
        "constructor",
        "length",
        "toString",
        "valueOf",
        "then",
        # framework internals that are never query parameters
        "props",
        "children",
        "className",
        "render",
        "component",
        "methods",
        "computed",
        "watch",
        "created",
        "mounted",
        "beforeMount",
        "useState",
        "useEffect",
        "dispatch",
        "setState",
    }
)


@dataclass
class FormInfo:
    """A passive record of an HTML form.  ParamScout never submits these."""

    action: str
    method: str
    fields: list[str]
    origin: str
    enctype: str = ""
    context: str = ""


@dataclass
class ExtractionResult:
    """Everything one extractor pulled out of one document."""

    params: list[tuple[str, Evidence]] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    endpoints: list[tuple[str, Evidence]] = field(default_factory=list)

    def merge(self, other: ExtractionResult) -> ExtractionResult:
        self.params.extend(other.params)
        self.urls.extend(other.urls)
        self.scripts.extend(other.scripts)
        self.forms.extend(other.forms)
        self.endpoints.extend(other.endpoints)
        return self


def is_plausible_param_name(name: str, *, allow_stopwords: bool = True) -> bool:
    """Filter out junk that regexes inevitably capture."""

    if not name or len(name) > 64:
        return False
    if not PARAM_NAME_RE.match(name):
        return False
    if name.startswith(("-", ".")):
        return False
    if name.lower() in {"php", "asp", "aspx", "jsp", "html", "htm", "js", "css", "png", "jpg"}:
        return False
    if not allow_stopwords and name in JS_STOPWORDS:
        return False
    return True


def context_snippet(text: str, position: int, *, width: int = 60, line: int | None = None) -> str:
    """A redacted snippet of source around *position*, for report context."""

    start = max(0, position - width)
    end = min(len(text), position + width)
    snippet = text[start:end].replace("\n", " ").replace("\r", " ")
    snippet = re.sub(r"\s+", " ", snippet).strip()
    if len(snippet) > 2 * width + 8:
        snippet = snippet[: 2 * width + 8]
    return redact_text(snippet)


def line_of(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def params_from_query(
    query: str,
    *,
    kind: SourceKind,
    origin: str,
    detail: str = "",
    context: str = "",
    confidence: float | None = None,
    target: str = "",
) -> list[tuple[str, Evidence]]:
    """Turn a query string into ``(name, evidence)`` pairs, redacting values."""

    pairs: list[QueryPair] = parse_query(query)
    out: list[tuple[str, Evidence]] = []
    for pair in pairs:
        if not is_plausible_param_name(pair.name):
            continue
        redacted_value = (
            "[REDACTED]"
            if (is_sensitive_key(pair.name) or is_sensitive_value(pair.value))
            else pair.value
        )
        out.append(
            (
                pair.name,
                Evidence(
                    kind=kind,
                    origin=origin,
                    detail=detail or f"{pair.name}={redacted_value}",
                    context=redact_text(context)[:240],
                    confidence=confidence,
                    target=target or origin,
                ),
            )
        )
    return out
