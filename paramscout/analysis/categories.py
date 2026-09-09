"""Likely-purpose categorisation of parameter names.

**A category is a hint about intent, never a vulnerability claim.**  A
parameter named ``redirect`` is not an open redirect; a parameter named ``id``
is not an IDOR.  The category exists so a human can triage 400 candidates by
hand quickly, and so the report can group them sensibly.

Matching runs in two passes: exact names first (highest precision), then
substring/affix patterns.  Categories are evaluated in priority order, so
``returnUrl`` lands in *redirect/navigation* rather than *remote resource*.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class Category(StrEnum):
    REDIRECT = "redirect_navigation"
    IDENTIFIER = "resource_identifier"
    FILE = "file_path_reference"
    SEARCH = "search_filtering"
    REMOTE = "remote_resource_reference"
    DEBUG = "debug_configuration"
    PAGINATION = "pagination"
    AUTH = "authentication_session"
    UNKNOWN = "unknown_general"


CATEGORY_LABELS: dict[Category, str] = {
    Category.REDIRECT: "Redirect / navigation",
    Category.IDENTIFIER: "Resource identifier",
    Category.FILE: "File / path reference",
    Category.SEARCH: "Search / filtering",
    Category.REMOTE: "Remote-resource reference",
    Category.DEBUG: "Debug / configuration",
    Category.PAGINATION: "Pagination",
    Category.AUTH: "Authentication / session",
    Category.UNKNOWN: "Unknown / general purpose",
}

#: How much a *name-based* hint contributes to manual-review ordering.  These
#: weights are a triage convenience only and carry no security meaning.
CATEGORY_REVIEW_WEIGHT: dict[Category, float] = {
    Category.REDIRECT: 1.0,
    Category.REMOTE: 1.0,
    Category.FILE: 0.9,
    Category.IDENTIFIER: 0.75,
    Category.AUTH: 0.7,
    Category.DEBUG: 0.65,
    Category.SEARCH: 0.4,
    Category.PAGINATION: 0.2,
    Category.UNKNOWN: 0.25,
}


@dataclass(frozen=True)
class _Rule:
    category: Category
    exact: frozenset[str] = frozenset()
    patterns: tuple[re.Pattern[str], ...] = ()


_RULES: tuple[_Rule, ...] = (
    _Rule(
        Category.REDIRECT,
        exact=frozenset(
            {
                "next",
                "redirect",
                "redirecturl",
                "redirecturi",
                "redirectto",
                "return",
                "returnurl",
                "returnto",
                "returnpath",
                "continue",
                "goto",
                "destination",
                "forward",
                "forwardurl",
                "backurl",
                "back",
                "target",
                "targeturl",
                "out",
                "redir",
                "rurl",
                "r",
                "u",
            }
        ),
        patterns=(
            re.compile(r"(?i)redirect"),
            re.compile(r"(?i)^(return|back|next)[-_]?(to|url|uri|path)?$"),
            re.compile(r"(?i)(continue|goto|destination|forward)[-_]?(to|url|uri)?$"),
        ),
    ),
    _Rule(
        Category.REMOTE,
        exact=frozenset(
            {
                "url",
                "uri",
                "link",
                "host",
                "hostname",
                "endpoint",
                "callback",
                "cb",
                "webhook",
                "proxy",
                "feed",
                "rss",
                "domain",
                "server",
                "origin",
                "src",
                "source",
                "imageurl",
                "imgurl",
                "apiurl",
                "service",
                "fetch",
            }
        ),
        patterns=(
            re.compile(r"(?i)(^|[_\-])(url|uri|link|host|endpoint|callback|webhook|proxy|feed|domain)($|[_\-])"),
            re.compile(r"(?i)(url|uri|href|callback|webhook|proxy)$"),
        ),
    ),
    _Rule(
        Category.FILE,
        exact=frozenset(
            {
                "file",
                "filename",
                "filepath",
                "path",
                "template",
                "tpl",
                "view",
                "dir",
                "folder",
                "include",
                "inc",
                "attachment",
                "download",
                "doc",
                "document",
                "image",
                "img",
                "pdf",
                "layout",
                "theme",
                "resource",
            }
        ),
        patterns=(
            re.compile(r"(?i)(^|[_\-])(file|path|template|folder|dir|attachment|layout|theme)($|[_\-])"),
            re.compile(r"(?i)(file|path|template)$"),
        ),
    ),
    _Rule(
        Category.AUTH,
        exact=frozenset(
            {
                "token",
                "session",
                "sessionid",
                "sid",
                "code",
                "state",
                "auth",
                "authtoken",
                "accesstoken",
                "refreshtoken",
                "idtoken",
                "jwt",
                "ticket",
                "otp",
                "nonce",
                "signature",
                "sig",
                "apikey",
                "secret",
                "password",
                "passwd",
                "credential",
                "sso",
                "saml",
                "assertion",
                "login",
                "logout",
            }
        ),
        patterns=(
            re.compile(r"(?i)(token|secret|session|csrf|xsrf|password|apikey|api_key|auth|signature|nonce|ticket|assertion)"),
        ),
    ),
    _Rule(
        Category.IDENTIFIER,
        exact=frozenset(
            {
                "id",
                "uid",
                "userid",
                "user",
                "account",
                "accountid",
                "order",
                "orderid",
                "item",
                "itemid",
                "product",
                "productid",
                "pid",
                "oid",
                "ref",
                "reference",
                "record",
                "invoice",
                "customer",
                "org",
                "orgid",
                "tenant",
                "workspace",
                "project",
                "projectid",
                "report",
                "uuid",
                "key",
                "slug",
            }
        ),
        patterns=(
            re.compile(r"(?i)(^|[_\-])(user|account|order|item|product|customer|invoice|org|tenant|project|doc|report)[-_]?id($|[_\-])"),
            re.compile(r"(?i)id$"),
            re.compile(r"(?i)^ids?$"),
        ),
    ),
    _Rule(
        Category.DEBUG,
        exact=frozenset(
            {
                "debug",
                "trace",
                "mode",
                "env",
                "environment",
                "verbose",
                "test",
                "preview",
                "draft",
                "dump",
                "profile",
                "profiling",
                "log",
                "logging",
                "config",
                "settings",
                "feature",
                "flag",
                "beta",
                "dev",
                "admin",
                "internal",
                "xdebug",
                "stacktrace",
                "simulate",
            }
        ),
        patterns=(
            re.compile(r"(?i)(^|[_\-])(debug|trace|verbose|env|mode|preview|draft|beta|dev|internal)($|[_\-])"),
            re.compile(r"(?i)(debug|trace|verbose|preview)$"),
        ),
    ),
    _Rule(
        Category.SEARCH,
        exact=frozenset(
            {
                "q",
                "s",
                "search",
                "query",
                "keyword",
                "keywords",
                "term",
                "text",
                "filter",
                "sort",
                "sortby",
                "orderby",
                "order",
                "category",
                "cat",
                "tag",
                "tags",
                "find",
                "where",
                "group",
                "facet",
                "highlight",
            }
        ),
        patterns=(
            re.compile(r"(?i)(^|[_\-])(search|query|keyword|filter|sort|facet|term)($|[_\-])"),
            re.compile(r"(?i)(search|query|keyword|filter)$"),
        ),
    ),
    _Rule(
        Category.PAGINATION,
        exact=frozenset(
            {
                "page",
                "pageno",
                "pagenum",
                "offset",
                "limit",
                "perpage",
                "pagesize",
                "size",
                "cursor",
                "start",
                "rows",
                "count",
                "from",
                "to",
                "skip",
                "take",
                "after",
                "before",
            }
        ),
        patterns=(
            re.compile(r"(?i)(^|[_\-])(page|offset|limit|cursor|rows|skip|take)($|[_\-])"),
            re.compile(r"(?i)(page|offset|limit)$"),
        ),
    ),
)


@dataclass(frozen=True)
class Classification:
    """The category assigned to a parameter name, and why."""

    category: Category
    reason: str

    @property
    def label(self) -> str:
        return CATEGORY_LABELS[self.category]


def classify_parameter(name: str) -> Classification:
    """Assign a likely purpose to *name*.  Never a security judgement."""

    if not name:
        return Classification(Category.UNKNOWN, "empty parameter name")
    normalized = name.strip().lower().replace("_", "").replace("-", "").replace(".", "")
    bracketed = re.sub(r"\[\d*\]$", "", normalized)

    for rule in _RULES:
        for candidate in (normalized, bracketed):
            if candidate in rule.exact:
                return Classification(rule.category, f"exact name match '{name}'")
    for rule in _RULES:
        for pattern in rule.patterns:
            if pattern.search(name) or pattern.search(normalized):
                return Classification(rule.category, f"pattern '{pattern.pattern}' matched '{name}'")
    return Classification(Category.UNKNOWN, f"no known naming pattern for '{name}'")


def is_security_relevant_name(name: str) -> bool:
    """True when the *name alone* suggests security-relevant handling.

    Used only as a small triage weight.  It is explicitly not a vulnerability
    indicator.
    """

    return classify_parameter(name).category in {
        Category.REDIRECT,
        Category.REMOTE,
        Category.FILE,
        Category.AUTH,
        Category.IDENTIFIER,
        Category.DEBUG,
    }


def category_summary(names: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name in names:
        key = classify_parameter(name).category.value
        counts[key] = counts.get(key, 0) + 1
    return counts
