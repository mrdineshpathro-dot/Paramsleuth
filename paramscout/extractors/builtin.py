"""Conservative built-in parameter wordlist.

Chosen to be small and generic: names a real application plausibly accepts,
drawn from the same naming families ParamScout categorizes (navigation,
identifiers, search, pagination, and so on). This list is a *fallback* used
only in ``--active`` scans; it never implies any parameter exists or is
vulnerable. Prefer target-derived evidence and your own wordlists.
"""

BUILTIN_PARAMETERS: tuple[str, ...] = (
    # identifiers / resources
    "id", "user_id", "uid", "account", "order", "document", "item",
    "product", "post", "article", "message_id", "file_id",
    # navigation / redirect
    "next", "redirect", "return", "returnUrl", "continue", "dest", "url",
    # remote references
    "uri", "host", "endpoint", "callback", "webhook",
    # file / path
    "file", "path", "filename", "template", "dir", "download",
    # search / filtering
    "q", "search", "query", "filter", "sort", "order_by", "keyword", "term",
    # pagination
    "page", "offset", "limit", "cursor", "per_page", "page_size",
    # debug / configuration
    "debug", "trace", "mode", "env", "config", "verbose", "preview",
    # authentication / session (names only - probing never guesses secrets)
    "token", "session", "code", "state", "nonce",
    # generic UI / behavior
    "lang", "locale", "format", "view", "layout", "theme", "callback_url",
    "action", "status", "type", "category", "tab", "section", "expand",
    "compact", "mobile", "embed", "print", "export", "raw", "json",
    "fields", "include", "exclude", "select", "expand", "depth",
)

# Generic "noise" parameter names that are almost always harmless when they
# appear on the target's own query strings (used only to avoid wordlist
# repetition; extraction still keeps them).
COMMON_PARAMETERS: tuple[str, ...] = (
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "ref", "source", "campaign", "partner", "affiliate",
    "session_id", "timestamp", "_", "callback_fn",
)


def builtin_parameter_names() -> list[str]:
    return list(BUILTIN_PARAMETERS)
