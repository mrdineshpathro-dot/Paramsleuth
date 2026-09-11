"""Wordlist and URL-archive loading helpers (local files only)."""

from __future__ import annotations

import logging

from ..extractors.builtin import builtin_parameter_names
from ..extractors.base import load_urls_from_text

log = logging.getLogger("paramscout.wordlists")

_MAX_WORDLIST_WORDS = 50_000


def load_wordlist_file(path: str) -> list[str]:
    """Load one parameter name per line from *path* (comments allowed)."""
    names: list[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name = line.split()[0] if " " in line and "\t" not in line else line
            # keep the whole token up to whitespace
            token = line.split(None, 1)[0]
            if not token or "=" in token or "&" in token or len(token) > 512:
                continue
            names.append(token)
            if len(names) >= _MAX_WORDLIST_WORDS:
                log.warning("wordlist truncated at %d names", _MAX_WORDLIST_WORDS)
                break
    if not names:
        raise ValueError(f"wordlist {path!r} contains no usable parameter names")
    return names


def names_for_run(wordlist_path: str | None, use_builtin: bool) -> tuple[list[str], str | None]:
    """Return (names, provenance_label). Builtin names come last."""
    names: list[str] = []
    provenance = None
    if wordlist_path:
        user_names = load_wordlist_file(wordlist_path)
        names.extend(user_names)
        provenance = wordlist_path
    if use_builtin:
        names.extend(builtin_parameter_names())
        provenance = "builtin + user wordlist" if wordlist_path else "builtin wordlist"
    # Deduplicate while preserving order.
    seen: set[str] = set()
    deduped: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            deduped.append(name)
    return deduped, provenance


def urls_from_files(paths: list[str], max_bytes_per_file: int = 20 * 1024 * 1024) -> list[str]:
    """Read absolute http(s) URLs out of local text/JSON/HTML-ish inputs.

    Pure local operation: never performs network requests.
    """
    urls: list[str] = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                content = handle.read(max_bytes_per_file)
        except OSError as exc:
            log.warning("cannot read %s: %s", path, exc)
            continue
        urls.extend(load_urls_from_text(content))
    return urls
