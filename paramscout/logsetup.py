"""Logging configuration.

Logs go to stderr (never into machine-readable stdout). Branding and
progress text are suppressed in quiet mode. All dynamic values are passed
through :class:`paramscout.redaction.Redactor` before being logged by callers;
this module only wires the handler/formatter.
"""

from __future__ import annotations

import logging
import sys

_FMT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
_CONFIGURED = False


def configure_logging(quiet: bool = False, verbosity: int = 0) -> None:
    """Configure stderr logging once per process."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    root = logging.getLogger("paramscout")
    root.setLevel(logging.WARNING if quiet else logging.INFO if verbosity <= 0 else logging.DEBUG)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(_FMT))
    root.addHandler(handler)
    root.propagate = False
    _CONFIGURED = True
