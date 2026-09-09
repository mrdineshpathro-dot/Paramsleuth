"""Allow ``python -m paramscout`` in addition to the ``paramscout`` script."""

from __future__ import annotations

import sys

from paramscout.cli import main

if __name__ == "__main__":  # pragma: no cover - trivial entry point
    sys.exit(main())
