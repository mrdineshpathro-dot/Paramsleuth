"""Allow ``python -m paramscout`` to behave like the ``paramscout`` command."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
