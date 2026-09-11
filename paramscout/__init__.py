"""ParamScout - URL parameter discovery and analysis for authorized testing.

ParamScout discovers, validates, and prioritizes interesting URL parameters on
explicitly authorized targets. It supports offline extraction from collected
URLs, passive crawl-based discovery, and an opt-in (``--active``) mode for
controlled, conservative active probing.

Use ParamScout only on systems you own or have explicit permission to test.
"""

from .__about__ import (
    __author__,
    __author_email__,
    __description__,
    __license__,
    __support_url__,
    __title__,
    __version__,
)

__all__ = [
    "__title__",
    "__version__",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__support_url__",
]
