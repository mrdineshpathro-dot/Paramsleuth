"""ParamScout - passive-first URL parameter discovery for authorized targets.

ParamScout is a reconnaissance aid, not a vulnerability scanner.  It answers a
narrow question: *which URL parameters exist on an authorized target, and which
of them measurably change server behaviour?*  It never exploits anything and it
never labels a parameter "vulnerable".
"""

from __future__ import annotations

__version__ = "0.1.0"

USER_AGENT = f"ParamScout/{__version__} (authorized security testing; passive-first parameter discovery)"

__all__ = ["USER_AGENT", "__version__"]
