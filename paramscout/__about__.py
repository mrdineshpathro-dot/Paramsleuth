"""Project identity and attribution metadata for ParamScout.

These values are the single source of truth used by the CLI (``--version``,
``--about``), the HTTP User-Agent, and every report footer.  They are kept in
one module so branding stays consistent across the tool.

Privacy: the email and support link exist for contact and *voluntary* support
only. ParamScout never sends telemetry, scan results, target URLs, credentials,
or error reports to the author or to any external service, and it never opens
the support website automatically.
"""

__title__ = "ParamScout"
__version__ = "0.1.0"
__author__ = "Mrdineshpathro"
__author_email__ = "mrdineshpathro@gmail.com"
__description__ = (
    "A Python-based URL parameter discovery and analysis tool for authorized "
    "bug bounty hunting."
)
__support_url__ = "https://buymeacoffee.com/mrdineshpathro"
__license__ = "MIT"

# A short authorized-use notice reused by --about and log headers.
AUTHORIZED_USE_NOTICE = (
    "Authorized use only: run ParamScout solely against systems you own or "
    "where you hold explicit, written permission. Respect the target "
    "program's scope, rate limits, and rules. No telemetry, credentials, "
    "target URLs, or scan data ever leave your machine."
)

# User-Agent advertised on outbound HTTP requests. Identifies the tool and
# version; it is static and does not carry telemetry.
def user_agent() -> str:
    """Return the ParamScout User-Agent string."""
    return f"{__title__}/{__version__} (authorized security testing only)"
