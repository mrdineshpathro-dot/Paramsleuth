"""Local mock web application used by integration tests.

This package is a test fixture only - it is never shipped. It implements every
behaviour the integration tests need without contacting any public website:

- a parameter that changes page content (``/search?q=...``)
- a parameter that is only reflected (``/reflect?echo=...``)
- an endpoint that ignores all parameters (``/ignores``)
- a response containing dynamic timestamps (``/dynamic``)
- an endpoint that returns 429 with Retry-After (``/rate-limit``)
- an off-scope redirect (``/redirect-offscope``)
- a fake state-changing endpoint (``/checkout``) used with exclusions
- cookie/header authenticated area (``/private``), plus more.
"""
