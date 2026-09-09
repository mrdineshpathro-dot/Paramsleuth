"""Shared fixtures.

Every fixture here is local: the suite runs entirely against the mock
application on ``127.0.0.1`` / ``localhost`` and never contacts the internet.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from mockapp import MockApp, make_pair

from paramscout.config import ScanConfig
from paramscout.scope import Scope
from paramscout.urls import EndpointGrouping


@pytest.fixture()
def apps() -> Iterator[tuple[MockApp, MockApp]]:
    """A primary app on ``127.0.0.1`` and a second app on ``localhost``."""

    primary, secondary = make_pair()
    try:
        yield primary, secondary
    finally:
        primary.stop()
        secondary.stop()


@pytest.fixture()
def app(apps: tuple[MockApp, MockApp]) -> MockApp:
    return apps[0]


def fast_config(*, scope_hosts: list[str] | None = None) -> ScanConfig:
    """A scan configuration tuned for tests: local scope, high request rate."""

    config = ScanConfig()
    config.scope = Scope.from_hosts(
        scope_hosts or ["127.0.0.1"],
        allow_private_networks=True,
    )
    config.request.rate = 500.0
    config.request.global_rate = 900.0
    config.request.concurrency = 4
    config.request.global_concurrency = 8
    config.request.timeout = 5.0
    config.request.retries = 2
    config.request.max_requests = 400
    config.request.max_requests_per_endpoint = 120
    config.crawl.depth = 1
    config.crawl.max_pages = 20
    config.crawl.max_js_files = 5
    config.output.endpoint_grouping = EndpointGrouping.STRICT
    return config


@pytest.fixture()
def make_config():
    return fast_config
