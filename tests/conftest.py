"""Shared pytest fixtures: local mock servers and config helpers."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass

import pytest_asyncio
import uvicorn

from mockapp.server import MockApp


@dataclass
class LiveServer:
    app: MockApp
    hostname: str
    port: int
    task: asyncio.Task
    other_base: str = ""

    @property
    def base(self) -> str:
        return f"http://{self.hostname}:{self.port}"

    def url(self, path: str = "/") -> str:
        return f"{self.base}{path}"


def _bind(hostname: str) -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((hostname, 0))
    port = sock.getsockname()[1]
    return sock, port


async def _start(app: MockApp, hostname: str = "127.0.0.1") -> LiveServer:
    sock, port = _bind(hostname)
    app.port = port
    app.hostname = hostname
    config = uvicorn.Config(app, log_level="error", lifespan="off")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve(sockets=[sock]))
    for _ in range(200):
        if server.started:
            break
        await asyncio.sleep(0.01)
    if not server.started:
        task.cancel()
        raise RuntimeError("mock server failed to start")
    return LiveServer(app=app, hostname=hostname, port=port, task=task)


@pytest_asyncio.fixture
async def server_a():
    """One local mock server on a random port (127.0.0.1)."""
    live = await _start(MockApp())
    try:
        yield live
    finally:
        live.task.cancel()
        try:
            await live.task
        except (asyncio.CancelledError, Exception):
            pass


@pytest_asyncio.fixture
async def server_pair():
    """Two mock servers on different loopback hosts (distinct origins)."""
    a = MockApp()
    b = MockApp()
    live_a = await _start(a, "127.0.0.1")
    live_b = await _start(b, "127.0.0.2")
    live_a.app.other_base = live_b.base
    live_a.other_base = live_b.base
    try:
        yield live_a, live_b
    finally:
        for live in (live_a, live_b):
            live.task.cancel()
            try:
                await live.task
            except (asyncio.CancelledError, Exception):
                pass
