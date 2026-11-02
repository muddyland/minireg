"""A cold artifact fetch must not resolve DNS on the event loop.

``_open_upstream`` ran ``check_fetchable`` -- a synchronous
``socket.getaddrinfo`` -- before every cold fetch, so a slow resolver stalled
every request in the process. The resolver here records the thread it runs
on, and off the loop it blocks until a task on the event loop releases it --
so a passing fetch shows the loop kept running while DNS was pending.
"""

from __future__ import annotations

import asyncio
import socket
import threading

import httpx
import pytest
import respx

from app.config import settings
from app.services import artifacts
from tests.test_upstreams import make_upstream

PUBLIC = "93.184.215.14"


@pytest.fixture
def loop_bound_resolver(monkeypatch):
    """A getaddrinfo that only answers once the event loop has run a task."""
    monkeypatch.setattr(settings, "upstream_allow_private_addresses", False)
    released = threading.Event()
    calls: list[tuple[str, bool]] = []
    loop_thread = threading.get_ident()

    def slow_getaddrinfo(host, port, *args, **kwargs):
        on_loop = threading.get_ident() == loop_thread
        calls.append((host, on_loop))
        # Waiting on the loop thread would only deadlock the test; the call
        # is recorded and the assertion reports it instead.
        released.wait(timeout=0.0 if on_loop else 5.0)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC, port or 443))]

    monkeypatch.setattr(socket, "getaddrinfo", slow_getaddrinfo)

    async def release_from_the_loop():
        await asyncio.sleep(0)
        released.set()

    return calls, release_from_the_loop


async def _open(url, upstream, release):
    releaser = asyncio.create_task(release())
    try:
        response, _chunks = await artifacts._open_upstream(url, upstream, "x-1.0.tgz")
        await response.aclose()
    finally:
        await releaser
    return response


class TestNoBlockingResolve:
    @respx.mock
    async def test_provider_fetch_resolves_off_the_loop(self, loop_bound_resolver):
        calls, release = loop_bound_resolver
        url = "https://upstream.test/x/-/x-1.0.tgz"
        respx.get(url).mock(return_value=httpx.Response(200, content=b"tarball"))
        upstream = make_upstream(url="https://upstream.test")

        response = await _open(url, upstream, release)

        assert response.status_code == 200
        assert calls, "the provider path must still resolve and pin the host"
        assert not any(on_loop for _host, on_loop in calls), calls

    @respx.mock
    async def test_anonymous_fetch_resolves_off_the_loop(self, loop_bound_resolver):
        calls, release = loop_bound_resolver
        url = "https://files.upstream.test/x-1.0.tgz"
        respx.get(url).mock(return_value=httpx.Response(200, content=b"tarball"))

        response = await _open(url, None, release)

        assert response.status_code == 200
        assert calls == [("files.upstream.test", False)]

    async def test_anonymous_fetch_still_refuses_a_private_answer(self, monkeypatch):
        from app.services.artifacts import BlockedUrl

        monkeypatch.setattr(settings, "upstream_allow_private_addresses", False)
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))],
        )
        with pytest.raises(BlockedUrl):
            await artifacts._open_upstream("https://files.upstream.test/x.tgz", None, "x.tgz")
