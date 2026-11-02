"""MAX_METADATA_BYTES is enforced while a metadata body is read.

The limit used to be checked after httpx had read and inflated the whole
body, so a small gzip body could still take the process past its memory
limit, a chunked response with no Content-Length was buffered without bound,
and three of the providers' fetches never checked at all.
"""

from __future__ import annotations

import zlib

import httpx
import pytest
import respx

from app.config import settings
from app.models import Ecosystem, UpstreamKind
from app.upstreams.base import UpstreamError
from app.upstreams.cargo_provider import CargoProvider
from app.upstreams.npm_provider import NpmProvider
from app.upstreams.pypi_provider import PyPIProvider
from tests.test_upstreams import PACKUMENT, make_upstream

REG = "https://registry.example.com"
LIMIT = 64 * 1024


class CountingStream(httpx.AsyncByteStream):
    """Hands out raw body chunks one at a time and counts how many were
    taken, so a test can see where the reader stopped."""

    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.taken = 0

    async def __aiter__(self):
        for chunk in self.chunks:
            self.taken += 1
            yield chunk

    async def aclose(self) -> None:
        return None


def gzip_bomb(decoded_size: int, raw_chunk: int = 1024) -> list[bytes]:
    """A gzip body that inflates to ``decoded_size`` zero bytes, cut into
    ``raw_chunk``-byte pieces."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, 31)
    block = b"\0" * (1024 * 1024)
    body = b"".join(compressor.compress(block) for _ in range(decoded_size // len(block)))
    body += compressor.flush()
    return [body[i : i + raw_chunk] for i in range(0, len(body), raw_chunk)]


@pytest.fixture
def small_limit(monkeypatch):
    monkeypatch.setattr(settings, "max_metadata_bytes", LIMIT)


class TestDecodedSizeIsBounded:
    @respx.mock
    async def test_a_gzip_bomb_is_refused_before_it_is_inflated(self, small_limit):
        chunks = gzip_bomb(64 * 1024 * 1024)
        stream = CountingStream(chunks)
        respx.get(f"{REG}/bomb").mock(
            return_value=httpx.Response(
                200,
                headers={"content-encoding": "gzip", "content-type": "application/json"},
                stream=stream,
            )
        )
        with pytest.raises(UpstreamError, match="byte limit"):
            await NpmProvider(make_upstream()).fetch_package("bomb")
        # 64 MB inflated would need every raw chunk; the reader stopped once
        # the decoded count passed 64 KB.
        assert stream.taken < len(chunks) // 10

    @respx.mock
    async def test_a_chunked_body_with_no_length_is_cut_off(self, small_limit):
        stream = CountingStream([b"x" * 4096] * 1000)
        respx.get(f"{REG}/endless").mock(return_value=httpx.Response(200, stream=stream))
        with pytest.raises(UpstreamError, match="byte limit"):
            await NpmProvider(make_upstream()).request("GET", f"{REG}/endless", retries=0)
        assert stream.taken <= LIMIT // 4096 + 1

    @respx.mock
    async def test_a_declared_oversize_body_is_refused_unread(self, small_limit):
        stream = CountingStream([b"x" * (LIMIT + 1)])
        respx.get(f"{REG}/big").mock(
            return_value=httpx.Response(
                200, headers={"content-length": str(LIMIT + 1)}, stream=stream
            )
        )
        with pytest.raises(UpstreamError, match="over the"):
            await NpmProvider(make_upstream()).request("GET", f"{REG}/big", retries=0)
        assert stream.taken == 0

    @respx.mock
    async def test_a_body_within_the_limit_reads_as_before(self, small_limit):
        respx.get(f"{REG}/lodash").mock(return_value=httpx.Response(200, json=PACKUMENT))
        package = await NpmProvider(make_upstream()).fetch_package("lodash")
        assert package.name == "lodash"


class TestEveryProviderIsCovered:
    """These fetches never called check_body_size at all."""

    @respx.mock
    async def test_cargo_index_file(self, small_limit):
        upstream = make_upstream(ecosystem=Ecosystem.cargo, kind=UpstreamKind.cargo)
        provider = CargoProvider(upstream)
        respx.get(provider.index_url("serde")).mock(
            return_value=httpx.Response(200, stream=CountingStream([b"{}\n" * 30000]))
        )
        with pytest.raises(UpstreamError, match="byte limit"):
            await provider.fetch_package("serde")

    @respx.mock
    async def test_cargo_config_json(self, small_limit):
        upstream = make_upstream(ecosystem=Ecosystem.cargo, kind=UpstreamKind.cargo)
        provider = CargoProvider(upstream)
        chunks = gzip_bomb(64 * 1024 * 1024)
        stream = CountingStream(chunks)
        respx.get(f"{REG}/config.json").mock(
            return_value=httpx.Response(200, headers={"content-encoding": "gzip"}, stream=stream)
        )
        # Unusable config falls back to the default layout, as before; the
        # point is that it was not inflated into memory to find that out.
        assert await provider.registry_config() == {}
        assert 0 < stream.taken < len(chunks) // 10

    @respx.mock
    async def test_pypi_html_simple_page(self, small_limit):
        upstream = make_upstream(ecosystem=Ecosystem.pypi, kind=UpstreamKind.pypi)
        provider = PyPIProvider(upstream)
        page = b"<html><body>" + b'<a href="x-1.0.tar.gz">x-1.0.tar.gz</a>\n' * 5000
        respx.get(provider.project_url("x")).mock(
            return_value=httpx.Response(
                200, headers={"content-type": "text/html"}, stream=CountingStream([page])
            )
        )
        with pytest.raises(UpstreamError, match="byte limit"):
            await provider.fetch_package("x")
