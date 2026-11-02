"""SRI ``integrity`` verification of upstream artifacts.

An integrity string satisfied ``require_digest`` just by being present, while
the check itself only understood a single sha256/sha512 token and passed
silently on anything else.
"""

from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace

import httpx
import pytest
import respx
from sqlalchemy import update

from app import db as db_module
from app.models import Ecosystem, PackageFile, Upstream, UpstreamKind
from app.services import artifacts
from app.services.storage import Digests
from tests.test_artifact_cache import BODY, make_file, no_redis, store  # noqa: F401


def sri(algorithm: str, data: bytes = BODY) -> str:
    return f"{algorithm}-" + base64.b64encode(hashlib.new(algorithm, data).digest()).decode()


def stored_for(data: bytes = BODY):
    digests = Digests()
    digests.update(data)
    return digests.stored("x", already_existed=False)


def row(integrity: str | None, **digests):
    return SimpleNamespace(
        filename="pkg-1.0.0.tgz",
        sha256=digests.get("sha256"),
        sha1=digests.get("sha1"),
        md5=digests.get("md5"),
        blake2b_256=digests.get("blake2b_256"),
        integrity=integrity,
    )


def verify(integrity, *, require=False, extra=None, **digests):
    kwargs = {"extra": extra} if extra else {}
    artifacts._verify_digests(row(integrity, **digests), stored_for(), require=require, **kwargs)


class TestSriParsing:
    def test_single_matching_hash_passes(self):
        verify(sri("sha512"), require=True)
        verify(sri("sha256"), require=True)

    def test_strongest_algorithm_decides_in_a_list(self):
        wrong512 = sri("sha512", b"other bytes")
        with pytest.raises(artifacts.DigestMismatch, match="sha512"):
            verify(f"{wrong512} {sri('sha256')}")
        # A weaker hash that does not match is not consulted at all.
        verify(f"{sri('sha512')} {sri('sha256', b'other bytes')}", require=True)

    def test_any_value_of_the_strongest_algorithm_may_match(self):
        verify(f"{sri('sha512', b'other bytes')} {sri('sha512')}", require=True)

    def test_options_are_ignored(self):
        verify(f"{sri('sha512')}?foo=bar", require=True)

    def test_sha384_is_checked(self):
        actual = {"sha384": hashlib.sha384(BODY).digest()}
        verify(sri("sha384"), require=True, extra=actual)
        with pytest.raises(artifacts.DigestMismatch, match="sha384"):
            verify(sri("sha384", b"other bytes"), extra=actual)

    def test_an_undecodable_value_is_refused(self):
        with pytest.raises(artifacts.DigestMismatch):
            verify("sha512-not!base64!")

    def test_a_wrong_length_value_is_refused(self):
        short = base64.b64encode(b"\0" * 20).decode()
        with pytest.raises(artifacts.DigestMismatch):
            verify(f"sha512-{short}")

    def test_require_needs_a_digest_that_was_actually_compared(self):
        with pytest.raises(artifacts.ArtifactError, match="could be verified"):
            verify("md5-" + base64.b64encode(hashlib.md5(BODY).digest()).decode(), require=True)
        with pytest.raises(artifacts.ArtifactError, match="could be verified"):
            verify("garbage", require=True)
        # Without require, an SRI string naming nothing we know still passes.
        verify("garbage")

    def test_hex_digests_still_satisfy_require(self):
        verify(None, require=True, sha1=hashlib.sha1(BODY).hexdigest())
        with pytest.raises(artifacts.DigestMismatch):
            verify(None, sha256="0" * 64)


class TestDownloadPath:
    async def _file(self, integrity: str) -> int:
        async with db_module.session_scope() as session:
            upstream = Upstream(
                name=f"npmjs-{hashlib.sha1(integrity.encode()).hexdigest()[:8]}",
                ecosystem=Ecosystem.npm,
                kind=UpstreamKind.npm,
                url="https://upstream.test",
                tier=1,
                require_digest=True,
            )
            session.add(upstream)
            await session.flush()
            upstream_id = upstream.id
        file_id = await make_file(sha256=None, upstream_id=upstream_id)
        async with db_module.session_scope() as session:
            await session.execute(
                update(PackageFile).where(PackageFile.id == file_id).values(integrity=integrity)
            )
        return file_id

    @respx.mock
    async def test_sha384_only_integrity_is_verified_on_download(self, store):  # noqa: F811
        respx.get("https://cdn.upstream.test/a.tgz").mock(
            return_value=httpx.Response(200, content=BODY)
        )
        good = await self._file(sri("sha384"))
        bad = await self._file(sri("sha384", b"tampered"))
        async with db_module.get_sessionmaker()() as session:
            await artifacts.ensure_cached(session, await session.get(PackageFile, good))
        async with db_module.get_sessionmaker()() as session:
            with pytest.raises(artifacts.DigestMismatch, match="sha384"):
                await artifacts.ensure_cached(session, await session.get(PackageFile, bad))
