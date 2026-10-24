"""Upstream metadata freshness: what a refresh reads, sends, writes and drops.

Covers four failures that each looked fine in isolation:

* the freshness check loaded the whole packument (37 MB for vite), and a
  refresh loaded it again under the herd lock;
* every TTL expiry was an unconditional GET, although every registry we
  speak to answers a conditional one with an empty 304;
* every refresh rewrote every version's metadata, flushing once per version;
* changing the upstream set invalidated nothing, so a disabled -- say,
  compromised -- upstream's versions kept being served.
"""

from __future__ import annotations

import fnmatch
import hashlib
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
import respx
from sqlalchemy import select, update
from sqlalchemy.exc import InvalidRequestError

from app import db as db_module
from app.core import cache as cache_module
from app.models import (
    Ecosystem,
    Package,
    PackageFile,
    PackageVersion,
    Upstream,
    UpstreamKind,
)
from app.services import packages as packages_service
from app.services.resolver import Resolver
from app.upstreams.cargo_provider import CargoProvider
from app.upstreams.npm_provider import NpmProvider
from app.upstreams.pypi_provider import PyPIProvider
from app.upstreams.revalidation import UpstreamNotModified, Validators

from .test_integration import app_client, auth  # noqa: F401  (fixture import)
from .test_query_footprint import SqlRecorder

TARBALL = b"freshness-test-tarball" * 8
TARBALL_SHA1 = hashlib.sha1(TARBALL).hexdigest()
ETAG = '"abc123"'
LAST_MODIFIED = "Wed, 21 Oct 2026 07:28:00 GMT"


def packument(name: str, versions, host="https://upstream.test", **extra_by_version):
    docs = {}
    for version in versions:
        docs[version] = {
            "name": name,
            "version": version,
            "dist": {
                "shasum": TARBALL_SHA1,
                "tarball": f"{host}/{name}/-/{name}-{version}.tgz",
            },
            **extra_by_version.get(version.replace(".", "_"), {}),
        }
    return {
        "name": name,
        "dist-tags": {"latest": list(versions)[-1]},
        "time": dict.fromkeys(versions, "2024-01-01T00:00:00.000Z"),
        "versions": docs,
    }


def npm_upstream(name="primary", url="https://upstream.test", tier=1, **kw):
    return Upstream(
        name=name, ecosystem=Ecosystem.npm, kind=UpstreamKind.npm, url=url, tier=tier, **kw
    )


def pypi_upstream(name, url, tier=1, priority=100):
    return Upstream(
        name=name,
        ecosystem=Ecosystem.pypi,
        kind=UpstreamKind.pypi,
        url=url,
        tier=tier,
        priority=priority,
    )


def pypi_page(name, files):
    return {
        "meta": {"api-version": "1.1"},
        "name": name,
        "files": [
            {
                "filename": filename,
                "url": url,
                "hashes": {"sha256": hashlib.sha256(filename.encode()).hexdigest()},
            }
            for filename, url in files
        ],
    }


PYPI_JSON = {"content-type": "application/vnd.pypi.simple.v1+json"}


async def add(*rows):
    async with db_module.session_scope() as session:
        session.add_all(rows)
        await session.flush()
        return [r.id for r in rows]


async def expire(name: str, ecosystem=Ecosystem.npm) -> None:
    """Age the cached copy past its TTL without touching its validators."""
    async with db_module.session_scope() as session:
        await session.execute(
            update(Package)
            .where(Package.ecosystem == ecosystem, Package.normalized_name == name)
            .values(cached_at=datetime.now(UTC) - timedelta(days=1))
        )


async def stored(name: str, ecosystem=Ecosystem.npm):
    async with db_module.session_scope() as session:
        return (
            await session.execute(
                select(Package.cached_at, Package.cached_etag).where(
                    Package.ecosystem == ecosystem, Package.normalized_name == name
                )
            )
        ).first()


async def stored_versions(name: str, ecosystem=Ecosystem.npm) -> set[str]:
    async with db_module.session_scope() as session:
        return set(
            (
                await session.execute(
                    select(PackageVersion.version)
                    .join(Package, Package.id == PackageVersion.package_id)
                    .where(Package.ecosystem == ecosystem, Package.normalized_name == name)
                )
            ).scalars()
        )


async def stored_files(name: str, ecosystem=Ecosystem.pypi) -> set[str]:
    async with db_module.session_scope() as session:
        return set(
            (
                await session.execute(
                    select(PackageFile.filename)
                    .join(PackageVersion, PackageVersion.id == PackageFile.version_id)
                    .join(Package, Package.id == PackageVersion.package_id)
                    .where(Package.ecosystem == ecosystem, Package.normalized_name == name)
                )
            ).scalars()
        )


def versions_in(response) -> set[str]:
    assert response.status_code == 200, response.text
    return set(response.json()["versions"])


class FlushCounter:
    def __enter__(self):
        from sqlalchemy import event
        from sqlalchemy.orm import Session

        self.count = 0
        self._event = event
        self._target = Session
        event.listen(Session, "after_flush", self._on_flush)
        return self

    def __exit__(self, *exc):
        self._event.remove(self._target, "after_flush", self._on_flush)
        return False

    def _on_flush(self, session, context):
        self.count += 1


class FakeRedis:
    """Just enough of redis.asyncio for core.cache."""

    def __init__(self):
        self.data: dict[bytes, bytes] = {}

    @staticmethod
    def _k(key):
        return key.encode() if isinstance(key, str) else key

    async def get(self, key):
        return self.data.get(self._k(key))

    async def set(self, key, value, ex=None, nx=False):
        key = self._k(key)
        if nx and key in self.data:
            return None
        self.data[key] = value
        return True

    async def delete(self, *keys):
        for key in keys:
            self.data.pop(self._k(key), None)

    async def scan(self, cursor=0, match="*", count=None):
        return 0, [k for k in self.data if fnmatch.fnmatchcase(k.decode(), match)]

    async def eval(self, *args):
        return 1

    async def ping(self):
        return True

    async def aclose(self):
        return None

    def keys_like(self, pattern):
        return [k.decode() for k in self.data if fnmatch.fnmatchcase(k.decode(), pattern)]


@pytest.fixture
def fake_redis(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(cache_module, "_redis", fake)
    return fake


@pytest_asyncio.fixture
async def client(app_client):  # noqa: F811
    await add(npm_upstream())
    return app_client


# --------------------------------------------------------------------------- #
# 1. What a lookup loads
# --------------------------------------------------------------------------- #
class TestLeanPackageRow:
    async def _seed(self):
        async with db_module.session_scope() as session:
            package = Package(
                ecosystem=Ecosystem.npm,
                name="heavy",
                normalized_name="heavy",
                is_local=False,
                keywords=[],
                cached_document={"pad": "x" * 2048},
                cached_at=datetime.now(UTC),
            )
            session.add(package)
            await session.flush()
            for i in range(20):
                session.add(
                    PackageVersion(
                        package_id=package.id,
                        version=f"1.0.{i}",
                        normalized_version=f"1.0.{i}",
                        metadata_json={"pad": "y" * 256},
                    )
                )

    async def test_default_lookup_selects_no_heavy_column(self, client):
        await self._seed()
        async with db_module.session_scope() as session:
            with SqlRecorder() as sql:
                package = await packages_service.get_package_row(session, Ecosystem.npm, "heavy")
            assert len(package.versions) == 20
            sql.assert_no_heavy_columns("get_package_row()")
            # Reading one is a loud error, not a silent multi-megabyte load.
            with pytest.raises(InvalidRequestError):
                _ = package.cached_document

    async def test_documents_are_opt_in(self, client):
        await self._seed()
        async with db_module.session_scope() as session:
            package = await packages_service.get_package_row(
                session, Ecosystem.npm, "heavy", with_documents=True
            )
            assert package.cached_document == {"pad": "x" * 2048}
            assert all(v.metadata_json == {"pad": "y" * 256} for v in package.versions)

    async def test_opt_in_fills_in_an_instance_loaded_lean_earlier(self, client):
        """The identity map hands back the same object; documents an earlier
        lean query deferred must still arrive."""
        await self._seed()
        async with db_module.session_scope() as session:
            lean = await packages_service.get_package_row(session, Ecosystem.npm, "heavy")
            full = await packages_service.get_package_row(
                session, Ecosystem.npm, "heavy", with_documents=True
            )
            assert full is lean
            assert full.cached_document == {"pad": "x" * 2048}
            assert full.versions[0].metadata_json == {"pad": "y" * 256}

    async def test_fresh_fetch_reads_the_packument_once(self, client):
        await self._seed()
        async with db_module.session_scope() as session:
            with SqlRecorder() as sql:
                lookup = await packages_service.fetch_package(session, Ecosystem.npm, "heavy")
            assert lookup.fresh and lookup.package.cached_document
        assert len(sql.selects_touching("cached_document")) == 1

    async def test_fetch_without_documents_reads_none(self, client):
        await self._seed()
        async with db_module.session_scope() as session:
            with SqlRecorder() as sql:
                lookup = await packages_service.fetch_package(
                    session, Ecosystem.npm, "heavy", with_documents=False
                )
            assert len(lookup.package.versions) == 20
        sql.assert_no_heavy_columns("fetch_package(with_documents=False)")

    @respx.mock
    async def test_refresh_does_not_read_the_old_packument(self, client):
        """It used to be deserialised twice -- once to decide the copy was
        stale and again under the herd lock -- only to be replaced."""
        respx.get("https://upstream.test/leftpad").mock(
            return_value=httpx.Response(200, json=packument("leftpad", ["1.0.0", "1.1.0"]))
        )
        assert (await client.get("/npm/leftpad")).status_code == 200
        await expire("leftpad")

        async with db_module.session_scope() as session:
            with SqlRecorder() as sql:
                lookup = await packages_service.fetch_package(session, Ecosystem.npm, "leftpad")
            assert lookup.from_upstream
            assert set(lookup.package.cached_document["versions"]) == {"1.0.0", "1.1.0"}
            assert all(v.metadata_json["version"] == v.version for v in lookup.package.versions)
        # Neither the old packument nor the old per-version documents.
        sql.assert_no_heavy_columns("a refresh")

    async def test_locate_file_refetch_does_not_ask_for_documents(self):
        import inspect

        source = inspect.getsource(packages_service.locate_file)
        assert "with_documents=False" in source


# --------------------------------------------------------------------------- #
# 2. Conditional revalidation
# --------------------------------------------------------------------------- #
class TestValidatorStorage:
    def test_round_trip(self):
        v = Validators(upstream_id=7, etag='W/"x|y"', last_modified=LAST_MODIFIED)
        assert Validators.decode(v.encode()) == v

    def test_a_bare_legacy_etag_is_not_trusted(self):
        # Written before validators were bound to an upstream: whose is it?
        assert Validators.decode('"abc"') is None
        assert Validators.decode(None) is None

    def test_an_oversized_etag_is_dropped_not_truncated(self):
        v = Validators(upstream_id=1, etag='"' + "a" * 400 + '"', last_modified=LAST_MODIFIED)
        decoded = Validators.decode(v.encode())
        assert decoded.etag is None and decoded.last_modified == LAST_MODIFIED

    def test_headers(self):
        v = Validators(upstream_id=1, etag=ETAG, last_modified=LAST_MODIFIED)
        assert v.headers() == {"if-none-match": ETAG, "if-modified-since": LAST_MODIFIED}


class TestProvidersSendValidators:
    @respx.mock
    @pytest.mark.parametrize(
        "provider_cls,kind,url,target",
        [
            (NpmProvider, UpstreamKind.npm, "https://upstream.test", "https://upstream.test/x"),
            (
                PyPIProvider,
                UpstreamKind.pypi,
                "https://pypi.upstream.test/simple",
                "https://pypi.upstream.test/simple/x/",
            ),
            (
                CargoProvider,
                UpstreamKind.cargo,
                "https://index.upstream.test",
                "https://index.upstream.test/1/x",
            ),
        ],
    )
    async def test_304_is_not_modified(self, provider_cls, kind, url, target):
        route = respx.get(target).mock(return_value=httpx.Response(304))
        upstream = Upstream(id=3, name="u", ecosystem=Ecosystem.npm, kind=kind, url=url)
        validators = Validators(upstream_id=3, etag=ETAG, last_modified=LAST_MODIFIED)
        with pytest.raises(UpstreamNotModified):
            await provider_cls(upstream).fetch_package("x", validators=validators)
        sent = route.calls.last.request.headers
        assert sent["if-none-match"] == ETAG
        assert sent["if-modified-since"] == LAST_MODIFIED

    @respx.mock
    async def test_an_unsolicited_304_is_an_error_not_an_empty_project(self):
        from app.upstreams.base import UpstreamError

        respx.get("https://pypi.upstream.test/simple/x/").mock(return_value=httpx.Response(304))
        upstream = pypi_upstream("u", "https://pypi.upstream.test/simple")
        with pytest.raises(UpstreamError):
            await PyPIProvider(upstream).fetch_package("x")


class TestRevalidation:
    @respx.mock
    async def test_304_restarts_the_ttl_and_keeps_everything(self, client):
        route = respx.get("https://upstream.test/leftpad").mock(
            return_value=httpx.Response(
                200,
                json=packument("leftpad", ["1.0.0", "1.1.0"]),
                headers={"etag": ETAG, "last-modified": LAST_MODIFIED},
            )
        )
        assert versions_in(await client.get("/npm/leftpad")) == {"1.0.0", "1.1.0"}
        first = await stored("leftpad")
        assert Validators.decode(first.cached_etag).etag == ETAG

        await expire("leftpad")
        route.mock(return_value=httpx.Response(304))
        with SqlRecorder() as sql:
            response = await client.get("/npm/leftpad")
        assert versions_in(response) == {"1.0.0", "1.1.0"}
        assert response.json()["versions"]["1.1.0"]["dist"]["shasum"] == TARBALL_SHA1

        sent = route.calls.last.request.headers
        assert sent["if-none-match"] == ETAG
        assert sent["if-modified-since"] == LAST_MODIFIED

        after = await stored("leftpad")
        cached_at = after.cached_at.replace(tzinfo=UTC) if after.cached_at.tzinfo is None else after.cached_at
        assert datetime.now(UTC) - cached_at < timedelta(minutes=1)
        # Validators survive, so the next expiry revalidates again.
        assert after.cached_etag == first.cached_etag
        # Nothing was rewritten.
        writes = [
            s for s in sql.statements
            if s.lstrip().upper().startswith(("UPDATE", "INSERT", "DELETE"))
            and ("cached_document" in s or "package_versions" in s or "package_files" in s)
        ]
        assert writes == []

    @respx.mock
    async def test_validators_go_only_to_the_upstream_that_issued_them(self, client):
        route = respx.get("https://upstream.test/leftpad").mock(
            return_value=httpx.Response(200, json=packument("leftpad", ["1.0.0"]))
        )
        assert (await client.get("/npm/leftpad")).status_code == 200
        async with db_module.session_scope() as session:
            await session.execute(
                update(Package)
                .where(Package.normalized_name == "leftpad")
                .values(
                    cached_etag=Validators(upstream_id=999, etag=ETAG).encode(),
                    cached_at=datetime.now(UTC) - timedelta(days=1),
                )
            )
        assert (await client.get("/npm/leftpad")).status_code == 200
        assert "if-none-match" not in route.calls.last.request.headers

    @respx.mock
    async def test_a_merging_tier_is_never_revalidated(self, app_client):  # noqa: F811
        """A 304 from one index says nothing about the other's files."""
        await add(
            pypi_upstream("a", "https://a.upstream.test/simple", priority=1),
            pypi_upstream("b", "https://b.upstream.test/simple", priority=2),
        )
        a = respx.get("https://a.upstream.test/simple/widget/").mock(
            return_value=httpx.Response(
                200,
                json=pypi_page("widget", [("widget-1.0-py3-none-any.whl", "https://a.upstream.test/w1.whl")]),
                headers={**PYPI_JSON, "etag": ETAG},
            )
        )
        respx.get("https://b.upstream.test/simple/widget/").mock(return_value=httpx.Response(404))
        assert (await app_client.get("/pypi/simple/widget/", headers={"accept": "application/vnd.pypi.simple.v1+json"})).status_code == 200
        await expire("widget", Ecosystem.pypi)
        await app_client.get("/pypi/simple/widget/", headers={"accept": "application/vnd.pypi.simple.v1+json"})
        assert a.call_count == 2
        assert "if-none-match" not in a.calls.last.request.headers

    @respx.mock
    async def test_force_refresh_is_unconditional(self, client):
        route = respx.get("https://upstream.test/leftpad").mock(
            return_value=httpx.Response(
                200, json=packument("leftpad", ["1.0.0"]), headers={"etag": ETAG}
            )
        )
        assert (await client.get("/npm/leftpad")).status_code == 200
        async with db_module.session_scope() as session:
            await packages_service.fetch_package(
                session, Ecosystem.npm, "leftpad", force_refresh=True
            )
        assert "if-none-match" not in route.calls.last.request.headers

    async def test_resolver_reports_not_modified(self, client):
        class Stub:
            def __init__(self, upstream):
                self.id = upstream.id

            async def fetch_package(self, name, *, validators=None):
                assert validators is not None
                raise UpstreamNotModified()

        from app.services import resolver as resolver_module

        async with db_module.session_scope() as session:
            upstream = (await session.execute(select(Upstream))).scalars().first()
            original = resolver_module.build_provider
            resolver_module.build_provider = lambda u: Stub(u)
            try:
                result = await Resolver(session).resolve(
                    Ecosystem.npm, "x", validators=Validators(upstream.id, etag=ETAG)
                )
            finally:
                resolver_module.build_provider = original
        assert result.not_modified and result.package is None


# --------------------------------------------------------------------------- #
# 3. Refresh writes only what changed
# --------------------------------------------------------------------------- #
class TestIncrementalPersist:
    COUNT = 120

    @respx.mock
    async def test_an_unchanged_refresh_rewrites_no_version(self, client):
        versions = [f"1.0.{i}" for i in range(self.COUNT)]
        route = respx.get("https://upstream.test/big").mock(
            return_value=httpx.Response(200, json=packument("big", versions))
        )
        with FlushCounter() as flushes:
            assert (await client.get("/npm/big")).status_code == 200
        # One unit of work, not one per version. (Whether its INSERTs then
        # go out as one statement is the driver's business: asyncpg batches
        # them with insertmanyvalues, SQLite cannot.)
        assert flushes.count < 6, flushes.count

        await expire("big")
        # One version gets deprecated upstream, one new version appears.
        changed = packument(
            "big", [*versions, "2.0.0"], **{"1_0_5": {"deprecated": "use 2.x"}}
        )
        route.mock(return_value=httpx.Response(200, json=changed))
        with SqlRecorder() as sql:
            response = await client.get("/npm/big")
        assert response.status_code == 200
        body = response.json()
        assert body["versions"]["1.0.5"]["deprecated"] == "use 2.x"
        assert "2.0.0" in body["versions"]

        version_updates = [
            s for s in sql.statements if s.lstrip().upper().startswith("UPDATE PACKAGE_VERSIONS")
        ]
        file_updates = [
            s for s in sql.statements if s.lstrip().upper().startswith("UPDATE PACKAGE_FILES")
        ]
        # Exactly one version changed; it is the only one written.
        assert len(version_updates) == 1, version_updates
        assert "metadata_json" in version_updates[0]
        assert file_updates == []

    @respx.mock
    async def test_an_unchanged_version_keeps_its_stored_document(self, client):
        route = respx.get("https://upstream.test/leftpad").mock(
            return_value=httpx.Response(200, json=packument("leftpad", ["1.0.0"]))
        )
        assert (await client.get("/npm/leftpad")).status_code == 200
        await expire("leftpad")
        route.mock(return_value=httpx.Response(200, json=packument("leftpad", ["1.0.0", "1.1.0"])))
        body = (await client.get("/npm/leftpad")).json()
        assert body["versions"]["1.0.0"]["dist"]["shasum"] == TARBALL_SHA1
        assert set(body["versions"]) == {"1.0.0", "1.1.0"}


# --------------------------------------------------------------------------- #
# 4/5. Upstream changes invalidate what they should
# --------------------------------------------------------------------------- #
class TestUpstreamChangesInvalidate:
    @respx.mock
    async def test_disabling_pauses_and_deleting_removes(self, app_client):  # noqa: F811
        """Disabling is a routine toggle (maintenance, a flaky index, a token
        rotation) and must not destroy what re-enabling cannot restore.
        Deleting the upstream is what removes what it alone supplied."""
        ah = auth(app_client, "admin")
        bad, _good = await add(
            npm_upstream("bad", "https://upstream.test", tier=1),
            npm_upstream("good", "https://fallback.test", tier=2),
        )
        respx.get("https://upstream.test/leftpad").mock(
            return_value=httpx.Response(200, json=packument("leftpad", ["1.0.0", "6.6.6"]))
        )
        respx.get("https://upstream.test/leftpad/-/leftpad-6.6.6.tgz").mock(
            return_value=httpx.Response(200, content=TARBALL)
        )
        good_route = respx.get("https://fallback.test/leftpad").mock(
            return_value=httpx.Response(
                200, json=packument("leftpad", ["1.0.0"], host="https://fallback.test")
            )
        )
        assert versions_in(await app_client.get("/npm/leftpad")) == {"1.0.0", "6.6.6"}
        tgz = await app_client.get("/npm/leftpad/-/leftpad-6.6.6.tgz")
        assert tgz.status_code == 200

        resp = await app_client.patch(f"/api/admin/upstreams/{bad}", json={"enabled": False}, headers=ah)
        assert resp.status_code == 200

        # Paused: the cached tarball and the version both survive, including
        # the refresh the disable triggered (answered by the lower tier).
        assert (await app_client.get("/npm/leftpad/-/leftpad-6.6.6.tgz")).status_code == 200
        assert versions_in(await app_client.get("/npm/leftpad")) == {"1.0.0", "6.6.6"}
        assert good_route.call_count == 1
        assert await stored_versions("leftpad") == {"1.0.0", "6.6.6"}

        # Deleting it removes what it alone supplied, at once.
        resp = await app_client.delete(f"/api/admin/upstreams/{bad}", headers=ah)
        assert resp.status_code == 200
        assert (await app_client.get("/npm/leftpad/-/leftpad-6.6.6.tgz")).status_code == 404
        assert versions_in(await app_client.get("/npm/leftpad")) == {"1.0.0"}
        assert await stored_versions("leftpad") == {"1.0.0"}

    @respx.mock
    async def test_an_empty_higher_tier_answer_does_not_displace(self, app_client):  # noqa: F811
        """A tier that answers 200 with no files says nothing about lower
        tiers; pruning on it would purge every cached lower-tier file."""
        _internal, public = await add(
            pypi_upstream("internal", "https://a.upstream.test/simple", tier=1),
            pypi_upstream("public", "https://b.upstream.test/simple", tier=2),
        )
        internal_route = respx.get("https://a.upstream.test/simple/widget/").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://b.upstream.test/simple/widget/").mock(
            return_value=httpx.Response(
                200,
                json=pypi_page("widget", [("widget-1.0.tar.gz", "https://b.upstream.test/w.tar.gz")]),
                headers=PYPI_JSON,
            )
        )
        accept = {"accept": "application/vnd.pypi.simple.v1+json"}
        assert (await app_client.get("/pypi/simple/widget/", headers=accept)).status_code == 200
        assert await stored_files("widget") == {"widget-1.0.tar.gz"}

        # The internal index now answers 200 with an empty page.
        internal_route.mock(
            return_value=httpx.Response(200, json=pypi_page("widget", []), headers=PYPI_JSON)
        )
        await expire("widget", Ecosystem.pypi)
        assert (await app_client.get("/pypi/simple/widget/", headers=accept)).status_code == 200
        assert await stored_files("widget") == {"widget-1.0.tar.gz"}
        assert public is not None

    @respx.mock
    async def test_deleting_an_upstream_keeps_local_versions(self, app_client):  # noqa: F811
        """A reserved-namespace package can hold both local and upstream
        versions. Only the upstream's go."""
        (uid,) = await add(npm_upstream("only", "https://upstream.test"))
        async with db_module.session_scope() as session:
            package = Package(
                ecosystem=Ecosystem.npm, name="mixed", normalized_name="mixed",
                is_local=True, keywords=[],
            )
            session.add(package)
            await session.flush()
            local = PackageVersion(
                package_id=package.id, version="1.0.0", normalized_version="1.0.0",
                is_local=True, metadata_json={"name": "mixed", "version": "1.0.0"},
            )
            remote = PackageVersion(
                package_id=package.id, version="0.9.0", normalized_version="0.9.0",
                upstream_id=uid, metadata_json={"name": "mixed", "version": "0.9.0"},
            )
            session.add_all([local, remote])
            await session.flush()
            session.add(PackageFile(version_id=remote.id, filename="mixed-0.9.0.tgz", upstream_id=uid))

        resp = await app_client.delete(f"/api/admin/upstreams/{uid}", headers=auth(app_client, "admin"))
        assert resp.status_code == 200
        assert await stored_versions("mixed") == {"1.0.0"}

    async def test_deleting_an_upstream_clears_its_tags_latest_and_validators(self, app_client):  # noqa: F811
        """What named the removed versions must go with them, or a dist-tag
        points at nothing and a 304 from stale validators "confirms" a
        document whose versions are gone."""
        from app.models import DistTag
        from app.upstreams.revalidation import Validators

        (uid,) = await add(npm_upstream("only", "https://upstream.test"))
        async with db_module.session_scope() as session:
            package = Package(
                ecosystem=Ecosystem.npm, name="gone", normalized_name="gone",
                is_local=False, keywords=[], latest_version="2.0.0",
                cached_etag=Validators(upstream_id=uid, etag='"abc"').encode(),
            )
            session.add(package)
            await session.flush()
            session.add(
                PackageVersion(
                    package_id=package.id, version="2.0.0", normalized_version="2.0.0",
                    upstream_id=uid, metadata_json={"name": "gone", "version": "2.0.0"},
                )
            )
            session.add(DistTag(package_id=package.id, tag="latest", version="2.0.0"))

        resp = await app_client.delete(f"/api/admin/upstreams/{uid}", headers=auth(app_client, "admin"))
        assert resp.status_code == 200
        async with db_module.session_scope() as session:
            row = (
                await session.execute(
                    select(Package.latest_version, Package.cached_etag).where(Package.name == "gone")
                )
            ).one()
            tags = (await session.execute(select(DistTag.tag))).scalars().all()
        assert row.latest_version is None
        assert row.cached_etag is None
        assert tags == []

    @respx.mock
    async def test_deleting_one_index_keeps_the_others_files(self, app_client):  # noqa: F811
        a, b = await add(
            pypi_upstream("a", "https://a.upstream.test/simple", priority=1),
            pypi_upstream("b", "https://b.upstream.test/simple", priority=2),
        )
        respx.get("https://a.upstream.test/simple/widget/").mock(
            return_value=httpx.Response(
                200,
                json=pypi_page("widget", [("widget-1.0-py3-none-any.whl", "https://a.upstream.test/w.whl")]),
                headers=PYPI_JSON,
            )
        )
        respx.get("https://b.upstream.test/simple/widget/").mock(
            return_value=httpx.Response(
                200,
                json=pypi_page(
                    "widget",
                    [
                        ("widget-1.0.tar.gz", "https://b.upstream.test/w.tar.gz"),
                        ("widget-2.0.tar.gz", "https://b.upstream.test/w2.tar.gz"),
                    ],
                ),
                headers=PYPI_JSON,
            )
        )
        accept = {"accept": "application/vnd.pypi.simple.v1+json"}
        assert (await app_client.get("/pypi/simple/widget/", headers=accept)).status_code == 200
        assert await stored_files("widget") == {
            "widget-1.0-py3-none-any.whl", "widget-1.0.tar.gz", "widget-2.0.tar.gz"
        }

        # Disabling b is a pause: nothing is removed.
        await app_client.patch(
            f"/api/admin/upstreams/{b}", json={"enabled": False}, headers=auth(app_client, "admin")
        )
        assert await stored_files("widget") == {
            "widget-1.0-py3-none-any.whl", "widget-1.0.tar.gz", "widget-2.0.tar.gz"
        }
        # Deleting b removes only what b alone supplied.
        await app_client.delete(f"/api/admin/upstreams/{b}", headers=auth(app_client, "admin"))
        assert await stored_files("widget") == {"widget-1.0-py3-none-any.whl"}
        assert await stored_versions("widget", Ecosystem.pypi) == {"1.0"}
        async with db_module.session_scope() as session:
            version = (
                await session.execute(select(PackageVersion).where(PackageVersion.version == "1.0"))
            ).scalar_one()
            assert version.upstream_id == a

    async def test_adding_an_upstream_clears_misses_and_marks_stale(self, client, fake_redis):
        async with db_module.session_scope() as session:
            session.add(
                Package(
                    ecosystem=Ecosystem.npm, name="cached", normalized_name="cached",
                    is_local=False, keywords=[], cached_at=datetime.now(UTC),
                )
            )
        await cache_module.cache_set_json("pkg:npm:typo:miss", {"miss": True}, 300)
        await cache_module.cache_set_json("pkg:npm:cached:full", {"doc": 1}, 300)
        await cache_module.cache_set_json("pkg:pypi:other:miss", {"miss": True}, 300)

        resp = await client.post(
            "/api/admin/upstreams",
            json={"name": "new", "ecosystem": "npm", "kind": "npm", "url": "https://new.test"},
            headers=auth(client, "admin"),
        )
        assert resp.status_code == 201
        assert fake_redis.keys_like("pkg:npm:*") == []
        # Other ecosystems are untouched.
        assert fake_redis.keys_like("pkg:pypi:*") == ["pkg:pypi:other:miss"]
        assert (await stored("cached")).cached_at is None

    @respx.mock
    async def test_a_negative_cached_name_resolves_after_an_upstream_is_added(
        self, app_client, fake_redis  # noqa: F811
    ):
        respx.get("https://upstream.test/newpkg").mock(return_value=httpx.Response(404))
        assert (await app_client.get("/npm/newpkg")).status_code == 404  # no upstreams at all
        await add(npm_upstream("x", "https://elsewhere.test"))
        # Added behind the API's back: the miss is still remembered.
        respx.get("https://elsewhere.test/newpkg").mock(return_value=httpx.Response(404))
        assert (await app_client.get("/npm/newpkg")).status_code == 404
        assert fake_redis.keys_like("pkg:npm:newpkg:miss")

        resp = await app_client.post(
            "/api/admin/upstreams",
            json={"name": "has-it", "ecosystem": "npm", "kind": "npm", "url": "https://upstream.test"},
            headers=auth(app_client, "admin"),
        )
        assert resp.status_code == 201
        respx.get("https://upstream.test/newpkg").mock(
            return_value=httpx.Response(200, json=packument("newpkg", ["1.0.0"]))
        )
        assert versions_in(await app_client.get("/npm/newpkg")) == {"1.0.0"}

    async def test_tier_change_marks_stale_but_a_timeout_change_does_not(self, client, fake_redis):
        async with db_module.session_scope() as session:
            uid = (await session.execute(select(Upstream.id))).scalar_one()
            session.add(
                Package(
                    ecosystem=Ecosystem.npm, name="cached", normalized_name="cached",
                    is_local=False, keywords=[], cached_at=datetime.now(UTC),
                    cached_etag=Validators(uid, etag=ETAG).encode(),
                )
            )
        ah = auth(client, "admin")
        await cache_module.cache_set_json("pkg:npm:cached:full", {"doc": 1}, 300)

        await client.patch(f"/api/admin/upstreams/{uid}", json={"timeout_seconds": 5}, headers=ah)
        assert (await stored("cached")).cached_at is not None
        assert fake_redis.keys_like("pkg:npm:*")

        await client.patch(f"/api/admin/upstreams/{uid}", json={"tier": 3}, headers=ah)
        row = await stored("cached")
        assert row.cached_at is None
        assert row.cached_etag is not None  # same server, validators still good
        assert fake_redis.keys_like("pkg:npm:*") == []

        await client.patch(
            f"/api/admin/upstreams/{uid}", json={"url": "https://moved.test"}, headers=ah
        )
        assert (await stored("cached")).cached_etag is None


class TestProvenancePruning:
    @respx.mock
    async def test_a_higher_tier_answer_displaces_a_lower_tiers_versions(self, app_client):  # noqa: F811
        """The dependency-confusion residue: a public tier answered for an
        internal name once, and its versions outlived the internal registry
        coming back."""
        await add(
            npm_upstream("internal", "https://internal.test", tier=1),
            npm_upstream("public", "https://upstream.test", tier=2),
        )
        internal_route = respx.get("https://internal.test/corp-lib").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://upstream.test/corp-lib").mock(
            return_value=httpx.Response(200, json=packument("corp-lib", ["1.0.0", "99.0.0"]))
        )
        assert versions_in(await app_client.get("/npm/corp-lib")) == {"1.0.0", "99.0.0"}

        await expire("corp-lib")
        internal_route.mock(
            return_value=httpx.Response(
                200, json=packument("corp-lib", ["1.0.0", "1.1.0"], host="https://internal.test")
            )
        )
        body = (await app_client.get("/npm/corp-lib")).json()
        assert set(body["versions"]) == {"1.0.0", "1.1.0"}
        assert body["dist-tags"]["latest"] == "1.1.0"
        assert await stored_versions("corp-lib") == {"1.0.0", "1.1.0"}

    @respx.mock
    async def test_an_unavailable_upstream_keeps_serving(self, client):
        route = respx.get("https://upstream.test/leftpad").mock(
            return_value=httpx.Response(200, json=packument("leftpad", ["1.0.0", "1.1.0"]))
        )
        assert (await client.get("/npm/leftpad")).status_code == 200
        await expire("leftpad")
        route.mock(return_value=httpx.Response(503))
        assert versions_in(await client.get("/npm/leftpad")) == {"1.0.0", "1.1.0"}

    @respx.mock
    async def test_a_version_the_answering_upstream_dropped_is_kept(self, client):
        """Unchanged behaviour: an upstream deleting a version does not
        delete our copy."""
        route = respx.get("https://upstream.test/leftpad").mock(
            return_value=httpx.Response(200, json=packument("leftpad", ["1.0.0", "1.1.0"]))
        )
        assert (await client.get("/npm/leftpad")).status_code == 200
        await expire("leftpad")
        route.mock(return_value=httpx.Response(200, json=packument("leftpad", ["1.1.0"])))
        assert versions_in(await client.get("/npm/leftpad")) == {"1.0.0", "1.1.0"}

    @respx.mock
    async def test_a_name_an_upstream_no_longer_claims_is_pruned_on_refresh(self, client):
        respx.get("https://upstream.test/@corp/x").mock(
            return_value=httpx.Response(200, json=packument("@corp/x", ["1.0.0"]))
        )
        assert (await client.get("/npm/@corp/x")).status_code == 200
        # Another upstream now owns @corp/* and does not have it.
        await add(npm_upstream("corp", "https://internal.test", name_patterns=["@corp/*"]))
        respx.get("https://internal.test/@corp/x").mock(return_value=httpx.Response(404))
        await expire("@corp/x")
        assert (await client.get("/npm/@corp/x")).status_code == 404
        assert await stored_versions("@corp/x") == set()


class TestNoTransactionAcrossUpstreamIO:
    @respx.mock
    async def test_the_session_is_idle_while_the_upstream_is_asked(self, client):
        """Postgres kills a transaction left idle for 60 s; a slow upstream or
        a long wait on the herd lock must not hold one open."""
        seen: list[bool] = []
        async with db_module.session_scope() as session:
            # Something already read on this session, as a handler would have.
            await session.execute(select(Upstream.id))
            assert session.in_transaction()

            def respond(request):
                seen.append(session.in_transaction())
                return httpx.Response(200, json=packument("leftpad", ["1.0.0"]))

            respx.get("https://upstream.test/leftpad").mock(side_effect=respond)
            lookup = await packages_service.fetch_package(session, Ecosystem.npm, "leftpad")
            assert lookup.package is not None
        assert seen == [False]

    async def test_the_herd_wait_happens_outside_a_transaction(self, client, monkeypatch):
        seen: list[bool] = []
        real_guard = packages_service.herd_guard

        async with db_module.session_scope() as session:
            await session.execute(select(Upstream.id))

            class Spy(real_guard):
                async def __aenter__(self):
                    seen.append(session.in_transaction())
                    return await super().__aenter__()

            monkeypatch.setattr(packages_service, "herd_guard", Spy)
            with respx.mock:
                respx.get("https://upstream.test/nothing").mock(return_value=httpx.Response(404))
                await packages_service.fetch_package(session, Ecosystem.npm, "nothing")
        assert seen == [False]
