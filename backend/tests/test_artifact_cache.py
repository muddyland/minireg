"""The package artifact cache: transactions, streaming fills, leases, GC,
eviction and redirect checking, plus the cache primitives under them."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
import respx
from sqlalchemy import func, select, update

from app import db as db_module
from app.core import cache
from app.models import Blob, Ecosystem, Package, PackageFile, PackageVersion, Upstream, UpstreamKind
from app.services import artifacts
from app.services.storage import BlobStore, set_store

BODY = b"0123456789abcdef" * 4096  # 64 KiB
BODY_SHA = hashlib.sha256(BODY).hexdigest()


# --------------------------------------------------------------------------- #
# Fixtures and helpers
# --------------------------------------------------------------------------- #
class MemRedis:
    """Just enough of Redis for herd_guard and Lease: SET NX EX, EXISTS, and
    the token-checked renew/release scripts. Keys expire on a real clock."""

    def __init__(self):
        self.d: dict[str, tuple[bytes, float]] = {}

    def _live(self, k):
        item = self.d.get(k)
        if item is None:
            return None
        if item[1] <= time.monotonic():
            del self.d[k]
            return None
        return item[0]

    async def set(self, k, v, nx=False, ex=None):
        if nx and self._live(k) is not None:
            return None
        self.d[k] = (v, time.monotonic() + (ex or 3600))
        return True

    async def get(self, k):
        return self._live(k)

    async def exists(self, k):
        return int(self._live(k) is not None)

    async def eval(self, script, _n, k, token, *args):
        if self._live(k) != token:
            return 0
        if "expire" in script:
            self.d[k] = (token, time.monotonic() + float(args[0]))
            return 1
        del self.d[k]
        return 1


@pytest.fixture
def no_redis(monkeypatch):
    monkeypatch.setattr(cache, "_redis", None)
    monkeypatch.setattr(cache, "_down_until", time.monotonic() + 3600)
    monkeypatch.setattr(cache, "_tripped_client", None)


@pytest.fixture
def mem_redis(monkeypatch):
    fake = MemRedis()
    monkeypatch.setattr(cache, "_redis", fake)
    monkeypatch.setattr(cache, "_tripped_client", None)
    monkeypatch.setattr(cache, "_down_until", 0.0)
    return fake


@pytest_asyncio.fixture
async def store(tmp_path, no_redis):
    db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'artifacts.db'}")
    await db_module.create_schema()
    blob_store = BlobStore(str(tmp_path / "storage"))
    blob_store.ensure_dirs()
    set_store(blob_store)
    artifacts._fills.clear()
    artifacts._opening.clear()
    yield blob_store
    # Let any download task finish before the engine goes.
    for fill in list(artifacts._fills.values()):
        if fill.task is not None:
            fill.task.cancel()
            with contextlib.suppress(BaseException):
                await fill.task
    await db_module.dispose_engine()
    set_store(None)  # type: ignore[arg-type]


_counter = 0


async def make_file(
    *,
    url: str | None = "https://cdn.upstream.test/a.tgz",
    sha256: str | None = BODY_SHA,
    size: int | None = None,
    upstream_id: int | None = None,
) -> int:
    global _counter
    _counter += 1
    async with db_module.session_scope() as session:
        package = Package(
            ecosystem=Ecosystem.npm, name=f"pkg{_counter}", normalized_name=f"pkg{_counter}"
        )
        session.add(package)
        await session.flush()
        version = PackageVersion(package_id=package.id, version="1.0.0", normalized_version="1.0.0")
        session.add(version)
        await session.flush()
        row = PackageFile(
            version_id=version.id,
            filename=f"pkg{_counter}-1.0.0.tgz",
            upstream_url=url,
            upstream_id=upstream_id,
            sha256=sha256,
            size=size,
        )
        session.add(row)
        await session.flush()
        return row.id


async def store_cached(
    store: BlobStore, data: bytes, *, url: str | None, accessed: datetime
) -> str:
    """A file row whose blob is already cached (url=None means published here)."""
    stored = await store.put_bytes(data)
    file_id = await make_file(url=url, sha256=stored.sha256, size=stored.size)
    async with db_module.session_scope() as session:
        session.add(
            Blob(
                sha256=stored.sha256,
                size=stored.size,
                path=stored.path,
                refcount=1,
                last_accessed_at=accessed,
            )
        )
        await session.execute(
            update(PackageFile)
            .where(PackageFile.id == file_id)
            .values(blob_sha256=stored.sha256, cached_at=datetime.now(UTC))
        )
    return stored.sha256


def gated_body(first: bytes, rest: bytes, gate: asyncio.Event):
    async def body():
        yield first
        await gate.wait()
        yield rest

    return body()


async def drain(chunks) -> bytes:
    out = bytearray()
    async for chunk in chunks:
        out += chunk
    return bytes(out)


async def blob_rows() -> int:
    async with db_module.session_scope() as session:
        return (await session.execute(select(func.count()).select_from(Blob))).scalar_one()


# --------------------------------------------------------------------------- #
# 1. No transaction across the download
# --------------------------------------------------------------------------- #
class TestNoTransactionAcrossDownload:
    @respx.mock
    async def test_session_is_idle_during_the_download_and_usable_after(self, store):
        file_id = await make_file()
        seen = {}
        async with db_module.get_sessionmaker()() as session:
            row = await session.get(PackageFile, file_id)
            assert session.in_transaction()

            def respond(request):
                # Postgres kills a transaction idle this long; there must not be one.
                seen["in_transaction"] = session.in_transaction()
                return httpx.Response(200, content=BODY)

            respx.get("https://cdn.upstream.test/a.tgz").mock(side_effect=respond)
            await artifacts.ensure_cached(session, row)

            assert seen["in_transaction"] is False
            assert row.blob_sha256 == BODY_SHA
            # The caller's session keeps working, as the route handlers expect.
            assert (await session.execute(select(PackageFile.size))).scalar_one() == len(BODY)
            await session.commit()

    @respx.mock
    async def test_concurrent_waiters_hold_no_transaction_and_share_one_download(self, store):
        file_id = await make_file()
        gate = asyncio.Event()
        route = respx.get("https://cdn.upstream.test/a.tgz").mock(
            side_effect=lambda r: httpx.Response(200, content=gated_body(BODY[:10], BODY[10:], gate))
        )
        maker = db_module.get_sessionmaker()
        async with maker() as s1, maker() as s2:
            r1 = await s1.get(PackageFile, file_id)
            r2 = await s2.get(PackageFile, file_id)
            t1 = asyncio.create_task(artifacts.ensure_cached(s1, r1))
            await asyncio.sleep(0.05)
            t2 = asyncio.create_task(artifacts.ensure_cached(s2, r2))
            await asyncio.sleep(0.05)
            assert not s1.in_transaction() and not s2.in_transaction()
            gate.set()
            await asyncio.gather(t1, t2)
            assert r1.blob_sha256 == r2.blob_sha256 == BODY_SHA
        assert route.call_count == 1
        async with db_module.session_scope() as session:
            assert (await session.get(Blob, BODY_SHA)).refcount == 1


# --------------------------------------------------------------------------- #
# 3. Streaming while filling
# --------------------------------------------------------------------------- #
class TestStreamWhileFilling:
    @respx.mock
    async def test_first_bytes_arrive_before_the_download_finishes(self, store, monkeypatch):
        monkeypatch.setattr(artifacts, "STREAM_AFTER_SECONDS", 0.05)
        file_id = await make_file()
        gate = asyncio.Event()
        route = respx.get("https://cdn.upstream.test/a.tgz").mock(
            side_effect=lambda r: httpx.Response(
                200,
                headers={"content-length": str(len(BODY))},
                content=gated_body(BODY[:1000], BODY[1000:], gate),
            )
        )
        maker = db_module.get_sessionmaker()
        async with maker() as s1, maker() as s2:
            r1 = await s1.get(PackageFile, file_id)
            chunks, size, _ = await artifacts.stream_artifact(s1, r1)
            assert size == len(BODY)
            it = chunks.__aiter__()
            # Nothing is committed while the bytes are still arriving.
            assert r1.blob_sha256 is None and await blob_rows() == 0

            # A second client joins the same download rather than starting one.
            r2 = await s2.get(PackageFile, file_id)
            chunks2, size2, _ = await artifacts.stream_artifact(s2, r2)
            assert size2 == len(BODY)

            first = bytearray()
            reader = asyncio.create_task(it.__anext__())
            await asyncio.sleep(0.05)
            gate.set()
            first += await reader
            first += await drain(it)
            assert bytes(first) == BODY
            assert await drain(chunks2) == BODY
        assert route.call_count == 1
        assert store.exists(BODY_SHA)
        assert await blob_rows() == 1

    @respx.mock
    async def test_mismatch_mid_stream_cuts_the_connection_and_commits_nothing(
        self, store, monkeypatch
    ):
        monkeypatch.setattr(artifacts, "STREAM_AFTER_SECONDS", 0.05)
        file_id = await make_file(sha256="0" * 64)
        gate = asyncio.Event()
        respx.get("https://cdn.upstream.test/a.tgz").mock(
            side_effect=lambda r: httpx.Response(
                200,
                headers={"content-length": str(len(BODY))},
                content=gated_body(BODY[:1000], BODY[1000:], gate),
            )
        )
        async with db_module.get_sessionmaker()() as session:
            row = await session.get(PackageFile, file_id)
            chunks, size, _ = await artifacts.stream_artifact(session, row)
            got = bytearray()
            gate.set()
            with pytest.raises(artifacts.FillFailed):
                async for chunk in chunks:
                    got += chunk
            # The final chunk was withheld: the client sees a short body,
            # never a complete one that failed verification.
            assert len(got) < size
        assert await blob_rows() == 0
        assert not [p for p in store.blobs_dir.rglob("*") if p.is_file()]
        async with db_module.session_scope() as session:
            assert (await session.get(PackageFile, file_id)).blob_sha256 is None

    @respx.mock
    async def test_fast_downloads_still_fail_with_a_status(self, store):
        """Within STREAM_AFTER_SECONDS the request waits, so a mismatch is a 502."""
        file_id = await make_file(sha256="0" * 64)
        respx.get("https://cdn.upstream.test/a.tgz").mock(return_value=httpx.Response(200, content=BODY))
        async with db_module.get_sessionmaker()() as session:
            row = await session.get(PackageFile, file_id)
            with pytest.raises(artifacts.DigestMismatch):
                await artifacts.stream_artifact(session, row)

    async def test_peer_replica_partial_is_tailed_until_its_ok_marker(self, store):
        key, token = "77", "abc"
        partial = store.partial_path(key, token)
        partial.write_bytes(BODY[:1000])
        stream = artifacts._tail_peer(key, len(BODY))
        got = bytearray()

        async def finish_like_a_peer():
            await asyncio.sleep(0.3)
            with open(partial, "ab") as fh:
                fh.write(BODY[1000:])
            store.adopt(partial, BODY_SHA)
            store.write_marker(key, token, f"ok {BODY_SHA}")

        peer = asyncio.create_task(finish_like_a_peer())
        async for chunk in stream:
            got += chunk
        await peer
        assert bytes(got) == BODY

    async def test_peer_replica_failure_cuts_the_stream(self, store):
        key, token = "78", "def"
        partial = store.partial_path(key, token)
        partial.write_bytes(BODY[:1000])
        store.write_marker(key, token, "failed")
        # A failed marker means the partial is no longer "unfinished".
        assert store.partials_for(key) == []
        partial2 = store.partial_path(key, "ghi")
        partial2.write_bytes(BODY[:1000])

        async def fail_like_a_peer():
            await asyncio.sleep(0.3)
            partial2.unlink()
            store.write_marker(key, "ghi", "failed")

        peer = asyncio.create_task(fail_like_a_peer())
        with pytest.raises(artifacts.FillFailed):
            await drain(artifacts._tail_peer(key, len(BODY)))
        await peer


# --------------------------------------------------------------------------- #
# 4/7. Renewable leases
# --------------------------------------------------------------------------- #
class TestLease:
    async def test_lease_outlives_its_ttl_while_held_and_excludes_others(self, mem_redis):
        lease = cache.Lease("job", ttl=0.3)
        assert await lease.acquire()
        await asyncio.sleep(1.0)  # > 3 TTLs
        assert not await cache.Lease("job", ttl=0.3).acquire()
        await lease.release()
        assert await cache.lease_is_free("job")
        other = cache.Lease("job", ttl=0.3)
        assert await other.acquire()
        await other.release()

    async def test_dead_holder_lapses(self, mem_redis):
        await mem_redis.set("lock:job", b"someone-else", nx=True, ex=0.2)
        assert not await cache.Lease("job").acquire()
        await asyncio.sleep(0.3)
        lease = cache.Lease("job")
        assert await lease.acquire()
        await lease.release()

    @respx.mock
    async def test_download_lease_is_held_and_renewed_for_the_whole_fill(
        self, store, mem_redis, monkeypatch
    ):
        monkeypatch.setattr(artifacts, "LEASE_SECONDS", 0.3)
        file_id = await make_file()
        gate = asyncio.Event()
        respx.get("https://cdn.upstream.test/a.tgz").mock(
            side_effect=lambda r: httpx.Response(200, content=gated_body(BODY[:10], BODY[10:], gate))
        )
        async with db_module.get_sessionmaker()() as session:
            row = await session.get(PackageFile, file_id)
            task = asyncio.create_task(artifacts.ensure_cached(session, row))
            await asyncio.sleep(1.0)  # several lease TTLs into the download
            assert not await cache.lease_is_free(f"artifact-fill:{file_id}")
            gate.set()
            await task
        assert await cache.lease_is_free(f"artifact-fill:{file_id}")

    async def test_housekeeping_skips_while_another_replica_holds_it(self, mem_redis, monkeypatch):
        from app import main

        ran = []

        async def task():
            ran.append(1)

        for name in ("_prune_task", "_artifact_task", "_docker_task", "_cve_refresh_task"):
            monkeypatch.setattr(main, name, task)
        await mem_redis.set("lock:housekeeping", b"peer", nx=True, ex=60)
        assert await main.housekeeping_pass() is False
        assert ran == []
        mem_redis.d.clear()
        assert await main.housekeeping_pass() is True
        assert len(ran) == 4
        assert await cache.lease_is_free("housekeeping")


# --------------------------------------------------------------------------- #
# 5. herd_guard's local lock
# --------------------------------------------------------------------------- #
class TestHerdGuardLocalLock:
    async def test_a_third_request_cannot_slip_in_while_a_waiter_wakes(self, no_redis):
        active = 0
        peak = 0

        async def worker():
            nonlocal active, peak
            async with cache.herd_guard("race"):
                active += 1
                peak = max(peak, active)
                await asyncio.sleep(0.02)
                active -= 1

        first = cache.herd_guard("race")
        await first.__aenter__()
        waiter = asyncio.create_task(worker())
        await asyncio.sleep(0)  # the waiter is now queued on the lock
        await first.__aexit__(None, None, None)
        # Released, the waiter woken but not yet running: a newcomer must
        # still queue behind it rather than get a fresh lock.
        newcomer = asyncio.create_task(worker())
        await asyncio.gather(waiter, newcomer)
        assert peak == 1
        assert "lock:race" not in cache._local_locks

    async def test_wait_false_does_not_leak_entries(self, no_redis):
        async with cache.herd_guard("solo", wait=False) as got:
            assert got
            async with cache.herd_guard("solo", wait=False) as second:
                assert not second
        assert "lock:solo" not in cache._local_locks


# --------------------------------------------------------------------------- #
# 6. Valkey circuit breaker and reconnect
# --------------------------------------------------------------------------- #
class TestCacheBreaker:
    async def test_an_outage_costs_one_failure_per_backoff_then_recovers(self, monkeypatch):
        now = {"t": 1000.0}
        monkeypatch.setattr(cache.time, "monotonic", lambda: now["t"])
        monkeypatch.setattr(cache, "_breaker_backoff", 0.0)
        monkeypatch.setattr(cache, "_down_until", 0.0)
        monkeypatch.setattr(cache, "_tripped_client", None)

        class Flaky:
            def __init__(self):
                self.calls = 0
                self.up = False

            async def get(self, key):
                self.calls += 1
                if not self.up:
                    raise ConnectionError("down")
                return b'{"ok": 1}'

            async def set(self, *a, **k):
                self.calls += 1
                raise ConnectionError("down")

        flaky = Flaky()
        monkeypatch.setattr(cache, "_redis", flaky)
        for _ in range(5):
            assert await cache.cache_get_json("k") is None
            await cache.cache_set_json("k", 1, 10)
            async with cache.herd_guard("x"):
                pass
        assert flaky.calls == 1  # every later call short-circuited

        now["t"] += cache._BREAKER_MIN + 0.1
        flaky.up = True
        assert await cache.cache_get_json("k") == {"ok": 1}
        assert cache.redis_client() is flaky

    async def test_reconnects_after_a_boot_time_outage(self, monkeypatch):
        now = {"t": 1000.0}
        monkeypatch.setattr(cache.time, "monotonic", lambda: now["t"])
        monkeypatch.setattr(cache, "_redis", None)
        monkeypatch.setattr(cache, "_down_until", now["t"] + 5)
        monkeypatch.setattr(cache, "_tripped_client", None)

        class Good:
            async def ping(self):
                return True

            async def get(self, key):
                return b"1"

        attempts = []

        def from_url(*a, **k):
            attempts.append(1)
            return Good()

        monkeypatch.setattr(cache.aioredis, "from_url", from_url)
        assert await cache.cache_get_json("k") is None
        assert attempts == []  # still inside the backoff: no connect attempt
        now["t"] += 10
        assert await cache.cache_get_json("k") == 1
        assert attempts == [1]
        monkeypatch.setattr(cache, "_redis", None)


# --------------------------------------------------------------------------- #
# 2. Orphan blob files
# --------------------------------------------------------------------------- #
class TestOrphanFileSweep:
    async def test_old_unrecorded_files_go_recent_and_recorded_ones_stay(self, store):
        old_orphan = await store.put_bytes(b"orphan from a refused publish")
        new_orphan = await store.put_bytes(b"a write that has not committed yet")
        recorded = await store_cached(
            store, b"a real cached blob", url="https://x", accessed=datetime.now(UTC)
        )
        old = time.time() - artifacts.ORPHAN_FILE_GRACE_SECONDS - 60
        for sha in (old_orphan.sha256, recorded):
            os.utime(store.path_for(sha), (old, old))

        result = await artifacts.sweep_orphan_files()

        assert result["files"] == 1
        assert not store.exists(old_orphan.sha256)
        assert store.exists(new_orphan.sha256)
        assert store.exists(recorded)

    async def test_rewriting_an_existing_blob_protects_it_from_the_sweep(self, store):
        stored = await store.put_bytes(b"same bytes")
        old = time.time() - artifacts.ORPHAN_FILE_GRACE_SECONDS - 60
        os.utime(store.path_for(stored.sha256), (old, old))
        again = await store.put_bytes(b"same bytes")  # e.g. a publish of identical bytes
        assert again.already_existed
        await artifacts.sweep_orphan_files()
        assert store.exists(stored.sha256)

    async def test_orphan_rows_are_collected_in_batches(self, store):
        stored = await store.put_bytes(b"row with no file pointing at it")
        async with db_module.session_scope() as session:
            session.add(Blob(sha256=stored.sha256, size=stored.size, path=stored.path))
        async with db_module.session_scope() as session:
            assert await artifacts.collect_orphan_blobs(session) == 1
        assert not store.exists(stored.sha256)
        assert await blob_rows() == 0


# --------------------------------------------------------------------------- #
# 8. Eviction under a quota
# --------------------------------------------------------------------------- #
class TestQuotaEviction:
    @respx.mock
    async def test_download_at_quota_evicts_lru_upstream_copies_not_local_ones(
        self, store, monkeypatch
    ):
        long_ago = datetime.now(UTC) - timedelta(days=30)
        local = await store_cached(store, b"L" * 4000, url=None, accessed=long_ago - timedelta(days=1))
        oldest = await store_cached(store, b"A" * 4000, url="https://x/a", accessed=long_ago)
        newer = await store_cached(
            store, b"B" * 4000, url="https://x/b", accessed=long_ago + timedelta(days=1)
        )
        monkeypatch.setattr(artifacts.settings, "storage_quota_bytes", 12_000)

        payload = b"N" * 2000
        file_id = await make_file(sha256=hashlib.sha256(payload).hexdigest(), size=len(payload))
        respx.get("https://cdn.upstream.test/a.tgz").mock(return_value=httpx.Response(200, content=payload))
        async with db_module.get_sessionmaker()() as session:
            row = await session.get(PackageFile, file_id)
            await artifacts.ensure_cached(session, row)
            assert row.blob_sha256

        assert store.exists(local)  # published here: never evicted
        assert not store.exists(oldest)  # least recently read upstream copy
        assert store.exists(newer)
        async with db_module.session_scope() as session:
            evicted = (
                await session.execute(
                    select(PackageFile.blob_sha256, PackageFile.upstream_url).where(
                        PackageFile.upstream_url == "https://x/a"
                    )
                )
            ).one()
            # The row keeps its URL, so the next request fetches it again.
            assert evicted == (None, "https://x/a")

    @respx.mock
    async def test_quota_full_of_local_packages_still_refuses(self, store, monkeypatch):
        await store_cached(store, b"L" * 4000, url=None, accessed=datetime.now(UTC) - timedelta(days=9))
        monkeypatch.setattr(artifacts.settings, "storage_quota_bytes", 4000)
        file_id = await make_file()
        route = respx.get("https://cdn.upstream.test/a.tgz").mock(return_value=httpx.Response(200, content=BODY))
        async with db_module.get_sessionmaker()() as session:
            row = await session.get(PackageFile, file_id)
            with pytest.raises(artifacts.ArtifactError, match="quota"):
                await artifacts.ensure_cached(session, row)
        assert route.call_count == 0

    async def test_recently_read_blobs_are_spared(self, store, monkeypatch):
        recent = await store_cached(store, b"R" * 4000, url="https://x/r", accessed=datetime.now(UTC))
        monkeypatch.setattr(artifacts.settings, "storage_quota_bytes", 1000)
        result = await artifacts.enforce_quota()
        assert result["evicted"] == 0
        assert store.exists(recent)

    async def test_housekeeping_evicts_to_the_low_water_mark(self, store, monkeypatch):
        long_ago = datetime.now(UTC) - timedelta(days=30)
        shas = [
            await store_cached(
                store, bytes([65 + i]) * 1000, url=f"https://x/{i}", accessed=long_ago + timedelta(hours=i)
            )
            for i in range(10)
        ]
        monkeypatch.setattr(artifacts.settings, "storage_quota_bytes", 9000)
        result = await artifacts.enforce_quota()
        # 10 000 used, quota 9000, low water 8100: the two oldest go.
        assert result["evicted"] == 2
        assert [store.exists(s) for s in shas] == [False, False] + [True] * 8


# --------------------------------------------------------------------------- #
# 9. Redirects on the no-upstream path
# --------------------------------------------------------------------------- #
class TestRedirectChecks:
    @respx.mock
    async def test_redirect_to_a_disallowed_host_is_never_connected_to(self, store):
        file_id = await make_file()
        respx.get("https://cdn.upstream.test/a.tgz").mock(
            return_value=httpx.Response(302, headers={"location": "https://metadata.evil.test/latest"})
        )
        evil = respx.get("https://metadata.evil.test/latest").mock(
            return_value=httpx.Response(200, content=BODY)
        )
        async with db_module.get_sessionmaker()() as session:
            row = await session.get(PackageFile, file_id)
            with pytest.raises(artifacts.ArtifactError):
                await artifacts.ensure_cached(session, row)
        assert evil.call_count == 0

    @respx.mock
    async def test_allowed_redirect_is_followed(self, store):
        file_id = await make_file()
        respx.get("https://cdn.upstream.test/a.tgz").mock(
            return_value=httpx.Response(302, headers={"location": "https://files.upstream.test/a"})
        )
        respx.get("https://files.upstream.test/a").mock(return_value=httpx.Response(200, content=BODY))
        async with db_module.get_sessionmaker()() as session:
            row = await session.get(PackageFile, file_id)
            await artifacts.ensure_cached(session, row)
            assert row.blob_sha256 == BODY_SHA

    @respx.mock
    async def test_redirect_loops_are_bounded(self, store):
        file_id = await make_file()
        loop = respx.get("https://cdn.upstream.test/a.tgz").mock(
            return_value=httpx.Response(302, headers={"location": "https://cdn.upstream.test/a.tgz"})
        )
        async with db_module.get_sessionmaker()() as session:
            row = await session.get(PackageFile, file_id)
            with pytest.raises(artifacts.ArtifactError, match="redirects"):
                await artifacts.ensure_cached(session, row)
        assert loop.call_count == artifacts.MAX_REDIRECTS + 1


# --------------------------------------------------------------------------- #
# Upstream-row path still checks the upstream
# --------------------------------------------------------------------------- #
class TestUpstreamChecks:
    async def test_disabled_upstream_refuses_without_fetching(self, store):
        async with db_module.session_scope() as session:
            upstream = Upstream(
                name="off",
                ecosystem=Ecosystem.npm,
                kind=UpstreamKind.npm,
                url="https://upstream.test",
                enabled=False,
            )
            session.add(upstream)
            await session.flush()
            upstream_id = upstream.id
        file_id = await make_file(upstream_id=upstream_id)
        async with db_module.get_sessionmaker()() as session:
            row = await session.get(PackageFile, file_id)
            with pytest.raises(artifacts.ArtifactError, match="disabled"):
                await artifacts.ensure_cached(session, row)


async def test_blobs_from_a_disabled_upstream_are_not_evicted(store, monkeypatch):
    """Disabling an upstream is a pause: its cached copies cannot be fetched
    again while it is paused, so quota pressure must not take them."""
    from app.models import Ecosystem, Upstream, UpstreamKind

    long_ago = datetime.now(UTC) - timedelta(days=30)
    paused = await store_cached(store, b"P" * 4000, url="https://x/p", accessed=long_ago)
    live = await store_cached(
        store, b"Q" * 4000, url="https://x/q", accessed=long_ago + timedelta(days=1)
    )
    async with db_module.session_scope() as session:
        upstream = Upstream(
            name="paused", ecosystem=Ecosystem.npm, kind=UpstreamKind.npm,
            url="https://paused.test", tier=1, enabled=False,
        )
        session.add(upstream)
        await session.flush()
        await session.execute(
            update(PackageFile)
            .where(PackageFile.blob_sha256 == paused)
            .values(upstream_id=upstream.id)
        )
    monkeypatch.setattr(artifacts.settings, "storage_quota_bytes", 5000)
    await artifacts.enforce_quota()
    assert store.exists(paused)
    assert not store.exists(live)


def test_a_crashed_downloads_partial_is_not_tailed(store):
    """A partial with no marker that stopped growing belongs to a process
    that died; a reader must pick the live one, not wait out the stall."""
    store.partial_dir.mkdir(parents=True, exist_ok=True)
    dead = store.partial_dir / "file-7.deadtoken"
    live = store.partial_dir / "file-7.livetoken"
    dead.write_bytes(b"half")
    live.write_bytes(b"growing")
    old = time.time() - artifacts.PEER_STALL_SECONDS - 60
    os.utime(dead, (old, old))

    picked = store.partials_for("file-7", live_within=artifacts.PEER_STALL_SECONDS)
    assert [token for token, _ in picked] == ["livetoken"]
    # Without the filter both are listed, newest first.
    assert [token for token, _ in store.partials_for("file-7")] == ["livetoken", "deadtoken"]
