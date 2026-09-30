"""Content-addressed store for image blobs, with fills clients can read
while they are still being written.

Layers are the reason this is not ``services.storage.BlobStore``. That store
hashes a whole artifact into a temp file and only then renames it into
place, so the first client of a cold 2 GB layer would wait for the whole
download before receiving a byte -- long past any client's timeout. Here a
fill writes to ``partial/<digest>`` and every reader, the first one and any
that arrive meanwhile, tails that file as it grows. When the fill verifies
the digest it renames the file into place; if it fails the readers are told
and the file is deleted.

Layout, under ``STORAGE_PATH/oci``::

    blobs/sha256/ab/<hex>   verified, immutable, 0444
    partial/<hex>           a fill in progress (readers tail it)
    uploads/<uuid>          a client push in progress

A separate tree from the package store: package GC walks ``Blob`` rows and
would never see these, and eviction here has nothing to do with packages.

Single flight is per process (the in-memory ``_fills`` map) plus a Redis
lease so two replicas do not both download the same layer. The lease is
renewed while bytes keep arriving, rather than given one long TTL: the
package path's fixed 300 s lock was shorter than a large layer's download,
so a second replica started a duplicate fill half way through.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path

import aiofiles

from ..config import settings
from ..core import cache
from ..core.metrics import bump
from .errors import RegistryError

log = logging.getLogger(__name__)

CHUNK = 256 * 1024
#: How long a replica's claim on a fill lasts without a renewal.
LEASE_SECONDS = 30
#: How long a reader waits for a peer replica's fill to make progress before
#: giving up and fetching it itself.
PEER_STALL_SECONDS = 45


class FillFailed(Exception):
    """The upstream download for this blob failed; readers must stop."""


@dataclass(eq=False)
class Fill:
    """One in-progress download, shared by every reader in this process."""

    digest: str
    path: Path
    expected_size: int | None = None
    written: int = 0
    done: bool = False
    error: str | None = None
    changed: asyncio.Condition = field(default_factory=asyncio.Condition)
    task: asyncio.Task | None = None

    async def advance(self, written: int) -> None:
        async with self.changed:
            self.written = written
            self.changed.notify_all()

    async def finish(self, error: str | None = None) -> None:
        async with self.changed:
            self.done = True
            self.error = error
            self.changed.notify_all()


class OciStore:
    def __init__(self, root: str | Path | None = None) -> None:
        base = Path(root) if root else Path(settings.storage_path) / "oci"
        self.root = base
        self.blobs = base / "blobs" / "sha256"
        self.partial = base / "partial"
        self.uploads = base / "uploads"
        self._fills: dict[str, Fill] = {}
        #: Fills whose upstream stream is still being opened (token exchange,
        #: redirect, first byte). Later arrivals in this process wait on it
        #: instead of opening a second upstream connection.
        self._opening: dict[str, asyncio.Future] = {}

    def ensure_dirs(self) -> None:
        for d in (self.blobs, self.partial, self.uploads):
            d.mkdir(parents=True, exist_ok=True)

    # -- paths -------------------------------------------------------------- #
    @staticmethod
    def hex_of(digest: str) -> str:
        algo, _, hexpart = digest.partition(":")
        if algo != "sha256" or len(hexpart) != 64:
            raise ValueError(f"unsupported digest {digest!r}")
        return hexpart

    def path_for(self, digest: str) -> Path:
        h = self.hex_of(digest)
        return self.blobs / h[:2] / h

    def exists(self, digest: str) -> bool:
        return self.path_for(digest).is_file()

    def size_of(self, digest: str) -> int | None:
        p = self.path_for(digest)
        return p.stat().st_size if p.is_file() else None

    # -- small writes (manifests, reports) --------------------------------- #
    async def put_bytes(self, data: bytes, expected: str | None = None) -> str:
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        if expected and expected != digest:
            raise RegistryError("DIGEST_INVALID", f"content digest is {digest}, not {expected}")
        final = self.path_for(digest)
        if final.is_file():
            return digest
        self.ensure_dirs()
        tmp = self.partial / f"small-{secrets.token_hex(8)}"
        try:
            async with aiofiles.open(tmp, "wb") as fh:
                await fh.write(data)
                await fh.flush()
                await asyncio.to_thread(os.fsync, fh.fileno())
            final.parent.mkdir(parents=True, exist_ok=True)
            os.replace(tmp, final)
            os.chmod(final, 0o444)
        finally:
            tmp.unlink(missing_ok=True)
        return digest

    async def read_bytes(self, digest: str, limit: int | None = None) -> bytes | None:
        p = self.path_for(digest)
        if not p.is_file():
            return None
        if limit is not None and p.stat().st_size > limit:
            raise RegistryError("SIZE_INVALID", f"{digest} is larger than {limit} bytes")
        async with aiofiles.open(p, "rb") as fh:
            return await fh.read()

    # -- reads -------------------------------------------------------------- #
    async def iter_file(
        self, digest: str, start: int = 0, end: int | None = None
    ) -> AsyncIterator[bytes]:
        """Stream a stored blob, optionally a byte range (end inclusive)."""
        path = self.path_for(digest)
        async with aiofiles.open(path, "rb") as fh:
            if start:
                await fh.seek(start)
            remaining = None if end is None else end - start + 1
            while remaining is None or remaining > 0:
                chunk = await fh.read(CHUNK if remaining is None else min(CHUNK, remaining))
                if not chunk:
                    break
                if remaining is not None:
                    remaining -= len(chunk)
                yield chunk

    # -- fills -------------------------------------------------------------- #
    def current_fill(self, digest: str) -> Fill | None:
        return self._fills.get(digest)

    async def fill_and_stream(
        self,
        digest: str,
        opener: Callable[[], Awaitable[AsyncIterator[bytes]]],
        *,
        expected_size: int | None,
        on_complete: Callable[[str, int], object] | None = None,
    ) -> AsyncIterator[bytes]:
        """Return an iterator over the blob, downloading it once if needed.

        ``opener`` is awaited at most once per process (and, with Redis, once
        across replicas) to open the upstream stream. It is awaited here, in
        the caller's request, so an upstream 404 or 429 reaches the client as
        that status instead of as a 200 followed by a dropped connection. The
        download itself then runs as its own task, so a client that
        disconnects does not abort a fill other clients -- or the next pull
        -- are waiting on.
        """
        if self.exists(digest):
            return self.iter_file(digest)

        while True:
            fill = self._fills.get(digest)
            if fill is not None:
                bump("docker.fill.joined")
                return self._tail(fill)
            opening = self._opening.get(digest)
            if opening is None:
                break
            # Another request in this process is opening the upstream. Wait
            # for it rather than opening a second connection: with a hundred
            # CI jobs arriving together, that is a hundred upstream requests.
            try:
                outcome = await asyncio.shield(opening)
            except Exception:
                # Its open failed (a 429, say). That error belongs to its
                # client; this request makes its own attempt.
                continue
            return self._outcome_stream(digest, outcome)

        outcome = await self._start_fill(digest, opener, expected_size, on_complete)
        return self._outcome_stream(digest, outcome)

    def _outcome_stream(self, digest: str, outcome: Fill | str | None) -> AsyncIterator[bytes]:
        if isinstance(outcome, Fill):
            return self._tail(outcome)
        if outcome == "peer":
            return self._tail_peer(digest)
        return self.iter_file(digest)

    async def _start_fill(self, digest, opener, expected_size, on_complete) -> Fill | str | None:
        """Become the filler for ``digest``.

        Returns the Fill, ``"peer"`` when another replica is filling it
        (stream its partial file), or None when the blob is already complete.
        """
        self.ensure_dirs()
        hexd = self.hex_of(digest)
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._opening[digest] = future
        try:
            outcome = await self._open_fill(digest, hexd, opener, expected_size, on_complete)
        except BaseException as exc:
            if not future.done():
                future.set_exception(exc if isinstance(exc, Exception) else RuntimeError("cancelled"))
                # Nobody may be waiting; do not warn about an unread exception.
                future.exception()
            raise
        finally:
            self._opening.pop(digest, None)
        if not future.done():
            future.set_result(outcome)
        return outcome

    async def _open_fill(self, digest, hexd, opener, expected_size, on_complete) -> Fill | str | None:
        lease = _Lease(f"oci-fill:{hexd}")
        if not await lease.acquire():
            # A peer replica is filling it into the shared volume.
            bump("docker.fill.peer_wait")
            return "peer"
        # Re-check after the lease: a peer may have finished between our
        # existence check and the acquire.
        if self.exists(digest):
            await lease.release()
            return None
        try:
            source = await opener()
        except BaseException:
            await lease.release()
            raise
        fill = Fill(digest=digest, path=self.partial / hexd, expected_size=expected_size)
        # Create the file before any reader can look for it.
        fill.path.touch()
        self._fills[digest] = fill
        fill.task = asyncio.create_task(self._run_fill(fill, source, lease, on_complete))
        bump("docker.fill.started")
        return fill

    async def _tail_peer(self, digest: str) -> AsyncIterator[bytes]:
        """Stream a blob another replica is downloading into the shared volume.

        Waiting for the whole blob instead left the client with no bytes for
        as long as a multi-GB download took, which is past every client
        timeout. The peer verifies the digest before renaming its partial
        file into place; if it gives up it deletes the partial, and the
        stream is cut so the client retries (by then the dead peer's lease
        has lapsed and the retry fills it itself).
        """
        partial = self.partial / self.hex_of(digest)
        final = self.path_for(digest)
        deadline = time.monotonic() + PEER_STALL_SECONDS
        while not partial.exists() and not final.is_file():
            if time.monotonic() > deadline:
                raise FillFailed("a peer replica holds the download but has not started it")
            await asyncio.sleep(0.2)
        if final.is_file():
            async for chunk in self.iter_file(digest):
                yield chunk
            return
        try:
            fh = await aiofiles.open(partial, "rb")
        except FileNotFoundError:
            # Renamed between the check and the open.
            if final.is_file():
                async for chunk in self.iter_file(digest):
                    yield chunk
                return
            raise FillFailed("the peer replica's download failed") from None
        sent = 0
        last_progress = time.monotonic()
        try:
            while True:
                chunk = await fh.read(CHUNK)
                if chunk:
                    sent += len(chunk)
                    last_progress = time.monotonic()
                    yield chunk
                    continue
                if final.is_file():
                    size = final.stat().st_size
                    if sent >= size:
                        return
                    continue  # flushed just before the rename; read on
                if not partial.exists():
                    raise FillFailed("the peer replica's download failed")
                if time.monotonic() - last_progress > PEER_STALL_SECONDS:
                    raise FillFailed("the peer replica's download stalled")
                await asyncio.sleep(0.2)
        finally:
            await fh.close()

    async def _run_fill(self, fill: Fill, source, lease: _Lease, on_complete) -> None:
        hasher = hashlib.sha256()
        written = 0
        limit = settings.docker_max_blob_bytes
        error: str | None = None
        try:
            async with asyncio.timeout(settings.docker_blob_download_timeout_seconds):
                async with aiofiles.open(fill.path, "wb") as fh:
                    last_renew = time.monotonic()
                    async for chunk in source:
                        if not chunk:
                            continue
                        written += len(chunk)
                        if limit and written > limit:
                            raise FillFailed(f"blob exceeds the {limit} byte limit")
                        if fill.expected_size is not None and written > fill.expected_size:
                            raise FillFailed(
                                f"upstream sent more than the {fill.expected_size} bytes "
                                "the manifest declared"
                            )
                        hasher.update(chunk)
                        await fh.write(chunk)
                        # Flush so tailing readers see the bytes.
                        await fh.flush()
                        await fill.advance(written)
                        if time.monotonic() - last_renew > LEASE_SECONDS / 3:
                            await lease.renew()
                            last_renew = time.monotonic()
                    await asyncio.to_thread(os.fsync, fh.fileno())

            actual = "sha256:" + hasher.hexdigest()
            if actual != fill.digest:
                bump("docker.fill.digest_mismatch")
                raise FillFailed(f"upstream bytes hash to {actual}, not {fill.digest}")
            if fill.expected_size is not None and written != fill.expected_size:
                raise FillFailed(
                    f"upstream sent {written} bytes; the manifest declared {fill.expected_size}"
                )
            final = self.path_for(fill.digest)
            final.parent.mkdir(parents=True, exist_ok=True)
            os.replace(fill.path, final)
            os.chmod(final, 0o444)
            bump("docker.fill.completed")
            if on_complete is not None:
                with contextlib.suppress(Exception):
                    result = on_complete(fill.digest, written)
                    if asyncio.iscoroutine(result):
                        await result
        except asyncio.CancelledError:
            error = "fill cancelled"
            raise
        except TimeoutError:
            error = "upstream download timed out"
        except FillFailed as exc:
            error = str(exc)
        except RegistryError as exc:
            error = exc.message
        except Exception as exc:  # network errors, disk errors
            error = f"{type(exc).__name__}: {exc}"
        finally:
            with contextlib.suppress(Exception):
                await source.aclose()
            if error:
                bump("docker.fill.failed")
                log.warning("blob fill %s failed: %s", fill.digest, error)
                fill.path.unlink(missing_ok=True)
            self._fills.pop(fill.digest, None)
            await fill.finish(error)
            await lease.release()

    async def _tail(self, fill: Fill) -> AsyncIterator[bytes]:
        """Read a fill's partial file as it grows.

        The path is opened before waiting: once the fill completes it is
        renamed, and an open descriptor keeps reading the same inode.
        """
        path = fill.path
        # The fill task creates the file; give it a moment to exist.
        for _ in range(200):
            if path.exists() or fill.done:
                break
            await asyncio.sleep(0.01)
        if fill.done and fill.error:
            raise FillFailed(fill.error)
        if not path.exists():
            # Finished and renamed before we opened it.
            async for chunk in self.iter_file(fill.digest):
                yield chunk
            return

        sent = 0
        async with aiofiles.open(path, "rb") as fh:
            while True:
                chunk = await fh.read(CHUNK)
                if chunk:
                    sent += len(chunk)
                    yield chunk
                    continue
                # Caught up with the writer. Either it is finished, or wait
                # for it to report more bytes.
                async with fill.changed:
                    while not fill.done and fill.written <= sent:
                        await fill.changed.wait()
                    finished = fill.done and fill.written <= sent
                if fill.error:
                    # The response has already started. Dropping the
                    # connection is the only way left to tell the client, and
                    # its own digest check would reject the bytes anyway.
                    raise FillFailed(fill.error)
                if finished:
                    # One last read for anything flushed just before done.
                    while chunk := await fh.read(CHUNK):
                        yield chunk
                    return

    # -- uploads (push) ----------------------------------------------------- #
    def upload_path(self, upload_id: str) -> Path:
        if not upload_id.replace("-", "").isalnum():
            raise ValueError("bad upload id")
        return self.uploads / upload_id

    async def upload_append(self, upload_id: str, chunks: AsyncIterator[bytes], limit: int) -> int:
        path = self.upload_path(upload_id)
        size = path.stat().st_size if path.exists() else 0
        async with aiofiles.open(path, "ab") as fh:
            async for chunk in chunks:
                size += len(chunk)
                if limit and size > limit:
                    raise RegistryError("SIZE_INVALID", f"upload exceeds the {limit} byte limit")
                await fh.write(chunk)
        return size

    async def upload_commit(self, upload_id: str, digest: str) -> int:
        path = self.upload_path(upload_id)
        if not path.exists():
            path.touch()

        def _hash() -> tuple[str, int]:
            h = hashlib.sha256()
            n = 0
            with open(path, "rb") as fh:
                while chunk := fh.read(1024 * 1024):
                    h.update(chunk)
                    n += len(chunk)
            return "sha256:" + h.hexdigest(), n

        actual, size = await asyncio.to_thread(_hash)
        if actual != digest:
            path.unlink(missing_ok=True)
            raise RegistryError("DIGEST_INVALID", f"uploaded content is {actual}, not {digest}")
        final = self.path_for(digest)
        if final.is_file():
            path.unlink(missing_ok=True)
        else:
            final.parent.mkdir(parents=True, exist_ok=True)
            await asyncio.to_thread(_fsync_file, path)
            os.replace(path, final)
            os.chmod(final, 0o444)
        return size

    def upload_size(self, upload_id: str) -> int:
        path = self.upload_path(upload_id)
        return path.stat().st_size if path.exists() else 0

    def upload_discard(self, upload_id: str) -> None:
        with contextlib.suppress(ValueError):
            self.upload_path(upload_id).unlink(missing_ok=True)

    # -- deletes / housekeeping -------------------------------------------- #
    def delete(self, digest: str) -> bool:
        path = self.path_for(digest)
        if not path.is_file():
            return False
        with contextlib.suppress(OSError):
            os.chmod(path, 0o644)
        path.unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            path.parent.rmdir()
        return True

    def cleanup(self, older_than_seconds: int = 3600) -> int:
        """Remove partial fills and abandoned uploads nobody is writing."""
        cutoff = time.time() - older_than_seconds
        removed = 0
        for directory in (self.partial, self.uploads):
            if not directory.is_dir():
                continue
            for entry in directory.iterdir():
                if entry.name in self._fills or any(
                    f.path == entry for f in self._fills.values()
                ):
                    continue
                try:
                    if entry.is_file() and entry.stat().st_mtime < cutoff:
                        entry.unlink()
                        removed += 1
                except OSError:
                    continue
        return removed


class _Lease:
    """A renewable Redis lease. With no Redis it always succeeds (the
    in-process map already gives single flight within a replica)."""

    def __init__(self, key: str) -> None:
        self.key = f"lock:{key}"
        self.token = secrets.token_hex(16).encode()
        self.held = False

    async def acquire(self, *, force: bool = False) -> bool:
        client = cache.redis_client()
        if client is None:
            self.held = True
            return True
        try:
            if force:
                await client.set(self.key, self.token, ex=LEASE_SECONDS)
                self.held = True
                return True
            self.held = bool(await client.set(self.key, self.token, nx=True, ex=LEASE_SECONDS))
            return self.held
        except Exception:
            self.held = True
            return True

    async def renew(self) -> None:
        client = cache.redis_client()
        if client is None or not self.held:
            return
        with contextlib.suppress(Exception):
            await client.eval(_RENEW, 1, self.key, self.token, LEASE_SECONDS)

    async def release(self) -> None:
        client = cache.redis_client()
        if client is None or not self.held:
            return
        with contextlib.suppress(Exception):
            await client.eval(_RELEASE, 1, self.key, self.token)
        self.held = False


_RENEW = """
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('expire', KEYS[1], ARGV[2])
end
return 0
"""
_RELEASE = """
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('del', KEYS[1])
end
return 0
"""

_store: OciStore | None = None


def _fsync_file(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def get_oci_store() -> OciStore:
    global _store
    if _store is None:
        _store = OciStore()
        _store.ensure_dirs()
    return _store


def set_oci_store(store: OciStore | None) -> None:
    """Test hook."""
    global _store
    _store = store
