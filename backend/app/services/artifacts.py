"""Artifact fetch-and-cache.

Guarantees:

* A cached artifact is verified against the digest the upstream advertised
  before it is committed. A mismatch is treated as a poisoned upstream: the
  bytes are discarded and the fetch fails loudly. A client already receiving
  the bytes has its connection cut instead of being handed a silently
  truncated "success" (the last chunk is held back until verification).
* Concurrent requests for the same uncached artifact collapse into a single
  upstream download: per process through the in-memory fill map, across
  replicas through a renewable lease. Late arrivals read the partial file as
  it grows instead of waiting for the whole download.
* No database transaction is held across the network. Postgres ends a
  transaction idle for longer than ``idle_in_transaction_session_timeout``
  (60 s), and a multi-minute download used to leave the request's session on
  a dead connection, so the final write failed and every retry downloaded
  again.
* Artifacts are immutable. Once ``blob_sha256`` is set we never re-fetch.

Small or fast artifacts behave exactly as before: a request waits up to
``STREAM_AFTER_SECONDS`` for the fill to finish, so a digest mismatch on an
ordinary tarball is still answered with a 502. Only a fill that is still
running after that -- a 2 GB wheel -- is streamed to the client while it
downloads.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import secrets
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiofiles
import httpx
from sqlalchemy import delete, exists, func, select, tuple_, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..core.cache import Lease, herd_guard, lease_is_free
from ..db import session_scope
from ..models import Blob, PackageFile, Upstream
from ..upstreams.base import UpstreamError
from ..upstreams.netguard import BlockedUrl, check_fetchable
from .resolver import build_provider
from .storage import Digests, StoredBlob, get_store

log = logging.getLogger(__name__)

#: How long a replica's claim on a download lasts without renewal.
LEASE_SECONDS = 30
#: How long a reader waits for a peer replica's download to make progress.
PEER_STALL_SECONDS = 45
#: How long a request waits for a cold download to finish before it commits
#: to a 200 and streams the bytes as they arrive.
STREAM_AFTER_SECONDS = 5.0
#: Redirect hops followed for an artifact URL with no upstream row.
MAX_REDIRECTS = 5
#: Blob files with no ``Blob`` row are deleted only once they are this old, so
#: a write that has renamed its file but not yet committed its row is never
#: touched.
ORPHAN_FILE_GRACE_SECONDS = 24 * 3600
#: Eviction never takes a blob read this recently (it may be streaming now).
EVICT_GRACE = timedelta(minutes=10)
#: Eviction frees down to this fraction of the quota, so it does not run again
#: on the very next download.
LOW_WATER = 0.9


class ArtifactError(Exception):
    pass


def _as_artifact_error(exc: Exception, filename: str) -> ArtifactError:
    """Wrap a low-level failure so route handlers answer 502 rather than 500.

    `BlockedUrl` and `OSError` (a full disk, a read-only volume) both used to
    escape as unhandled exceptions past every `except ArtifactError` in the
    API layer.
    """
    return ArtifactError(f"{filename}: {exc}")


class DigestMismatch(ArtifactError):
    """Upstream bytes did not match the advertised digest."""


class FillFailed(ArtifactError):
    """A download being streamed to the client failed part way through."""


# --------------------------------------------------------------------------- #
# Fills
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class _Expected:
    """What the file row says to expect, copied out of the request's session
    so the download task never touches an ORM object it does not own."""

    file_id: int
    filename: str
    sha256: str | None
    sha1: str | None
    md5: str | None
    blake2b_256: str | None
    integrity: str | None
    require_digest: bool
    verify: bool


@dataclass(eq=False)
class _Fill:
    """One in-progress download, shared by every reader in this process."""

    key: str
    token: str
    path: Path
    filename: str
    expected_size: int | None
    loop: asyncio.AbstractEventLoop
    written: int = 0
    done: bool = False
    error: ArtifactError | None = None
    sha256: str | None = None
    changed: asyncio.Condition = field(default_factory=asyncio.Condition)
    finished: asyncio.Event = field(default_factory=asyncio.Event)
    task: asyncio.Task | None = None

    async def advance(self, written: int) -> None:
        async with self.changed:
            self.written = written
            self.changed.notify_all()

    async def finish(self, error: ArtifactError | None) -> None:
        async with self.changed:
            self.done = True
            self.error = error
            self.changed.notify_all()
        self.finished.set()

    def raise_error(self) -> None:
        if self.error is not None:
            # A fresh instance per waiter: re-raising one shared object from
            # several tasks keeps growing its traceback.
            raise type(self.error)(str(self.error))


_fills: dict[str, _Fill] = {}
_opening: dict[str, asyncio.Future] = {}


def _lease_key(key: str) -> str:
    return f"artifact-fill:{key}"


def _current_fill(key: str) -> _Fill | None:
    fill = _fills.get(key)
    if fill is not None and fill.loop is not asyncio.get_running_loop():
        # Left behind by a loop that has since closed (tests run one loop per
        # test); it will never finish.
        _fills.pop(key, None)
        return None
    return fill


async def _end_transaction(session: AsyncSession) -> None:
    """Commit before anything slow, so no transaction idles across it.

    The session stays usable afterwards (``expire_on_commit`` is off), and
    the next statement simply begins a new transaction.
    """
    await session.commit()


async def _start_or_join(session: AsyncSession, file_row: PackageFile, verify: bool):
    """Become, or find, the downloader for ``file_row``.

    Returns the :class:`_Fill` in this process, ``"peer"`` when another
    replica holds the download, or None when the file is already cached.
    """
    key = str(file_row.id)
    while True:
        fill = _current_fill(key)
        if fill is not None:
            return fill
        opening = _opening.get(key)
        if opening is None:
            break
        # Another request here is opening the upstream; wait for it rather
        # than opening a second connection.
        try:
            return await asyncio.shield(opening)
        except Exception:
            # Its open failed. That error belongs to its client; this request
            # makes its own attempt.
            continue

    future: asyncio.Future = asyncio.get_running_loop().create_future()
    _opening[key] = future
    try:
        outcome = await _open_fill(session, file_row, verify)
    except BaseException as exc:
        if not future.done():
            future.set_exception(exc if isinstance(exc, Exception) else ArtifactError("cancelled"))
            future.exception()  # nobody may be waiting; do not warn
        raise
    finally:
        _opening.pop(key, None)
    if not future.done():
        future.set_result(outcome)
    return outcome


async def _open_fill(session: AsyncSession, file_row: PackageFile, verify: bool):
    key = str(file_row.id)
    store = get_store()
    lease = Lease(_lease_key(key), ttl=LEASE_SECONDS)
    if not await lease.acquire():
        return "peer"
    try:
        # Re-check under the lease: a peer may have just cached it.
        await session.refresh(file_row)
        if file_row.blob_sha256 and store.exists(file_row.blob_sha256):
            await _end_transaction(session)
            await lease.release()
            return None
        if not file_row.upstream_url:
            raise ArtifactError(f"no upstream URL recorded for {file_row.filename}")

        upstream = None
        if file_row.upstream_id:
            upstream = await session.get(Upstream, file_row.upstream_id)
            if upstream is None:
                raise ArtifactError(
                    f"{file_row.filename}: the upstream it came from no longer exists; "
                    "re-resolve the package"
                )
            if not upstream.enabled:
                # Disabling a compromised upstream has to stop fetches through
                # it, not just stop new resolutions.
                raise ArtifactError(
                    f"{file_row.filename}: upstream '{upstream.name}' is disabled"
                )

        expected = _Expected(
            file_id=file_row.id,
            filename=file_row.filename,
            sha256=file_row.sha256,
            sha1=file_row.sha1,
            md5=file_row.md5,
            blake2b_256=file_row.blake2b_256,
            integrity=file_row.integrity,
            require_digest=_digest_required(upstream),
            verify=verify,
        )
        url = file_row.upstream_url
        size_hint = file_row.size
        await _end_transaction(session)

        # Publishes never reach here (they have no upstream URL), so a full
        # store evicts cached upstream copies, never local packages.
        await _make_room(size_hint or 0, file_row.filename)

        loop = asyncio.get_running_loop()
        deadline = loop.time() + settings.artifact_download_timeout_seconds
        try:
            async with asyncio.timeout_at(deadline):
                response, chunks = await _open_upstream(url, upstream, file_row.filename)
        except BlockedUrl as exc:
            log.warning("refused to fetch %s: %s", url, exc)
            raise _as_artifact_error(exc, file_row.filename) from exc
        except TimeoutError as exc:
            raise _as_artifact_error(
                Exception("upstream download timed out"), file_row.filename
            ) from exc
        except (UpstreamError, httpx.HTTPError, OSError) as exc:
            raise _as_artifact_error(exc, file_row.filename) from exc

        declared = _declared_length(response)
        limit = settings.max_artifact_bytes
        if declared is not None and limit and declared > limit:
            await response.aclose()
            raise ArtifactError(
                f"{file_row.filename}: upstream artifact exceeds the {limit} byte limit"
            )
        token = secrets.token_hex(8)
        try:
            store.ensure_dirs()
            path = store.partial_path(key, token)
            path.touch()
        except OSError as exc:
            await response.aclose()
            raise _as_artifact_error(exc, file_row.filename) from exc
        fill = _Fill(
            key=key,
            token=token,
            path=path,
            filename=file_row.filename,
            expected_size=declared if declared is not None else size_hint,
            loop=loop,
        )
        _fills[key] = fill
        fill.task = asyncio.create_task(
            _run_fill(fill, response, chunks, expected, lease, deadline)
        )
        return fill
    except BaseException:
        await lease.release()
        raise


def _declared_length(response: httpx.Response) -> int | None:
    """The body length the upstream promised, when it is the decoded length.

    httpx inflates `Content-Encoding`, so with one set Content-Length counts
    the wrong bytes.
    """
    encoding = (response.headers.get("content-encoding") or "").strip().lower()
    if encoding and encoding != "identity":
        return None
    try:
        value = int(response.headers.get("content-length", ""))
    except ValueError:
        return None
    return value if value >= 0 else None


async def _open_upstream(
    url: str, upstream: Upstream | None, filename: str
) -> tuple[httpx.Response, AsyncIterator[bytes]]:
    """Open the artifact URL, checking every hop before connecting to it.

    The URL comes from upstream metadata, so it is checked against the
    allowlist before a socket is opened, and again on every redirect.
    """
    check_fetchable(url, upstream_url=upstream.url if upstream else None)
    if upstream is not None:
        response, chunks = await build_provider(upstream).stream(url)
    else:
        # No upstream row (e.g. an absolute URL from a merged document): fetch
        # anonymously with the shared client. Redirects are followed by hand:
        # httpx's own follow_redirects connects to every hop before anything
        # here could look at it, so inspecting `response.history` afterwards
        # was too late to stop a redirect into the internal network.
        from ..upstreams.base import get_http_client

        client = get_http_client()
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            request = client.build_request("GET", current)
            response = await client.send(request, stream=True, follow_redirects=False)
            if response.status_code not in (301, 302, 303, 307, 308):
                break
            location = response.headers.get("location")
            await response.aclose()
            if not location:
                raise ArtifactError(f"{filename}: redirect with no Location header")
            current = str(httpx.URL(current).join(location))
            check_fetchable(current)
        else:
            raise ArtifactError(f"{filename}: too many redirects fetching {url}")
        chunks = response.aiter_bytes(settings.stream_chunk_size)
    if response.status_code >= 400:
        await response.aclose()
        raise ArtifactError(f"upstream returned HTTP {response.status_code} for {url}")
    return response, chunks


async def _run_fill(
    fill: _Fill,
    response: httpx.Response,
    chunks: AsyncIterator[bytes],
    expected: _Expected,
    lease: Lease,
    deadline: float,
) -> None:
    """Download into the partial file, verify, then commit. Runs as its own
    task, so a client that disconnects does not abort a download other
    clients -- or the next request -- are waiting on."""
    store = get_store()
    digests = Digests()
    limit = settings.max_artifact_bytes
    error: ArtifactError | None = None
    try:
        try:
            # The whole download gets one deadline. The client's read timeout
            # is per chunk, so an upstream trickling a byte every ten seconds
            # never tripped it.
            async with asyncio.timeout_at(deadline):
                async with aiofiles.open(fill.path, "wb") as fh:
                    async for chunk in chunks:
                        if not chunk:
                            continue
                        # httpx transparently inflates Content-Encoding, so
                        # counting decoded bytes is where the cap means anything.
                        if limit and digests.size + len(chunk) > limit:
                            raise ArtifactError(
                                f"{fill.filename}: upstream artifact exceeds the "
                                f"{limit} byte limit"
                            )
                        digests.update(chunk)
                        await fh.write(chunk)
                        # Flush so tailing readers see the bytes.
                        await fh.flush()
                        await fill.advance(digests.size)
                    await asyncio.to_thread(os.fsync, fh.fileno())
        finally:
            with contextlib.suppress(Exception):
                await response.aclose()

        sha256 = digests.sha256.hexdigest()
        stored = digests.stored(store.relative_path_for(sha256), already_existed=False)
        if expected.verify:
            _verify_digests(expected, stored, require=expected.require_digest)
        store.adopt(fill.path, sha256)
        await _record(expected.file_id, stored)
        fill.sha256 = sha256
        store.write_marker(fill.key, fill.token, f"ok {sha256}")
    except asyncio.CancelledError:
        error = ArtifactError(f"{fill.filename}: download cancelled")
        raise
    except TimeoutError:
        error = ArtifactError(f"{fill.filename}: upstream download timed out")
    except ArtifactError as exc:
        error = exc
    except OSError as exc:
        log.error("storing %s failed: %s", fill.filename, exc)
        error = _as_artifact_error(exc, fill.filename)
    except Exception as exc:  # network errors, database errors
        error = ArtifactError(f"{fill.filename}: {type(exc).__name__}: {exc}")
    finally:
        if error is not None:
            log.warning("artifact download failed: %s", error)
            fill.path.unlink(missing_ok=True)
            store.write_marker(fill.key, fill.token, "failed")
        if _fills.get(fill.key) is fill:
            del _fills[fill.key]
        await fill.finish(error)
        await lease.release()


async def _record(file_id: int, stored: StoredBlob) -> None:
    """Point the file row at its verified blob, in a session of our own.

    The Blob row is locked first, as ``purge_file`` and eviction do, so a
    concurrent purge cannot delete the row (and file) between this read and
    the write and leave a committed pointer to a file that is gone.
    """
    store = get_store()
    async with session_scope() as session:
        blob = await session.get(Blob, stored.sha256, with_for_update=True)
        row = await session.get(PackageFile, file_id, with_for_update=True)
        if row is None:
            raise ArtifactError(f"file {file_id} was deleted while it downloaded")
        if not store.exists(stored.sha256):
            raise ArtifactError(f"{row.filename}: blob was removed while it was recorded; retry")
        now = datetime.now(UTC)
        if row.blob_sha256 != stored.sha256:
            if row.blob_sha256:
                # A stale pointer to a file that went missing: let go of it
                # rather than leak its refcount.
                old = await session.get(Blob, row.blob_sha256, with_for_update=True)
                if old is not None:
                    old.refcount -= 1
                    if old.refcount <= 0:
                        await session.delete(old)
            if blob is None:
                session.add(
                    Blob(sha256=stored.sha256, size=stored.size, path=stored.path, refcount=1)
                )
            else:
                blob.refcount += 1
                blob.last_accessed_at = now
        elif blob is None:
            session.add(Blob(sha256=stored.sha256, size=stored.size, path=stored.path, refcount=1))

        row.blob_sha256 = stored.sha256
        row.size = stored.size
        row.cached_at = now
        row.sha256 = row.sha256 or stored.sha256
        row.sha1 = row.sha1 or stored.sha1
        row.md5 = row.md5 or stored.md5
        row.blake2b_256 = row.blake2b_256 or stored.blake2b_256
        row.integrity = row.integrity or stored.integrity


async def _tail(fill: _Fill, promised: int) -> AsyncIterator[bytes]:
    """Stream a fill's partial file as it grows.

    The last chunk is held back until the fill has verified and committed,
    so a digest failure always cuts the connection short of the promised
    length; the client never sees a complete body that was not verified.
    """
    chunk_size = settings.stream_chunk_size
    try:
        fh = await aiofiles.open(fill.path, "rb")
    except FileNotFoundError:
        # Renamed into place or deleted before we opened it.
        await fill.finished.wait()
        if fill.error is not None:
            raise FillFailed(str(fill.error)) from None
        async for chunk in _from_blob(fill.sha256, promised):
            yield chunk
        return

    held = b""
    sent = 0
    try:
        while True:
            chunk = await fh.read(chunk_size)
            if chunk:
                sent += len(chunk)
                if sent > promised:
                    raise FillFailed(f"{fill.filename}: upstream sent more than {promised} bytes")
                if held:
                    yield held
                held = chunk
                continue
            async with fill.changed:
                while not fill.done and fill.written <= sent:
                    await fill.changed.wait()
            if not fill.done:
                continue
            # One last read for anything flushed just before the end.
            while chunk := await fh.read(chunk_size):
                sent += len(chunk)
                if held:
                    yield held
                held = chunk
            if fill.error is not None:
                # The response has started, so dropping the connection is the
                # only way left to tell the client.
                raise FillFailed(str(fill.error))
            if sent != promised:
                raise FillFailed(
                    f"{fill.filename}: upstream sent {sent} bytes, not the {promised} declared"
                )
            if held:
                yield held
            return
    finally:
        await fh.close()


async def _from_blob(sha256: str | None, promised: int) -> AsyncIterator[bytes]:
    store = get_store()
    if not sha256 or store.size_of(sha256) != promised:
        raise FillFailed("downloaded artifact does not match the declared size")
    async for chunk in store.iter_blob(sha256):
        yield chunk


async def _tail_peer(key: str, promised: int) -> AsyncIterator[bytes]:
    """Stream an artifact another replica is downloading into the shared volume.

    The peer verifies before it writes its ``ok`` marker; a ``failed`` marker,
    or no progress for ``PEER_STALL_SECONDS``, cuts the stream so the client
    retries (by when a dead peer's lease has lapsed and the retry downloads
    it itself).
    """
    store = get_store()
    chunk_size = settings.stream_chunk_size
    deadline = time.monotonic() + PEER_STALL_SECONDS
    while True:
        sha = store.finished_for(key)
        if sha:
            async for chunk in _from_blob(sha, promised):
                yield chunk
            return
        partials = store.partials_for(key)
        if partials:
            token, path = partials[0]
            break
        if time.monotonic() > deadline:
            raise FillFailed("a peer replica holds the download but has not started it")
        await asyncio.sleep(0.2)

    try:
        fh = await aiofiles.open(path, "rb")
    except FileNotFoundError:
        fh = None
    held = b""
    sent = 0
    last_progress = time.monotonic()
    try:
        while True:
            chunk = await fh.read(chunk_size) if fh is not None else b""
            if chunk:
                sent += len(chunk)
                if sent > promised:
                    raise FillFailed(f"upstream sent more than {promised} bytes")
                if held:
                    yield held
                held = chunk
                last_progress = time.monotonic()
                continue
            outcome = store.read_marker(key, token)
            if outcome is not None:
                if not outcome.startswith("ok "):
                    raise FillFailed("the peer replica's download failed")
                if fh is None:
                    async for chunk in _from_blob(outcome[3:].strip(), promised):
                        yield chunk
                    return
                while chunk := await fh.read(chunk_size):
                    sent += len(chunk)
                    if held:
                        yield held
                    held = chunk
                if sent != promised:
                    raise FillFailed(f"upstream sent {sent} bytes, not the {promised} declared")
                if held:
                    yield held
                return
            if time.monotonic() - last_progress > PEER_STALL_SECONDS:
                raise FillFailed("the peer replica's download stalled")
            await asyncio.sleep(0.2)
    finally:
        if fh is not None:
            await fh.close()


async def _wait_for_peer(key: str) -> None:
    """Wait, holding no transaction, until a peer replica lets go of a download."""
    deadline = time.monotonic() + settings.artifact_download_timeout_seconds + LEASE_SECONDS
    while time.monotonic() < deadline:
        await asyncio.sleep(0.5)
        if await lease_is_free(_lease_key(key)):
            return
    raise ArtifactError("timed out waiting for another replica's download of this artifact")


async def _obtain(
    session: AsyncSession, file_row: PackageFile, *, verify: bool, stream: bool
) -> tuple[AsyncIterator[bytes], int] | None:
    """Cache ``file_row``. With ``stream``, may instead return a live stream
    of a download still in progress, with the length it will have.

    Returns None once the artifact is cached and ``file_row`` reflects it.
    """
    store = get_store()
    await _end_transaction(session)
    for _ in range(3):
        outcome = await _start_or_join(session, file_row, verify)
        if outcome is None:
            break
        if outcome == "peer":
            size = file_row.size
            if stream and size:
                return _tail_peer(str(file_row.id), size), size
            await _wait_for_peer(str(file_row.id))
            continue
        fill: _Fill = outcome
        if stream and fill.expected_size is not None:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(fill.finished.wait(), STREAM_AFTER_SECONDS)
            if not fill.done:
                return _tail(fill, fill.expected_size), fill.expected_size
        else:
            await fill.finished.wait()
        fill.raise_error()
        break
    # Pick up what the download committed in its own session.
    await session.refresh(file_row)
    if not file_row.blob_sha256 or not store.exists(file_row.blob_sha256):
        raise ArtifactError(f"{file_row.filename}: artifact could not be cached; retry")
    return None


async def ensure_cached(
    session: AsyncSession, file_row: PackageFile, *, verify: bool = True
) -> PackageFile:
    """Make sure ``file_row`` has a local blob, downloading it if needed.

    Commits ``session`` before any network I/O or wait; the session remains
    usable afterwards.
    """
    store = get_store()
    if file_row.blob_sha256 and store.exists(file_row.blob_sha256):
        return file_row
    if not file_row.upstream_url:
        raise ArtifactError(f"no upstream URL recorded for {file_row.filename}")
    await _obtain(session, file_row, verify=verify, stream=False)
    return file_row


async def stream_artifact(
    session: AsyncSession, file_row: PackageFile
) -> tuple[AsyncIterator[bytes], int, str]:
    """Return ``(chunks, size, content_type)`` for an artifact.

    A cold artifact whose download is still running after
    ``STREAM_AFTER_SECONDS`` is streamed while it downloads; ``file_row``'s
    ``blob_sha256`` is then still unset, because nothing is committed until
    the bytes verify.
    """
    store = get_store()
    if not file_row.blob_sha256 or not store.exists(file_row.blob_sha256):
        if not file_row.upstream_url:
            raise ArtifactError(f"no upstream URL recorded for {file_row.filename}")
        live = await _obtain(session, file_row, verify=True, stream=True)
        if live is not None:
            chunks, size = live
            return chunks, size, file_row.content_type

    size = file_row.size or store.size_of(file_row.blob_sha256) or 0
    await session.execute(
        update(Blob)
        .where(Blob.sha256 == file_row.blob_sha256)
        .values(last_accessed_at=datetime.now(UTC), access_count=Blob.access_count + 1)
    )
    return store.iter_blob(file_row.blob_sha256), size, file_row.content_type


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #
def _digest_required(upstream: Upstream | None) -> bool:
    """Whether this upstream must advertise a digest for its artifacts."""
    if upstream is None:
        return False
    value = getattr(upstream, "require_digest", None)
    return True if value is None else bool(value)


def _verify_digests(file_row, stored, *, require: bool = False) -> None:
    """Compare against whatever the upstream told us to expect.

    ``file_row`` is a PackageFile or anything with the same digest
    attributes. We check every digest we were given, not just one: an
    upstream that publishes sha1 (npm) and one that publishes sha256 (PyPI)
    both get checked.

    With ``require`` set, an artifact whose metadata carried *no* digest at all
    is rejected rather than accepted on trust. Verification is otherwise
    opt-in by the upstream: no advertised digest meant no check, and the
    digest we then served to clients was derived from whatever bytes arrived,
    so the client's own verification proved nothing.
    """
    checks = (
        ("sha256", file_row.sha256, stored.sha256),
        ("sha1", file_row.sha1, stored.sha1),
        ("md5", file_row.md5, stored.md5),
        ("blake2b_256", file_row.blake2b_256, stored.blake2b_256),
    )
    if require and not any(expected for _, expected, _ in checks) and not file_row.integrity:
        raise ArtifactError(
            f"{file_row.filename}: upstream published no digest for this artifact "
            "and this upstream is configured to require one"
        )
    for algorithm, expected, actual in checks:
        if expected and expected.lower() != actual.lower():
            raise DigestMismatch(
                f"{file_row.filename}: {algorithm} mismatch "
                f"(expected {expected}, got {actual})"
            )

    # npm SRI integrity string, e.g. "sha512-<base64>".
    if file_row.integrity and "-" in file_row.integrity:
        import base64
        import hashlib

        algorithm, _, encoded = file_row.integrity.partition("-")
        algorithm = algorithm.lower()
        if algorithm in ("sha256", "sha512"):
            try:
                expected_bytes = base64.b64decode(encoded)
            except Exception:
                return
            actual_hex = stored.sha512 if algorithm == "sha512" else stored.sha256
            if (
                hashlib.new(algorithm).digest_size == len(expected_bytes)
                and expected_bytes.hex() != actual_hex
            ):
                raise DigestMismatch(
                    f"{file_row.filename}: SRI integrity mismatch ({algorithm})"
                )


# --------------------------------------------------------------------------- #
# Quota and eviction
# --------------------------------------------------------------------------- #
async def _stored_bytes(session: AsyncSession) -> int:
    total = (await session.execute(select(func.coalesce(func.sum(Blob.size), 0)))).scalar()
    return int(total or 0)


def _has_local_reference():
    """A blob backs a locally published file when any PackageFile pointing at
    it has no upstream URL: published files exist nowhere else, so they are
    never evicted, while a cached upstream copy can always be fetched again."""
    return exists().where(
        PackageFile.blob_sha256 == Blob.sha256, PackageFile.upstream_url.is_(None)
    )


async def _make_room(incoming: int, filename: str) -> None:
    """Keep a download inside ``storage_quota_bytes``, evicting if needed.

    Reaching the quota used to turn every uncached artifact into a 502 until
    an admin purged something by hand.
    """
    quota = settings.storage_quota_bytes
    if not quota:
        return
    async with session_scope() as session:
        used = await _stored_bytes(session)
    if used + incoming < quota:
        return
    async with herd_guard("artifact-evict", ttl=60):
        await evict_to(max(0, int(quota * LOW_WATER) - incoming))
    async with session_scope() as session:
        used = await _stored_bytes(session)
    if used + incoming >= quota:
        raise ArtifactError(
            f"blob storage is at its quota ({used} of {quota} bytes) and nothing "
            f"more can be evicted; not caching {filename}"
        )


async def evict_to(target: int) -> dict:
    """Evict least-recently-read cached upstream blobs until the recorded
    total is at most ``target`` bytes.

    The file rows keep their metadata and upstream URL, so an evicted
    artifact is simply fetched again on its next request. Blobs that back a
    locally published file, and blobs read within ``EVICT_GRACE``, are never
    taken.
    """
    store = get_store()
    async with session_scope() as session:
        used = await _stored_bytes(session)
    cutoff = datetime.now(UTC) - EVICT_GRACE
    evicted = freed = 0
    last: tuple | None = None
    while used - freed > target:
        victims: list[str] = []
        async with session_scope() as session:
            query = (
                select(Blob.sha256, Blob.size, Blob.last_accessed_at)
                .where(Blob.last_accessed_at < cutoff, ~_has_local_reference())
                .order_by(Blob.last_accessed_at.asc(), Blob.sha256.asc())
                .limit(200)
            )
            if last is not None:
                query = query.where(tuple_(Blob.last_accessed_at, Blob.sha256) > last)
            rows = (await session.execute(query)).all()
            if not rows:
                break
            for sha, size, accessed in rows:
                last = (accessed, sha)
                if used - freed <= target:
                    break
                # Lock and re-check: it may have been read, or a local file
                # may have started sharing it, since the batch was selected.
                still = (
                    await session.execute(
                        select(Blob.sha256)
                        .where(
                            Blob.sha256 == sha,
                            Blob.last_accessed_at < cutoff,
                            ~_has_local_reference(),
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if still is None:
                    continue
                await session.execute(
                    update(PackageFile)
                    .where(PackageFile.blob_sha256 == sha)
                    .values(blob_sha256=None, cached_at=None)
                )
                await session.execute(delete(Blob).where(Blob.sha256 == sha))
                victims.append(sha)
                freed += int(size or 0)
        # Files go only after the rows are committed: a failed commit must
        # not leave rows pointing at deleted files.
        for sha in victims:
            store.delete(sha)
        evicted += len(victims)
    if evicted:
        log.info("evicted %d cached artifacts (%d bytes) to stay under %d", evicted, freed, target)
    return {"evicted": evicted, "freed_bytes": freed, "target": target}


async def enforce_quota() -> dict:
    """Housekeeping: bring the store back under quota, to the low-water mark."""
    quota = settings.storage_quota_bytes
    if not quota:
        return {"quota": 0}
    async with session_scope() as session:
        used = await _stored_bytes(session)
    if used <= quota:
        return {"used": used, "quota": quota}
    return await evict_to(int(quota * LOW_WATER))


# --------------------------------------------------------------------------- #
# Purge and garbage collection
# --------------------------------------------------------------------------- #
async def purge_file(session: AsyncSession, file_row: PackageFile) -> bool:
    """Drop the cached bytes for one file, keeping its metadata."""
    if not file_row.blob_sha256:
        return False
    sha = file_row.blob_sha256
    file_row.blob_sha256 = None
    file_row.cached_at = None

    # Same lock as a download's commit takes, so the two cannot interleave
    # into a deleted blob with a live reference.
    blob = await session.get(Blob, sha, with_for_update=True)
    if blob is not None:
        blob.refcount -= 1
        if blob.refcount <= 0:
            await session.delete(blob)
            await session.flush()
            get_store().delete(sha)
    await session.flush()
    return True


async def collect_orphan_blobs(session: AsyncSession) -> int:
    """Delete Blob rows (and their files) no PackageFile points at.

    Selects keys in batches rather than loading every orphan row at once.
    """
    referenced = exists().where(PackageFile.blob_sha256 == Blob.sha256)
    store = get_store()
    removed = 0
    while True:
        shas = (
            (await session.execute(select(Blob.sha256).where(~referenced).limit(500)))
            .scalars()
            .all()
        )
        if not shas:
            break
        for sha in shas:
            result = await session.execute(
                delete(Blob).where(Blob.sha256 == sha, ~referenced)
            )
            if result.rowcount:
                store.delete(sha)
                removed += 1
        await session.flush()
        if len(shas) < 500:
            break
    return removed


async def sweep_orphan_files(grace_seconds: int = ORPHAN_FILE_GRACE_SECONDS) -> dict:
    """Delete blob files that no ``Blob`` row records.

    They come from a download whose row never committed, or a publish refused
    after its bytes were stored. Row-based GC never sees them and the quota
    never counts them, so without this they filled the disk silently. Only
    files older than ``grace_seconds`` are touched, so a write that has
    renamed its file but not yet committed its row is safe.

    The directory walk goes shard by shard (1/256 of the store each) in a
    worker thread, and the row lookups go in batches.
    """
    store = get_store()
    cutoff = time.time() - grace_seconds
    removed = freed = 0
    for shard in store.shard_dirs():
        candidates = await asyncio.to_thread(store.scan_shard, shard, cutoff)
        for start in range(0, len(candidates), 500):
            batch = candidates[start : start + 500]
            async with session_scope() as session:
                known = set(
                    (await session.execute(select(Blob.sha256).where(Blob.sha256.in_(batch))))
                    .scalars()
                    .all()
                )
            for sha in batch:
                if sha in known:
                    continue
                size = store.delete_if_older(sha, cutoff)
                if size:
                    removed += 1
                    freed += size
    if removed:
        log.info("removed %d unrecorded blob files (%d bytes)", removed, freed)
    return {"files": removed, "freed_bytes": freed}


async def run_housekeeping() -> dict:
    """The artifact store's share of the hourly housekeeping pass."""
    async with session_scope() as session:
        orphan_rows = await collect_orphan_blobs(session)
    orphan_files = await sweep_orphan_files()
    quota = await enforce_quota()
    tmp = get_store().cleanup_tmp()
    return {
        "orphan_blobs": orphan_rows,
        "orphan_files": orphan_files,
        "quota": quota,
        "tmp_removed": tmp,
    }
