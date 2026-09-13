"""Artifact fetch-and-cache.

Guarantees:

* A cached artifact is verified against the digest the upstream advertised
  before it is ever served. A mismatch is treated as a poisoned upstream:
  the bytes are discarded and the fetch fails loudly.
* Concurrent requests for the same uncached artifact collapse into a single
  upstream download.
* Artifacts are immutable. Once ``blob_sha256`` is set we never re-fetch.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..core.cache import herd_guard
from ..models import Blob, PackageFile, Upstream
from ..upstreams.netguard import BlockedUrl, check_fetchable
from .resolver import build_provider
from .storage import get_store

log = logging.getLogger(__name__)


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


async def ensure_cached(
    session: AsyncSession, file_row: PackageFile, *, verify: bool = True
) -> PackageFile:
    """Make sure ``file_row`` has a local blob, downloading it if needed."""
    store = get_store()

    if file_row.blob_sha256 and store.exists(file_row.blob_sha256):
        return file_row

    if not file_row.upstream_url:
        raise ArtifactError(f"no upstream URL recorded for {file_row.filename}")

    lock_key = f"artifact:{file_row.id}"
    async with herd_guard(lock_key, ttl=300):
        # Re-check after acquiring: a peer may have just cached it.
        await session.refresh(file_row)
        if file_row.blob_sha256 and store.exists(file_row.blob_sha256):
            return file_row

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

        # Refuse to cache past the quota. Publishes are exempt (they have no
        # upstream URL and reach this code only when already stored), because a
        # local package exists nowhere else while a cached artifact can always
        # be fetched again.
        if settings.storage_quota_bytes:
            used = await _stored_bytes(session)
            if used >= settings.storage_quota_bytes:
                raise ArtifactError(
                    f"blob storage is at its quota ({used} of "
                    f"{settings.storage_quota_bytes} bytes); not caching "
                    f"{file_row.filename}"
                )

        try:
            stored = await _download(file_row.upstream_url, upstream, file_row.filename)
        except BlockedUrl as exc:
            log.warning("refused to fetch %s: %s", file_row.upstream_url, exc)
            raise _as_artifact_error(exc, file_row.filename) from exc
        except TimeoutError as exc:
            raise _as_artifact_error(
                Exception("upstream download timed out"), file_row.filename
            ) from exc
        except OSError as exc:
            log.error("storing %s failed: %s", file_row.filename, exc)
            raise _as_artifact_error(exc, file_row.filename) from exc

        if verify:
            try:
                _verify_digests(file_row, stored, require=_digest_required(upstream))
            except (DigestMismatch, ArtifactError):
                # The bytes are already in the blob store: put_stream renames
                # into place before anything is verified. Nothing references
                # them and orphan GC only walks Blob rows, so without this they
                # sat on disk forever and were re-downloaded on every retry.
                await _discard_unreferenced(session, stored.sha256)
                raise

        # Record the blob, or bump its refcount if another file shares it.
        blob = await session.get(Blob, stored.sha256)
        if blob is None:
            session.add(
                Blob(
                    sha256=stored.sha256,
                    size=stored.size,
                    path=stored.path,
                    refcount=1,
                )
            )
        else:
            blob.refcount += 1

        file_row.blob_sha256 = stored.sha256
        file_row.size = stored.size
        file_row.cached_at = datetime.now(UTC)
        file_row.sha256 = file_row.sha256 or stored.sha256
        file_row.sha1 = file_row.sha1 or stored.sha1
        file_row.md5 = file_row.md5 or stored.md5
        file_row.blake2b_256 = file_row.blake2b_256 or stored.blake2b_256
        file_row.integrity = file_row.integrity or stored.integrity
        await session.commit()
        return file_row


def _digest_required(upstream: Upstream | None) -> bool:
    """Whether this upstream must advertise a digest for its artifacts."""
    if upstream is None:
        return False
    value = getattr(upstream, "require_digest", None)
    return True if value is None else bool(value)


async def _stored_bytes(session: AsyncSession) -> int:
    total = (await session.execute(select(func.coalesce(func.sum(Blob.size), 0)))).scalar()
    return int(total or 0)


async def _discard_unreferenced(session: AsyncSession, sha256: str) -> None:
    """Delete a just-downloaded blob that no row points at."""
    blob = await session.get(Blob, sha256)
    if blob is not None:
        return
    with contextlib.suppress(Exception):
        get_store().delete(sha256)


def _verify_digests(file_row: PackageFile, stored, *, require: bool = False) -> None:
    """Compare against whatever the upstream told us to expect.

    We check every digest we were given, not just one: an upstream that
    publishes sha1 (npm) and one that publishes sha256 (PyPI) both get checked.

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


def _capped(chunks: AsyncIterator[bytes], filename: str) -> AsyncIterator[bytes]:
    """Stop a download that runs past the artifact size cap.

    httpx transparently inflates `Content-Encoding`, so a small compressed
    body can expand without limit; counting decoded bytes is the only place
    the cap means anything.
    """
    limit = settings.max_artifact_bytes

    async def _iter():
        seen = 0
        async for chunk in chunks:
            seen += len(chunk)
            if limit and seen > limit:
                raise ArtifactError(
                    f"{filename}: upstream artifact exceeds the {limit} byte limit"
                )
            yield chunk

    return _iter()


async def _download(url: str, upstream: Upstream | None, filename: str = "artifact"):
    """Stream an artifact from an upstream into the blob store.

    The URL comes from upstream metadata, so it is checked against the
    allowlist before a socket is opened, and again on every redirect hop.
    """
    check_fetchable(url, upstream_url=upstream.url if upstream else None)

    # The whole download gets one deadline. The client's read timeout is
    # per-chunk, so an upstream trickling a byte every ten seconds never
    # tripped it and held the herd-guard lock for that file indefinitely.
    async with asyncio.timeout(settings.artifact_download_timeout_seconds):
        if upstream is not None:
            provider = build_provider(upstream)
            response, chunks = await provider.stream(url)
            try:
                if response.status_code >= 400:
                    raise ArtifactError(
                        f"upstream returned HTTP {response.status_code} for {url}"
                    )
                return await get_store().put_stream(_capped(chunks, filename))
            finally:
                await response.aclose()

        # No upstream row (e.g. an absolute URL from a merged document): fetch
        # anonymously with the shared client.
        from ..upstreams.base import get_http_client

        client = get_http_client()
        async with client.stream("GET", url, follow_redirects=True) as response:
            for hop in response.history:
                check_fetchable(str(hop.headers.get("location") or response.url))
            if response.status_code >= 400:
                raise ArtifactError(f"HTTP {response.status_code} fetching {url}")
            return await get_store().put_stream(
                _capped(response.aiter_bytes(settings.stream_chunk_size), filename)
            )


async def stream_artifact(
    session: AsyncSession, file_row: PackageFile
) -> tuple[AsyncIterator[bytes], int, str]:
    """Return ``(chunks, size, content_type)`` for a cached artifact."""
    store = get_store()
    if not file_row.blob_sha256 or not store.exists(file_row.blob_sha256):
        await ensure_cached(session, file_row)

    size = file_row.size or store.size_of(file_row.blob_sha256) or 0
    await session.execute(
        update(Blob)
        .where(Blob.sha256 == file_row.blob_sha256)
        .values(last_accessed_at=datetime.now(UTC), access_count=Blob.access_count + 1)
    )
    return store.iter_blob(file_row.blob_sha256), size, file_row.content_type


async def purge_file(session: AsyncSession, file_row: PackageFile) -> bool:
    """Drop the cached bytes for one file, keeping its metadata."""
    if not file_row.blob_sha256:
        return False
    sha = file_row.blob_sha256
    file_row.blob_sha256 = None
    file_row.cached_at = None

    blob = await session.get(Blob, sha)
    if blob is not None:
        blob.refcount -= 1
        if blob.refcount <= 0:
            await session.delete(blob)
            get_store().delete(sha)
    await session.flush()
    return True


async def collect_orphan_blobs(session: AsyncSession) -> int:
    """Delete blobs no PackageFile points at. Safety net for crashes."""
    referenced = select(PackageFile.blob_sha256).where(PackageFile.blob_sha256.isnot(None))
    orphans = (
        await session.execute(select(Blob).where(Blob.sha256.notin_(referenced)))
    ).scalars().all()
    store = get_store()
    removed = 0
    for blob in orphans:
        store.delete(blob.sha256)
        await session.delete(blob)
        removed += 1
    return removed
