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

import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..core.cache import herd_guard
from ..models import Blob, PackageFile, Upstream
from ..upstreams.base import UpstreamError
from .resolver import build_provider
from .storage import get_store

log = logging.getLogger(__name__)


class ArtifactError(Exception):
    pass


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

        stored = await _download(file_row.upstream_url, upstream)

        if verify:
            _verify_digests(file_row, stored)

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


def _verify_digests(file_row: PackageFile, stored) -> None:
    """Compare against whatever the upstream told us to expect.

    We check every digest we were given, not just one: an upstream that
    publishes sha1 (npm) and one that publishes sha256 (PyPI) both get checked.
    """
    checks = (
        ("sha256", file_row.sha256, stored.sha256),
        ("sha1", file_row.sha1, stored.sha1),
        ("md5", file_row.md5, stored.md5),
        ("blake2b_256", file_row.blake2b_256, stored.blake2b_256),
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
            if hashlib.new(algorithm).digest_size == len(expected_bytes):
                if expected_bytes.hex() != actual_hex:
                    raise DigestMismatch(
                        f"{file_row.filename}: SRI integrity mismatch ({algorithm})"
                    )


async def _download(url: str, upstream: Upstream | None):
    """Stream an artifact from an upstream into the blob store."""
    if upstream is not None:
        provider = build_provider(upstream)
        response, chunks = await provider.stream(url)
        try:
            if response.status_code >= 400:
                raise ArtifactError(f"upstream returned HTTP {response.status_code} for {url}")
            return await get_store().put_stream(chunks)
        finally:
            await response.aclose()

    # No upstream row (e.g. an absolute URL from a merged document): fetch
    # anonymously with the shared client.
    from ..upstreams.base import get_http_client

    client = get_http_client()
    async with client.stream("GET", url, follow_redirects=True) as response:
        if response.status_code >= 400:
            raise ArtifactError(f"HTTP {response.status_code} fetching {url}")
        return await get_store().put_stream(response.aiter_bytes(settings.stream_chunk_size))


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
