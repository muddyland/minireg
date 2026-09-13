"""Content-addressed local blob store.

Artifacts are immutable, so the sha256 of the bytes *is* the identity. Two
packages that ship byte-identical files share one blob. Layout:

    /data/packages/blobs/ab/cd/abcd....  (sha256, 2-level fan-out)
    /data/packages/tmp/                  (staging, same filesystem => atomic rename)

Writes stage to ``tmp`` and ``os.replace`` into place, so a crashed or
concurrent write can never expose a truncated artifact to a client.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import logging
import os
import shutil
import tempfile
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import aiofiles

from ..config import settings

log = logging.getLogger(__name__)


@dataclass(slots=True)
class StoredBlob:
    sha256: str
    size: int
    path: str
    sha1: str
    md5: str
    blake2b_256: str
    sha512: str
    already_existed: bool

    @property
    def integrity(self) -> str:
        """npm's ``dist.integrity`` SRI string. npm publishes sha512."""
        return "sha512-" + base64.b64encode(bytes.fromhex(self.sha512)).decode()


class Digests:
    """Computes every digest both ecosystems need in a single pass."""

    __slots__ = ("blake2b", "md5", "sha1", "sha256", "sha512", "size")

    def __init__(self) -> None:
        self.sha256 = hashlib.sha256()
        self.sha1 = hashlib.sha1()
        self.md5 = hashlib.md5()
        self.blake2b = hashlib.blake2b(digest_size=32)
        self.sha512 = hashlib.sha512()
        self.size = 0

    def update(self, chunk: bytes) -> None:
        self.sha256.update(chunk)
        self.sha1.update(chunk)
        self.md5.update(chunk)
        self.blake2b.update(chunk)
        self.sha512.update(chunk)
        self.size += len(chunk)


class BlobStore:
    def __init__(self, root: str | None = None) -> None:
        self.root = Path(root or settings.storage_path)
        self.blobs_dir = self.root / "blobs"
        self.tmp_dir = self.root / "tmp"

    def ensure_dirs(self) -> None:
        self.blobs_dir.mkdir(parents=True, exist_ok=True)
        self.tmp_dir.mkdir(parents=True, exist_ok=True)

    # -- paths ------------------------------------------------------------- #
    def path_for(self, sha256: str) -> Path:
        return self.blobs_dir / sha256[:2] / sha256[2:4] / sha256

    def relative_path_for(self, sha256: str) -> str:
        return str(self.path_for(sha256).relative_to(self.root))

    def exists(self, sha256: str) -> bool:
        return self.path_for(sha256).is_file()

    # -- writes ------------------------------------------------------------ #
    async def put_bytes(self, data: bytes) -> StoredBlob:
        return await self.put_stream(_iter_bytes(data, settings.stream_chunk_size))

    async def put_stream(self, chunks: AsyncIterator[bytes]) -> StoredBlob:
        """Stream to a temp file while hashing, then atomically link into place."""
        self.ensure_dirs()
        digests = Digests()
        fd, tmp_name = tempfile.mkstemp(dir=self.tmp_dir, prefix="up-")
        os.close(fd)
        tmp_path = Path(tmp_name)
        try:
            async with aiofiles.open(tmp_path, "wb") as fh:
                async for chunk in chunks:
                    if not chunk:
                        continue
                    digests.update(chunk)
                    await fh.write(chunk)

            sha256 = digests.sha256.hexdigest()
            final = self.path_for(sha256)
            already = final.is_file()
            if already:
                tmp_path.unlink(missing_ok=True)
            else:
                final.parent.mkdir(parents=True, exist_ok=True)
                # Same filesystem, so this is atomic; a racing writer producing
                # identical bytes is harmless by construction.
                os.replace(tmp_path, final)
                os.chmod(final, 0o444)

            return StoredBlob(
                sha256=sha256,
                size=digests.size,
                path=self.relative_path_for(sha256),
                sha1=digests.sha1.hexdigest(),
                md5=digests.md5.hexdigest(),
                blake2b_256=digests.blake2b.hexdigest(),
                sha512=digests.sha512.hexdigest(),
                already_existed=already,
            )
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise

    # -- reads ------------------------------------------------------------- #
    def blob_path(self, sha256: str) -> Path:
        """Filesystem path of a stored blob, for readers that can work
        incrementally instead of loading the whole artifact."""
        return self.path_for(sha256)

    async def read_bytes(self, sha256: str) -> bytes | None:
        path = self.path_for(sha256)
        if not path.is_file():
            return None
        async with aiofiles.open(path, "rb") as fh:
            return await fh.read()

    async def iter_blob(self, sha256: str, chunk_size: int | None = None) -> AsyncIterator[bytes]:
        path = self.path_for(sha256)
        size = chunk_size or settings.stream_chunk_size
        async with aiofiles.open(path, "rb") as fh:
            while True:
                chunk = await fh.read(size)
                if not chunk:
                    break
                yield chunk

    def size_of(self, sha256: str) -> int | None:
        path = self.path_for(sha256)
        return path.stat().st_size if path.is_file() else None

    # -- deletes / stats --------------------------------------------------- #
    def delete(self, sha256: str) -> bool:
        path = self.path_for(sha256)
        if not path.is_file():
            return False
        with contextlib.suppress(OSError):
            os.chmod(path, 0o644)
        path.unlink(missing_ok=True)
        # Prune now-empty fan-out directories.
        for parent in (path.parent, path.parent.parent):
            try:
                parent.rmdir()
            except OSError:
                break
        return True

    async def disk_usage(self) -> dict[str, int]:
        def _walk() -> dict[str, int]:
            total = count = 0
            for dirpath, _dirs, files in os.walk(self.blobs_dir):
                for name in files:
                    try:
                        total += os.stat(os.path.join(dirpath, name)).st_size
                        count += 1
                    except OSError:
                        continue
            usage = shutil.disk_usage(self.root) if self.root.exists() else None
            return {
                "blob_bytes": total,
                "blob_count": count,
                "disk_total": usage.total if usage else 0,
                "disk_used": usage.used if usage else 0,
                "disk_free": usage.free if usage else 0,
            }

        return await asyncio.to_thread(_walk)

    def cleanup_tmp(self, older_than_seconds: int = 3600) -> int:
        """Reap staging files orphaned by a crash."""
        import time

        if not self.tmp_dir.is_dir():
            return 0
        cutoff = time.time() - older_than_seconds
        removed = 0
        for entry in self.tmp_dir.iterdir():
            try:
                if entry.is_file() and entry.stat().st_mtime < cutoff:
                    entry.unlink()
                    removed += 1
            except OSError:
                continue
        return removed


async def _iter_bytes(data: bytes, chunk: int) -> AsyncIterator[bytes]:
    for i in range(0, len(data), chunk):
        yield data[i : i + chunk]


_store: BlobStore | None = None


def get_store() -> BlobStore:
    global _store
    if _store is None:
        _store = BlobStore()
        _store.ensure_dirs()
    return _store


def set_store(store: BlobStore) -> None:
    """Test hook."""
    global _store
    _store = store
