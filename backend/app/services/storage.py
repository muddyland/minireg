"""Content-addressed local blob store.

Artifacts are immutable, so the sha256 of the bytes *is* the identity. Two
packages that ship byte-identical files share one blob. Layout:

    /data/packages/blobs/ab/cd/abcd....  (sha256, 2-level fan-out)
    /data/packages/tmp/                  (staging, same filesystem => atomic rename)
    /data/packages/partial/              (artifact fills clients read while they grow)

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
import time
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

    def stored(self, path: str, *, already_existed: bool) -> StoredBlob:
        return StoredBlob(
            sha256=self.sha256.hexdigest(),
            size=self.size,
            path=path,
            sha1=self.sha1.hexdigest(),
            md5=self.md5.hexdigest(),
            blake2b_256=self.blake2b.hexdigest(),
            sha512=self.sha512.hexdigest(),
            already_existed=already_existed,
        )


class BlobStore:
    def __init__(self, root: str | None = None) -> None:
        self.root = Path(root or settings.storage_path)
        self.blobs_dir = self.root / "blobs"
        self.tmp_dir = self.root / "tmp"
        self.partial_dir = self.root / "partial"

    def ensure_dirs(self) -> None:
        self.blobs_dir.mkdir(parents=True, exist_ok=True)
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        self.partial_dir.mkdir(parents=True, exist_ok=True)

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
                # Flush to the platter before the rename makes the blob
                # reachable. Without this, a power loss between the two can
                # leave a truncated file at the final path while the database
                # has already committed its sha256 -- and reads are not
                # re-verified, so it would be served with a correct-looking
                # ETag forever.
                await fh.flush()
                await asyncio.to_thread(os.fsync, fh.fileno())

            sha256 = digests.sha256.hexdigest()
            final = self.path_for(sha256)
            already = final.is_file()
            if already:
                tmp_path.unlink(missing_ok=True)
                # Mark it as in use again, so the orphan-file sweep (which
                # spares recently modified files) cannot delete it between
                # here and the caller committing its Blob row.
                with contextlib.suppress(OSError):
                    os.utime(final)
            else:
                final.parent.mkdir(parents=True, exist_ok=True)
                # Same filesystem, so this is atomic; a racing writer producing
                # identical bytes is harmless by construction.
                os.replace(tmp_path, final)
                os.chmod(final, 0o444)

            return digests.stored(self.relative_path_for(sha256), already_existed=already)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise

    def adopt(self, staged: Path, sha256: str) -> str:
        """Move an already hashed and fsynced file into place as ``sha256``.

        Returns its store-relative path. Replacing an existing copy is safe:
        the bytes are identical by construction, and the fresh mtime keeps
        the orphan-file sweep away until the caller has committed its row.
        """
        final = self.path_for(sha256)
        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staged, final)
        os.chmod(final, 0o444)
        return self.relative_path_for(sha256)

    # -- fills in progress ------------------------------------------------- #
    # A fill writes ``partial/<file id>.<token>`` and, once it is over, a
    # ``.done`` marker holding ``ok <sha256>`` or ``failed``. Readers in other
    # replicas tail the partial file and learn the outcome from the marker.
    def partial_path(self, key: str, token: str) -> Path:
        return self.partial_dir / f"{key}.{token}"

    def marker_path(self, key: str, token: str) -> Path:
        return self.partial_dir / f"{key}.{token}.done"

    def write_marker(self, key: str, token: str, outcome: str) -> None:
        with contextlib.suppress(OSError):
            self.marker_path(key, token).write_text(outcome)

    def read_marker(self, key: str, token: str) -> str | None:
        try:
            return self.marker_path(key, token).read_text()
        except OSError:
            return None

    def partials_for(self, key: str, *, live_within: float | None = None) -> list[tuple[str, Path]]:
        """``(token, path)`` of every unfinished partial file for ``key``,
        most recently written first.

        ``live_within`` drops partials not written to for that many seconds:
        a process that crashed mid-download leaves its partial behind with no
        marker, and a reader that picked it would wait out the whole stall
        timeout instead of the live download beside it.
        """
        found: list[tuple[float, str, Path]] = []
        now = time.time()
        with contextlib.suppress(OSError):
            for entry in self.partial_dir.glob(f"{key}.*"):
                name = entry.name
                if name.endswith(".done"):
                    continue
                token = name[len(key) + 1 :]
                if self.marker_path(key, token).exists():
                    continue
                try:
                    mtime = entry.stat().st_mtime
                except OSError:
                    continue
                if live_within is not None and now - mtime > live_within:
                    continue
                found.append((mtime, token, entry))
        found.sort(key=lambda item: item[0], reverse=True)
        return [(token, entry) for _, token, entry in found]

    def finished_for(self, key: str) -> str | None:
        """sha256 of a successful fill of ``key`` whose blob is still stored."""
        with contextlib.suppress(OSError):
            for entry in self.partial_dir.glob(f"{key}.*.done"):
                with contextlib.suppress(OSError):
                    outcome = entry.read_text()
                    if outcome.startswith("ok "):
                        sha = outcome[3:].strip()
                        if self.exists(sha):
                            return sha
        return None

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
        """Reap staging files, partial fills and fill markers left by a crash.

        A live fill writes continuously and is bounded by the artifact
        download timeout, so nothing it still uses is an hour old.
        """
        import time

        cutoff = time.time() - older_than_seconds
        removed = 0
        for directory in (self.tmp_dir, self.partial_dir):
            if not directory.is_dir():
                continue
            for entry in directory.iterdir():
                try:
                    if entry.is_file() and entry.stat().st_mtime < cutoff:
                        entry.unlink()
                        removed += 1
                except OSError:
                    continue
        return removed

    # -- orphan-file sweep -------------------------------------------------- #
    def shard_dirs(self) -> list[Path]:
        """The top-level fan-out directories (at most 256)."""
        try:
            return sorted(p for p in self.blobs_dir.iterdir() if p.is_dir())
        except OSError:
            return []

    @staticmethod
    def scan_shard(shard: Path, cutoff: float) -> list[str]:
        """Names of blob files under one shard last modified before ``cutoff``.

        One shard is ~1/256 of the store, so the list stays small even for a
        store of millions of blobs; the caller walks shard by shard.
        """
        found: list[str] = []
        for dirpath, _dirs, files in os.walk(shard):
            for name in files:
                if len(name) != 64 or not _is_hex(name):
                    continue
                try:
                    if os.stat(os.path.join(dirpath, name)).st_mtime < cutoff:
                        found.append(name)
                except OSError:
                    continue
        return found

    def delete_if_older(self, sha256: str, cutoff: float) -> int:
        """Delete a blob file unless it was modified since ``cutoff``.

        Re-checks the mtime at the last moment: a writer that found the file
        already present touches it before committing its row.
        Returns the bytes freed (0 if nothing was deleted).
        """
        path = self.path_for(sha256)
        try:
            st = path.stat()
        except OSError:
            return 0
        if st.st_mtime >= cutoff:
            return 0
        return st.st_size if self.delete(sha256) else 0


def _is_hex(name: str) -> bool:
    try:
        int(name, 16)
    except ValueError:
        return False
    return name == name.lower()


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
