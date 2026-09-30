"""Pushing images to the local namespace.

A push is: blob uploads (POST to open a session, optional PATCH chunks, PUT
with the digest to commit -- or a single POST with the digest, or a
cross-repository mount), then a manifest PUT. The manifest PUT is where the
rules are enforced:

* only under the local namespace, never an upstream's path;
* the first pusher owns the repository; others (admins aside) are refused;
* every blob and child manifest it references must already be in this
  repository -- otherwise a manifest could point at a layer uploaded into
  someone else's repository and read it back;
* digests are immutable (content-addressed), tags are movable by the owner;
* the image is queued for a scan at push priority, and pulls of it wait for
  that scan (push policy, see ``policy``).
"""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..core.metrics import bump
from ..models import (
    DockerBlob,
    DockerManifest,
    DockerManifestRef,
    DockerRepoBlob,
    DockerRepoManifest,
    DockerRepository,
    DockerTag,
    DockerUpload,
)
from . import manifest as mf
from .auth import RegistryIdentity
from .errors import RegistryError
from .naming import Target, is_digest
from .registry import get_repo, link, set_tag, store_manifest
from .store import get_oci_store

log = logging.getLogger(__name__)

UPLOAD_TTL = timedelta(hours=24)


async def repo_for_push(
    session: AsyncSession, target: Target, ident: RegistryIdentity
) -> DockerRepository:
    """The repository, created and owned by this user on first push."""
    repo = await get_repo(session, target, create=True)
    assert repo is not None
    if repo.owner_user_id is None:
        repo.owner_user_id = ident.user_id
        await session.flush()
    elif repo.owner_user_id != ident.user_id and not (ident.user and ident.user.is_admin):
        raise RegistryError(
            "DENIED", f"{target.canonical} belongs to another user; only its owner can push to it"
        )
    return repo


async def add_repo_blob(session: AsyncSession, repo: DockerRepository, digest: str) -> None:
    exists = (
        await session.execute(
            select(DockerRepoBlob.id).where(
                DockerRepoBlob.repository_id == repo.id, DockerRepoBlob.digest == digest
            )
        )
    ).first()
    if exists:
        return
    try:
        async with session.begin_nested():
            session.add(DockerRepoBlob(repository_id=repo.id, digest=digest))
            await session.flush()
    except IntegrityError:
        pass


async def record_local_blob(session: AsyncSession, digest: str, size: int) -> None:
    blob = await session.get(DockerBlob, digest)
    if blob is None:
        try:
            async with session.begin_nested():
                session.add(DockerBlob(digest=digest, size=size, is_local=True))
                await session.flush()
        except IntegrityError:
            pass
    elif not blob.is_local:
        # An upstream layer re-pushed as part of a local image: it now backs
        # something that exists nowhere else, so it must not be evicted.
        blob.is_local = True


# -- upload sessions ------------------------------------------------------- #
async def start_upload(session: AsyncSession, repo: DockerRepository, ident: RegistryIdentity) -> DockerUpload:
    upload = DockerUpload(id=secrets.token_hex(16), repository_id=repo.id, user_id=ident.user_id)
    session.add(upload)
    await session.flush()
    get_oci_store().upload_path(upload.id).touch()
    return upload


async def get_upload(session: AsyncSession, repo: DockerRepository, upload_id: str) -> DockerUpload:
    upload = await session.get(DockerUpload, upload_id)
    if upload is None or upload.repository_id != repo.id:
        raise RegistryError("BLOB_UPLOAD_UNKNOWN", "upload session not found")
    return upload


async def finish_upload(
    session: AsyncSession, repo: DockerRepository, upload: DockerUpload, digest: str
) -> int:
    if not is_digest(digest):
        raise RegistryError("DIGEST_INVALID", f"unsupported digest {digest!r}")
    size = await get_oci_store().upload_commit(upload.id, digest)
    await record_local_blob(session, digest, size)
    await add_repo_blob(session, repo, digest)
    await session.delete(upload)
    bump("docker.push.blob")
    return size


async def mount_blob(
    session: AsyncSession,
    repo: DockerRepository,
    digest: str,
    source: DockerRepository | None,
    ident: RegistryIdentity,
) -> bool:
    """Cross-repository mount. Allowed only from a repository the caller can
    already read, and only for a blob that repository really holds."""
    from .registry import blob_in_repo

    if source is None or not get_oci_store().exists(digest):
        return False
    if source.quarantined:
        return False
    if not await blob_in_repo(session, source, digest):
        return False
    await record_local_blob(session, digest, get_oci_store().size_of(digest) or 0)
    await add_repo_blob(session, repo, digest)
    bump("docker.push.mount")
    return True


# -- manifests ------------------------------------------------------------- #
async def put_manifest(
    session: AsyncSession,
    target: Target,
    repo: DockerRepository,
    reference: str,
    body: bytes,
    content_type: str | None,
    ident: RegistryIdentity,
) -> DockerManifest:
    from .registry import blob_in_repo

    parsed = mf.parse(body, content_type)
    missing = []
    for ref in parsed.refs:
        if ref.ref_type == "manifest":
            child = (
                await session.execute(select(DockerManifest).where(DockerManifest.digest == ref.digest))
            ).scalar_one_or_none()
            if child is None or not (
                await session.execute(
                    select(DockerRepoManifest.id).where(
                        DockerRepoManifest.repository_id == repo.id,
                        DockerRepoManifest.manifest_id == child.id,
                    )
                )
            ).first():
                missing.append(ref.digest)
        elif not get_oci_store().exists(ref.digest) or not await blob_in_repo(session, repo, ref.digest):
            missing.append(ref.digest)
    if missing:
        code = "MANIFEST_BLOB_UNKNOWN"
        raise RegistryError(
            code,
            f"manifest references {len(missing)} blob(s) not uploaded to {target.canonical}",
            detail={"digests": missing[:10]},
        )

    expected = reference if is_digest(reference) else None
    manifest = await store_manifest(
        session, body, content_type, expected_digest=expected, upstream_id=None, pushed_by=ident.user_id
    )
    await link(session, repo, manifest)
    if not is_digest(reference):
        await set_tag(session, repo, reference, manifest, user_id=ident.user_id)
    repo.last_pushed_at = datetime.now(UTC)
    bump("docker.push.manifest")
    return manifest


# -- deletes --------------------------------------------------------------- #
async def delete_manifest(session: AsyncSession, repo: DockerRepository, digest: str) -> None:
    manifest = (
        await session.execute(select(DockerManifest).where(DockerManifest.digest == digest))
    ).scalar_one_or_none()
    if manifest is None:
        raise RegistryError("MANIFEST_UNKNOWN", f"manifest {digest} not found")
    link_row = (
        await session.execute(
            select(DockerRepoManifest).where(
                DockerRepoManifest.repository_id == repo.id,
                DockerRepoManifest.manifest_id == manifest.id,
            )
        )
    ).scalar_one_or_none()
    if link_row is None:
        raise RegistryError("MANIFEST_UNKNOWN", f"manifest {digest} is not in {repo.name}")
    await session.execute(
        delete(DockerTag).where(DockerTag.repository_id == repo.id, DockerTag.manifest_id == manifest.id)
    )
    await session.delete(link_row)
    bump("docker.push.delete")


async def delete_tag(session: AsyncSession, repo: DockerRepository, tag: str) -> None:
    row = (
        await session.execute(
            select(DockerTag).where(DockerTag.repository_id == repo.id, DockerTag.tag == tag)
        )
    ).scalar_one_or_none()
    if row is None:
        raise RegistryError("MANIFEST_UNKNOWN", f"tag {tag} not found")
    await session.delete(row)


async def delete_blob(session: AsyncSession, repo: DockerRepository, digest: str) -> None:
    """Unlink a blob from a local repository. The bytes are reclaimed by GC
    once nothing references them."""
    result = await session.execute(
        delete(DockerRepoBlob).where(DockerRepoBlob.repository_id == repo.id, DockerRepoBlob.digest == digest)
    )
    if not result.rowcount:
        raise RegistryError("BLOB_UNKNOWN", f"blob {digest} is not in {repo.name}")


# -- housekeeping ---------------------------------------------------------- #
async def reap_uploads(session: AsyncSession) -> int:
    cutoff = datetime.now(UTC) - UPLOAD_TTL
    stale = (
        await session.execute(select(DockerUpload).where(DockerUpload.updated_at < cutoff))
    ).scalars().all()
    for upload in stale:
        get_oci_store().upload_discard(upload.id)
        await session.delete(upload)
    return len(stale)


async def upload_count(session: AsyncSession) -> int:
    return (await session.execute(select(func.count()).select_from(DockerUpload))).scalar_one()


__all__ = [
    "DockerManifestRef",
    "add_repo_blob",
    "delete_blob",
    "delete_manifest",
    "delete_tag",
    "finish_upload",
    "get_upload",
    "mount_blob",
    "put_manifest",
    "reap_uploads",
    "record_local_blob",
    "repo_for_push",
    "settings",
    "start_upload",
]
