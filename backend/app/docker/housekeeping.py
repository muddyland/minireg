"""Hourly image housekeeping, run from the main housekeeping loop.

* **Garbage collection.** Blobs and manifests are reference-counted by the
  tables themselves: a blob is live while any linked manifest (or an index's
  child) names it, or a local repository holds it from a push. Unlinked
  manifests and unreferenced blobs are deleted.
* **Eviction.** Over the storage budget, the least recently pulled cached
  images are unlinked -- oldest first, never pinned repositories, never
  pushed images (they exist nowhere else) -- until GC brings usage under the
  budget.
* **Watch list.** Watched tags are revalidated and their layers pre-fetched,
  so the first CI job of the day finds them warm and scanned.
* **Rescans.** Digests whose last scan is older than the policy's rescan age
  are queued as SBOM rescans.
* **KEV.** The CISA catalogue is refreshed once a day.
* **Uploads.** Abandoned push sessions and partial files are removed.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.metrics import bump
from ..db import session_scope
from ..models import (
    DockerBlob,
    DockerFinding,
    DockerManifest,
    DockerManifestRef,
    DockerRepoBlob,
    DockerRepoManifest,
    DockerRepository,
    DockerScan,
    DockerScanJob,
    DockerTag,
    Setting,
)
from . import push as push_ops
from . import registry as reg
from . import scanning
from .policy import load_policy
from .store import get_oci_store

log = logging.getLogger(__name__)

_KEV_KEY = "docker_kev_refreshed_at"


async def run_housekeeping() -> dict:
    report: dict = {}
    for name, step in (
        ("uploads", _uploads),
        ("watch", _watch),
        ("evict", _evict),
        ("gc", _gc),
        ("orphans", _orphan_files),
        ("rescan", _rescans),
        ("kev", _kev),
    ):
        started = time.monotonic()
        try:
            report[name] = await step()
        except Exception:
            log.exception("docker housekeeping step %s failed", name)
            report[name] = "error"
        bump("docker.housekeeping.seconds", int(time.monotonic() - started), step=name)
    if any(v not in (0, None, {}, "skipped") for v in report.values()):
        log.info("docker housekeeping: %s", report)
    return report


async def _uploads() -> int:
    async with session_scope() as session:
        removed = await push_ops.reap_uploads(session)
    removed += get_oci_store().cleanup(older_than_seconds=6 * 3600)
    return removed


async def _rescans() -> int:
    async with session_scope() as session:
        queued = await scanning.schedule_rescans(session)
        await scanning.prune_jobs(session)
    return queued


async def _kev() -> int | str:
    async with session_scope() as session:
        row = await session.get(Setting, _KEV_KEY)
        last = (row.value or {}).get("at") if row else None
        if last:
            try:
                if datetime.now(UTC) - datetime.fromisoformat(last) < timedelta(hours=24):
                    return "skipped"
            except ValueError:
                pass
        count = await scanning.refresh_kev(session)
        if row is None:
            session.add(Setting(key=_KEV_KEY, value={"at": datetime.now(UTC).isoformat()}))
        else:
            row.value = {"at": datetime.now(UTC).isoformat()}
    return count


async def _watch() -> int:
    """Revalidate and pre-fetch watched tags."""
    done = 0
    async with session_scope() as session:
        repos = (
            await session.execute(
                select(DockerRepository).where(
                    DockerRepository.is_local.is_(False),
                    DockerRepository.upstream_id.isnot(None),
                )
            )
        ).scalars().all()
        watched = [(r.id, r.name, list(r.watched_tags or [])) for r in repos if r.watched_tags]
    for _repo_id, name, tags in watched:
        for tag in tags[:20]:
            try:
                await refresh_watched(name, tag)
                done += 1
            except Exception as exc:
                log.warning("watch refresh %s:%s failed: %s", name, tag, exc)
    return done


async def refresh_watched(name: str, tag: str) -> dict:
    """Revalidate one tag, pre-fetch the platforms the policy scans, and
    queue scans. Returns a summary for the admin API."""
    async with session_scope() as session:
        target = await reg.resolve_target(session, name, mirror_host=False)
        repo = await reg.get_repo(session, target, create=True)
        assert repo is not None
        served = await reg.refresh_tag(session, target, repo, tag)
        policy = await load_policy(session)
        manifests = [served.manifest]
        if served.manifest.is_index:
            children = (
                await session.execute(
                    select(DockerManifestRef).where(
                        DockerManifestRef.manifest_id == served.manifest.id,
                        DockerManifestRef.ref_type == "manifest",
                    )
                )
            ).scalars().all()
            manifests = []
            for child in children:
                if child.platform in ("unknown/unknown", None):
                    continue
                if not policy.scans_platform(child.platform):
                    continue
                child_served = await reg.get_manifest(session, target, repo, child.digest, head=True)
                manifests.append(child_served.manifest)
        fetched = 0
        for m in manifests:
            fetched += await reg.prefetch_image(session, target, m)
            if policy.scanning_enabled:
                await scanning.enqueue(
                    session, m, repo.name, reason="watch", priority=scanning.PRIORITY_WATCH
                )
        return {
            "digest": served.manifest.digest,
            "source": served.source,
            "platforms": [m.platform for m in manifests],
            "layers_fetched": fetched,
        }


# --------------------------------------------------------------------------- #
# GC and eviction
# --------------------------------------------------------------------------- #
def _live_manifest_ids():
    """Manifests linked to a repository, plus the children of linked indexes,
    plus anything that refers to a linked manifest (signatures, SBOMs)."""
    linked = select(DockerRepoManifest.manifest_id)
    child_digests = select(DockerManifestRef.digest).where(
        DockerManifestRef.manifest_id.in_(linked), DockerManifestRef.ref_type == "manifest"
    )
    return linked, child_digests


async def _gc() -> dict:
    store = get_oci_store()
    removed_manifests = removed_blobs = freed = 0
    async with session_scope() as session:
        linked, child_digests = _live_manifest_ids()
        linked_digests = select(DockerManifest.digest).where(DockerManifest.id.in_(linked))
        # Grace period: a manifest fetched by digest before its index arrives,
        # or mid-push, is briefly unlinked.
        grace = datetime.now(UTC) - timedelta(hours=1)
        dead = (
            await session.execute(
                select(DockerManifest).where(
                    DockerManifest.id.notin_(linked),
                    DockerManifest.digest.notin_(child_digests),
                    or_(
                        DockerManifest.subject_digest.is_(None),
                        DockerManifest.subject_digest.notin_(linked_digests),
                    ),
                    DockerManifest.created_at < grace,
                )
            )
        ).scalars().all()
        for m in dead:
            for digest in (m.digest, m.sbom_digest):
                if digest:
                    store.delete(digest)
            reports = (
                await session.execute(
                    select(DockerScan.report_digest).where(
                        DockerScan.manifest_id == m.id, DockerScan.report_digest.isnot(None)
                    )
                )
            ).scalars().all()
            for digest in reports:
                store.delete(digest)
            freed += m.size
            # Explicit rather than relying on ON DELETE CASCADE: SQLite does
            # not enforce foreign keys unless asked, and a dead manifest's
            # refs would otherwise keep every blob it named alive.
            for table in (DockerManifestRef, DockerFinding, DockerScan, DockerScanJob, DockerTag):
                await session.execute(delete(table).where(table.manifest_id == m.id))
            await session.delete(m)
            removed_manifests += 1
        await session.flush()

        referenced = select(DockerManifestRef.digest).where(
            DockerManifestRef.ref_type.in_(("blob", "config"))
        )
        held = select(DockerRepoBlob.digest)
        orphans = (
            await session.execute(
                select(DockerBlob).where(
                    DockerBlob.digest.notin_(referenced),
                    DockerBlob.digest.notin_(held),
                    DockerBlob.created_at < grace,
                )
            )
        ).scalars().all()
        for blob in orphans:
            store.delete(blob.digest)
            freed += blob.size
            await session.delete(blob)
            removed_blobs += 1
    if removed_blobs or removed_manifests:
        bump("docker.gc.freed_bytes", freed)
    return {"manifests": removed_manifests, "blobs": removed_blobs, "freed_bytes": freed}


#: A stored file younger than this is left alone by the orphan sweep: a
#: manifest or upload is written to the store a moment before its row.
ORPHAN_GRACE_SECONDS = 6 * 3600
_ORPHAN_BATCH = 500


def _stored_files(store, older_than: float) -> list[tuple[str, int]]:
    """(digest, size) of every file in the blob tree last modified before
    ``older_than``. Runs in a thread; the tree can hold a lot of files."""
    out: list[tuple[str, int]] = []
    root = store.blobs
    if not root.is_dir():
        return out
    for shard in root.iterdir():
        if not shard.is_dir():
            continue
        for entry in shard.iterdir():
            try:
                st = entry.stat()
            except OSError:
                continue
            name = entry.name
            if len(name) != 64 or not entry.is_file() or st.st_mtime >= older_than:
                continue
            out.append((f"sha256:{name}", st.st_size))
    return out


async def _orphan_files() -> dict:
    """Reconcile the blob tree with the tables.

    A completed fill records its DockerBlob row afterwards, in a separate
    transaction whose failure is suppressed (the client already has its
    bytes). When that write fails the file stays on disk with no row: GC
    walks rows, so it never deletes it, and usage() never counts it -- the
    store drifts above what the budget believes it holds.

    Each file is looked up by digest. Anything a table knows about -- a
    blob row, a manifest, an SBOM, a scan report -- is left alone. A file
    that a manifest still names gets its missing DockerBlob row back, so it
    is counted and collected like any other blob. One that nothing names is
    deleted.
    """
    import asyncio

    store = get_oci_store()
    cutoff = time.time() - ORPHAN_GRACE_SECONDS
    files = await asyncio.to_thread(_stored_files, store, cutoff)
    adopted = deleted = freed = 0
    for start in range(0, len(files), _ORPHAN_BATCH):
        batch = dict(files[start : start + _ORPHAN_BATCH])
        digests = list(batch)
        async with session_scope() as session:
            known: set[str] = set()
            for column in (
                DockerBlob.digest,
                DockerManifest.digest,
                DockerManifest.sbom_digest,
                DockerScan.report_digest,
            ):
                known.update(
                    (await session.execute(select(column).where(column.in_(digests)))).scalars().all()
                )
            missing = [d for d in digests if d not in known]
            if not missing:
                continue
            named = {
                digest: (media_type, upstream_id)
                for digest, media_type, upstream_id in (
                    await session.execute(
                        select(
                            DockerManifestRef.digest,
                            DockerManifestRef.media_type,
                            DockerManifest.upstream_id,
                        )
                        .join(DockerManifest, DockerManifest.id == DockerManifestRef.manifest_id)
                        .where(
                            DockerManifestRef.digest.in_(missing),
                            DockerManifestRef.ref_type.in_(("blob", "config")),
                        )
                    )
                ).all()
            }
            held = set(
                (
                    await session.execute(
                        select(DockerRepoBlob.digest).where(DockerRepoBlob.digest.in_(missing))
                    )
                ).scalars().all()
            )
            for digest in missing:
                size = batch[digest]
                if digest in named or digest in held:
                    media_type, upstream_id = named.get(digest, (None, None))
                    session.add(
                        DockerBlob(
                            digest=digest,
                            size=size,
                            media_type=media_type,
                            upstream_id=upstream_id,
                            # Held by a push, or named only by a pushed image:
                            # exists nowhere else, so never evictable.
                            is_local=digest in held or (digest in named and upstream_id is None),
                        )
                    )
                    adopted += 1
                elif store.delete(digest):
                    deleted += 1
                    freed += size
    if adopted or deleted:
        bump("docker.orphans.adopted", adopted)
        bump("docker.orphans.deleted", deleted)
        log.warning(
            "blob store drift: recorded %d file(s) that had no row, deleted %d unreferenced "
            "file(s) (%d bytes)",
            adopted,
            deleted,
            freed,
        )
    return {"adopted": adopted, "deleted": deleted, "freed_bytes": freed}


async def _evict() -> dict:
    async with session_scope() as session:
        policy = await load_policy(session)
        budget = policy.budget()
        if not budget:
            return {"budget": 0}
        used = (await reg.usage(session))["total_bytes"]
        if used <= budget:
            return {"used": used, "budget": budget}
        return await evict_to(session, budget, used)


async def evict_to(session: AsyncSession, budget: int, used: int) -> dict:
    """Unlink least-recently-pulled cached images until the unique bytes they
    held bring usage under ``budget``. GC then deletes the files."""
    target_free = used - int(budget * 0.9)  # hysteresis: free to 90%
    freed = 0
    evicted = 0
    candidates = (
        await session.execute(
            select(DockerRepoManifest, DockerManifest, DockerRepository)
            .join(DockerManifest, DockerManifest.id == DockerRepoManifest.manifest_id)
            .join(DockerRepository, DockerRepository.id == DockerRepoManifest.repository_id)
            .where(
                DockerRepository.is_local.is_(False),
                DockerRepository.pinned.is_(False),
                DockerManifest.upstream_id.isnot(None),
            )
            .order_by(DockerRepoManifest.last_pulled_at.asc())
            .limit(2000)
        )
    ).all()
    for link_row, manifest, repo in candidates:
        if freed >= target_free:
            break
        if repo.watched_tags:
            tagged = (
                await session.execute(
                    select(func.count())
                    .select_from(DockerTag)
                    .where(
                        DockerTag.repository_id == repo.id,
                        DockerTag.manifest_id == manifest.id,
                        DockerTag.tag.in_(repo.watched_tags),
                    )
                )
            ).scalar_one()
            if tagged:
                continue
        freed += await _unique_bytes(session, manifest)
        await session.execute(
            delete(DockerTag).where(
                DockerTag.repository_id == repo.id, DockerTag.manifest_id == manifest.id
            )
        )
        await session.delete(link_row)
        evicted += 1
    if evicted:
        bump("docker.evicted", evicted)
        log.info("evicted %d cached images (~%d bytes) to stay under %d", evicted, freed, budget)
    return {"evicted": evicted, "approx_freed": freed, "budget": budget}


async def _unique_bytes(session: AsyncSession, manifest: DockerManifest) -> int:
    """Bytes only this manifest references (approximate; shared base layers
    are not counted, which is why eviction frees *to* 90% of budget)."""
    other = (
        select(DockerManifestRef.id)
        .where(
            DockerManifestRef.digest == DockerBlob.digest,
            DockerManifestRef.manifest_id != manifest.id,
        )
        .exists()
    )
    mine = select(DockerManifestRef.digest).where(DockerManifestRef.manifest_id == manifest.id)
    total = (
        await session.execute(
            select(func.coalesce(func.sum(DockerBlob.size), 0)).where(
                and_(DockerBlob.digest.in_(mine), ~other, DockerBlob.is_local.is_(False))
            )
        )
    ).scalar_one()
    return int(total or 0) + manifest.size


__all__ = ["evict_to", "refresh_watched", "run_housekeeping"]
