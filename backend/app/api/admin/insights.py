"""Admin: statistics, audit log, vulnerability review, package and cache admin."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime, timedelta

import orjson
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer, selectinload

from ...core.deps import Identity, client_ip, require_admin
from ...core.naming import order_version_rows
from ...db import get_session, session_scope
from ...models import (
    AuditLog,
    Blob,
    DownloadLog,
    Ecosystem,
    Package,
    PackageFile,
    PackageVersion,
    PackageVulnerability,
    Upstream,
    User,
    Vulnerability,
)
from ...services import artifacts, audit, packages
from ...services.osv import OsvScanner
from ...services.packages import _escape_like
from ...services.provenance import package_upstreams
from ...services.storage import get_store
from ...services.vulns import dedupe_by_cve

log = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(require_admin)])


def _since(days: int) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)


# --------------------------------------------------------------------------- #
# Dashboard / stats
# --------------------------------------------------------------------------- #
@router.get("/stats/overview")
async def stats_overview(
    days: int = Query(default=30, ge=1, le=365),
    session: AsyncSession = Depends(get_session),
) -> dict:
    since = _since(days)

    package_counts = dict(
        (
            await session.execute(
                select(Package.ecosystem, func.count(Package.id)).group_by(Package.ecosystem)
            )
        ).all()
    )
    version_count = (await session.execute(select(func.count(PackageVersion.id)))).scalar_one()
    # Indexing an upstream imports bare project names, which can be hundreds of
    # thousands of rows for public PyPI. Counting those as "packages" makes the
    # dashboard meaningless, so report them separately from packages we have
    # actually resolved content for.
    with_content = (
        await session.execute(
            select(func.count(func.distinct(PackageVersion.package_id)))
        )
    ).scalar_one()
    file_count = (await session.execute(select(func.count(PackageFile.id)))).scalar_one()
    cached_count = (
        await session.execute(
            select(func.count(PackageFile.id)).where(PackageFile.blob_sha256.isnot(None))
        )
    ).scalar_one()

    downloads_total = (
        await session.execute(select(func.count(DownloadLog.id)).where(DownloadLog.ts >= since))
    ).scalar_one()
    artifact_downloads = (
        await session.execute(
            select(func.count(DownloadLog.id)).where(
                DownloadLog.ts >= since, DownloadLog.kind == "file"
            )
        )
    ).scalar_one()
    bytes_served = (
        await session.execute(
            select(func.coalesce(func.sum(DownloadLog.bytes_sent), 0)).where(
                DownloadLog.ts >= since
            )
        )
    ).scalar_one()
    cache_hits = (
        await session.execute(
            select(func.count(DownloadLog.id)).where(
                DownloadLog.ts >= since, DownloadLog.cache_hit.is_(True)
            )
        )
    ).scalar_one()

    user_count = (await session.execute(select(func.count(User.id)))).scalar_one()
    active_users = (
        await session.execute(
            select(func.count(User.id)).where(User.last_login_at >= since)
        )
    ).scalar_one()

    vuln_count = (await session.execute(select(func.count(Vulnerability.id)))).scalar_one()
    affected_versions = (
        await session.execute(
            select(func.count(func.distinct(PackageVulnerability.version_id)))
        )
    ).scalar_one()

    upstreams = (await session.execute(select(Upstream))).scalars().all()

    return {
        "window_days": days,
        "packages": {
            "npm": package_counts.get(Ecosystem.npm, 0),
            "pypi": package_counts.get(Ecosystem.pypi, 0),
            "total": sum(package_counts.values()),
            # Names that resolved to at least one version.
            "with_content": with_content,
            "index_only": max(0, sum(package_counts.values()) - with_content),
        },
        "versions": version_count,
        "files": {"total": file_count, "cached": cached_count},
        "downloads": {
            "total": downloads_total,
            "artifacts": artifact_downloads,
            "metadata": downloads_total - artifact_downloads,
            "bytes_served": int(bytes_served or 0),
            "cache_hit_rate": round(cache_hits / downloads_total, 4) if downloads_total else None,
        },
        "users": {"total": user_count, "active_in_window": active_users},
        "security": {"known_cves": vuln_count, "affected_versions": affected_versions},
        "upstreams": {
            "total": len(upstreams),
            "enabled": sum(1 for u in upstreams if u.enabled),
            "healthy": sum(1 for u in upstreams if u.enabled and u.healthy),
        },
    }


@router.get("/stats/top-packages")
async def top_packages(
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=25, ge=1, le=200),
    ecosystem: Ecosystem | None = None,
    kind: str = Query(default="file", pattern="^(file|metadata|all)$"),
    session: AsyncSession = Depends(get_session),
) -> dict:
    conditions = [DownloadLog.ts >= _since(days)]
    if ecosystem is not None:
        conditions.append(DownloadLog.ecosystem == ecosystem.value)
    if kind != "all":
        conditions.append(DownloadLog.kind == kind)

    rows = (
        await session.execute(
            select(
                DownloadLog.ecosystem,
                DownloadLog.package_name,
                func.count(DownloadLog.id).label("downloads"),
                func.coalesce(func.sum(DownloadLog.bytes_sent), 0).label("bytes"),
                func.count(func.distinct(DownloadLog.user_id)).label("distinct_users"),
            )
            .where(and_(*conditions))
            .group_by(DownloadLog.ecosystem, DownloadLog.package_name)
            .order_by(desc("downloads"))
            .limit(limit)
        )
    ).all()

    return {
        "packages": [
            {
                "ecosystem": r.ecosystem,
                "name": r.package_name,
                "downloads": r.downloads,
                "bytes": int(r.bytes or 0),
                "distinct_users": r.distinct_users,
            }
            for r in rows
        ]
    }


@router.get("/stats/downloads-timeline")
async def downloads_timeline(
    days: int = Query(default=30, ge=1, le=365),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Daily download counts, split by ecosystem, for the dashboard chart."""
    from ...db import get_engine

    # date_trunc is Postgres; SQLite needs a different expression for tests.
    if get_engine().dialect.name == "postgresql":
        bucket = func.date_trunc("day", DownloadLog.ts)
    else:
        bucket = func.date(DownloadLog.ts)

    rows = (
        await session.execute(
            select(
                bucket.label("day"),
                DownloadLog.ecosystem,
                func.count(DownloadLog.id).label("downloads"),
                func.coalesce(func.sum(DownloadLog.bytes_sent), 0).label("bytes"),
            )
            .where(DownloadLog.ts >= _since(days))
            .group_by("day", DownloadLog.ecosystem)
            .order_by("day")
        )
    ).all()

    return {
        "points": [
            {
                "day": r.day.isoformat() if hasattr(r.day, "isoformat") else str(r.day),
                "ecosystem": r.ecosystem,
                "downloads": r.downloads,
                "bytes": int(r.bytes or 0),
            }
            for r in rows
        ]
    }


@router.get("/stats/recent-logins")
async def recent_logins(
    limit: int = Query(default=50, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
) -> dict:
    rows = (
        await session.execute(
            select(AuditLog)
            .where(
                AuditLog.action.in_(
                    [audit.LOGIN_SUCCESS, audit.LOGIN_OIDC, audit.LOGIN_FAILED]
                )
            )
            .order_by(AuditLog.ts.desc())
            .limit(limit)
        )
    ).scalars().all()

    return {
        "logins": [
            {
                "ts": r.ts,
                "username": r.actor_username,
                "user_id": r.actor_user_id,
                "action": r.action,
                "success": r.success,
                "ip": r.ip,
                "user_agent": r.user_agent,
                "method": (r.detail or {}).get("method", "oidc" if r.action == audit.LOGIN_OIDC else "password"),
                "detail": r.detail,
            }
            for r in rows
        ]
    }


@router.get("/stats/storage")
async def storage_stats(session: AsyncSession = Depends(get_session)) -> dict:
    usage = await get_store().disk_usage()

    blob_rows = (
        await session.execute(
            select(
                func.count(Blob.sha256),
                func.coalesce(func.sum(Blob.size), 0),
                func.coalesce(func.sum(Blob.access_count), 0),
            )
        )
    ).one()

    # Logical size counts every reference; the difference from physical size is
    # what deduplication saved.
    logical = (
        await session.execute(
            select(func.coalesce(func.sum(PackageFile.size), 0)).where(
                PackageFile.blob_sha256.isnot(None)
            )
        )
    ).scalar_one()

    by_ecosystem = (
        await session.execute(
            select(
                Package.ecosystem,
                func.count(PackageFile.id),
                func.coalesce(func.sum(PackageFile.size), 0),
            )
            .select_from(PackageFile)
            .join(PackageVersion, PackageVersion.id == PackageFile.version_id)
            .join(Package, Package.id == PackageVersion.package_id)
            .where(PackageFile.blob_sha256.isnot(None))
            .group_by(Package.ecosystem)
        )
    ).all()

    physical = int(blob_rows[1] or 0)
    return {
        "disk": {
            "total": usage["disk_total"],
            "used": usage["disk_used"],
            "free": usage["disk_free"],
            "blob_bytes_on_disk": usage["blob_bytes"],
            "blob_files_on_disk": usage["blob_count"],
        },
        "blobs": {
            "count": blob_rows[0],
            "physical_bytes": physical,
            "logical_bytes": int(logical or 0),
            "deduplicated_bytes": max(0, int(logical or 0) - physical),
            "total_accesses": int(blob_rows[2] or 0),
        },
        "by_ecosystem": [
            {"ecosystem": eco.value if hasattr(eco, "value") else eco, "files": count, "bytes": int(size or 0)}
            for eco, count, size in by_ecosystem
        ],
    }


# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #
@router.get("/audit")
async def list_audit(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    action: str | None = None,
    username: str | None = None,
    success: bool | None = None,
    days: int = Query(default=90, ge=1, le=3650),
    session: AsyncSession = Depends(get_session),
) -> dict:
    conditions = [AuditLog.ts >= _since(days)]
    if action:
        conditions.append(AuditLog.action.like(f"{_escape_like(action)}%", escape="\\"))
    if username:
        conditions.append(AuditLog.actor_username == username)
    if success is not None:
        conditions.append(AuditLog.success.is_(success))

    total = (
        await session.execute(select(func.count(AuditLog.id)).where(and_(*conditions)))
    ).scalar_one()
    rows = (
        await session.execute(
            select(AuditLog)
            .where(and_(*conditions))
            .order_by(AuditLog.ts.desc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()

    return {
        "total": total,
        "entries": [
            {
                "id": r.id,
                "ts": r.ts,
                "action": r.action,
                "actor_username": r.actor_username,
                "actor_user_id": r.actor_user_id,
                "actor_type": r.actor_type,
                "target_type": r.target_type,
                "target_id": r.target_id,
                "success": r.success,
                "ip": r.ip,
                "user_agent": r.user_agent,
                "detail": r.detail,
            }
            for r in rows
        ],
    }


@router.get("/audit/actions")
async def audit_actions(session: AsyncSession = Depends(get_session)) -> dict:
    rows = (
        await session.execute(
            select(AuditLog.action, func.count(AuditLog.id))
            .group_by(AuditLog.action)
            .order_by(AuditLog.action)
        )
    ).all()
    return {"actions": [{"action": a, "count": c} for a, c in rows]}


@router.get("/downloads")
async def list_downloads(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    ecosystem: Ecosystem | None = None,
    package_name: str | None = None,
    username: str | None = None,
    days: int = Query(default=7, ge=1, le=365),
    session: AsyncSession = Depends(get_session),
) -> dict:
    conditions = [DownloadLog.ts >= _since(days)]
    if ecosystem is not None:
        conditions.append(DownloadLog.ecosystem == ecosystem.value)
    if package_name:
        conditions.append(DownloadLog.package_name == package_name)
    if username:
        conditions.append(DownloadLog.username == username)

    total = (
        await session.execute(select(func.count(DownloadLog.id)).where(and_(*conditions)))
    ).scalar_one()
    rows = (
        await session.execute(
            select(DownloadLog)
            .where(and_(*conditions))
            .order_by(DownloadLog.ts.desc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()

    return {
        "total": total,
        "entries": [
            {
                "id": r.id,
                "ts": r.ts,
                "ecosystem": r.ecosystem,
                "package_name": r.package_name,
                "version": r.version,
                "filename": r.filename,
                "kind": r.kind,
                "username": r.username,
                "ip": r.ip,
                "user_agent": r.user_agent,
                "bytes_sent": r.bytes_sent,
                "cache_hit": r.cache_hit,
                "status": r.status,
                "duration_ms": r.duration_ms,
            }
            for r in rows
        ],
    }


#: Concurrent live tails allowed. Each one wakes on a timer and takes a
#: connection for a moment, so a handful is fine and an unbounded number
#: would quietly eat the pool.
MAX_DOWNLOAD_STREAMS = 8
_active_streams = 0

#: How often the tail looks for new rows. Requests are written by a batching
#: recorder that drains every couple of seconds, so polling faster than this
#: would spend queries to find nothing.
STREAM_POLL_SECONDS = 1.0
#: Rows emitted per tick. A burst bigger than this is drained over the next
#: few ticks rather than flooding the browser in one frame.
STREAM_BATCH = 200
#: Idle comment interval. Proxies drop a connection that says nothing.
STREAM_HEARTBEAT_SECONDS = 15.0
#: A tail left open in a forgotten tab should not last forever.
STREAM_MAX_SECONDS = 3600.0


def _download_row(row: DownloadLog) -> dict:
    return {
        "id": row.id,
        "ts": row.ts.isoformat() if row.ts else None,
        "ecosystem": row.ecosystem,
        "package_name": row.package_name,
        "version": row.version,
        "filename": row.filename,
        "kind": row.kind,
        "username": row.username,
        "ip": row.ip,
        "user_agent": row.user_agent,
        "bytes_sent": row.bytes_sent,
        "cache_hit": row.cache_hit,
        "status": row.status,
        "duration_ms": row.duration_ms,
    }


@router.get("/downloads/stream")
async def stream_downloads(
    request: Request,
    ecosystem: Ecosystem | None = None,
    package_name: str | None = None,
    username: str | None = None,
    since_id: int | None = Query(
        default=None,
        ge=0,
        description=(
            "Resume after this row id. Omit to start from the newest row. A "
            "client reconnecting after the tail aged out should pass the last "
            "id it saw, or it loses everything recorded during the gap."
        ),
    ),
) -> StreamingResponse:
    """Server-sent events: package requests as they are recorded.

    Implemented by tailing the table on its primary key rather than by
    subscribing to the in-process recorder. The recorder is per-process, so
    an in-memory fan-out would show a replica only its own share of the
    traffic; the table is what every replica agrees on.

    The request's own session is deliberately not used. It is held for the
    life of the response, and this response lives for as long as the operator
    leaves the page open -- one pooled connection each would be a slow way to
    exhaust the pool. Each poll opens and closes its own instead.
    """
    global _active_streams
    if _active_streams >= MAX_DOWNLOAD_STREAMS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many live tails are open; close one and retry",
        )

    conditions = []
    if ecosystem is not None:
        conditions.append(DownloadLog.ecosystem == ecosystem.value)
    if package_name:
        conditions.append(DownloadLog.package_name == package_name)
    if username:
        conditions.append(DownloadLog.username == username)

    async def events():
        global _active_streams
        _active_streams += 1
        started = time.monotonic()
        last_sent = started
        cursor: int | None = None
        try:
            # Resume where the client left off, or start from "now": on a
            # fresh connection the table's history is already on the page
            # below, so replaying it would only duplicate rows.
            if since_id is not None:
                cursor = since_id
            else:
                async with session_scope() as session:
                    cursor = (
                        await session.execute(
                            select(func.coalesce(func.max(DownloadLog.id), 0))
                        )
                    ).scalar_one()
            yield f": tailing from #{cursor}\n\n"

            while True:
                if await request.is_disconnected():
                    return
                if time.monotonic() - started > STREAM_MAX_SECONDS:
                    yield "event: expired\ndata: {}\n\n"
                    return

                async with session_scope() as session:
                    rows = (
                        await session.execute(
                            select(DownloadLog)
                            .where(and_(DownloadLog.id > cursor, *conditions))
                            .order_by(DownloadLog.id.asc())
                            .limit(STREAM_BATCH)
                        )
                    ).scalars().all()

                if rows:
                    cursor = rows[-1].id
                    payload = orjson.dumps([_download_row(r) for r in rows]).decode()
                    yield f"event: downloads\ndata: {payload}\n\n"
                    last_sent = time.monotonic()
                elif time.monotonic() - last_sent > STREAM_HEARTBEAT_SECONDS:
                    yield ": keepalive\n\n"
                    last_sent = time.monotonic()

                await asyncio.sleep(STREAM_POLL_SECONDS)
        except asyncio.CancelledError:
            raise
        finally:
            _active_streams -= 1

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "cache-control": "no-cache, no-transform",
            # nginx buffers proxied responses by default, which would hold
            # every event until the buffer filled. The shipped config turns
            # buffering off; this covers a config that does not.
            "x-accel-buffering": "no",
            "connection": "keep-alive",
        },
    )


# --------------------------------------------------------------------------- #
# Vulnerabilities
# --------------------------------------------------------------------------- #
@router.get("/vulnerabilities")
async def list_vulnerabilities(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    ecosystem: Ecosystem | None = None,
    min_score: float = Query(default=0.0, ge=0.0, le=10.0),
    max_score: float = Query(default=10.0, ge=0.0, le=10.0),
    severity: str | None = None,
    search: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict:
    conditions = []
    if ecosystem is not None:
        conditions.append(Vulnerability.ecosystem == ecosystem)
    if min_score > 0.0 or max_score < 10.0:
        conditions.append(
            and_(Vulnerability.cvss_score >= min_score, Vulnerability.cvss_score <= max_score)
        )
    if severity:
        conditions.append(Vulnerability.severity_label == severity.lower())
    if search:
        pattern = f"%{_escape_like(search.lower())}%"
        conditions.append(
            Vulnerability.cve_id.ilike(pattern, escape="\\")
            | Vulnerability.summary.ilike(pattern, escape="\\")
        )

    where = and_(*conditions) if conditions else True
    total = (
        await session.execute(select(func.count(Vulnerability.id)).where(where))
    ).scalar_one()

    rows = (
        await session.execute(
            select(
                Vulnerability,
                func.count(PackageVulnerability.id).label("affected"),
            )
            .outerjoin(
                PackageVulnerability, PackageVulnerability.vulnerability_id == Vulnerability.id
            )
            .where(where)
            .group_by(Vulnerability.id)
            .order_by(Vulnerability.cvss_score.desc().nullslast(), Vulnerability.id)
            .limit(limit)
            .offset(offset)
        )
    ).all()

    return {
        "total": total,
        "vulnerabilities": [
            {
                "id": v.id,
                "cve_id": v.cve_id,
                "ecosystem": v.ecosystem.value,
                "summary": v.summary,
                "cvss_score": v.cvss_score,
                "cvss_vector": v.cvss_vector,
                "severity_type": v.severity_type,
                "severity": v.severity_label,
                "aliases": v.aliases,
                "published": v.published,
                "modified": v.modified,
                "affected_versions": affected,
                "references": (v.references or [])[:5],
            }
            for v, affected in rows
        ],
    }


@router.get("/vulnerabilities/{osv_id}/affected")
async def vulnerability_affected(
    osv_id: str, session: AsyncSession = Depends(get_session)
) -> dict:
    vuln = await session.get(Vulnerability, osv_id)
    if vuln is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    rows = (
        await session.execute(
            select(
                Package.ecosystem,
                Package.name,
                PackageVersion.version,
                PackageVulnerability,
            )
            .join(PackageVersion, PackageVersion.package_id == Package.id)
            .join(
                PackageVulnerability, PackageVulnerability.version_id == PackageVersion.id
            )
            .where(PackageVulnerability.vulnerability_id == osv_id)
            .order_by(Package.normalized_name, PackageVersion.version)
        )
    ).all()

    return {
        "vulnerability": {
            "id": vuln.id,
            "cve_id": vuln.cve_id,
            "summary": vuln.summary,
            "details": vuln.details,
            "cvss_score": vuln.cvss_score,
            "severity": vuln.severity_label,
            "references": vuln.references,
        },
        "affected": [
            {
                "ecosystem": eco.value,
                "package": name,
                "version": version,
                "fixed_version": link.fixed_version,
                "suppressed": link.suppressed,
                "suppressed_reason": link.suppressed_reason,
                "link_id": link.id,
            }
            for eco, name, version, link in rows
        ],
    }


class SuppressRequest(BaseModel):
    suppressed: bool
    reason: str | None = None


@router.post("/vulnerabilities/links/{link_id}/suppress")
async def suppress_vulnerability(
    link_id: int,
    payload: SuppressRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    """Accept the risk for one package/CVE pairing.

    Note: this affects `npm audit` reporting only. It does NOT lift a block --
    the block list and CVE range policy are always enforced.
    """
    link = await session.get(PackageVulnerability, link_id)
    if link is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    link.suppressed = payload.suppressed
    link.suppressed_reason = payload.reason if payload.suppressed else None

    await audit.record_audit(
        session,
        audit.VULN_SUPPRESSED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="vulnerability",
        target_id=link.vulnerability_id,
        ip=client_ip(request),
        detail={
            "version_id": link.version_id,
            "suppressed": payload.suppressed,
            "reason": payload.reason,
        },
    )
    await session.commit()
    return {"ok": True}


@router.post("/rescore")
async def rescore_vulnerabilities(
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    """Recompute every stored CVSS score from the OSV records already held.

    Needed after a change to the scoring code: existing rows keep whatever
    score they were given when they were first fetched, so a corrected equation
    would otherwise only apply to newly discovered vulnerabilities. Uses no
    network -- the full OSV record is stored alongside each row.
    """
    result = await OsvScanner(session).rescore_stored()
    await audit.record_audit(
        session,
        "admin.scan.rescored",
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        ip=client_ip(request),
        detail=result,
    )
    await session.commit()
    return result


@router.post("/scan")
async def trigger_scan(
    request: Request,
    ecosystem: Ecosystem | None = None,
    package_name: str | None = None,
    rescan_all: bool = False,
    limit: int = Query(default=500, ge=1, le=5000),
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    """Scan stored versions against OSV. Bounded so the request stays fast."""
    conditions = []
    if ecosystem is not None:
        conditions.append(Package.ecosystem == ecosystem)
    if package_name:
        conditions.append(Package.normalized_name == package_name.lower())
    if not rescan_all:
        conditions.append(PackageVersion.scanned_at.is_(None))

    rows = (
        await session.execute(
            select(Package.ecosystem, Package.name, PackageVersion)
            .join(PackageVersion, PackageVersion.package_id == Package.id)
            .options(defer(PackageVersion.metadata_json))
            .where(and_(*conditions) if conditions else True)
            .order_by(PackageVersion.first_seen_at.desc())
            .limit(limit)
        )
    ).all()

    if not rows:
        return {"scanned": 0, "with_cves": 0, "message": "nothing to scan"}

    scanner = OsvScanner(session)
    by_ecosystem: dict[Ecosystem, list] = {}
    for eco, name, version in rows:
        by_ecosystem.setdefault(eco, []).append((name, version))

    scanned = 0
    with_cves = 0
    for eco, items in by_ecosystem.items():
        results = await scanner.scan_versions(
            eco, [(n, v.version) for n, v in items]
        )
        for name, version in items:
            result = results.get((name, version.version))
            if result is None or not result.scanned:
                continue
            await scanner.apply_to_version(version, result, name)
            scanned += 1
            if result.cves:
                with_cves += 1

    await audit.record_audit(
        session,
        audit.SCAN_TRIGGERED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        ip=client_ip(request),
        detail={
            "ecosystem": ecosystem.value if ecosystem else "all",
            "package": package_name,
            "rescan_all": rescan_all,
            "scanned": scanned,
            "with_cves": with_cves,
        },
    )
    await session.commit()
    return {"scanned": scanned, "with_cves": with_cves}


# --------------------------------------------------------------------------- #
# Packages
# --------------------------------------------------------------------------- #
@router.get("/packages")
async def list_packages(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    ecosystem: Ecosystem | None = None,
    search: str | None = None,
    local_only: bool = False,
    session: AsyncSession = Depends(get_session),
) -> dict:
    conditions = []
    if ecosystem is not None:
        conditions.append(Package.ecosystem == ecosystem)
    if search:
        conditions.append(
            Package.normalized_name.ilike(f"%{_escape_like(search.lower())}%", escape="\\")
        )
    if local_only:
        conditions.append(Package.is_local.is_(True))

    where = and_(*conditions) if conditions else True
    total = (await session.execute(select(func.count(Package.id)).where(where))).scalar_one()

    rows = (
        await session.execute(
            select(Package)
            .where(where)
            .options(
                # Up to 500 packages a page, and the entity carries the whole
                # cached packument -- tens of megabytes each for the popular
                # ones. Only the version count and worst score are read below.
                defer(Package.cached_document),
                selectinload(Package.versions).options(
                    defer(PackageVersion.metadata_json)
                ),
            )
            .order_by(Package.download_count.desc(), Package.normalized_name)
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()

    return {
        "total": total,
        "packages": [
            {
                "id": p.id,
                "ecosystem": p.ecosystem.value,
                "name": p.name,
                "normalized_name": p.normalized_name,
                "description": p.description,
                "latest_version": p.latest_version,
                "version_count": len(p.versions),
                "is_local": p.is_local,
                "download_count": p.download_count,
                "first_seen_at": p.first_seen_at,
                "cached_at": p.cached_at,
                "max_cvss": max(
                    (v.max_cvss for v in p.versions if v.max_cvss is not None), default=None
                ),
            }
            for p in rows
        ],
    }


@router.get("/packages/{package_id}")
async def package_detail(
    package_id: int, session: AsyncSession = Depends(get_session)
) -> dict:
    package = (
        await session.execute(
            select(Package)
            .where(Package.id == package_id)
            .options(
                selectinload(Package.versions).selectinload(PackageVersion.files),
                selectinload(Package.dist_tags),
            )
        )
    ).scalar_one_or_none()
    if package is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="package not found")

    cve_rows = (
        await session.execute(
            select(PackageVulnerability.version_id, Vulnerability)
            .join(Vulnerability, Vulnerability.id == PackageVulnerability.vulnerability_id)
            .where(
                PackageVulnerability.version_id.in_([v.id for v in package.versions] or [0])
            )
        )
    ).all()
    cves_by_version: dict[int, list] = {}
    for version_id, vuln in cve_rows:
        cves_by_version.setdefault(version_id, []).append(
            {
                "id": vuln.id,
                "cve_id": vuln.cve_id,
                "cvss_score": vuln.cvss_score,
                "severity": vuln.severity_label,
                "summary": vuln.summary,
            }
        )
    cves_by_version = {
        version_id: dedupe_by_cve(items) for version_id, items in cves_by_version.items()
    }

    return {
        "upstreams": await package_upstreams(session, package),
        "package": {
            "id": package.id,
            "ecosystem": package.ecosystem.value,
            "name": package.name,
            "normalized_name": package.normalized_name,
            "description": package.description,
            "author": package.author,
            "homepage": package.homepage,
            "license": package.license,
            "keywords": package.keywords,
            "latest_version": package.latest_version,
            "is_local": package.is_local,
            "download_count": package.download_count,
            "first_seen_at": package.first_seen_at,
            "cached_at": package.cached_at,
            "dist_tags": {t.tag: t.version for t in package.dist_tags},
        },
        "versions": [
            {
                "id": v.id,
                "version": v.version,
                "yanked": v.yanked,
                "yanked_reason": v.yanked_reason,
                "deprecated": v.deprecated,
                "is_local": v.is_local,
                "published_at": v.published_at,
                "requires_python": v.requires_python,
                "max_cvss": v.max_cvss,
                "scanned_at": v.scanned_at,
                "cves": cves_by_version.get(v.id, []),
                "files": [
                    {
                        "id": f.id,
                        "filename": f.filename,
                        "size": f.size,
                        "cached": bool(f.blob_sha256),
                        "sha256": f.sha256,
                        "packagetype": f.packagetype,
                        "yanked": f.yanked,
                        "download_count": f.download_count,
                        "upload_time": f.upload_time,
                    }
                    for f in v.files
                ],
            }
            for v in order_version_rows(package.ecosystem.value, package.versions, reverse=True)
        ],
    }


@router.delete("/packages/{package_id}")
async def delete_package(
    package_id: int,
    request: Request,
    purge_only: bool = Query(default=False, description="drop cached bytes but keep metadata"),
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    package = (
        await session.execute(
            select(Package)
            .where(Package.id == package_id)
            .options(selectinload(Package.versions).selectinload(PackageVersion.files))
        )
    ).scalar_one_or_none()
    if package is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="package not found")

    purged = 0
    for version in package.versions:
        for file_row in version.files:
            if await artifacts.purge_file(session, file_row):
                purged += 1

    name, ecosystem = package.name, package.ecosystem.value
    normalized = package.normalized_name
    if not purge_only:
        await session.delete(package)

    await audit.record_audit(
        session,
        audit.PACKAGE_DELETED if not purge_only else audit.CACHE_PURGED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="package",
        target_id=f"{ecosystem}:{name}",
        ip=client_ip(request),
        detail={"purged_files": purged, "purge_only": purge_only},
    )
    await session.commit()
    await packages.invalidate_package_cache(ecosystem, normalized)
    return {"ok": True, "purged_files": purged}


# --------------------------------------------------------------------------- #
# Cache maintenance
# --------------------------------------------------------------------------- #
@router.post("/cache/purge")
async def purge_cache(
    request: Request,
    ecosystem: Ecosystem | None = None,
    older_than_days: int | None = Query(default=None, ge=1),
    unused_only: bool = True,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    """Evict cached artifacts. Locally published files are never evicted --
    they have no upstream to re-fetch from."""
    conditions = [
        PackageFile.blob_sha256.isnot(None),
        PackageVersion.is_local.is_(False),
    ]
    if older_than_days:
        conditions.append(PackageFile.cached_at < _since(older_than_days))
    if unused_only:
        conditions.append(PackageFile.download_count == 0)

    stmt = (
        select(PackageFile)
        .join(PackageVersion, PackageVersion.id == PackageFile.version_id)
        .join(Package, Package.id == PackageVersion.package_id)
        .where(and_(*conditions))
    )
    if ecosystem is not None:
        stmt = stmt.where(Package.ecosystem == ecosystem)

    rows = (await session.execute(stmt.limit(10000))).scalars().all()
    freed = 0
    for file_row in rows:
        size = file_row.size or 0
        if await artifacts.purge_file(session, file_row):
            freed += size

    orphans = await artifacts.collect_orphan_blobs(session)

    await audit.record_audit(
        session,
        audit.CACHE_PURGED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        ip=client_ip(request),
        detail={
            "files_purged": len(rows),
            "bytes_freed": freed,
            "orphan_blobs": orphans,
            "ecosystem": ecosystem.value if ecosystem else "all",
            "older_than_days": older_than_days,
            "unused_only": unused_only,
        },
    )
    await session.commit()
    return {"files_purged": len(rows), "bytes_freed": freed, "orphan_blobs_removed": orphans}


@router.post("/cache/gc")
async def garbage_collect(
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    orphans = await artifacts.collect_orphan_blobs(session)
    tmp_removed = get_store().cleanup_tmp()
    await audit.record_audit(
        session,
        "admin.cache.gc",
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        ip=client_ip(request),
        detail={"orphan_blobs": orphans, "tmp_files": tmp_removed},
    )
    await session.commit()
    return {"orphan_blobs_removed": orphans, "tmp_files_removed": tmp_removed}
