"""JSON API for container images: UI pages, admin operations, scanner worker.

Three audiences, three guards:

* signed-in users browse images, findings and SBOMs (``require_user``);
* admins change policy, quarantine, pin, watch, rescan (``require_admin``);
* the scanner worker claims jobs and posts results with a token holding the
  ``scanner`` scope, and nothing else can use those routes.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..core.deps import Identity, client_ip, require_admin, require_user
from ..core.security import encrypt_credential
from ..db import get_session
from ..docker import details as image_details
from ..docker import housekeeping, scanning
from ..docker import registry as reg
from ..docker.errors import RegistryError
from ..docker.naming import PRESETS, host_matches
from ..docker.policy import KEY_DOCKER_POLICY, ImagePolicy, evaluate_pull, invalidate_policy, load_policy
from ..docker.store import get_oci_store
from ..docker.upstream import RATELIMITS, RegistryClient
from ..models import (
    DockerFinding,
    DockerManifest,
    DockerManifestRef,
    DockerRepoManifest,
    DockerRepository,
    DockerScan,
    DockerScanJob,
    DockerTag,
    Ecosystem,
    KevEntry,
    Setting,
    Upstream,
    UpstreamKind,
)
from ..services import audit

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/docker", tags=["docker"])


# --------------------------------------------------------------------------- #
# Serialisation
# --------------------------------------------------------------------------- #
def manifest_payload(m: DockerManifest) -> dict[str, Any]:
    return {
        "digest": m.digest,
        "media_type": m.media_type,
        "kind": m.kind,
        "is_index": m.is_index,
        "platform": m.platform,
        "size": m.size,
        "total_size": m.total_size,
        "layer_count": m.layer_count,
        "artifact_type": m.artifact_type,
        "subject_digest": m.subject_digest,
        "local": m.upstream_id is None,
        "scan_status": m.scan_status,
        "scanned_at": m.scanned_at,
        "severity_counts": {k: v for k, v in (m.severity_counts or {}).items() if k != "fixable"},
        "fixable_counts": (m.severity_counts or {}).get("fixable") or {},
        "max_cvss": m.max_cvss,
        "fixable_count": m.fixable_count,
        "kev_count": m.kev_count,
        "has_sbom": bool(m.sbom_digest),
        "policy_block_reason": m.policy_block_reason,
        "created_at": m.created_at,
        "last_accessed_at": m.last_accessed_at,
    }


def repo_payload(r: DockerRepository, upstream_names: dict[int, str] | None = None) -> dict[str, Any]:
    return {
        "name": r.name,
        "upstream": (upstream_names or {}).get(r.upstream_id) if r.upstream_id else None,
        "remote_name": r.remote_name,
        "local": r.is_local,
        "pinned": r.pinned,
        "quarantined": r.quarantined,
        "quarantine_reason": r.quarantine_reason,
        "watched_tags": r.watched_tags or [],
        "pull_count": r.pull_count,
        "created_at": r.created_at,
        "last_pulled_at": r.last_pulled_at,
        "last_pushed_at": r.last_pushed_at,
        "indexed_only": r.indexed_only,
    }


async def _upstream_names(session: AsyncSession) -> dict[int, str]:
    rows = (
        await session.execute(select(Upstream.id, Upstream.name).where(Upstream.ecosystem == Ecosystem.docker))
    ).all()
    return dict(rows)


async def _repo_or_404(session: AsyncSession, name: str) -> DockerRepository:
    repo = (
        await session.execute(select(DockerRepository).where(DockerRepository.name == name))
    ).scalar_one_or_none()
    if repo is None:
        raise HTTPException(status_code=404, detail="repository not found")
    return repo


async def _manifest_or_404(session: AsyncSession, digest: str) -> DockerManifest:
    m = (
        await session.execute(select(DockerManifest).where(DockerManifest.digest == digest))
    ).scalar_one_or_none()
    if m is None:
        raise HTTPException(status_code=404, detail="manifest not found")
    return m


# --------------------------------------------------------------------------- #
# Browsing
# --------------------------------------------------------------------------- #
@router.get("/images")
async def list_images(
    q: str | None = None,
    scope: str | None = Query(default=None, pattern="^(local|cached|quarantined|watched)$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_user),
) -> dict:
    conds = [DockerRepository.indexed_only.is_(False)]
    if q:
        conds.append(DockerRepository.name.contains(q.strip().lower()[:200]))
    if scope == "local":
        conds.append(DockerRepository.is_local.is_(True))
    elif scope == "cached":
        conds.append(DockerRepository.is_local.is_(False))
    elif scope == "quarantined":
        conds.append(DockerRepository.quarantined.is_(True))
    total = (await session.execute(select(func.count()).select_from(DockerRepository).where(and_(*conds)))).scalar_one()
    repos = (
        await session.execute(
            select(DockerRepository)
            .where(and_(*conds))
            .order_by(DockerRepository.last_pulled_at.desc().nullslast(), DockerRepository.name)
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    if scope == "watched":
        repos = [r for r in repos if r.watched_tags]
    ups = {
        u.id: u
        for u in (await session.execute(select(Upstream).where(Upstream.ecosystem == Ecosystem.docker))).scalars()
    }
    names = {i: u.name for i, u in ups.items()}
    out = []
    for r in repos:
        summary = await _repo_summary(session, r)
        out.append(
            {
                **repo_payload(r, names),
                **summary,
                "pull_reference": _pull_ref(r, ups.get(r.upstream_id) if r.upstream_id else None),
            }
        )
    return {"total": total, "images": out}


async def _repo_summary(session: AsyncSession, repo: DockerRepository) -> dict:
    tag_count = (
        await session.execute(select(func.count()).select_from(DockerTag).where(DockerTag.repository_id == repo.id))
    ).scalar_one()
    manifests = (
        await session.execute(
            select(DockerManifest)
            .join(DockerRepoManifest, DockerRepoManifest.manifest_id == DockerManifest.id)
            .where(DockerRepoManifest.repository_id == repo.id, DockerManifest.kind == "image")
        )
    ).scalars().all()
    worst: dict[str, int] = {}
    kev = 0
    scanned = 0
    size = 0
    for m in manifests:
        size = max(size, m.total_size)
        if m.scan_status == "scanned":
            scanned += 1
            kev += m.kev_count
            for sev in ("CRITICAL", "HIGH"):
                worst[sev] = max(worst.get(sev, 0), int((m.severity_counts or {}).get(sev, 0)))
    return {
        "tag_count": tag_count,
        "image_count": len(manifests),
        "scanned_count": scanned,
        "worst_counts": worst,
        "kev_count": kev,
        "largest_image_bytes": size,
    }


@router.get("/repository")
async def get_repository(
    name: str,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_user),
) -> dict:
    repo = await _repo_or_404(session, name)
    names = await _upstream_names(session)
    tags = (
        await session.execute(
            select(DockerTag, DockerManifest)
            .join(DockerManifest, DockerManifest.id == DockerTag.manifest_id)
            .where(DockerTag.repository_id == repo.id)
            .order_by(DockerTag.updated_at.desc())
        )
    ).all()
    tag_list = []
    for tag, m in tags:
        children = []
        if m.is_index:
            children = await _children(session, m)
        tag_list.append(
            {
                "tag": tag.tag,
                "checked_at": tag.checked_at,
                "updated_at": tag.updated_at,
                "manifest": manifest_payload(m),
                "platforms": children,
            }
        )
    untagged = (
        await session.execute(
            select(DockerManifest)
            .join(DockerRepoManifest, DockerRepoManifest.manifest_id == DockerManifest.id)
            .where(
                DockerRepoManifest.repository_id == repo.id,
                DockerManifest.id.notin_(select(DockerTag.manifest_id).where(DockerTag.repository_id == repo.id)),
            )
            .order_by(DockerManifest.last_accessed_at.desc())
            .limit(100)
        )
    ).scalars().all()
    upstream = await session.get(Upstream, repo.upstream_id) if repo.upstream_id else None
    return {
        **repo_payload(repo, names),
        "pull_reference": _pull_ref(repo, upstream),
        "tags": tag_list,
        "digests": [manifest_payload(m) for m in untagged],
    }


def _pull_ref(repo: DockerRepository, upstream: Upstream | None) -> str:
    """The shortest name a client can use for this repository."""
    host = settings.public_url.split("://", 1)[-1]
    name = repo.name
    if upstream is not None and ((upstream.extra or {}).get("default") or upstream.name == "dockerhub"):
        remote = repo.remote_name or ""
        short = remote[len("library/"):] if remote.startswith("library/") else remote
        first = short.split("/", 1)[0]
        # Only drop the prefix if the short form would route back here.
        if first and first not in PRESETS and first != settings.docker_local_namespace:
            name = short
    return f"{host}/{name}"


async def _children(session: AsyncSession, index: DockerManifest) -> list[dict]:
    refs = (
        await session.execute(
            select(DockerManifestRef)
            .where(DockerManifestRef.manifest_id == index.id, DockerManifestRef.ref_type == "manifest")
            .order_by(DockerManifestRef.position)
        )
    ).scalars().all()
    rows = {
        m.digest: m
        for m in (
            await session.execute(
                select(DockerManifest).where(DockerManifest.digest.in_([r.digest for r in refs]))
            )
        ).scalars().all()
    }
    out = []
    for r in refs:
        m = rows.get(r.digest)
        out.append(
            {
                "digest": r.digest,
                "platform": r.platform,
                "size": r.size,
                "attestation": (r.annotations or {}).get("vnd.docker.reference.type") == "attestation-manifest"
                or r.platform == "unknown/unknown",
                "fetched": m is not None,
                "manifest": manifest_payload(m) if m else None,
            }
        )
    return out


def split_reference(ref: str, also_ours: str | None = None) -> tuple[str, str | None, str | None]:
    """``[host/]name[:tag][@digest]`` -> (name, tag, digest).

    The host is dropped when it is one of ours, so the exact string a user
    passes to `docker pull` works. ``also_ours`` is the host the request came
    in on: someone reaching the registry as ``localhost:5055`` pulls
    ``localhost:5055/alpine``, whatever PUBLIC_URL says. Only ever stripped,
    never routed to, so a forged Host header cannot send the lookup anywhere.
    A tag is only looked for in the last path segment: in
    ``localhost:5000/x`` the colon belongs to the host.
    """
    ref = ref.strip()
    ours = {settings.public_url.split("://", 1)[-1].lower().rstrip("/")}
    if settings.docker_mirror_hostname:
        ours.add(settings.docker_mirror_hostname.lower())
    if also_ours:
        ours.add(also_ours.lower())
    first, sep, rest = ref.partition("/")
    if sep and first.lower() in ours:
        ref = rest
    name, _, digest = ref.partition("@")
    head, slash, last = name.rpartition("/")
    tag = None
    if ":" in last:
        last, tag = last.split(":", 1)
        name = f"{head}{slash}{last}"
    return name, tag or None, digest or None


def _pick_platform(children: list[dict], wanted: str) -> dict | None:
    """The child `docker pull --platform` would take.

    Exact first; then a request without a variant matches one with it, the
    way Docker treats linux/arm64 as linux/arm64/v8.
    """
    exact = next((c for c in children if c["platform"] == wanted), None)
    if exact is not None or wanted.count("/") != 1:
        return exact
    return next((c for c in children if (c["platform"] or "").startswith(wanted + "/")), None)


@router.get("/inspect")
async def inspect_image(
    request: Request,
    ref: str = Query(min_length=1, max_length=512),
    platform: str = Query(default="linux/amd64", max_length=64),
    findings: int = Query(default=50, ge=0, le=2000),
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_user),
) -> dict:
    """Resolve an image reference the way `docker pull` would, and report it.

    For the CLI: one call answers "what is this image, has it been scanned,
    and would a pull be allowed?". A reference that is not cached yet is
    fetched from its upstream (manifests only, no layers) and queued for a
    scan like a pull would, so `minireg audit --image` works on an image
    nobody has pulled. A multi-platform tag is judged on ``platform``, with
    the index's own verdict (the worst platform) taking precedence, which is
    what Docker would get.
    """
    name, tag, digest = split_reference(ref, request.headers.get("host"))
    reference = digest or tag or "latest"
    try:
        target = await reg.resolve_target(session, name, mirror_host=False)
        repo = await reg.get_repo(session, target, create=not target.local)
        if repo is None:
            raise RegistryError("NAME_UNKNOWN", f"repository {target.canonical} not found")
        top = (await reg.get_manifest(session, target, repo, reference, head=True)).manifest
        image = top
        platforms: list[str] = []
        if top.is_index:
            children = [c for c in await _children(session, top) if not c["attestation"]]
            platforms = [c["platform"] for c in children if c["platform"]]
            pick = _pick_platform(children, platform)
            if pick is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"no {platform} image (it has: {', '.join(platforms) or 'none'})",
                )
            image = (await reg.get_manifest(session, target, repo, pick["digest"], head=True)).manifest
    except RegistryError as exc:
        status_code = exc.status if exc.status >= 400 else 400
        raise HTTPException(status_code=status_code, detail=exc.message) from exc

    policy = await load_policy(session)
    wants_scan = (
        image.kind == "image"
        and image.scan_status == "unscanned"
        and policy.scanning_enabled
        and not repo.quarantined
        and (policy.scan_on_pull or image.upstream_id is None)
        and policy.scans_platform(image.platform)
    )
    if wants_scan:
        priority = scanning.PRIORITY_PUSH if image.upstream_id is None else scanning.PRIORITY_PULL
        await scanning.enqueue(session, image, repo.name, reason="cli", priority=priority)

    # What `docker pull` would get: the tag's own verdict (for an index, the
    # worst platform), then the platform image's.
    verdict = await evaluate_pull(session, repo, top, policy)
    if verdict.allowed and image is not top:
        verdict = await evaluate_pull(session, repo, image, policy)

    rows: list[DockerFinding] = []
    total = 0
    if findings and image.scan_status == "scanned":
        conds = [DockerFinding.manifest_id == image.id]
        total = (
            await session.execute(select(func.count()).select_from(DockerFinding).where(and_(*conds)))
        ).scalar_one()
        rows = list(
            (
                await session.execute(
                    select(DockerFinding).where(and_(*conds)).order_by(*FINDING_ORDER).limit(findings)
                )
            ).scalars()
        )
    tags = (
        await session.execute(
            select(DockerTag.tag)
            .where(DockerTag.repository_id == repo.id)
            .order_by(DockerTag.updated_at.desc())
            .limit(30)
        )
    ).scalars().all()
    upstream = await session.get(Upstream, repo.upstream_id) if repo.upstream_id else None
    pull_ref = _pull_ref(repo, upstream)
    await session.commit()
    return {
        "reference": ref,
        "repository": repo.name,
        "upstream": getattr(upstream, "name", None),
        "local": repo.is_local,
        "quarantined": repo.quarantined,
        "pull_reference": pull_ref + (f"@{digest}" if digest else f":{tag or 'latest'}"),
        "digest": top.digest,
        "is_index": top.is_index,
        "platforms": platforms,
        "platform": image.platform,
        "image": manifest_payload(image),
        "verdict": {
            "allowed": verdict.allowed,
            "code": None if verdict.allowed else verdict.code,
            "reason": verdict.reason,
            "retry_after": verdict.retry_after,
        },
        "findings_total": total,
        "findings": [finding_payload(f, policy) for f in rows],
        "tags": list(tags),
    }


@router.get("/manifest/{digest}")
async def get_manifest_detail(
    digest: str,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_user),
) -> dict:
    m = await _manifest_or_404(session, digest)
    layers = (
        await session.execute(
            select(DockerManifestRef)
            .where(DockerManifestRef.manifest_id == m.id)
            .order_by(DockerManifestRef.position)
        )
    ).scalars().all()
    repos = (
        await session.execute(
            select(DockerRepository.name)
            .join(DockerRepoManifest, DockerRepoManifest.repository_id == DockerRepository.id)
            .where(DockerRepoManifest.manifest_id == m.id)
        )
    ).scalars().all()
    scans = (
        await session.execute(
            select(DockerScan).where(DockerScan.manifest_id == m.id).order_by(DockerScan.id.desc()).limit(10)
        )
    ).scalars().all()
    job = (
        await session.execute(
            select(DockerScanJob)
            .where(DockerScanJob.manifest_id == m.id)
            .order_by(DockerScanJob.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    return {
        **manifest_payload(m),
        "repositories": list(repos),
        "children": await _children(session, m) if m.is_index else [],
        "layers": [
            {
                "type": r.ref_type,
                "digest": r.digest,
                "media_type": r.media_type,
                "size": r.size,
                "cached": get_oci_store().exists(r.digest),
            }
            for r in layers
            if r.ref_type != "manifest"
        ],
        "scans": [
            {
                "id": s.id,
                "mode": s.mode,
                "created_at": s.created_at,
                "trivy_version": s.trivy_version,
                "db_updated_at": s.db_updated_at,
                "os": " ".join(x for x in (s.os_family, s.os_name) if x) or None,
                "finding_count": s.finding_count,
                "severity_counts": {k: v for k, v in (s.severity_counts or {}).items() if k != "fixable"},
                "duration_ms": s.duration_ms,
                "has_report": bool(s.report_digest),
            }
            for s in scans
        ],
        "last_job": None
        if job is None
        else {
            "status": job.status,
            "reason": job.reason,
            "mode": job.mode,
            "attempts": job.attempts,
            "error": job.error,
            "created_at": job.created_at,
            "finished_at": job.finished_at,
        },
    }


@router.get("/manifest/{digest}/findings")
async def list_findings(
    digest: str,
    severity: str | None = None,
    fixable: bool | None = None,
    kev: bool | None = None,
    q: str | None = None,
    limit: int = Query(default=200, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_user),
) -> dict:
    m = await _manifest_or_404(session, digest)
    conds = [DockerFinding.manifest_id == m.id]
    if severity:
        conds.append(DockerFinding.severity.in_([s.upper() for s in severity.split(",")]))
    if fixable is True:
        conds.append(and_(DockerFinding.fixed_version.isnot(None), DockerFinding.fixed_version != ""))
    elif fixable is False:
        conds.append(or_(DockerFinding.fixed_version.is_(None), DockerFinding.fixed_version == ""))
    if kev is not None:
        conds.append(DockerFinding.kev.is_(kev))
    if q:
        like = f"%{q.strip()[:100]}%"
        conds.append(or_(DockerFinding.vuln_id.ilike(like), DockerFinding.pkg_name.ilike(like)))
    total = (await session.execute(select(func.count()).select_from(DockerFinding).where(and_(*conds)))).scalar_one()
    rows = (
        await session.execute(
            select(DockerFinding).where(and_(*conds)).order_by(*FINDING_ORDER).limit(limit).offset(offset)
        )
    ).scalars().all()
    policy = await load_policy(session)
    return {"total": total, "findings": [finding_payload(f, policy) for f in rows]}


#: Findings order everywhere: known-exploited first, then by score.
FINDING_ORDER = (
    DockerFinding.kev.desc(),
    func.coalesce(DockerFinding.cvss, 0).desc(),
    DockerFinding.vuln_id,
)


def finding_payload(f: DockerFinding, policy: ImagePolicy) -> dict[str, Any]:
    return {
        "vuln_id": f.vuln_id,
        "pkg_name": f.pkg_name,
        "pkg_type": f.pkg_type,
        "installed_version": f.installed_version,
        "fixed_version": f.fixed_version,
        "severity": f.severity,
        "cvss": f.cvss,
        "title": f.title,
        "url": f.url,
        "layer_digest": f.layer_digest,
        "kev": f.kev,
        "denied": f.vuln_id in policy.deny_cves,
        "accepted": f.vuln_id in policy.allow_cves,
    }


async def _config_bytes(session: AsyncSession, m: DockerManifest) -> bytes | None:
    """The image config blob: from the store, else fetched (a few KB) from the
    upstream through a repository that holds this manifest."""
    if not m.config_digest:
        return None
    store = get_oci_store()
    if store.exists(m.config_digest):
        return await store.read_bytes(m.config_digest, limit=image_details.MAX_CONFIG_BYTES)
    repo = (
        await session.execute(
            select(DockerRepository)
            .join(DockerRepoManifest, DockerRepoManifest.repository_id == DockerRepository.id)
            .where(DockerRepoManifest.manifest_id == m.id, DockerRepository.is_local.is_(False))
            .limit(1)
        )
    ).scalar_one_or_none()
    if repo is None:
        return None
    try:
        target = await reg.resolve_target(session, repo.name, mirror_host=False)
        blob = await reg.open_blob(session, target, repo, m.config_digest)
        body = bytearray()
        async for chunk in blob.chunks:
            body.extend(chunk)
            if len(body) > image_details.MAX_CONFIG_BYTES:
                return None
        return bytes(body)
    except RegistryError as exc:
        log.info("config %s for %s not available: %s", m.config_digest, m.digest, exc.message)
        return None


@router.get("/manifest/{digest}/config")
async def get_image_config(
    digest: str,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_user),
) -> dict:
    """Entrypoint, env, labels, ports and the build history of an image,
    with each layer paired to the step that produced it."""
    m = await _manifest_or_404(session, digest)
    if m.kind != "image":
        raise HTTPException(status_code=404, detail="only images have a config")
    config = image_details.parse_config(await _config_bytes(session, m))
    layers = (
        await session.execute(
            select(DockerManifestRef)
            .where(DockerManifestRef.manifest_id == m.id, DockerManifestRef.ref_type == "blob")
            .order_by(DockerManifestRef.position)
        )
    ).scalars().all()
    await session.commit()
    steps = image_details.layer_history(len(layers), config["history"]) if config else [None] * len(layers)
    diff_ids = (config or {}).get("diff_ids") or []
    store = get_oci_store()
    return {
        "digest": m.digest,
        "available": config is not None,
        "config": config,
        "layers": [
            {
                "index": i,
                "digest": ref.digest,
                "media_type": ref.media_type,
                "size": ref.size,
                "cached": store.exists(ref.digest),
                "diff_id": diff_ids[i] if i < len(diff_ids) else None,
                "created_by": (steps[i] or {}).get("created_by"),
                "created": (steps[i] or {}).get("created"),
                "comment": (steps[i] or {}).get("comment"),
            }
            for i, ref in enumerate(layers)
        ],
    }


@router.get("/manifest/{digest}/packages")
async def get_image_packages(
    digest: str,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_user),
) -> dict:
    """The SBOM as a package list: name, version, type, licences, and the
    layer each package came from. The raw CycloneDX is at ``/sbom``."""
    m = await _manifest_or_404(session, digest)
    if not m.sbom_digest:
        raise HTTPException(status_code=404, detail="no SBOM recorded for this image yet")
    cached = image_details.SBOM_CACHE.get(m.sbom_digest)
    if cached is None:
        raw = await get_oci_store().read_bytes(m.sbom_digest, limit=image_details.MAX_SBOM_BYTES)
        if raw is None:
            raise HTTPException(status_code=404, detail="SBOM file missing")
        cached = image_details.summarize_sbom(raw) or {}
        image_details.SBOM_CACHE.put(m.sbom_digest, cached)
    # Findings per package, so the list can show which ones are vulnerable.
    vulnerable = (
        await session.execute(
            select(DockerFinding.pkg_name, DockerFinding.installed_version, DockerFinding.severity, func.count())
            .where(DockerFinding.manifest_id == m.id)
            .group_by(DockerFinding.pkg_name, DockerFinding.installed_version, DockerFinding.severity)
        )
    ).all()
    findings: dict[str, dict[str, int]] = {}
    for pkg, version, severity, n in vulnerable:
        key = f"{pkg}@{version or ''}"
        findings.setdefault(key, {})[(severity or "UNKNOWN").upper()] = n
    return {**cached, "findings_by_package": findings}


@router.get("/manifest/{digest}/sbom")
async def download_sbom(
    digest: str,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_user),
) -> Response:
    m = await _manifest_or_404(session, digest)
    if not m.sbom_digest:
        raise HTTPException(status_code=404, detail="no SBOM recorded for this image yet")
    body = await get_oci_store().read_bytes(m.sbom_digest)
    if body is None:
        raise HTTPException(status_code=404, detail="SBOM file missing")
    short = digest.split(":")[-1][:12]
    return Response(
        body,
        media_type="application/vnd.cyclonedx+json",
        headers={"Content-Disposition": f'attachment; filename="sbom-{short}.cdx.json"'},
    )


@router.get("/vulnerabilities")
async def search_vulnerabilities(
    cve: str | None = None,
    package: str | None = None,
    severity: str | None = None,
    kev: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_user),
) -> dict:
    """Which images contain a given CVE (or package, or severity)?

    Returns one row per image manifest, with the repositories and tags that
    currently point at it -- the answer to "we just heard about CVE-X, what
    do we run that has it?".
    """
    conds = []
    if cve:
        conds.append(DockerFinding.vuln_id == cve.strip().upper())
    if package:
        conds.append(DockerFinding.pkg_name.ilike(f"%{package.strip()[:100]}%"))
    if severity:
        conds.append(DockerFinding.severity.in_([s.upper() for s in severity.split(",")]))
    if kev is not None:
        conds.append(DockerFinding.kev.is_(kev))
    if not conds:
        return await _vuln_summary(session)
    rows = (
        await session.execute(
            select(
                DockerFinding.manifest_id,
                func.count(),
                func.max(DockerFinding.cvss),
                func.max(DockerFinding.fixed_version),
            )
            .where(and_(*conds))
            .group_by(DockerFinding.manifest_id)
            .limit(limit)
        )
    ).all()
    out = []
    for manifest_id, count, cvss, fixed in rows:
        m = await session.get(DockerManifest, manifest_id)
        if m is None:
            continue
        placements = (
            await session.execute(
                select(DockerRepository.name, DockerTag.tag)
                .join(DockerRepoManifest, DockerRepoManifest.repository_id == DockerRepository.id)
                .outerjoin(
                    DockerTag,
                    and_(DockerTag.repository_id == DockerRepository.id, DockerTag.manifest_id == m.id),
                )
                .where(DockerRepoManifest.manifest_id == m.id)
            )
        ).all()
        # Children of a multi-platform image are usually pulled through the
        # index's tag, not their own: report the index's tags too.
        parent_tags = (
            await session.execute(
                select(DockerRepository.name, DockerTag.tag, DockerManifestRef.platform)
                .join(DockerManifest, DockerManifest.id == DockerManifestRef.manifest_id)
                .join(DockerTag, DockerTag.manifest_id == DockerManifest.id)
                .join(DockerRepository, DockerRepository.id == DockerTag.repository_id)
                .where(DockerManifestRef.digest == m.digest, DockerManifestRef.ref_type == "manifest")
            )
        ).all()
        where = sorted(
            {f"{r}:{t}" if t else r for r, t in placements} | {f"{r}:{t}" for r, t, _p in parent_tags}
        )
        out.append(
            {
                **manifest_payload(m),
                "matching_findings": count,
                "max_matching_cvss": cvss,
                "a_fixed_version": fixed,
                "where": where[:50],
            }
        )
    out.sort(key=lambda r: (-(r["max_matching_cvss"] or 0), r["digest"]))
    return {"images": out, "kev_entry": await _kev_entry(session, cve) if cve else None}


async def _kev_entry(session: AsyncSession, cve: str) -> dict | None:
    e = await session.get(KevEntry, cve.strip().upper())
    if e is None:
        return None
    return {
        "cve_id": e.cve_id,
        "vendor": e.vendor,
        "product": e.product,
        "name": e.name,
        "date_added": e.date_added,
        "ransomware": e.ransomware,
    }


async def _vuln_summary(session: AsyncSession) -> dict:
    top = (
        await session.execute(
            select(
                DockerFinding.vuln_id,
                func.max(DockerFinding.severity),
                func.max(DockerFinding.cvss),
                func.count(func.distinct(DockerFinding.manifest_id)),
                func.max(DockerFinding.title),
            )
            .where(or_(DockerFinding.kev.is_(True), DockerFinding.severity == "CRITICAL"))
            .group_by(DockerFinding.vuln_id)
            .order_by(func.count(func.distinct(DockerFinding.manifest_id)).desc())
            .limit(50)
        )
    ).all()
    kev_ids = set(
        (
            await session.execute(
                select(KevEntry.cve_id).where(KevEntry.cve_id.in_([r[0] for r in top]))
            )
        ).scalars().all()
    )
    return {
        "top": [
            {
                "vuln_id": v,
                "severity": s,
                "cvss": c,
                "image_count": n,
                "title": t,
                "kev": v in kev_ids,
            }
            for v, s, c, n, t in top
        ],
        "kev_catalogue_size": (await session.execute(select(func.count()).select_from(KevEntry))).scalar_one(),
    }


@router.get("/client-config")
async def client_config(identity: Identity = Depends(require_user), session: AsyncSession = Depends(get_session)) -> dict:
    base = settings.public_url
    scheme, _, host = base.partition("://")
    upstreams, default = await reg.docker_upstreams(session)
    mirror_host = settings.docker_mirror_hostname
    mirror_url = f"{scheme}://{mirror_host}" if mirror_host else base
    hub_note = None
    if not mirror_host:
        hub_note = (
            "Mirror mode is using the main hostname. An image whose first path segment is also "
            "an upstream name (for example quay/...) resolves to that upstream there; set "
            "DOCKER_MIRROR_HOSTNAME to give Docker Hub a dedicated hostname if that matters."
        )
    local = settings.docker_local_namespace
    return {
        "host": host,
        "public_url": base,
        "local_namespace": local,
        "default_upstream": default.name if default else None,
        "upstreams": sorted(upstreams),
        "mirror_url": mirror_url,
        "mirror_note": hub_note,
        "examples": {
            "hub": f"docker pull {host}/alpine:3.20",
            "hub_explicit": f"docker pull {host}/dockerhub/library/alpine:3.20",
            "other": [f"docker pull {host}/{n}/<image>:<tag>" for n in sorted(upstreams) if n != (default.name if default else None)][:6],
            "push": [
                f"docker login {host} -u <username>   # password: an API token with docker:push",
                f"docker tag myapp:1.0 {host}/{local}/<team>/myapp:1.0",
                f"docker push {host}/{local}/<team>/myapp:1.0",
            ],
        },
        # Docker only talks plain HTTP to a registry listed as insecure; a
        # mirror on http:// is otherwise skipped silently, and every pull goes
        # straight to Hub as if nothing were configured.
        "daemon_json": (
            {"registry-mirrors": [mirror_url], "insecure-registries": [mirror_host or host]}
            if scheme == "http"
            else {"registry-mirrors": [mirror_url]}
        ),
        "containerd_hosts_toml": "\n".join(
            [
                'server = "https://registry-1.docker.io"',
                "",
                f'[host."{mirror_url}"]',
                '  capabilities = ["pull", "resolve"]',
            ]
        ),
        "containerd_path": "/etc/containerd/certs.d/docker.io/hosts.toml",
        "podman_registries_conf": "\n".join(
            [
                "[[registry]]",
                'prefix = "docker.io"',
                'location = "docker.io"',
                "",
                "[[registry.mirror]]",
                f'location = "{mirror_host or host}"',
            ]
        ),
        "k8s_pull_secret": (
            f"kubectl create secret docker-registry minireg --docker-server={host} "
            "--docker-username=<username> --docker-password=<api-token>"
        ),
        "gitlab_ci": "\n".join(
            [
                "# .gitlab-ci.yml: pull job images through the cache",
                f"image: {host}/python:3.12-slim",
                "",
                "variables:",
                "  # Dockerfile FROM lines, via --build-arg BASE_REGISTRY",
                f"  BASE_REGISTRY: {host}/",
            ]
        ),
        "trivy_db": f"{host}/ghcr/aquasecurity/trivy-db:2" if "ghcr" in upstreams else None,
    }


# --------------------------------------------------------------------------- #
# Admin
# --------------------------------------------------------------------------- #
class RepositoryUpdate(BaseModel):
    pinned: bool | None = None
    quarantined: bool | None = None
    quarantine_reason: str | None = Field(default=None, max_length=500)
    watched_tags: list[str] | None = Field(default=None, max_length=20)


@router.patch("/repository")
async def update_repository(
    payload: RepositoryUpdate,
    request: Request,
    name: str,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    from ..docker.naming import is_tag

    repo = await _repo_or_404(session, name)
    changes: dict[str, Any] = {}
    for field in ("pinned", "quarantined", "quarantine_reason"):
        value = getattr(payload, field)
        if value is not None and getattr(repo, field) != value:
            setattr(repo, field, value or (None if field == "quarantine_reason" else value))
            changes[field] = value
    if payload.watched_tags is not None:
        tags = sorted({t.strip() for t in payload.watched_tags if t.strip()})
        bad = [t for t in tags if not is_tag(t)]
        if bad:
            raise HTTPException(status_code=400, detail=f"invalid tag(s): {', '.join(bad)}")
        if repo.is_local and tags:
            raise HTTPException(status_code=400, detail="watching applies to cached upstream images")
        repo.watched_tags = tags
        changes["watched_tags"] = tags
    await audit.record_audit(
        session,
        "admin.docker.repository.updated",
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="docker_repository",
        target_id=repo.name[:255],
        ip=client_ip(request),
        detail=changes,
    )
    await session.commit()
    return repo_payload(repo, await _upstream_names(session))


class RefreshRequest(BaseModel):
    tag: str = Field(min_length=1, max_length=128)


@router.post("/repository/refresh")
async def refresh_repository_tag(
    payload: RefreshRequest,
    name: str,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    try:
        return await housekeeping.refresh_watched(name, payload.tag)
    except RegistryError as exc:
        raise HTTPException(status_code=exc.status if exc.status < 500 else 502, detail=exc.message) from exc


@router.delete("/repository")
async def purge_repository(
    name: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    """Forget a cached repository. Files are reclaimed by the next GC. Local
    repositories are refused here: deleting pushed images goes through the
    registry API by their owner, so it is audited as theirs."""
    repo = await _repo_or_404(session, name)
    if repo.is_local:
        raise HTTPException(status_code=400, detail="local repositories are deleted through the registry API")
    from sqlalchemy import delete as sa_delete

    from ..models import DockerRepoBlob

    # Explicit, for the same reason as GC: SQLite does not enforce the FK
    # cascades, and stray link rows would keep the images alive.
    for table in (DockerTag, DockerRepoManifest, DockerRepoBlob):
        await session.execute(sa_delete(table).where(table.repository_id == repo.id))
    await session.delete(repo)
    await audit.record_audit(
        session,
        audit.CACHE_PURGED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="docker_repository",
        target_id=name[:255],
        ip=client_ip(request),
        detail={"ecosystem": "docker"},
    )
    await session.commit()
    return {"ok": True}


@router.post("/manifest/{digest}/rescan")
async def rescan(
    digest: str,
    request: Request,
    full: bool = False,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    m = await _manifest_or_404(session, digest)
    if m.kind != "image":
        raise HTTPException(
            status_code=400,
            detail=f"this is {'an' if m.kind[0] in 'aeiou' else 'a'} {m.kind}, not a runnable image; "
            "scan the platform images it lists",
        )
    repo = (
        await session.execute(
            select(DockerRepository.name)
            .join(DockerRepoManifest, DockerRepoManifest.repository_id == DockerRepository.id)
            .where(DockerRepoManifest.manifest_id == m.id)
            .limit(1)
        )
    ).scalar_one_or_none()
    if repo is None:
        raise HTTPException(status_code=409, detail="no repository holds this image any more")
    mode = "sbom" if m.sbom_digest and not full else "image"
    if m.scan_status == "failed":
        m.scan_status = "unscanned"
    job = await scanning.enqueue(session, m, repo, reason="manual", priority=scanning.PRIORITY_MANUAL, mode=mode)
    await audit.record_audit(
        session,
        audit.SCAN_TRIGGERED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="image",
        target_id=digest,
        ip=client_ip(request),
        detail={"ecosystem": "docker", "mode": mode},
    )
    await session.commit()
    return {"queued": job is not None, "mode": mode}


# -- policy ---------------------------------------------------------------- #
@router.get("/policy")
async def get_policy(
    session: AsyncSession = Depends(get_session), identity: Identity = Depends(require_admin)
) -> dict:
    policy = await load_policy(session)
    return {**policy.to_dict(), "effective_budget_bytes": policy.budget()}


@router.put("/policy")
async def put_policy(
    payload: dict,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    policy = ImagePolicy.from_dict(payload)
    value = policy.to_dict()
    row = await session.get(Setting, KEY_DOCKER_POLICY)
    if row is None:
        session.add(Setting(key=KEY_DOCKER_POLICY, value=value, updated_by=identity.username))
    else:
        row.value = value
        row.updated_by = identity.username
    await audit.record_audit(
        session,
        audit.SETTING_UPDATED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="setting",
        target_id=KEY_DOCKER_POLICY,
        ip=client_ip(request),
        detail=value,
    )
    await session.commit()
    await invalidate_policy()
    # Pushed images carry a verdict; a new push bar re-judges them.
    await scanning.reapply_push_policy(session)
    await session.commit()
    return {**value, "effective_budget_bytes": policy.budget()}


# -- stats / dashboard ------------------------------------------------------ #
@router.get("/stats")
async def stats(
    session: AsyncSession = Depends(get_session), identity: Identity = Depends(require_admin)
) -> dict:
    policy = await load_policy(session)
    use = await reg.usage(session)
    since = datetime.now(UTC) - timedelta(days=1)
    from ..models import DownloadLog

    pulls = (
        await session.execute(
            select(DownloadLog.cache_hit, func.count())
            .where(DownloadLog.ecosystem == "docker", DownloadLog.kind == "metadata", DownloadLog.ts >= since)
            .group_by(DownloadLog.cache_hit)
        )
    ).all()
    hits = sum(n for hit, n in pulls if hit)
    total = sum(n for _hit, n in pulls)
    severity = (
        await session.execute(
            select(DockerManifest.scan_status, func.count())
            .where(DockerManifest.kind == "image")
            .group_by(DockerManifest.scan_status)
        )
    ).all()
    kev_images = (
        await session.execute(select(func.count()).select_from(DockerManifest).where(DockerManifest.kev_count > 0))
    ).scalar_one()
    critical_images = (
        await session.execute(
            select(func.count())
            .select_from(DockerManifest)
            .where(DockerManifest.scan_status == "scanned", DockerManifest.max_cvss >= 9.0)
        )
    ).scalar_one()
    blocked = (
        await session.execute(
            select(func.count()).select_from(DockerManifest).where(DockerManifest.policy_block_reason.isnot(None))
        )
    ).scalar_one()
    quarantined = (
        await session.execute(
            select(func.count()).select_from(DockerRepository).where(DockerRepository.quarantined.is_(True))
        )
    ).scalar_one()
    return {
        "storage": {**use, "budget_bytes": policy.budget()},
        "pulls_24h": {"total": total, "cache_hits": hits},
        "scan_status": dict(severity),
        "queue": await scanning.queue_depth(session),
        "kev_images": kev_images,
        "critical_images": critical_images,
        "push_blocked_images": blocked,
        "quarantined_repositories": quarantined,
        "upstream_ratelimits": RATELIMITS,
        "scanner_last_seen": _scanner_last_seen,
    }


# -- upstream presets -------------------------------------------------------- #
@router.get("/presets")
async def list_presets(
    session: AsyncSession = Depends(get_session), identity: Identity = Depends(require_admin)
) -> dict:
    existing = set(
        (await session.execute(select(Upstream.name).where(Upstream.ecosystem == Ecosystem.docker))).scalars().all()
    )
    return {
        "presets": [
            {
                "name": p.name,
                "label": p.label,
                "url": p.url,
                "blob_hosts": list(p.blob_hosts),
                "note": p.note,
                "configured": p.name in existing,
            }
            for p in PRESETS.values()
        ]
    }


class PresetCreate(BaseModel):
    credential: str | None = Field(default=None, max_length=4096)
    tier: int = Field(default=1, ge=1, le=100)


@router.post("/presets/{name}", status_code=status.HTTP_201_CREATED)
async def add_preset(
    name: str,
    payload: PresetCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    preset = PRESETS.get(name)
    if preset is None:
        raise HTTPException(status_code=404, detail="unknown preset")
    exists = (await session.execute(select(Upstream.id).where(Upstream.name == name))).first()
    if exists:
        raise HTTPException(status_code=409, detail=f"upstream '{name}' already exists")
    upstream = Upstream(
        name=preset.name,
        ecosystem=Ecosystem.docker,
        kind=UpstreamKind.oci,
        url=preset.url,
        tier=payload.tier,
        auth_type="basic" if payload.credential else "none",
        credential_enc=encrypt_credential(payload.credential) if payload.credential else None,
        require_digest=True,
        extra={"blob_hosts": list(preset.blob_hosts), "preset": preset.name},
    )
    session.add(upstream)
    await session.flush()
    await audit.record_audit(
        session,
        audit.UPSTREAM_CREATED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="upstream",
        target_id=str(upstream.id),
        ip=client_ip(request),
        detail={"name": upstream.name, "ecosystem": "docker", "preset": True, "url": upstream.url},
    )
    await session.commit()
    from .admin.management import upstream_payload

    return upstream_payload(upstream)


@router.post("/upstreams/{upstream_id}/index")
async def index_gitlab(
    upstream_id: int,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    """List a GitLab container registry's repositories into search."""
    upstream = await session.get(Upstream, upstream_id)
    if upstream is None or upstream.kind != UpstreamKind.gitlab_oci:
        raise HTTPException(status_code=400, detail="only GitLab container registry upstreams can be indexed")
    try:
        names = await RegistryClient(upstream).list_gitlab_repositories()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"listing failed: {exc}") from exc
    added = 0
    for remote in names[:5000]:
        canonical = f"{upstream.name}/{remote}".lower()
        exists = (await session.execute(select(DockerRepository.id).where(DockerRepository.name == canonical))).first()
        if exists:
            continue
        session.add(
            DockerRepository(
                name=canonical, upstream_id=upstream.id, remote_name=remote.lower(), indexed_only=True
            )
        )
        added += 1
    upstream.last_indexed_at = datetime.now(UTC)
    await session.commit()
    return {"discovered": len(names), "added": added}


# --------------------------------------------------------------------------- #
# Scanner worker protocol
# --------------------------------------------------------------------------- #
_scanner_last_seen: dict[str, str] = {}


async def require_scanner(identity: Identity = Depends(require_user)) -> Identity:
    # Exactly the scanner scope: not "admin", which token_has_scope would
    # accept. An admin token has no business posting scan results, and the
    # scanner token has no business doing anything else.
    scopes = (identity.token.scopes or []) if identity.token is not None else []
    if "scanner" not in scopes:
        raise HTTPException(status_code=403, detail="scanner routes need a token with the 'scanner' scope")
    return identity


class ClaimRequest(BaseModel):
    worker: str = Field(min_length=1, max_length=128)
    trivy_version: str | None = Field(default=None, max_length=32)
    db_updated_at: str | None = Field(default=None, max_length=64)


@router.post("/scanner/claim", response_model=None)
async def scanner_claim(
    payload: ClaimRequest,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_scanner),
) -> Response | dict:
    _scanner_last_seen[payload.worker] = datetime.now(UTC).isoformat()
    if len(_scanner_last_seen) > 64:
        _scanner_last_seen.pop(next(iter(_scanner_last_seen)))
    policy = await load_policy(session)
    if not policy.scanning_enabled:
        return Response(status_code=204)
    job = await scanning.claim(session, payload.worker)
    if job is None:
        await session.commit()
        return Response(status_code=204)
    manifest = await session.get(DockerManifest, job.manifest_id)
    if manifest is None or manifest.kind != "image":
        await scanning.skip(session, job, "not a scannable image")
        await session.commit()
        return Response(status_code=204)
    if policy.max_scan_bytes and manifest.total_size > policy.max_scan_bytes:
        await scanning.skip(
            session, job, f"image is {manifest.total_size} bytes, over the {policy.max_scan_bytes} scan limit"
        )
        await session.commit()
        return Response(status_code=204)
    if job.mode == "sbom" and not manifest.sbom_digest:
        job.mode = "image"
    await session.commit()
    return {
        "job_id": job.id,
        "mode": job.mode,
        "digest": manifest.digest,
        "repository": job.repository,
        "image": f"{job.repository}@{manifest.digest}",
        "platform": manifest.platform,
        "total_size": manifest.total_size,
        "timeout_seconds": policy.scan_timeout_seconds,
        "severities": policy.severities,
        "ignore_unfixed": policy.ignore_unfixed,
        "lease_seconds": int(scanning.LEASE.total_seconds()),
    }


async def _running_job(session: AsyncSession, job_id: int, worker: str | None = None) -> DockerScanJob:
    job = await session.get(DockerScanJob, job_id)
    if job is None or job.status != "running":
        raise HTTPException(status_code=409, detail="job is not running (lease expired or already finished)")
    if worker and job.worker != worker:
        raise HTTPException(status_code=409, detail="job belongs to another worker")
    return job


@router.post("/scanner/jobs/{job_id}/heartbeat")
async def scanner_heartbeat(
    job_id: int,
    worker: str = Query(max_length=128),
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_scanner),
) -> dict:
    job = await _running_job(session, job_id, worker)
    await scanning.renew(session, job)
    await session.commit()
    return {"lease_until": job.lease_until}


@router.get("/scanner/jobs/{job_id}/sbom")
async def scanner_sbom(
    job_id: int,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_scanner),
) -> Response:
    job = await _running_job(session, job_id)
    m = await session.get(DockerManifest, job.manifest_id)
    if m is None or not m.sbom_digest:
        raise HTTPException(status_code=404, detail="no stored SBOM")
    body = await get_oci_store().read_bytes(m.sbom_digest)
    if body is None:
        raise HTTPException(status_code=404, detail="SBOM file missing")
    return Response(body, media_type="application/vnd.cyclonedx+json")


@router.post("/scanner/jobs/{job_id}/result")
async def scanner_result(
    job_id: int,
    worker: str = Form(max_length=128),
    duration_ms: int | None = Form(default=None),
    report: UploadFile = File(...),
    sbom: UploadFile | None = File(default=None),
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_scanner),
) -> dict:
    job = await _running_job(session, job_id, worker)
    started = time.perf_counter()
    report_raw = await _read_upload(report, scanning.MAX_REPORT_BYTES)
    sbom_raw = await _read_upload(sbom, scanning.MAX_SBOM_BYTES) if sbom is not None else None
    try:
        scan = await scanning.ingest(session, job, report_raw, sbom_raw, duration_ms)
    except scanning.ReportInvalid as exc:
        await session.rollback()
        job = await _running_job(session, job_id, worker)
        await scanning.fail(session, job, f"rejected report: {exc}")
        await session.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await session.commit()
    log.info(
        "scan %s of job %s ingested: %d findings in %.0fms",
        scan.id,
        job_id,
        scan.finding_count,
        (time.perf_counter() - started) * 1000,
    )
    return {"scan_id": scan.id, "findings": scan.finding_count}


async def _read_upload(upload: UploadFile, limit: int) -> bytes:
    data = await upload.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(status_code=413, detail=f"upload exceeds {limit} bytes")
    return data


class FailRequest(BaseModel):
    worker: str = Field(max_length=128)
    error: str = Field(max_length=4000)
    #: The worker decided this image cannot be scanned at all (e.g. no
    #: supported OS). Recorded, not retried.
    permanent: bool = False


@router.post("/scanner/jobs/{job_id}/fail")
async def scanner_fail(
    job_id: int,
    payload: FailRequest,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_scanner),
) -> dict:
    job = await _running_job(session, job_id, payload.worker)
    if payload.permanent:
        await scanning.skip(session, job, payload.error)
    else:
        await scanning.fail(session, job, payload.error)
    await session.commit()
    return {"status": job.status}


@router.get("/scanner/config")
async def scanner_config(
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_scanner),
) -> dict:
    """Where the worker fetches the Trivy database from.

    Through this registry's ghcr upstream when one exists, so N workers and
    every restart pull the 1.4 GB database from the local cache rather than
    from ghcr.io (which rate-limits it hard). Addressed on whichever of our
    origins the worker used, so a sidecar on the internal URL stays there.
    """
    from ..docker.auth import _public_base

    upstreams, _ = await reg.docker_upstreams(session)
    base = _public_base(request)
    host = base.split("://", 1)[-1]
    db_repo = settings.docker_trivy_db_repository
    if not db_repo and "ghcr" in upstreams:
        db_repo = f"{host}/ghcr/aquasecurity/trivy-db:2"
    java_repo = f"{host}/ghcr/aquasecurity/trivy-java-db:1" if "ghcr" in upstreams else None
    return {
        "registry": base,
        "db_repository": db_repo or None,
        "java_db_repository": java_repo,
        "insecure": base.startswith("http://"),
    }


def blob_host_allowed(upstream: Upstream, host: str) -> bool:
    extra = upstream.extra or {}
    return host_matches(host, extra.get("blob_hosts") or [])
