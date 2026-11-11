"""Admin: "where's my risk" -- every known vulnerability, packages and images
together, ordered by what is exposed right now.

Package advisories (OSV, per version) and image findings (Trivy, per
platform manifest) are kept apart everywhere else. Here they are grouped by
vulnerability id -- the CVE where there is one -- so one row answers: how bad
is it, is it known to be exploited, is there a fix, and which of *my*
packages and images carry it, and were any of them served lately.

"Served lately" is the exposure signal. For a package version it is the last
time one of its cached artifacts was downloaded (``Blob.last_accessed_at``,
updated on every download); for an image, the last pull of an affected
manifest (``DockerRepoManifest.last_pulled_at``). Both are columns already
indexed for eviction, so the page costs two grouped queries, not a scan of
the request log.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.deps import require_admin
from ...db import get_session
from ...models import (
    Blob,
    DockerFinding,
    DockerManifest,
    DockerManifestRef,
    DockerRepoManifest,
    DockerRepository,
    DockerTag,
    KevEntry,
    Package,
    PackageFile,
    PackageVersion,
    PackageVulnerability,
    Vulnerability,
)
from ...services.osv import severity_label
from ...services.packages import _escape_like
from ...services.policy import PolicyEngine

router = APIRouter(dependencies=[Depends(require_admin)])

SEVERITIES = ("none", "low", "medium", "high", "critical")
_TRIVY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _rank(label: str | None) -> int:
    return SEVERITIES.index(label) if label in SEVERITIES else 0


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def _package_groups(session: AsyncSession, search: str | None) -> dict[str, dict]:
    malicious = case(
        (or_(Vulnerability.id.like("MAL-%"), Vulnerability.severity_type == "MALICIOUS"), 1),
        else_=0,
    )
    conditions = [PackageVulnerability.suppressed.is_(False)]
    if search:
        conditions.append(Vulnerability.cve_id.ilike(f"%{_escape_like(search)}%", escape="\\"))
    rows = (
        await session.execute(
            select(
                Vulnerability.cve_id,
                func.max(Vulnerability.cvss_score),
                func.max(malicious),
                func.min(Vulnerability.summary),
                func.min(Vulnerability.id),
                func.count(func.distinct(PackageVulnerability.version_id)),
                func.count(func.distinct(PackageVersion.package_id)),
                func.max(case((PackageVulnerability.fixed_version.is_not(None), 1), else_=0)),
                func.max(Blob.last_accessed_at),
            )
            .join(PackageVulnerability, PackageVulnerability.vulnerability_id == Vulnerability.id)
            .join(PackageVersion, PackageVersion.id == PackageVulnerability.version_id)
            .outerjoin(PackageFile, PackageFile.version_id == PackageVersion.id)
            .outerjoin(Blob, Blob.sha256 == PackageFile.blob_sha256)
            .where(and_(*conditions))
            .group_by(Vulnerability.cve_id)
        )
    ).all()
    return {
        key: {
            "cvss": score,
            "malicious": bool(mal),
            "title": summary,
            "osv_id": osv_id,
            "versions": versions,
            "packages": packages,
            "fix": bool(fix),
            "last_served": _aware(last),
        }
        for key, score, mal, summary, osv_id, versions, packages, fix, last in rows
    }


async def _image_groups(session: AsyncSession, search: str | None) -> dict[str, dict]:
    rank = case(*((DockerFinding.severity == k, v) for k, v in _TRIVY_RANK.items()), else_=0)
    conditions = []
    if search:
        conditions.append(DockerFinding.vuln_id.ilike(f"%{_escape_like(search)}%", escape="\\"))
    rows = (
        await session.execute(
            select(
                DockerFinding.vuln_id,
                func.max(DockerFinding.cvss),
                func.max(rank),
                func.max(case((DockerFinding.kev.is_(True), 1), else_=0)),
                func.min(DockerFinding.title),
                func.count(func.distinct(DockerFinding.manifest_id)),
                func.count(func.distinct(DockerRepoManifest.repository_id)),
                func.max(case((DockerFinding.fixed_version.is_not(None), 1), else_=0)),
                func.max(DockerRepoManifest.last_pulled_at),
            )
            .outerjoin(DockerRepoManifest, DockerRepoManifest.manifest_id == DockerFinding.manifest_id)
            .where(and_(*conditions) if conditions else True)
            .group_by(DockerFinding.vuln_id)
        )
    ).all()
    labels = {v: k.lower() for k, v in _TRIVY_RANK.items()}
    return {
        key: {
            "cvss": cvss,
            "severity": labels.get(int(sev or 0), "unknown"),
            "kev": bool(kev),
            "title": title,
            "manifests": manifests,
            "repositories": repos,
            "fix": bool(fix),
            "last_pulled": _aware(last),
        }
        for key, cvss, sev, kev, title, manifests, repos, fix, last in rows
    }


@router.get("/risk")
async def risk_overview(
    source: str = Query(default="all", pattern="^(all|packages|images)$"),
    min_severity: str = Query(default="none", pattern="^(none|low|medium|high|critical)$"),
    in_use_days: int = Query(default=30, ge=1, le=365),
    only_in_use: bool = False,
    search: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=200, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
) -> dict:
    search = search.strip() if search else None
    since = datetime.now(UTC) - timedelta(days=in_use_days)
    packages = await _package_groups(session, search) if source != "images" else {}
    images = await _image_groups(session, search) if source != "packages" else {}
    kev_ids = set(
        (await session.execute(select(KevEntry.cve_id))).scalars().all()
    )

    items = []
    for key in set(packages) | set(images):
        p = packages.get(key)
        i = images.get(key)
        cvss = max((x["cvss"] for x in (p, i) if x and x["cvss"] is not None), default=None)
        # Packages are rated by CVSS. Image findings carry the rating of the
        # distribution that built the package (what image policy enforces),
        # which can be far below the NVD score for its own build -- so an
        # image-only CVE takes that rating, not the CVSS.
        labels = []
        if p:
            labels.append("critical" if p["malicious"] else (severity_label(p["cvss"]) if p["cvss"] is not None else None))
        if i:
            labels.append(i["severity"])
        label = max((x for x in labels if x), key=_rank, default=None)
        kev = key in kev_ids or bool(i and i["kev"])
        served = bool(p and p["last_served"] and p["last_served"] >= since)
        pulled = bool(i and i["last_pulled"] and i["last_pulled"] >= since)
        in_use = served or pulled
        if _rank(label) < _rank(min_severity):
            continue
        if only_in_use and not in_use:
            continue
        last_used = max(
            (t for t in (p and p["last_served"], i and i["last_pulled"]) if t), default=None
        )
        items.append(
            {
                "id": key,
                "title": (p and p["title"]) or (i and i["title"]),
                "cvss": cvss,
                "severity": label,
                "kev": kev,
                "malicious": bool(p and p["malicious"]),
                "fix_available": bool((p and p["fix"]) or (i and i["fix"])),
                "in_use": in_use,
                "last_used": last_used,
                "packages": None
                if p is None
                else {"packages": p["packages"], "versions": p["versions"], "served_recently": served},
                "images": None
                if i is None
                else {
                    "repositories": i["repositories"],
                    "manifests": i["manifests"],
                    "pulled_recently": pulled,
                },
            }
        )

    # Exposed first, then known-exploited and malware, then severity.
    items.sort(
        key=lambda r: (
            r["in_use"],
            r["kev"] or r["malicious"],
            r["cvss"] if r["cvss"] is not None else -1,
            r["last_used"] or datetime.min.replace(tzinfo=UTC),
        ),
        reverse=True,
    )
    summary = {
        "total": len(items),
        "in_use": sum(1 for r in items if r["in_use"]),
        "kev_in_use": sum(1 for r in items if r["kev"] and r["in_use"]),
        "critical_in_use": sum(1 for r in items if r["severity"] == "critical" and r["in_use"]),
        "malware": sum(1 for r in items if r["malicious"]),
        "no_fix": sum(1 for r in items if not r["fix_available"]),
    }
    return {"summary": summary, "in_use_days": in_use_days, "items": items[:limit]}


@router.get("/risk/detail")
async def risk_detail(
    id: str = Query(min_length=1, max_length=64),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Every package version and image carrying one vulnerability."""
    engine = PolicyEngine(session)
    version_rows = (
        await session.execute(
            select(Package, PackageVersion, PackageVulnerability, Vulnerability)
            .join(PackageVersion, PackageVersion.package_id == Package.id)
            .join(PackageVulnerability, PackageVulnerability.version_id == PackageVersion.id)
            .join(Vulnerability, Vulnerability.id == PackageVulnerability.vulnerability_id)
            .where(Vulnerability.cve_id == id)
            .order_by(Package.normalized_name, PackageVersion.version)
            .limit(500)
        )
    ).all()
    served = {}
    if version_rows:
        served = dict(
            (
                await session.execute(
                    select(PackageFile.version_id, func.max(Blob.last_accessed_at))
                    .join(Blob, Blob.sha256 == PackageFile.blob_sha256)
                    .where(PackageFile.version_id.in_([v.id for _, v, _, _ in version_rows]))
                    .group_by(PackageFile.version_id)
                )
            ).all()
        )
    packages = []
    seen = set()
    for package, version, link, vuln in version_rows:
        if (version.id) in seen:
            continue
        seen.add(version.id)
        verdict = await engine.evaluate_version(package.ecosystem, package.normalized_name, version)
        packages.append(
            {
                "ecosystem": package.ecosystem.value,
                "name": package.name,
                "version": version.version,
                "fixed_version": link.fixed_version,
                "suppressed": link.suppressed,
                "advisory": vuln.id,
                "blocked": verdict.blocked,
                "block_reason": verdict.reason,
                "last_served": _aware(served.get(version.id)),
                "downloads": int(package.download_count or 0),
            }
        )

    findings = (
        await session.execute(
            select(DockerFinding, DockerManifest)
            .join(DockerManifest, DockerManifest.id == DockerFinding.manifest_id)
            .where(DockerFinding.vuln_id == id)
            .limit(500)
        )
    ).all()
    images = []
    if findings:
        manifest_ids = {m.id for _, m in findings}
        digests = {m.digest for _, m in findings}
        links = (
            await session.execute(
                select(DockerRepoManifest, DockerRepository)
                .join(DockerRepository, DockerRepository.id == DockerRepoManifest.repository_id)
                .where(DockerRepoManifest.manifest_id.in_(manifest_ids))
            )
        ).all()
        # Tags point at the platform manifest itself or at an index that
        # lists it.
        parents = (
            await session.execute(
                select(DockerManifestRef.manifest_id, DockerManifestRef.digest).where(
                    DockerManifestRef.digest.in_(digests)
                )
            )
        ).all()
        parent_of: dict[str, set[int]] = {}
        for parent_id, digest in parents:
            parent_of.setdefault(digest, set()).add(parent_id)
        tag_rows = (
            await session.execute(
                select(DockerTag.repository_id, DockerTag.manifest_id, DockerTag.tag).where(
                    DockerTag.manifest_id.in_(
                        manifest_ids | {p for ids in parent_of.values() for p in ids}
                    )
                )
            )
        ).all()
        tags: dict[tuple[int, int], list[str]] = {}
        for repo_id, manifest_id, tag in tag_rows:
            tags.setdefault((repo_id, manifest_id), []).append(tag)
        by_manifest: dict[int, list] = {}
        for link, repo in links:
            by_manifest.setdefault(link.manifest_id, []).append((link, repo))
        for finding, manifest in findings:
            for link, repo in by_manifest.get(manifest.id, []):
                repo_tags = list(tags.get((repo.id, manifest.id), []))
                for parent_id in parent_of.get(manifest.digest, ()):
                    repo_tags += tags.get((repo.id, parent_id), [])
                images.append(
                    {
                        "repository": repo.name,
                        "tags": sorted(set(repo_tags)),
                        "digest": manifest.digest,
                        "platform": manifest.platform,
                        "package": finding.pkg_name,
                        "installed_version": finding.installed_version,
                        "fixed_version": finding.fixed_version,
                        "severity": finding.severity.lower(),
                        "kev": finding.kev,
                        "quarantined": repo.quarantined,
                        "last_pulled": _aware(link.last_pulled_at),
                    }
                )
    if not packages and not images:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    images.sort(key=lambda r: r["last_pulled"] or datetime.min.replace(tzinfo=UTC), reverse=True)
    packages.sort(key=lambda r: r["last_served"] or datetime.min.replace(tzinfo=UTC), reverse=True)
    return {"id": id, "packages": packages, "images": images}
