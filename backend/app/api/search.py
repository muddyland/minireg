"""Package search for logged-in users (both ecosystems), plus client config help."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..config import settings
from ..core.deps import Identity, require_user
from ..core.naming import normalize_name_for, order_version_rows
from ..db import get_session
from ..models import Ecosystem, Package, PackageVersion, PackageVulnerability, Vulnerability
from ..services import packages
from ..services.policy import PolicyEngine
from ..services.provenance import package_upstreams
from ..services.resolver import Resolver
from ..services.vulns import dedupe_by_cve

router = APIRouter(prefix="/api", tags=["search"])


@router.get("/search")
async def search(
    q: str = Query(default="", max_length=200),
    ecosystem: Ecosystem | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    include_upstream: bool = False,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_user),
) -> dict:
    """Search the local index; optionally fan out to upstreams too.

    Blocked packages are filtered out of results for non-admins so the index
    does not advertise something the registry will refuse to serve.
    """
    rows, total = await packages.search_local(
        session, ecosystem, q.strip(), limit=limit, offset=offset
    )
    policy = PolicyEngine(session)

    results = []
    for row in rows:
        verdict = await policy.evaluate(row.ecosystem, row.normalized_name)
        if verdict.blocked and not identity.is_admin:
            continue
        results.append(
            {
                "ecosystem": row.ecosystem.value,
                "name": row.name,
                "normalized_name": row.normalized_name,
                "description": row.description,
                "latest_version": row.latest_version,
                "author": row.author,
                "homepage": row.homepage,
                "license": row.license,
                "keywords": row.keywords,
                "download_count": row.download_count,
                "is_local": row.is_local,
                "source": "local",
                "blocked": verdict.blocked,
                "block_reason": verdict.reason if verdict.blocked else None,
            }
        )

    if include_upstream and q.strip() and ecosystem is not None:
        known = {r["normalized_name"] for r in results}
        for hit in await Resolver(session).search_upstreams(ecosystem, q.strip(), size=limit):
            normalized = normalize_name_for(ecosystem.value, hit.name)
            if normalized in known:
                continue
            if (await policy.evaluate(ecosystem, normalized)).blocked:
                continue
            results.append(
                {
                    "ecosystem": ecosystem.value,
                    "name": hit.name,
                    "normalized_name": normalized,
                    "description": hit.description,
                    "latest_version": hit.version,
                    "author": hit.author,
                    "homepage": hit.links.get("homepage"),
                    "license": None,
                    "keywords": hit.keywords,
                    "download_count": 0,
                    "is_local": False,
                    "source": "upstream",
                    "blocked": False,
                    "block_reason": None,
                }
            )

    return {"total": total, "results": results[:limit], "query": q}


@router.get("/packages/{ecosystem}/{name:path}")
async def package_detail(
    ecosystem: Ecosystem,
    name: str,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_user),
) -> dict:
    """Read-only package view for the user-facing search UI."""
    normalized = normalize_name_for(ecosystem.value, name)
    verdict = await PolicyEngine(session).is_name_blocked(ecosystem, normalized)

    package = (
        await session.execute(
            select(Package)
            .where(Package.ecosystem == ecosystem, Package.normalized_name == normalized)
            .options(
                selectinload(Package.versions).selectinload(PackageVersion.files),
                selectinload(Package.dist_tags),
            )
        )
    ).scalar_one_or_none()

    if package is None:
        lookup = await packages.fetch_package(session, ecosystem, name)
        package = lookup.package
    if package is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="package not found")

    cve_rows = (
        await session.execute(
            select(PackageVulnerability.version_id, Vulnerability)
            .join(Vulnerability, Vulnerability.id == PackageVulnerability.vulnerability_id)
            .where(PackageVulnerability.version_id.in_([v.id for v in package.versions] or [0]))
        )
    ).all()
    cves: dict[int, list] = {}
    for version_id, vuln in cve_rows:
        cves.setdefault(version_id, []).append(
            {
                "cve_id": vuln.cve_id,
                "osv_id": vuln.id,
                "cvss_score": vuln.cvss_score,
                "severity": vuln.severity_label,
                "summary": vuln.summary,
            }
        )
    # OSV often carries several records for one CVE (a GHSA and a PYSEC entry,
    # say); listing both makes a package look twice as vulnerable as it is.
    cves = {version_id: dedupe_by_cve(items) for version_id, items in cves.items()}

    return {
        "ecosystem": ecosystem.value,
        "upstreams": await package_upstreams(session, package),
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
        "blocked": verdict.blocked,
        "block_reason": verdict.reason if verdict.blocked else None,
        "dist_tags": {t.tag: t.version for t in package.dist_tags},
        "install_command": (
            f"npm install {package.name}"
            if ecosystem == Ecosystem.npm
            else f"pip install {package.name}"
        ),
        "versions": [
            {
                "version": v.version,
                "yanked": v.yanked,
                "deprecated": v.deprecated,
                "published_at": v.published_at,
                "requires_python": v.requires_python,
                "max_cvss": v.max_cvss,
                "cves": cves.get(v.id, []),
                "files": [
                    {"filename": f.filename, "size": f.size, "cached": bool(f.blob_sha256)}
                    for f in v.files
                ],
            }
            for v in order_version_rows(ecosystem.value, package.versions, reverse=True)
        ],
    }


@router.get("/client-config")
async def client_config(identity: Identity = Depends(require_user)) -> dict:
    """Copy-pasteable client configuration.

    Getting these strings exactly right is the difference between a working
    registry and an afternoon of support questions, so we generate them from
    the configured public URL rather than documenting them statically.
    """
    base = settings.public_url
    host = base.split("://", 1)[-1]

    return {
        "public_url": base,
        "npm": {
            "registry": f"{base}/npm/",
            "npmrc": "\n".join(
                [
                    f"registry={base}/npm/",
                    f"//{host}/npm/:_authToken=${{MINIREG_TOKEN}}",
                ]
            ),
            "commands": [
                f"npm config set registry {base}/npm/",
                f'npm config set //{host}/npm/:_authToken "<your-token>"',
            ],
            "scoped_example": f"npm config set @myscope:registry {base}/npm/",
        },
        "pip": {
            "index_url": f"{base}/pypi/simple/",
            "pip_conf": "\n".join(
                [
                    "[global]",
                    f"index-url = {base}/pypi/simple/",
                    f"trusted-host = {host.split(':')[0]}",
                ]
            ),
            "commands": [
                f"pip config set global.index-url {base}/pypi/simple/",
                f"pip install --index-url {base}/pypi/simple/ <package>",
            ],
            "authenticated_index_url": f"https://__token__:<your-token>@{host}/pypi/simple/",
        },
        "twine": {
            "repository_url": f"{base}/pypi/legacy/",
            "pypirc": "\n".join(
                [
                    "[distutils]",
                    "index-servers =",
                    "    minireg",
                    "",
                    "[minireg]",
                    f"repository = {base}/pypi/legacy/",
                    "username = __token__",
                    "password = <your-token>",
                ]
            ),
            "commands": [
                f"twine upload --repository-url {base}/pypi/legacy/ "
                "-u __token__ -p <your-token> dist/*",
            ],
        },
        "uv": {
            "index_url": f"{base}/pypi/simple/",
            "commands": [f"uv pip install --index-url {base}/pypi/simple/ <package>"],
        },
        "poetry": {
            "commands": [
                f"poetry source add --priority=primary minireg {base}/pypi/simple/",
                "poetry config http-basic.minireg __token__ <your-token>",
            ]
        },
    }
