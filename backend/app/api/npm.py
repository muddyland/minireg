"""npm registry endpoints.

Mounted at ``/npm``, so clients configure:

    npm config set registry http://minireg.example.com/npm/

Routes implemented (npm registry API):

    GET    /-/ping
    GET    /-/whoami
    PUT    /-/user/org.couchdb.user:{user}      npm login / adduser
    POST   /-/v1/login                          web login handshake
    GET    /-/v1/search                         search
    GET    /-/package/{pkg}/dist-tags           read tags
    PUT    /-/package/{pkg}/dist-tags/{tag}     set tag
    DELETE /-/package/{pkg}/dist-tags/{tag}     remove tag
    POST   /-/npm/v1/security/advisories/bulk   npm audit
    POST   /-/npm/v1/security/audits/quick      npm audit (legacy)
    GET    /{pkg}                               packument (full/abbreviated)
    GET    /{pkg}/{version}                     version document
    GET    /{pkg}/-/{filename}                  tarball
    PUT    /{pkg}                               publish / deprecate
    PUT    /{pkg}/-rev/{rev}                    unpublish versions (packument edit)
    DELETE /{pkg}/-rev/{rev}                    unpublish package
    DELETE /{pkg}/-/{filename}/-rev/{rev}       unpublish version
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from datetime import UTC, datetime
from typing import Any

import orjson
from fastapi import APIRouter, Depends, Header, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer, selectinload

from ..config import settings
from ..core.cache import cache_get_bytes, cache_get_json, cache_set_bytes, cache_set_json
from ..core.deps import (
    Identity,
    client_ip,
    rate_limited_publish,
    rate_limited_read,
    resolve_identity,
)
from ..core.naming import max_semver, npm_path_to_name, npm_tarball_filename, semver_key
from ..db import get_session
from ..models import DistTag, Ecosystem, Package, PackageFile, PackageVersion
from ..services import artifacts, audit, npm_publish, npm_render, ownership, packages
from ..services.osv import inline_scan
from ..services.policy import PolicyEngine
from ..services.storage import get_store

log = logging.getLogger(__name__)
router = APIRouter(tags=["npm"])

ECOSYSTEM = Ecosystem.npm

#: Largest rendered packument kept in Valkey. The cache runs with a fixed
#: memory cap and allkeys-lru, so one multi-megabyte document evicts hundreds
#: of herd-guard locks and rate-limit counters. Bigger documents are rendered
#: from the database on each request instead.
PACKUMENT_CACHE_MAX_BYTES = 1024 * 1024


def json_response(payload: Any, status_code: int = 200, headers: dict | None = None) -> Response:
    """orjson is ~5x faster than the stdlib encoder, and packuments are big."""
    return Response(
        content=orjson.dumps(payload),
        status_code=status_code,
        media_type="application/json",
        headers=headers,
    )


def npm_error(message: str, status_code: int) -> JSONResponse:
    """npm surfaces the ``error`` field to the user verbatim.

    Every 404 carries registry.npmjs.org's exact body, ``{"error": "Not
    found"}``, whatever went missing; tools match on it. The specific reason
    rides along in ``detail``.
    """
    if status_code == status.HTTP_404_NOT_FOUND:
        body: dict[str, str] = {"error": "Not found"}
        if message and message != "Not found":
            body["detail"] = message
        return JSONResponse(body, status_code=status_code)
    return JSONResponse({"error": message}, status_code=status_code)


def strong_etag(body: bytes) -> str:
    return '"' + hashlib.sha256(body).hexdigest() + '"'


def etag_matches(if_none_match: str | None, etag: str) -> bool:
    """RFC 9110 If-None-Match: weak comparison, ``*`` matches anything."""
    if not if_none_match:
        return False
    wanted = etag.removeprefix("W/")
    for candidate in if_none_match.split(","):
        candidate = candidate.strip()
        if candidate == "*" or candidate.removeprefix("W/") == wanted:
            return True
    return False


def document_response(
    request: Request, body: bytes, *, content_type: str, vary_accept: bool = False
) -> Response:
    """Serve already-serialised JSON with a strong ETag, or a 304."""
    etag = strong_etag(body)
    headers = {"etag": etag}
    if vary_accept:
        # The abbreviated and full packument share a URL.
        headers["vary"] = "Accept"
    if etag_matches(request.headers.get("if-none-match"), etag):
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)
    return Response(content=body, media_type=content_type, headers=headers)


# --------------------------------------------------------------------------- #
# Lean package lookups
#
# `packages.get_package_row` / `fetch_package` select the Package entity, and
# with it `cached_document` -- the whole upstream packument, 37 MB for vite.
# The routes below need a handful of columns, so they never touch it unless a
# refresh from upstream is genuinely due (which has to parse the document
# anyway).
# --------------------------------------------------------------------------- #
async def _refresh_if_stale(
    session: AsyncSession, name: str, normalized: str
) -> packages.PackageLookup | None:
    """Run the upstream refresh only when the local row is missing or stale.

    Returns the lookup when one was made (callers read ``from_upstream``),
    ``None`` when the local copy was fresh and nothing heavy was loaded.
    """
    row = (
        await session.execute(
            select(Package.is_local, Package.cached_at).where(
                Package.ecosystem == ECOSYSTEM, Package.normalized_name == normalized
            )
        )
    ).first()
    if row is not None and not packages.is_stale(row):
        return None
    return await packages.fetch_package(session, ECOSYSTEM, name)


async def _lean_package(
    session: AsyncSession,
    normalized: str,
    *,
    with_versions: bool = False,
    with_files: bool = False,
) -> Package | None:
    """The Package row without ``cached_document``; versions without
    ``metadata_json``. Nothing loaded here may touch either attribute."""
    options: list = [defer(Package.cached_document), selectinload(Package.dist_tags)]
    if with_versions:
        version_opts: list = [defer(PackageVersion.metadata_json)]
        if with_files:
            version_opts.append(selectinload(PackageVersion.files))
        options.append(selectinload(Package.versions).options(*version_opts))
    stmt = (
        select(Package)
        .options(*options)
        .where(Package.ecosystem == ECOSYSTEM, Package.normalized_name == normalized)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def _version_columns(session: AsyncSession, package_id: int) -> list:
    """What the policy engine reads per version, and nothing else."""
    return list(
        (
            await session.execute(
                select(
                    PackageVersion.version,
                    PackageVersion.max_cvss,
                    PackageVersion.has_fix,
                    PackageVersion.scanned_at,
                ).where(PackageVersion.package_id == package_id)
            )
        ).all()
    )


# --------------------------------------------------------------------------- #
# Service endpoints
# --------------------------------------------------------------------------- #
@router.get("/-/ping")
async def ping() -> Response:
    return json_response({})


@router.get("/-/whoami")
async def whoami(identity: Identity = Depends(resolve_identity)) -> Response:
    if not identity.is_authenticated:
        return npm_error("unauthenticated", status.HTTP_401_UNAUTHORIZED)
    return json_response({"username": identity.username})


@router.put("/-/user/org.couchdb.user:{username}")
async def npm_login(
    username: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> Response:
    """``npm login --auth-type=legacy``.

    We deliberately do NOT mint a token from a password here: publishing
    requires an API token created in the UI. This endpoint exists so the CLI
    gets a coherent error instead of a confusing 404.
    """
    await audit.record_audit(
        session,
        audit.LOGIN_FAILED,
        actor_username=username,
        actor_type="anonymous",
        success=False,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={"reason": "legacy npm login is disabled", "ecosystem": "npm"},
    )
    await session.commit()
    return npm_error(
        "This registry does not accept password logins. Create an API token in "
        f"the web UI at {settings.public_url} and run: "
        f"npm config set //{settings.public_url.split('://')[-1]}/npm/:_authToken <token>",
        status.HTTP_401_UNAUTHORIZED,
    )


@router.post("/-/v1/login")
async def npm_web_login() -> Response:
    """``npm login`` (web flow) probes this; a 404 makes the CLI fall back to
    the legacy flow, which is what we want."""
    return npm_error("web login is not supported", status.HTTP_404_NOT_FOUND)


# --------------------------------------------------------------------------- #
# Search
# --------------------------------------------------------------------------- #
@router.get("/-/v1/search")
async def search(
    request: Request,
    text: str = "",
    size: int = 20,
    from_: int = 0,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_read),
) -> Response:
    # npm sends the offset as `from`, which is a Python keyword.
    offset = int(request.query_params.get("from", from_) or 0)
    size = max(1, min(int(size), 250))
    query = (text or "").strip()

    cache_id = f"search:npm:{query}:{size}:{offset}"
    cached = await cache_get_json(cache_id)
    if cached is not None:
        return json_response(cached)

    rows, total = await packages.search_local(session, ECOSYSTEM, query, limit=size, offset=offset)
    policy = PolicyEngine(session)

    objects = []
    for row in rows:
        verdict = await policy.evaluate(ECOSYSTEM, row.normalized_name)
        if verdict.blocked:
            continue
        objects.append(
            npm_render.build_search_object(
                name=row.name,
                version=row.latest_version,
                description=row.description,
                keywords=row.keywords or [],
                author=row.author,
                date=row.updated_at,
                score=1.0 if row.normalized_name == query.lower() else 0.5,
            )
        )

    payload = npm_render.render_search_response(objects, total)
    await cache_set_json(cache_id, payload, settings.search_cache_ttl)
    return json_response(payload)


# --------------------------------------------------------------------------- #
# dist-tags
# --------------------------------------------------------------------------- #
@router.get("/-/package/{package_name:path}/dist-tags")
async def get_dist_tags(
    package_name: str,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_read),
) -> Response:
    name = npm_path_to_name(package_name)
    normalized = packages.normalized_for(ECOSYSTEM, name)
    await _refresh_if_stale(session, name, normalized)
    package = await _lean_package(session, normalized)
    if package is None:
        return npm_error("package not found", status.HTTP_404_NOT_FOUND)

    policy = PolicyEngine(session)
    verdict = await policy.evaluate(ECOSYSTEM, package.normalized_name)
    if verdict.blocked:
        return npm_error(verdict.reason or "package is blocked", status.HTTP_403_FORBIDDEN)

    # A tag pointing at a blocked version is a download the client is about to
    # be refused, so filter the same set the packument filters. `latest` is
    # re-pointed at the newest version that survives rather than dropped, which
    # is what lets `npm install pkg` degrade to an installable release.
    version_rows = await _version_columns(session, package.id)
    blocked = await _blocked_from_rows(policy, package.normalized_name, version_rows)
    tags = {t.tag: t.version for t in package.dist_tags if t.version not in blocked}
    if "latest" not in tags:
        survivors = [v.version for v in version_rows if v.version not in blocked]
        fallback = max_semver(survivors) if survivors else None
        if fallback:
            tags["latest"] = fallback
    return json_response(tags)


@router.put("/-/package/{package_name:path}/dist-tags/{tag}")
async def set_dist_tag(
    package_name: str,
    tag: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_publish),
) -> Response:
    name = npm_path_to_name(package_name)
    body = (await request.body()).decode("utf-8", "replace").strip()
    # The body is a bare JSON string: `"1.0.0"`.
    version = body.strip('"').strip()
    if not version:
        return npm_error("a version is required", status.HTTP_400_BAD_REQUEST)

    from ..core.naming import is_valid_semver

    if is_valid_semver(tag):
        return npm_error(
            "dist-tag must not be a valid semver version", status.HTTP_400_BAD_REQUEST
        )

    package = await _lean_package(session, name.lower())
    if package is None:
        return npm_error("package not found", status.HTTP_404_NOT_FOUND)

    try:
        await ownership.authorize_mutation(
            package,
            user_id=identity.user_id,
            is_admin=identity.is_admin and identity.has_scope("admin"),
            action="retag",
        )
    except ownership.PublishDenied as denied:
        return npm_error(denied.reason, denied.status_code)

    exists = (
        await session.execute(
            select(PackageVersion.id).where(
                PackageVersion.package_id == package.id, PackageVersion.version == version
            )
        )
    ).scalar_one_or_none()
    if exists is None:
        return npm_error(f"version {version} is not published", status.HTTP_404_NOT_FOUND)

    row = next((t for t in package.dist_tags if t.tag == tag), None)
    if row is None:
        session.add(DistTag(package_id=package.id, tag=tag, version=version))
    else:
        row.version = version
    if tag == "latest":
        package.latest_version = version

    await audit.record_audit(
        session,
        audit.DIST_TAG_UPDATED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="package",
        target_id=f"npm:{name}",
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={"tag": tag, "version": version},
    )
    await session.commit()
    await packages.invalidate_package_cache("npm", package.normalized_name)
    return json_response({"ok": True})


@router.delete("/-/package/{package_name:path}/dist-tags/{tag}")
async def delete_dist_tag(
    package_name: str,
    tag: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_publish),
) -> Response:
    if tag == "latest":
        return npm_error("the 'latest' tag cannot be removed", status.HTTP_400_BAD_REQUEST)

    name = npm_path_to_name(package_name)
    package = await _lean_package(session, name.lower())
    if package is None:
        return npm_error("package not found", status.HTTP_404_NOT_FOUND)

    try:
        await ownership.authorize_mutation(
            package,
            user_id=identity.user_id,
            is_admin=identity.is_admin and identity.has_scope("admin"),
            action="retag",
        )
    except ownership.PublishDenied as denied:
        return npm_error(denied.reason, denied.status_code)

    row = next((t for t in package.dist_tags if t.tag == tag), None)
    if row is None:
        return npm_error("tag not found", status.HTTP_404_NOT_FOUND)
    await session.delete(row)

    await audit.record_audit(
        session,
        audit.DIST_TAG_UPDATED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="package",
        target_id=f"npm:{name}",
        ip=client_ip(request),
        detail={"tag": tag, "removed": True},
    )
    await session.commit()
    await packages.invalidate_package_cache("npm", package.normalized_name)
    return json_response({"ok": True})


# --------------------------------------------------------------------------- #
# npm audit
# --------------------------------------------------------------------------- #
#: Names accepted in one `npm audit` call. The endpoint costs a query per
#: name, so an unbounded body is a cheap way to make the database do work.
MAX_AUDIT_BULK_NAMES = 4000


@router.post("/-/npm/v1/security/advisories/bulk")
async def audit_bulk(
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_read),
) -> Response:
    """``npm audit`` bulk endpoint.

    Answers from our own CVE store, so audit results match the CVE policy this
    registry actually enforces.

    Carries the same read dependency as every other read route: it reports
    which packages and versions are cached and what is known about them, which
    is not something to hand out anonymously when reads require a token.
    """
    try:
        body = await request.json()
    except ValueError:
        return json_response({})
    if isinstance(body, dict) and len(body) > MAX_AUDIT_BULK_NAMES:
        return npm_error(
            f"too many packages in one request (limit {MAX_AUDIT_BULK_NAMES})",
            status.HTTP_413_CONTENT_TOO_LARGE,
        )
    if not isinstance(body, dict):
        return json_response({})

    from ..models import PackageVulnerability, Vulnerability

    # name as sent -> the versions installed
    requested: dict[str, set[str]] = {}
    for name, versions in body.items():
        if not isinstance(name, str) or not isinstance(versions, list):
            continue
        requested[name] = {v for v in versions if isinstance(v, str)}
    if not requested:
        return json_response({})

    by_normalized: dict[str, list[str]] = {}
    for name in requested:
        by_normalized.setdefault(packages.normalized_for(ECOSYSTEM, name), []).append(name)

    # Columns only, a bounded number of queries for any body size. This used
    # to load the Package entity -- and with it the whole upstream packument
    # -- once per name, for up to 4000 names: an `npm audit` of a large
    # lockfile was enough to OOM the container.
    package_ids: dict[int, str] = {}
    for chunk in _chunks(list(by_normalized), AUDIT_QUERY_CHUNK):
        for package_id, normalized in (
            await session.execute(
                select(Package.id, Package.normalized_name).where(
                    Package.ecosystem == ECOSYSTEM, Package.normalized_name.in_(chunk)
                )
            )
        ).all():
            package_ids[package_id] = normalized
    if not package_ids:
        return json_response({})

    # Every known affected version per (package, vulnerability), not just the
    # installed ones: the advisory's `vulnerable_versions` has to describe the
    # vulnerability, because arborist memoises advisories by id and tests each
    # installed version against that one range.
    affected: dict[tuple[int, str], set[str]] = {}
    fixes: dict[tuple[int, str], set[str]] = {}
    for chunk in _chunks(list(package_ids), AUDIT_QUERY_CHUNK):
        rows = (
            await session.execute(
                select(
                    PackageVersion.package_id,
                    PackageVersion.version,
                    PackageVulnerability.vulnerability_id,
                    PackageVulnerability.fixed_version,
                )
                .join(PackageVersion, PackageVersion.id == PackageVulnerability.version_id)
                .where(
                    PackageVersion.package_id.in_(chunk),
                    PackageVulnerability.suppressed.is_(False),
                )
            )
        ).all()
        for package_id, version, vuln_id, fixed in rows:
            affected.setdefault((package_id, vuln_id), set()).add(version)
            if fixed:
                fixes.setdefault((package_id, vuln_id), set()).add(fixed)

    # Keep only vulnerabilities that hit at least one installed version.
    hits: dict[str, list[tuple[str, set[str]]]] = {}  # request name -> [(vuln, versions)]
    for (package_id, vuln_id), versions in affected.items():
        for name in by_normalized[package_ids[package_id]]:
            if versions & requested[name]:
                hits.setdefault(name, []).append((vuln_id, versions))
    if not hits:
        return json_response({})

    vuln_ids = sorted({vuln_id for entries in hits.values() for vuln_id, _ in entries})
    details: dict[str, Any] = {}
    for chunk in _chunks(vuln_ids, AUDIT_QUERY_CHUNK):
        for row in (
            await session.execute(
                select(
                    Vulnerability.id,
                    Vulnerability.cve_id,
                    Vulnerability.summary,
                    Vulnerability.severity_label,
                    Vulnerability.cvss_score,
                    Vulnerability.cvss_vector,
                ).where(Vulnerability.id.in_(chunk))
            )
        ).all():
            details[row.id] = row

    normalized_to_id = {normalized: pid for pid, normalized in package_ids.items()}
    out: dict[str, list[dict]] = {}
    for name, entries in hits.items():
        package_id = normalized_to_id[packages.normalized_for(ECOSYSTEM, name)]
        advisories = []
        for vuln_id, versions in sorted(entries, key=lambda e: e[0]):
            vuln = details.get(vuln_id)
            if vuln is None:
                continue
            fixed = fixes.get((package_id, vuln_id))
            fix_version = max_semver(sorted(fixed)) if fixed else None
            advisories.append(
                {
                    "id": vuln.id,
                    "url": f"https://osv.dev/vulnerability/{vuln.id}",
                    "title": vuln.summary or vuln.cve_id,
                    "severity": npm_severity(vuln.severity_label, vuln.cvss_score),
                    "vulnerable_versions": " || ".join(sorted(versions, key=semver_key)),
                    "cwe": [],
                    "cvss": {"score": vuln.cvss_score or 0.0, "vectorString": vuln.cvss_vector},
                    **({"fixAvailable": {"version": fix_version}} if fix_version else {}),
                }
            )
        if advisories:
            out[name] = advisories
    return json_response(out)


#: Bound on the IN-list of each audit query; SQLite caps bound parameters.
AUDIT_QUERY_CHUNK = 500

#: Our labels are the CVSS qualitative scale (osv.SEVERITY_BANDS); npm's are
#: info|low|moderate|high|critical, and it rejects anything else.
_NPM_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "moderate",
    "moderate": "moderate",
    "low": "low",
}


def npm_severity(label: str | None, score: float | None) -> str:
    """Map a stored severity onto npm's vocabulary.

    * CVSS ``none`` (a score of 0.0) is npm's ``info``: rated, no impact.
    * No label but a score: derived from the score.
    * Neither: ``low``, not ``info``. An unrated record is still a CVE that
      matched this version, and ``info`` is what ``npm audit --audit-level=low``
      -- the usual CI setting -- ignores; reporting it at the lowest real
      level keeps it visible without overstating it.
    """
    mapped = _NPM_SEVERITY.get((label or "").lower())
    if mapped:
        return mapped
    if (label or "").lower() == "none":
        return "info"
    if score is not None:
        from ..services.osv import severity_label

        return _NPM_SEVERITY.get(severity_label(score) or "", "info")
    return "low"


def _chunks(items: list, size: int):
    for start in range(0, len(items), size):
        yield items[start : start + size]


@router.post("/-/npm/v1/security/audits/quick")
async def audit_quick() -> Response:
    return json_response({"actions": [], "advisories": {}, "metadata": {"vulnerabilities": {}}})


# --------------------------------------------------------------------------- #
# Tarball
# --------------------------------------------------------------------------- #
@router.get("/{package_name:path}/-/{filename}")
async def get_tarball(
    package_name: str,
    filename: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_read),
) -> Response:
    started = time.perf_counter()
    name = npm_path_to_name(package_name)
    normalized = name.lower()

    # A narrow join, not the whole package graph: fetch_package eager-loads
    # every version and the Package entity, which carries the entire upstream
    # packument. Deserialising 37 MB of JSON per concurrent tarball request is
    # what the container's memory limit is there to survive.
    located = await packages.locate_file(session, ECOSYSTEM, normalized, filename=filename)
    if located is None:
        return npm_error("tarball not found", status.HTTP_404_NOT_FOUND)
    package, version_row, file_row = located

    # Policy is enforced on the artifact path too -- a blocked package must not
    # be downloadable even if a client already has the metadata cached.
    verdict = await PolicyEngine(session).evaluate(
        ECOSYSTEM,
        normalized,
        version_row.version if version_row else None,
        max_cvss=version_row.max_cvss if version_row else None,
        has_fix=bool(version_row and version_row.has_fix),
        scanned=bool(version_row and version_row.scanned_at),
    )
    if verdict.blocked:
        audit.record_download(
            audit.DownloadEvent(
                ecosystem="npm",
                package_name=name,
                version=version_row.version if version_row else None,
                filename=filename,
                user_id=identity.user_id,
                username=identity.username,
                ip=client_ip(request),
                user_agent=request.headers.get("user-agent"),
                status=403,
            )
        )
        return npm_error(verdict.reason or "package is blocked", status.HTTP_403_FORBIDDEN)

    # The bytes are content-addressed, so a client holding this digest holds
    # exactly these bytes. Answer before fetching or streaming anything.
    known_digest = file_row.blob_sha256 or file_row.sha256
    if known_digest and etag_matches(request.headers.get("if-none-match"), f'"{known_digest}"'):
        return Response(
            status_code=status.HTTP_304_NOT_MODIFIED,
            headers={
                "etag": f'"{known_digest}"',
                "cache-control": "public, max-age=31536000, immutable",
            },
        )

    was_cached = bool(file_row.blob_sha256 and get_store().exists(file_row.blob_sha256))
    try:
        chunks, size, content_type = await artifacts.stream_artifact(session, file_row)
    except artifacts.DigestMismatch as exc:
        log.error("digest mismatch serving %s: %s", filename, exc)
        return npm_error("artifact failed integrity verification", status.HTTP_502_BAD_GATEWAY)
    except artifacts.ArtifactError as exc:
        log.warning("artifact fetch failed: %s", exc)
        return npm_error(str(exc), status.HTTP_502_BAD_GATEWAY)

    await packages.bump_download_counters(session, package.id, file_row.id)
    await session.commit()

    audit.record_download(
        audit.DownloadEvent(
            ecosystem="npm",
            package_name=name,
            version=version_row.version if version_row else None,
            filename=filename,
            kind="file",
            user_id=identity.user_id,
            username=identity.username,
            token_id=identity.token_id,
            ip=client_ip(request),
            user_agent=request.headers.get("user-agent"),
            bytes_sent=size,
            cache_hit=was_cached,
            upstream_id=file_row.upstream_id,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
    )

    headers = {
        "content-length": str(size),
        # Artifacts are immutable, so let clients and proxies keep them forever.
        "cache-control": "public, max-age=31536000, immutable",
        "etag": f'"{file_row.blob_sha256}"',
    }
    return StreamingResponse(
        chunks, media_type=content_type or "application/octet-stream", headers=headers
    )


# --------------------------------------------------------------------------- #
# Publish / unpublish
# --------------------------------------------------------------------------- #
def _apply_deprecations(
    by_version: dict[str, PackageVersion],
    submitted: dict[str, Any],
    *,
    missing_means_undeprecate: bool,
) -> dict[str, str | None]:
    """Copy ``deprecated`` from a submitted packument onto stored versions."""
    changed: dict[str, str | None] = {}
    for version, meta in submitted.items():
        row = by_version.get(version)
        if row is None or not isinstance(meta, dict):
            continue
        if "deprecated" not in meta and not missing_means_undeprecate:
            continue
        message = meta.get("deprecated")
        # An empty string is npm's "undeprecate".
        new = message if isinstance(message, str) and message else None
        if new != row.deprecated:
            row.deprecated = new
            changed[version] = new
        elif missing_means_undeprecate:
            changed[version] = new
    return changed


async def _retire_version_row(
    session: AsyncSession,
    package: Package,
    version_row: PackageVersion,
    identity: Identity,
) -> None:
    """Tombstone one version, drop its bytes and its row.

    The tombstone is what keeps the version number from being reused with
    different content; the same mechanism both unpublish routes use.
    """
    primary = next((f for f in version_row.files if f.blob_sha256), None)
    await ownership.retire_version(
        session,
        ECOSYSTEM,
        package.normalized_name,
        version_row.version,
        version_row.normalized_version,
        sha256=primary.blob_sha256 if primary else None,
        integrity=primary.integrity if primary else None,
        user=identity.user,
        username=identity.username,
    )
    for file_row in version_row.files:
        await artifacts.purge_file(session, file_row)
    await session.delete(version_row)


# Declared before the bare `PUT /{package_name:path}` publish route on
# purpose: that pattern is greedy and would otherwise take this URL, then fail
# name validation on "pkg/-rev/3-abc".
@router.put("/{package_name:path}/-rev/{rev}")
async def update_packument(
    package_name: str,
    rev: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_publish),
) -> Response:
    """``npm unpublish pkg@1.2.3`` when other versions remain.

    libnpmpublish GETs the packument, deletes the version (and any dist-tag
    naming it) locally, PUTs the edited document here, then DELETEs the
    tarball. Versions present in the store but absent from the body are
    retired. ``deprecated`` edits arriving on this route are applied too.
    The ``rev`` is not compared: our ``_rev`` is synthesised, not a CouchDB
    revision, and authorisation is what guards the write.
    """
    name = npm_path_to_name(package_name)
    try:
        body = orjson.loads(await request.body())
    except orjson.JSONDecodeError:
        return npm_error("request body is not valid JSON", status.HTTP_400_BAD_REQUEST)
    if not isinstance(body, dict):
        return npm_error("request body must be a JSON object", status.HTTP_400_BAD_REQUEST)
    declared = body.get("name") or body.get("_id")
    if declared is not None and declared != name:
        return npm_error(
            f"package name '{declared}' does not match the request path '{name}'",
            status.HTTP_400_BAD_REQUEST,
        )
    submitted = body.get("versions")
    if not isinstance(submitted, dict):
        # Treating a missing map as "no versions" would retire everything.
        return npm_error("'versions' must be an object", status.HTTP_400_BAD_REQUEST)
    if body.get("_attachments"):
        return npm_error(
            "publish new versions with PUT /{package}, not a revision update",
            status.HTTP_400_BAD_REQUEST,
        )

    package = await _lean_package(session, name.lower(), with_versions=True, with_files=True)
    if package is None:
        return npm_error("package not found", status.HTTP_404_NOT_FOUND)

    by_version = {v.version: v for v in package.versions}
    removed = [by_version[v] for v in sorted(by_version, key=semver_key) if v not in submitted]
    survivors = [v for v in by_version if v in submitted]
    if removed and not survivors:
        return npm_error(
            "this update would remove every version; unpublish the package instead",
            status.HTTP_400_BAD_REQUEST,
        )

    is_admin = identity.is_admin and identity.has_scope("admin")
    try:
        await ownership.authorize_mutation(
            package,
            user_id=identity.user_id,
            is_admin=is_admin,
            action="unpublish" if removed else "deprecate",
        )
    except ownership.PublishDenied as denied:
        return npm_error(denied.reason, denied.status_code)
    if any(not row.is_local for row in removed) and not is_admin:
        return npm_error(
            "only locally published versions can be unpublished", status.HTTP_403_FORBIDDEN
        )

    removed_versions = {row.version for row in removed}
    for row in removed:
        await _retire_version_row(session, package, row, identity)

    changed = _apply_deprecations(
        {v: by_version[v] for v in survivors}, submitted, missing_means_undeprecate=False
    )

    if removed_versions:
        # A tag must never name a version that is gone. `latest` follows the
        # client's choice when it names a survivor, else the newest survivor.
        submitted_tags = body.get("dist-tags") if isinstance(body.get("dist-tags"), dict) else {}
        wanted = submitted_tags.get("latest")
        if not (isinstance(wanted, str) and wanted in survivors):
            wanted = max_semver(survivors) or survivors[-1]
        for tag_row in list(package.dist_tags):
            if tag_row.version not in removed_versions:
                continue
            if tag_row.tag == "latest":
                # Repointed in place: a delete plus an insert of the same
                # (package, tag) trips the unique constraint, because the
                # unit of work flushes inserts before deletes.
                tag_row.version = wanted
            else:
                # delete-orphan cascade removes the row.
                package.dist_tags.remove(tag_row)
        latest_row = next((t for t in package.dist_tags if t.tag == "latest"), None)
        if latest_row is None:
            package.dist_tags.append(DistTag(package_id=package.id, tag="latest", version=wanted))
            package.latest_version = wanted
        else:
            package.latest_version = latest_row.version

    for version in sorted(removed_versions, key=semver_key):
        await audit.record_audit(
            session,
            audit.PACKAGE_UNPUBLISHED,
            actor_user_id=identity.user_id,
            actor_username=identity.username,
            target_type="package",
            target_id=f"npm:{package.name}@{version}",
            ip=client_ip(request),
            user_agent=request.headers.get("user-agent"),
            detail={"scope": "version", "via": "packument-update"},
        )
    if changed:
        await audit.record_audit(
            session,
            "registry.deprecate",
            actor_user_id=identity.user_id,
            actor_username=identity.username,
            target_type="package",
            target_id=f"npm:{package.name}",
            ip=client_ip(request),
            detail={"changed": changed},
        )
    await session.commit()
    await packages.invalidate_package_cache("npm", package.normalized_name)
    return json_response({"ok": True, "id": package.name})


@router.put("/{package_name:path}")
async def publish(
    package_name: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_publish),
) -> Response:
    name = npm_path_to_name(package_name)
    try:
        body = orjson.loads(await request.body())
    except orjson.JSONDecodeError:
        return npm_error("request body is not valid JSON", status.HTTP_400_BAD_REQUEST)

    try:
        parsed = npm_publish.parse_publish_document(body, name)
    except npm_publish.PublishError as exc:
        return npm_error(exc.message, exc.status_code)

    normalized = parsed.name.lower()

    # The block list is enforced on publish too, so a blocked name cannot be
    # squatted locally to bypass the policy.
    verdict = await PolicyEngine(session).is_name_blocked(ECOSYSTEM, normalized)
    if verdict.blocked:
        await _record_publish_denied(session, request, identity, parsed.name, verdict.reason)
        return npm_error(verdict.reason or "package is blocked", status.HTTP_403_FORBIDDEN)

    if parsed.intent == "deprecate":
        return await _handle_deprecate(session, request, identity, parsed)
    return await _handle_publish(session, request, identity, parsed)


async def _record_publish_denied(
    session: AsyncSession,
    request: Request,
    identity: Identity,
    target: str,
    reason: str | None,
    extra: dict | None = None,
    *,
    actor: tuple[int | None, str | None] | None = None,
) -> None:
    """Audit a refused publish on a session with nothing else pending.

    ``actor`` lets a caller that has just rolled back pass the identity it
    captured beforehand. Reading it off ``identity`` after a rollback would
    lazy-load an expired User inside a sync attribute access, which asyncio
    SQLAlchemy cannot do.
    """
    actor_id, actor_name = actor if actor is not None else (
        identity.user_id,
        identity.username,
    )
    await audit.record_audit(
        session,
        audit.PACKAGE_PUBLISH_DENIED,
        actor_user_id=actor_id,
        actor_username=actor_name,
        target_type="package",
        target_id=f"npm:{target}",
        success=False,
        ip=client_ip(request),
        detail={"reason": reason, **(extra or {})},
    )
    await session.commit()


async def _handle_publish(
    session: AsyncSession, request: Request, identity: Identity, parsed: npm_publish.PublishRequest
) -> Response:
    normalized = parsed.name.lower()

    # Ownership first, before a single row is touched. Everything below flips
    # `is_local`, and a package with any local version is never refreshed from
    # upstream again -- so the check has to happen before the mutation, not
    # after it.
    try:
        grant = await ownership.authorize_publish(
            session,
            ECOSYSTEM,
            parsed.name,
            user_id=identity.user_id,
            is_admin=identity.is_admin and identity.has_scope("admin"),
        )
        for version in parsed.versions:
            await ownership.assert_not_retired(session, ECOSYSTEM, normalized, version)
    except ownership.PublishDenied as denied:
        await _record_publish_denied(session, request, identity, parsed.name, denied.reason)
        return npm_error(denied.reason, denied.status_code)

    package = grant.package
    if package is None:
        package = Package(
            ecosystem=ECOSYSTEM,
            name=parsed.name,
            normalized_name=normalized,
            is_local=True,
            owner_user_id=grant.owner_user_id,
        )
        # Initialise the collections so SQLAlchemy treats them as loaded.
        # Touching an unloaded relationship on a brand-new instance would
        # trigger a lazy load, which is illegal on an async session.
        package.versions = []
        package.dist_tags = []
        session.add(package)
        await session.flush()
    package.is_local = True
    if package.owner_user_id is None:
        package.owner_user_id = grant.owner_user_id
    if parsed.description:
        package.description = parsed.description

    existing = {v.version for v in package.versions}
    store = get_store()
    published: list[str] = []

    # Every check runs before any bytes reach the blob store. Storing first
    # meant a refused publish (bad digest, CVE policy) left a file on disk
    # with no Blob row, which garbage collection never looks for.
    staged: list[tuple[str, dict, npm_publish.Attachment, Any]] = []
    for version, meta in parsed.versions.items():
        if version in existing:
            # npm's own wording; the CLI prints this to the user.
            return npm_error(
                "You cannot publish over the previously published versions: " + version,
                status.HTTP_409_CONFLICT,
            )

        attachment = npm_publish.match_attachment(parsed, version)
        if attachment is None:
            return npm_error(
                f"no tarball attachment found for version {version}", status.HTTP_400_BAD_REQUEST
            )

        # Verify against the digests the client declared, if any.
        digests = npm_publish.digest_tarball(attachment.data)
        try:
            npm_publish.verify_declared_digests(version, meta, digests)
        except npm_publish.PublishError as exc:
            return npm_error(exc.message, exc.status_code)
        npm_publish.annotate_install_script(meta, attachment.data)

        # Inline CVE check before the version becomes visible.
        scan = await inline_scan(session, ECOSYSTEM, parsed.name, version)
        policy = PolicyEngine(session)
        cve_verdict = await policy.evaluate(
            ECOSYSTEM,
            normalized,
            version,
            max_cvss=scan.max_score,
            has_fix=scan.has_fix,
            scanned=scan.scanned,
        )
        if cve_verdict.blocked:
            # Capture the actor before the rollback expires the ORM objects
            # the Identity is holding.
            actor = (identity.user_id, identity.username)
            # Roll back everything this request touched before recording the
            # denial. Committing here used to persist the package row and its
            # `is_local` flip: a refused publish of `express` froze the cached
            # package at its current versions, and a refused publish of a name
            # we had never cached created an empty local package that answered
            # 404 for everyone, forever.
            await session.rollback()
            await _record_publish_denied(
                session,
                request,
                identity,
                f"{parsed.name}@{version}",
                cve_verdict.reason,
                extra={"max_cvss": scan.max_score},
                actor=actor,
            )
            return npm_error(cve_verdict.reason or "blocked by CVE policy", status.HTTP_403_FORBIDDEN)
        staged.append((version, meta, attachment, scan))

    for version, meta, attachment, scan in staged:
        stored = await store.put_bytes(attachment.data)

        version_row = PackageVersion(
            package_id=package.id,
            version=version,
            normalized_version=version,
            metadata_json=meta,
            is_local=True,
            published_at=datetime.now(UTC),
            max_cvss=scan.max_score,
            scanned_at=datetime.now(UTC) if scan.scanned else None,
        )
        session.add(version_row)
        await session.flush()

        from ..models import Blob

        blob = await session.get(Blob, stored.sha256)
        if blob is None:
            session.add(Blob(sha256=stored.sha256, size=stored.size, path=stored.path, refcount=1))
        else:
            blob.refcount += 1

        session.add(
            PackageFile(
                version_id=version_row.id,
                filename=attachment.filename,
                blob_sha256=stored.sha256,
                size=stored.size,
                content_type=attachment.content_type,
                sha256=stored.sha256,
                sha1=stored.sha1,
                md5=stored.md5,
                blake2b_256=stored.blake2b_256,
                # Recomputed from the stored bytes, never copied from the
                # publish document. A client-supplied SRI string is served to
                # every installer, so a wrong one -- deliberate or not -- makes
                # the version permanently uninstallable with EINTEGRITY.
                integrity=stored.integrity,
                upload_time=datetime.now(UTC),
                cached_at=datetime.now(UTC),
            )
        )
        package.versions.append(version_row)
        published.append(version)

        if scan.scanned and scan.cves:
            from ..services.osv import OsvScanner

            await OsvScanner(session).apply_to_version(version_row, scan, parsed.name)

    # dist-tags from the publish document; default `latest` when absent.
    # A tag naming a version that does not exist is a broken package -- npm
    # resolves `latest` before anything else and reports "no matching version
    # found" -- so the document's tags are filtered to versions we actually
    # have, the same check the standalone dist-tag endpoint already made.
    known = {v.version for v in package.versions} | set(published)
    tags = {t: v for t, v in (parsed.dist_tags or {}).items() if v in known}
    if not tags and published:
        tags = {"latest": max_semver(published) or published[-1]}
    existing_tags = {t.tag: t for t in package.dist_tags}
    for tag, version in tags.items():
        row = existing_tags.get(tag)
        if row is None:
            session.add(DistTag(package_id=package.id, tag=tag, version=version))
        else:
            row.version = version
        if tag == "latest":
            package.latest_version = version

    if package.latest_version is None:
        package.latest_version = max_semver([v.version for v in package.versions])

    await audit.record_audit(
        session,
        audit.PACKAGE_PUBLISHED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="package",
        target_id=f"npm:{parsed.name}",
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={"versions": published, "ecosystem": "npm"},
    )
    await session.commit()
    await packages.invalidate_package_cache("npm", normalized)

    # Mirror to any GitLab upstream configured as a publish target.
    await _forward_to_publish_targets(session, parsed)

    return json_response(
        npm_publish.publish_ok_response(parsed.name, published[0] if published else None),
        status_code=status.HTTP_201_CREATED,
    )


async def _handle_deprecate(
    session: AsyncSession, request: Request, identity: Identity, parsed: npm_publish.PublishRequest
) -> Response:
    package = await _lean_package(session, parsed.name.lower(), with_versions=True)
    if package is None:
        return npm_error("package not found", status.HTTP_404_NOT_FOUND)

    try:
        await ownership.authorize_mutation(
            package,
            user_id=identity.user_id,
            is_admin=identity.is_admin and identity.has_scope("admin"),
            action="deprecate",
        )
    except ownership.PublishDenied as denied:
        return npm_error(denied.reason, denied.status_code)

    by_version = {v.version: v for v in package.versions}
    changed = _apply_deprecations(by_version, parsed.versions, missing_means_undeprecate=True)

    await audit.record_audit(
        session,
        "registry.deprecate",
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="package",
        target_id=f"npm:{parsed.name}",
        ip=client_ip(request),
        detail={"changed": changed},
    )
    await session.commit()
    await packages.invalidate_package_cache("npm", package.normalized_name)
    return json_response({"ok": True})


async def _forward_to_publish_targets(
    session: AsyncSession, parsed: npm_publish.PublishRequest
) -> None:
    """Best-effort mirror of a publish to GitLab upstreams marked as targets."""
    from ..models import Upstream
    from ..services.resolver import build_provider

    targets = (
        await session.execute(
            select(Upstream).where(
                Upstream.ecosystem == ECOSYSTEM,
                Upstream.enabled.is_(True),
                Upstream.allow_publish.is_(True),
            )
        )
    ).scalars().all()
    for upstream in targets:
        try:
            provider = build_provider(upstream)
            if not provider.supports_publish:
                continue
            ok, message = await provider.publish(parsed.raw, "npm")
            log.info("mirror publish %s -> %s: %s", parsed.name, upstream.name, message)
            if not ok:
                log.warning("mirror publish to %s failed: %s", upstream.name, message)
        except Exception:
            log.exception("mirror publish to %s raised", upstream.name)


# The per-version route is declared first on purpose. Both patterns start with
# a greedy `{package_name:path}`, so whichever is registered first wins: with
# the package-level route ahead of it, `DELETE /npm/pkg/-/pkg-1.0.0.tgz/-rev/1`
# -- the URL `npm unpublish pkg@1.0.0` actually sends -- was swallowed by the
# package route, which then looked up a package literally named
# "pkg/-/pkg-1.0.0.tgz" and answered "package not found".
@router.delete("/{package_name:path}/-/{filename}/-rev/{rev}")
async def unpublish_version(
    package_name: str,
    filename: str,
    rev: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_publish),
) -> Response:
    name = npm_path_to_name(package_name)
    package = await _lean_package(session, name.lower(), with_versions=True, with_files=True)
    if package is None:
        return npm_error("package not found", status.HTTP_404_NOT_FOUND)

    target = None
    for version_row in package.versions:
        for file_row in version_row.files:
            if file_row.filename == filename:
                target = (version_row, file_row)
                break
    if target is None:
        # `npm unpublish pkg@1.2.3` retires the version with a packument PUT
        # first and only then deletes the tarball. By then the version is
        # already gone; answering 404 here made the CLI report a failure for
        # an unpublish that had succeeded.
        if await _is_retired_tarball(session, package, filename):
            try:
                await ownership.authorize_mutation(
                    package,
                    user_id=identity.user_id,
                    is_admin=identity.is_admin and identity.has_scope("admin"),
                    action="unpublish",
                )
            except ownership.PublishDenied as denied:
                return npm_error(denied.reason, denied.status_code)
            return json_response({"ok": True})
        return npm_error("version not found", status.HTTP_404_NOT_FOUND)

    version_row, file_row = target
    if not version_row.is_local and not (identity.is_admin and identity.has_scope("admin")):
        return npm_error(
            "only locally published versions can be unpublished", status.HTTP_403_FORBIDDEN
        )
    try:
        await ownership.authorize_mutation(
            package,
            user_id=identity.user_id,
            is_admin=identity.is_admin and identity.has_scope("admin"),
            action="unpublish",
        )
    except ownership.PublishDenied as denied:
        return npm_error(denied.reason, denied.status_code)

    await ownership.retire_version(
        session,
        ECOSYSTEM,
        package.normalized_name,
        version_row.version,
        version_row.normalized_version,
        sha256=file_row.blob_sha256,
        integrity=file_row.integrity,
        user=identity.user,
        username=identity.username,
    )
    await _retire_version_row(session, package, version_row, identity)

    await audit.record_audit(
        session,
        audit.PACKAGE_UNPUBLISHED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="package",
        target_id=f"npm:{name}@{version_row.version}",
        ip=client_ip(request),
        detail={"scope": "version", "filename": filename},
    )
    await session.commit()
    await packages.invalidate_package_cache("npm", package.normalized_name)
    return json_response({"ok": True})


async def _is_retired_tarball(session: AsyncSession, package: Package, filename: str) -> bool:
    from ..models import RetiredVersion

    retired = (
        await session.execute(
            select(RetiredVersion.version).where(
                RetiredVersion.ecosystem == ECOSYSTEM,
                RetiredVersion.normalized_name == package.normalized_name,
            )
        )
    ).scalars().all()
    return any(npm_tarball_filename(package.name, v) == filename for v in retired)


@router.delete("/{package_name:path}/-rev/{rev}")
async def unpublish_package(
    package_name: str,
    rev: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_publish),
) -> Response:
    name = npm_path_to_name(package_name)
    package = await _lean_package(session, name.lower(), with_versions=True, with_files=True)
    if package is None:
        return npm_error("package not found", status.HTTP_404_NOT_FOUND)

    try:
        await ownership.authorize_mutation(
            package,
            user_id=identity.user_id,
            is_admin=identity.is_admin and identity.has_scope("admin"),
            action="unpublish",
        )
    except ownership.PublishDenied as denied:
        return npm_error(denied.reason, denied.status_code)

    for version_row in package.versions:
        # Tombstone every local version before the rows go. Without this the
        # version numbers become free again and can be republished with
        # different bytes.
        if version_row.is_local:
            primary = next((f for f in version_row.files if f.blob_sha256), None)
            await ownership.retire_version(
                session,
                ECOSYSTEM,
                package.normalized_name,
                version_row.version,
                version_row.normalized_version,
                sha256=primary.blob_sha256 if primary else None,
                integrity=primary.integrity if primary else None,
                user=identity.user,
                username=identity.username,
            )
        for file_row in version_row.files:
            await artifacts.purge_file(session, file_row)
    await session.delete(package)

    await audit.record_audit(
        session,
        audit.PACKAGE_UNPUBLISHED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="package",
        target_id=f"npm:{name}",
        ip=client_ip(request),
        detail={"scope": "package"},
    )
    await session.commit()
    await packages.invalidate_package_cache("npm", name.lower())
    return json_response({"ok": True})


# --------------------------------------------------------------------------- #
# Packument / version document
#
# These share one catch-all because `/{pkg}/{version}` and `/{pkg}` are
# genuinely ambiguous for scoped packages: `/@babel/core` is a packument, not
# version "core" of package "@babel". Only the leading `@` disambiguates, so we
# split the path ourselves instead of letting the router guess.
# --------------------------------------------------------------------------- #
def split_package_path(path: str) -> tuple[str, str | None] | None:
    """``"@babel/core/1.2.3"`` -> ``("@babel/core", "1.2.3")``.

    Accepts the ``%2f``-encoded scope form npm sends as well as the literal
    slash form other clients use.
    """
    path = npm_path_to_name(path.strip("/"))
    if not path:
        return None
    segments = [s for s in path.split("/") if s]
    if not segments:
        return None

    if segments[0].startswith("@"):
        if len(segments) < 2:
            return None  # a bare scope is not a package
        name = f"{segments[0]}/{segments[1]}"
        rest = segments[2:]
    else:
        name = segments[0]
        rest = segments[1:]

    if not rest:
        return name, None
    if len(rest) == 1:
        return name, rest[0]
    return None


@router.get("/{full_path:path}")
async def get_package_or_version(
    full_path: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_read),
    accept: str | None = Header(default=None),
) -> Response:
    parsed = split_package_path(full_path)
    if parsed is None:
        return npm_error("Not found", status.HTTP_404_NOT_FOUND)
    name, version = parsed
    if version is None:
        return await _packument_response(name, request, session, identity, accept)
    return await _version_response(name, version, request, session, identity)


async def _version_response(
    name: str,
    version: str,
    request: Request,
    session: AsyncSession,
    identity: Identity,
) -> Response:
    normalized = packages.normalized_for(ECOSYSTEM, name)
    lookup = await _refresh_if_stale(session, name, normalized)
    package = await _lean_package(session, normalized)
    if package is None:
        return npm_error("package not found", status.HTTP_404_NOT_FOUND)

    async def load_version(wanted: str) -> PackageVersion | None:
        # One version row, with its metadata: that is all the document needs.
        return (
            await session.execute(
                select(PackageVersion)
                .options(selectinload(PackageVersion.files))
                .where(PackageVersion.package_id == package.id, PackageVersion.version == wanted)
            )
        ).scalar_one_or_none()

    resolved = version
    version_row = await load_version(version)
    if version_row is None:
        # A dist-tag is also accepted here, e.g. GET /lodash/latest.
        tag = next((t for t in package.dist_tags if t.tag == version), None)
        resolved = tag.version if tag else (package.latest_version if version == "latest" else None)
        if resolved is None:
            return npm_error("version not found", status.HTTP_404_NOT_FOUND)
        version_row = await load_version(resolved)
    if version_row is None:
        return npm_error("version not found", status.HTTP_404_NOT_FOUND)

    verdict = await PolicyEngine(session).evaluate(
        ECOSYSTEM,
        package.normalized_name,
        resolved,
        max_cvss=version_row.max_cvss,
        has_fix=version_row.has_fix,
        scanned=bool(version_row.scanned_at),
    )
    if verdict.blocked:
        return npm_error(verdict.reason or "package is blocked", status.HTTP_403_FORBIDDEN)

    audit.record_download(
        audit.DownloadEvent(
            ecosystem="npm",
            package_name=package.name,
            version=resolved,
            kind="metadata",
            user_id=identity.user_id,
            username=identity.username,
            token_id=identity.token_id,
            ip=client_ip(request),
            user_agent=request.headers.get("user-agent"),
            cache_hit=not (lookup is not None and lookup.from_upstream),
        )
    )
    return document_response(
        request,
        orjson.dumps(npm_render.render_version_document(package, version_row)),
        content_type=npm_render.FULL_CONTENT_TYPE,
    )


async def _packument_response(
    name: str,
    request: Request,
    session: AsyncSession,
    identity: Identity,
    accept: str | None,
) -> Response:
    abbreviated = npm_render.wants_abbreviated(accept)
    normalized = name.lower()

    # Cheap check before touching upstreams: never fetch a blocked package.
    policy = PolicyEngine(session)
    name_verdict = await policy.is_name_blocked(ECOSYSTEM, normalized)
    if name_verdict.blocked:
        return npm_error(name_verdict.reason or "package is blocked", status.HTTP_403_FORBIDDEN)

    content_type = (
        npm_render.ABBREVIATED_CONTENT_TYPE if abbreviated else npm_render.FULL_CONTENT_TYPE
    )
    cache_id = packages.cache_key("npm", normalized, "abbrev" if abbreviated else "full")
    # Stored serialised and served as stored: a hit costs a hash for the ETag,
    # not a parse and a re-encode of the whole document.
    cached = await cache_get_bytes(cache_id)
    if cached is not None:
        audit.record_download(
            audit.DownloadEvent(
                ecosystem="npm",
                package_name=name,
                kind="metadata",
                user_id=identity.user_id,
                username=identity.username,
                ip=client_ip(request),
                user_agent=request.headers.get("user-agent"),
                cache_hit=True,
            )
        )
        return document_response(request, cached, content_type=content_type, vary_accept=True)

    lookup = await packages.fetch_package(session, ECOSYSTEM, name)
    if lookup.package is None or not lookup.package.versions:
        return npm_error("Not found", status.HTTP_404_NOT_FOUND)
    package = lookup.package

    # Inline CVE scan for versions we have never scanned.
    await _scan_new_versions(session, package)

    document = npm_render.render_packument(package, abbreviated=abbreviated)

    # Drop versions blocked by CVE policy so a client cannot resolve to them.
    blocked = await _blocked_versions(policy, package)
    if blocked:
        document["versions"] = {
            v: meta for v, meta in document["versions"].items() if v not in blocked
        }
        document["dist-tags"] = {
            tag: version
            for tag, version in document["dist-tags"].items()
            if version not in blocked
        }
        if not document["versions"]:
            return npm_error(
                "all versions of this package are blocked by policy", status.HTTP_403_FORBIDDEN
            )
        if "latest" not in document["dist-tags"]:
            remaining = max_semver(list(document["versions"]))
            if remaining:
                document["dist-tags"]["latest"] = remaining

    body = orjson.dumps(document)
    del document
    # Size-capped: the cache shares a fixed memory budget (allkeys-lru) with
    # herd-guard locks and rate-limit counters, which a few large documents
    # would evict. Large packuments are rendered per request instead.
    if len(body) <= PACKUMENT_CACHE_MAX_BYTES:
        await cache_set_bytes(cache_id, body, settings.meta_cache_ttl)

    audit.record_download(
        audit.DownloadEvent(
            ecosystem="npm",
            package_name=package.name,
            kind="metadata",
            user_id=identity.user_id,
            username=identity.username,
            token_id=identity.token_id,
            ip=client_ip(request),
            user_agent=request.headers.get("user-agent"),
            cache_hit=not lookup.from_upstream,
            upstream_id=lookup.upstream.id if lookup.upstream else None,
        )
    )
    return document_response(request, body, content_type=content_type, vary_accept=True)


async def _scan_new_versions(session: AsyncSession, package: Package) -> None:
    """Scan versions we have not seen before, within the inline budget."""
    if not settings.osv_inline_scan:
        return
    unscanned = [v for v in package.versions if v.scanned_at is None]
    if not unscanned:
        return

    from ..services.osv import OsvScanner

    scanner = OsvScanner(session)
    # Bound the work: a cold popular package can have hundreds of versions, and
    # only the resolvable ones matter for an install. Order by semver, not by
    # string -- lexically `9.0.0` beats `10.2.1`, so a package past its ninth
    # major release had its newest versions dropped from the sample and served
    # unscanned. The dist-tag targets are always included: those are what an
    # unpinned install actually resolves to.
    tagged = {t.version for t in package.dist_tags}
    if package.latest_version:
        tagged.add(package.latest_version)
    pinned = [v for v in unscanned if v.version in tagged]
    rest = sorted(unscanned, key=lambda v: semver_key(v.version), reverse=True)
    targets: list = []
    for version_row in [*pinned, *rest]:
        if version_row not in targets:
            targets.append(version_row)
        if len(targets) >= 25:
            break
    try:
        # The inline budget is what keeps a cold packument from hanging on a
        # slow OSV. Without it this used the 30 s API timeout, twice, while a
        # client waited.
        results = await asyncio.wait_for(
            scanner.scan_versions(ECOSYSTEM, [(package.name, v.version) for v in targets]),
            timeout=settings.osv_inline_timeout_seconds,
        )
    except (TimeoutError, asyncio.CancelledError):
        log.info("inline scan budget exceeded for %s; leaving versions unscanned", package.name)
        return
    except Exception:
        log.debug("inline scan batch failed for %s", package.name, exc_info=True)
        return
    for version_row in targets:
        result = results.get((package.name, version_row.version))
        if result is not None:
            await scanner.apply_to_version(version_row, result, package.name)
    await session.commit()


async def _blocked_versions(policy: PolicyEngine, package: Package) -> set[str]:
    return await _blocked_from_rows(policy, package.normalized_name, package.versions)


async def _blocked_from_rows(policy: PolicyEngine, normalized: str, rows) -> set[str]:
    """``rows`` are PackageVersion entities or column rows with ``version``,
    ``max_cvss``, ``has_fix`` and ``scanned_at``."""
    blocked: set[str] = set()
    for version_row in rows:
        verdict = await policy.evaluate(
            ECOSYSTEM,
            normalized,
            version_row.version,
            max_cvss=version_row.max_cvss,
            has_fix=version_row.has_fix,
            scanned=bool(version_row.scanned_at),
        )
        if verdict.blocked:
            blocked.add(version_row.version)
    return blocked
