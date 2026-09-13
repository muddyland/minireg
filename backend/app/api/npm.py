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
    DELETE /{pkg}/-rev/{rev}                    unpublish package
    DELETE /{pkg}/-/{filename}/-rev/{rev}       unpublish version
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime
from typing import Any

import orjson
from fastapi import APIRouter, Depends, Header, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..core.cache import cache_get_json, cache_set_json
from ..core.deps import (
    Identity,
    client_ip,
    rate_limited_publish,
    rate_limited_read,
    resolve_identity,
)
from ..core.naming import max_semver, npm_path_to_name, semver_key
from ..db import get_session
from ..models import DistTag, Ecosystem, Package, PackageFile, PackageVersion
from ..services import artifacts, audit, npm_publish, npm_render, packages
from ..services.osv import inline_scan
from ..services.policy import PolicyEngine
from ..services.storage import get_store

log = logging.getLogger(__name__)
router = APIRouter(tags=["npm"])

ECOSYSTEM = Ecosystem.npm


def json_response(payload: Any, status_code: int = 200, headers: dict | None = None) -> Response:
    """orjson is ~5x faster than the stdlib encoder, and packuments are big."""
    return Response(
        content=orjson.dumps(payload),
        status_code=status_code,
        media_type="application/json",
        headers=headers,
    )


def npm_error(message: str, status_code: int) -> JSONResponse:
    """npm surfaces the ``error`` field to the user verbatim."""
    return JSONResponse({"error": message}, status_code=status_code)


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
    lookup = await packages.fetch_package(session, ECOSYSTEM, name)
    if lookup.package is None:
        return npm_error("package not found", status.HTTP_404_NOT_FOUND)

    verdict = await PolicyEngine(session).evaluate(ECOSYSTEM, lookup.package.normalized_name)
    if verdict.blocked:
        return npm_error(verdict.reason or "package is blocked", status.HTTP_403_FORBIDDEN)

    # A tag pointing at a blocked version is a download the client is about to
    # be refused, so filter the same set the packument filters. `latest` is
    # re-pointed at the newest version that survives rather than dropped, which
    # is what lets `npm install pkg` degrade to an installable release.
    blocked = await _blocked_versions(PolicyEngine(session), lookup.package)
    tags = {
        t.tag: t.version for t in lookup.package.dist_tags if t.version not in blocked
    }
    if "latest" not in tags:
        survivors = [
            v.version for v in lookup.package.versions if v.version not in blocked
        ]
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

    package = await packages.get_package_row(
        session, ECOSYSTEM, name.lower(), load_files=False
    )
    if package is None:
        return npm_error("package not found", status.HTTP_404_NOT_FOUND)

    exists = (
        await session.execute(
            select(PackageVersion).where(
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
    package = await packages.get_package_row(session, ECOSYSTEM, name.lower(), load_files=False)
    if package is None:
        return npm_error("package not found", status.HTTP_404_NOT_FOUND)

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
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        )
    if not isinstance(body, dict):
        return json_response({})

    from ..models import PackageVulnerability, Vulnerability

    out: dict[str, list[dict]] = {}
    for name, versions in body.items():
        if not isinstance(versions, list):
            continue
        package = await packages.get_package_row(session, ECOSYSTEM, name.lower(), load_files=False)
        if package is None:
            continue
        rows = (
            await session.execute(
                select(Vulnerability, PackageVersion.version, PackageVulnerability.fixed_version)
                .join(PackageVulnerability, PackageVulnerability.vulnerability_id == Vulnerability.id)
                .join(PackageVersion, PackageVersion.id == PackageVulnerability.version_id)
                .where(
                    PackageVersion.package_id == package.id,
                    PackageVersion.version.in_(versions),
                    PackageVulnerability.suppressed.is_(False),
                )
            )
        ).all()
        advisories = [
            {
                "id": vuln.id,
                "url": f"https://osv.dev/vulnerability/{vuln.id}",
                "title": vuln.summary or vuln.cve_id,
                "severity": vuln.severity_label or "unknown",
                "vulnerable_versions": version,
                "cwe": [],
                "cvss": {"score": vuln.cvss_score or 0.0, "vectorString": vuln.cvss_vector},
                **({"fixAvailable": {"version": fixed}} if fixed else {}),
            }
            for vuln, version, fixed in rows
        ]
        if advisories:
            out[name] = advisories
    return json_response(out)


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

    lookup = await packages.fetch_package(session, ECOSYSTEM, name)
    if lookup.package is None:
        return npm_error("package not found", status.HTTP_404_NOT_FOUND)
    package = lookup.package

    file_row = (
        await session.execute(
            select(PackageFile)
            .join(PackageVersion, PackageVersion.id == PackageFile.version_id)
            .where(PackageVersion.package_id == package.id, PackageFile.filename == filename)
        )
    ).scalar_one_or_none()
    if file_row is None:
        return npm_error("tarball not found", status.HTTP_404_NOT_FOUND)

    version_row = await session.get(PackageVersion, file_row.version_id)

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

    was_cached = bool(file_row.blob_sha256 and get_store().exists(file_row.blob_sha256))
    try:
        chunks, size, content_type = await artifacts.stream_artifact(session, file_row)
    except artifacts.DigestMismatch as exc:
        log.error("digest mismatch serving %s: %s", filename, exc)
        return npm_error("artifact failed integrity verification", status.HTTP_502_BAD_GATEWAY)
    except artifacts.ArtifactError as exc:
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
        await audit.record_audit(
            session,
            audit.PACKAGE_PUBLISH_DENIED,
            actor_user_id=identity.user_id,
            actor_username=identity.username,
            target_type="package",
            target_id=f"npm:{parsed.name}",
            success=False,
            ip=client_ip(request),
            detail={"reason": verdict.reason},
        )
        await session.commit()
        return npm_error(verdict.reason or "package is blocked", status.HTTP_403_FORBIDDEN)

    if parsed.intent == "deprecate":
        return await _handle_deprecate(session, request, identity, parsed)
    return await _handle_publish(session, request, identity, parsed)


async def _handle_publish(
    session: AsyncSession, request: Request, identity: Identity, parsed: npm_publish.PublishRequest
) -> Response:
    normalized = parsed.name.lower()
    package = await packages.get_package_row(session, ECOSYSTEM, normalized)
    if package is None:
        package = Package(
            ecosystem=ECOSYSTEM,
            name=parsed.name,
            normalized_name=normalized,
            is_local=True,
        )
        # Initialise the collections so SQLAlchemy treats them as loaded.
        # Touching an unloaded relationship on a brand-new instance would
        # trigger a lazy load, which is illegal on an async session.
        package.versions = []
        package.dist_tags = []
        session.add(package)
        await session.flush()
    package.is_local = True
    if parsed.description:
        package.description = parsed.description

    existing = {v.version for v in package.versions}
    store = get_store()
    published: list[str] = []

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

        stored = await store.put_bytes(attachment.data)

        # Verify against the digests the client declared, if any.
        declared = (meta.get("dist") or {})
        if declared.get("shasum") and declared["shasum"].lower() != stored.sha1:
            return npm_error(
                f"shasum mismatch for {version}: declared {declared['shasum']}, got {stored.sha1}",
                status.HTTP_400_BAD_REQUEST,
            )

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
            await audit.record_audit(
                session,
                audit.PACKAGE_PUBLISH_DENIED,
                actor_user_id=identity.user_id,
                actor_username=identity.username,
                target_type="package",
                target_id=f"npm:{parsed.name}@{version}",
                success=False,
                ip=client_ip(request),
                detail={"reason": cve_verdict.reason, "max_cvss": scan.max_score},
            )
            await session.commit()
            return npm_error(cve_verdict.reason or "blocked by CVE policy", status.HTTP_403_FORBIDDEN)

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
                integrity=declared.get("integrity") or stored.integrity,
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
    tags = parsed.dist_tags or {}
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
    package = await packages.get_package_row(session, ECOSYSTEM, parsed.name.lower())
    if package is None:
        return npm_error("package not found", status.HTTP_404_NOT_FOUND)

    changed = {}
    by_version = {v.version: v for v in package.versions}
    for version, meta in parsed.versions.items():
        row = by_version.get(version)
        if row is None:
            continue
        message = meta.get("deprecated")
        # An empty string is npm's "undeprecate".
        row.deprecated = message if isinstance(message, str) and message else None
        changed[version] = row.deprecated

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


@router.delete("/{package_name:path}/-rev/{rev}")
async def unpublish_package(
    package_name: str,
    rev: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_publish),
) -> Response:
    name = npm_path_to_name(package_name)
    package = await packages.get_package_row(session, ECOSYSTEM, name.lower())
    if package is None:
        return npm_error("package not found", status.HTTP_404_NOT_FOUND)
    if not package.is_local and not identity.is_admin:
        return npm_error(
            "only locally published packages can be unpublished", status.HTTP_403_FORBIDDEN
        )

    for version_row in package.versions:
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
    package = await packages.get_package_row(session, ECOSYSTEM, name.lower())
    if package is None:
        return npm_error("package not found", status.HTTP_404_NOT_FOUND)

    target = None
    for version_row in package.versions:
        for file_row in version_row.files:
            if file_row.filename == filename:
                target = (version_row, file_row)
                break
    if target is None:
        return npm_error("version not found", status.HTTP_404_NOT_FOUND)

    version_row, file_row = target
    if not version_row.is_local and not identity.is_admin:
        return npm_error(
            "only locally published versions can be unpublished", status.HTTP_403_FORBIDDEN
        )

    await artifacts.purge_file(session, file_row)
    await session.delete(version_row)

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
    lookup = await packages.fetch_package(session, ECOSYSTEM, name)
    if lookup.package is None:
        return npm_error("package not found", status.HTTP_404_NOT_FOUND)
    package = lookup.package

    resolved = version
    if not any(v.version == version for v in package.versions):
        # A dist-tag is also accepted here, e.g. GET /lodash/latest.
        tag = next((t for t in package.dist_tags if t.tag == version), None)
        resolved = tag.version if tag else (package.latest_version if version == "latest" else None)
    if resolved is None:
        return npm_error("version not found", status.HTTP_404_NOT_FOUND)

    version_row = next((v for v in package.versions if v.version == resolved), None)
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
            cache_hit=not lookup.from_upstream,
        )
    )
    return json_response(npm_render.render_version_document(package, version_row))


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

    cache_id = packages.cache_key("npm", normalized, "abbrev" if abbreviated else "full")
    cached = await cache_get_json(cache_id)
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
        return json_response(
            cached,
            headers={"content-type": (
                npm_render.ABBREVIATED_CONTENT_TYPE if abbreviated else npm_render.FULL_CONTENT_TYPE
            )},
        )

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

    await cache_set_json(cache_id, document, settings.meta_cache_ttl)

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
    return json_response(
        document,
        headers={"content-type": (
            npm_render.ABBREVIATED_CONTENT_TYPE if abbreviated else npm_render.FULL_CONTENT_TYPE
        )},
    )


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
    blocked: set[str] = set()
    for version_row in package.versions:
        verdict = await policy.evaluate(
            ECOSYSTEM,
            package.normalized_name,
            version_row.version,
            max_cvss=version_row.max_cvss,
            has_fix=version_row.has_fix,
            scanned=bool(version_row.scanned_at),
        )
        if verdict.blocked:
            blocked.add(version_row.version)
    return blocked
