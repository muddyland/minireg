"""PyPI endpoints.

Mounted at ``/pypi``, so clients configure:

    pip:   --index-url http://minireg.example.com/pypi/simple/
    twine: --repository-url http://minireg.example.com/pypi/legacy/

Routes:

    GET  /simple/                        project index (HTML or JSON)
    GET  /simple/{project}/              project detail (HTML or JSON)
    GET  /files/{project}/{filename}     artifact
    GET  /files/{project}/{filename}.metadata   PEP 658 sidecar
    GET  /{project}/json                 Warehouse-compatible JSON API
    POST /legacy/                        twine upload
    POST /                               twine upload (alias)
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime

import orjson
from fastapi import APIRouter, Depends, Header, Query, Request, Response, status
from fastapi.responses import PlainTextResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..core.cache import cache_get_json, cache_set_json
from ..core.deps import Identity, client_ip, rate_limited_publish, rate_limited_read
from ..core.naming import normalize_pypi_name
from ..db import get_session
from ..models import Blob, Ecosystem, Package, PackageFile, PackageVersion
from ..services import artifacts, audit, ownership, packages, pypi_publish, pypi_render
from ..services.osv import OsvScanner, inline_scan
from ..services.policy import PolicyEngine
from ..services.storage import get_store

log = logging.getLogger(__name__)
router = APIRouter(tags=["pypi"])

ECOSYSTEM = Ecosystem.pypi


def json_response(payload, status_code: int = 200, content_type: str | None = None) -> Response:
    return Response(
        content=orjson.dumps(payload),
        status_code=status_code,
        media_type=content_type or "application/json",
    )


def upload_error(message: str, status_code: int) -> PlainTextResponse:
    """twine prints the response body verbatim, so plain text is the most
    useful thing we can return."""
    return PlainTextResponse(message, status_code=status_code)


# --------------------------------------------------------------------------- #
# Simple index
# --------------------------------------------------------------------------- #
@router.get("/simple/")
@router.get("/simple")
async def simple_index(
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_read),
    accept: str | None = Header(default=None),
    format: str | None = Query(default=None),
) -> Response:
    """The full project list.

    Only locally known projects are listed: enumerating an upstream's entire
    index on demand would be enormous and is not something pip needs.
    """
    # `Package.blocked` is vestigial and never written, so it was filtering
    # nothing; the real verdict is computed below.
    rows = (
        await session.execute(
            select(Package.name)
            .where(Package.ecosystem == ECOSYSTEM)
            .order_by(Package.normalized_name)
        )
    ).scalars().all()

    # One engine, reused: rules and settings are memoised on the instance, so
    # this is one cache read rather than three per project. A mirror that has
    # indexed public PyPI holds hundreds of thousands of names here, and the
    # previous shape made that millions of sequential round trips.
    policy = PolicyEngine(session)
    names = [
        name
        for name in rows
        if (await policy.evaluate(ECOSYSTEM, normalize_pypi_name(name), _name_level=True)).allowed
    ]

    if pypi_render.wants_json(accept, format):
        return json_response(
            pypi_render.render_index_json(names), content_type=pypi_render.JSON_CONTENT_TYPE
        )
    return Response(
        content=pypi_render.render_index_html(names),
        media_type=pypi_render.HTML_CONTENT_TYPE,
    )


@router.get("/simple/{project}/")
@router.get("/simple/{project}")
async def simple_project(
    project: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_read),
    accept: str | None = Header(default=None),
    format: str | None = Query(default=None),
) -> Response:
    normalized = normalize_pypi_name(project)

    # PEP 503 requires the normalized URL; redirect so caches stay coherent.
    if project != normalized:
        return Response(
            status_code=status.HTTP_301_MOVED_PERMANENTLY,
            headers={"location": f"{settings.pypi_base}/simple/{normalized}/"},
        )

    policy = PolicyEngine(session)
    name_verdict = await policy.is_name_blocked(ECOSYSTEM, normalized)
    if name_verdict.blocked:
        return PlainTextResponse(
            name_verdict.reason or "package is blocked", status_code=status.HTTP_403_FORBIDDEN
        )

    as_json = pypi_render.wants_json(accept, format)
    cache_id = packages.cache_key("pypi", normalized, "json" if as_json else "html")
    cached = await cache_get_json(cache_id)
    if cached is not None:
        audit.record_download(
            audit.DownloadEvent(
                ecosystem="pypi",
                package_name=normalized,
                kind="metadata",
                user_id=identity.user_id,
                username=identity.username,
                ip=client_ip(request),
                user_agent=request.headers.get("user-agent"),
                cache_hit=True,
            )
        )
        if as_json:
            return json_response(cached, content_type=pypi_render.JSON_CONTENT_TYPE)
        return Response(content=cached["html"], media_type=pypi_render.HTML_CONTENT_TYPE)

    lookup = await packages.fetch_package(session, ECOSYSTEM, project)
    if lookup.package is None:
        return PlainTextResponse("Not Found", status_code=status.HTTP_404_NOT_FOUND)
    package = lookup.package

    await _scan_new_versions(session, package)
    excluded = await _blocked_versions(policy, package)

    if excluded and len(excluded) == len(package.versions):
        return PlainTextResponse(
            "all versions of this project are blocked by policy",
            status_code=status.HTTP_403_FORBIDDEN,
        )

    audit.record_download(
        audit.DownloadEvent(
            ecosystem="pypi",
            package_name=normalized,
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

    if as_json:
        payload = pypi_render.render_project_json(package, excluded_versions=excluded)
        await cache_set_json(cache_id, payload, settings.meta_cache_ttl)
        return json_response(payload, content_type=pypi_render.JSON_CONTENT_TYPE)

    html = pypi_render.render_project_html(package, excluded_versions=excluded)
    await cache_set_json(cache_id, {"html": html}, settings.meta_cache_ttl)
    return Response(content=html, media_type=pypi_render.HTML_CONTENT_TYPE)


# --------------------------------------------------------------------------- #
# Artifacts
# --------------------------------------------------------------------------- #
async def _locate_file(
    session: AsyncSession, project: str, filename: str
) -> tuple[Package, PackageVersion, PackageFile] | None:
    return await packages.locate_file(
        session, ECOSYSTEM, normalize_pypi_name(project), filename=filename
    )


@router.get("/files/{project}/{filename}")
async def get_file(
    project: str,
    filename: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_read),
) -> Response:
    started = time.perf_counter()

    # PEP 658 sidecar request.
    if filename.endswith(".metadata"):
        return await _get_core_metadata(session, project, filename[: -len(".metadata")])

    located = await _locate_file(session, project, filename)
    if located is None:
        return PlainTextResponse("Not Found", status_code=status.HTTP_404_NOT_FOUND)
    package, version_row, file_row = located

    verdict = await PolicyEngine(session).evaluate(
        ECOSYSTEM,
        package.normalized_name,
        version_row.version,
        max_cvss=version_row.max_cvss,
        has_fix=version_row.has_fix,
        scanned=bool(version_row.scanned_at),
    )
    if verdict.blocked:
        audit.record_download(
            audit.DownloadEvent(
                ecosystem="pypi",
                package_name=package.normalized_name,
                version=version_row.version,
                filename=filename,
                user_id=identity.user_id,
                username=identity.username,
                ip=client_ip(request),
                status=403,
            )
        )
        return PlainTextResponse(
            verdict.reason or "package is blocked", status_code=status.HTTP_403_FORBIDDEN
        )

    was_cached = bool(file_row.blob_sha256 and get_store().exists(file_row.blob_sha256))
    try:
        chunks, size, content_type = await artifacts.stream_artifact(session, file_row)
    except artifacts.DigestMismatch as exc:
        log.error("digest mismatch serving %s: %s", filename, exc)
        return PlainTextResponse(
            "artifact failed integrity verification", status_code=status.HTTP_502_BAD_GATEWAY
        )
    except artifacts.ArtifactError as exc:
        log.warning("artifact fetch failed: %s", exc)
        return PlainTextResponse(str(exc), status_code=status.HTTP_502_BAD_GATEWAY)

    await packages.bump_download_counters(session, package.id, file_row.id)
    await session.commit()

    audit.record_download(
        audit.DownloadEvent(
            ecosystem="pypi",
            package_name=package.normalized_name,
            version=version_row.version,
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

    return StreamingResponse(
        chunks,
        media_type=content_type or "application/octet-stream",
        headers={
            "content-length": str(size),
            "cache-control": "public, max-age=31536000, immutable",
            "etag": f'"{file_row.blob_sha256}"',
            "content-disposition": f'attachment; filename="{filename}"',
        },
    )


async def _get_core_metadata(session: AsyncSession, project: str, filename: str) -> Response:
    """PEP 658: serve ``*.dist-info/METADATA`` without the whole wheel."""
    located = await _locate_file(session, project, filename)
    if located is None:
        return PlainTextResponse("Not Found", status_code=status.HTTP_404_NOT_FOUND)
    package, version_row, file_row = located

    # Policy first. Without it this route both described a blocked release and,
    # on a cache miss below, fetched the blocked wheel from upstream to do so.
    verdict = await PolicyEngine(session).evaluate(
        ECOSYSTEM,
        package.normalized_name,
        version_row.version,
        max_cvss=version_row.max_cvss,
        has_fix=version_row.has_fix,
        scanned=bool(version_row.scanned_at),
    )
    if verdict.blocked:
        return PlainTextResponse(
            verdict.reason or "blocked", status_code=status.HTTP_403_FORBIDDEN
        )

    stored = (file_row.core_metadata or {}).get("_raw")
    if stored:
        return PlainTextResponse(stored, media_type="text/plain")

    # Not extracted yet: pull it out of the cached wheel. Read the METADATA
    # member straight from the blob on disk -- loading the whole wheel into
    # memory to reach a few kilobytes of text is how a handful of concurrent
    # `pip install torch` requests used to exhaust the container.
    await artifacts.ensure_cached(session, file_row)
    metadata = await asyncio.to_thread(
        pypi_publish.extract_wheel_metadata_from_path,
        get_store().blob_path(file_row.blob_sha256),
        file_row.filename,
    )
    if not metadata or "_raw" not in metadata:
        return PlainTextResponse("Not Found", status_code=status.HTTP_404_NOT_FOUND)

    file_row.core_metadata = {**(file_row.core_metadata or {}), "_raw": metadata["_raw"]}
    await session.commit()
    return PlainTextResponse(metadata["_raw"], media_type="text/plain")


# --------------------------------------------------------------------------- #
# Warehouse-compatible JSON API
# --------------------------------------------------------------------------- #
@router.get("/{project}/json")
async def project_json(
    project: str,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_read),
) -> Response:
    normalized = normalize_pypi_name(project)
    verdict = await PolicyEngine(session).is_name_blocked(ECOSYSTEM, normalized)
    if verdict.blocked:
        return json_response({"message": verdict.reason}, status.HTTP_403_FORBIDDEN)

    lookup = await packages.fetch_package(session, ECOSYSTEM, project)
    if lookup.package is None:
        return json_response({"message": "Not Found"}, status.HTTP_404_NOT_FOUND)
    # The simple index filters blocked versions; this view has to agree with
    # it, or the JSON API becomes a directory of the very releases the
    # registry refuses to serve, file URLs included.
    excluded = await _blocked_versions(PolicyEngine(session), lookup.package)
    return json_response(
        pypi_render.render_json_api_project(lookup.package, excluded_versions=excluded)
    )


# --------------------------------------------------------------------------- #
# Upload
# --------------------------------------------------------------------------- #
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
        target_id=f"pypi:{target}",
        success=False,
        ip=client_ip(request),
        detail={"reason": reason, **(extra or {})},
    )
    await session.commit()


@router.post("/legacy/")
@router.post("/legacy")
@router.post("/")
async def upload(
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_publish),
) -> Response:
    try:
        form = await request.form()
    except Exception:
        return upload_error("could not parse the multipart form", status.HTTP_400_BAD_REQUEST)

    upload_file = form.get("content")
    if upload_file is None or not hasattr(upload_file, "read"):
        return upload_error("'content' file part is required", status.HTTP_400_BAD_REQUEST)

    content = await upload_file.read()
    filename = upload_file.filename or ""
    content_type = upload_file.content_type or "application/octet-stream"

    # Collapse the multi-dict, preserving repeated keys as lists.
    fields: dict = {}
    for key in form:
        if key == "content":
            continue
        values = form.getlist(key)
        fields[key] = values if key in pypi_publish.MULTIVALUED or len(values) > 1 else values[0]

    try:
        parsed = pypi_publish.parse_upload(fields, filename, content, content_type)
    except pypi_publish.UploadError as exc:
        return upload_error(exc.message, exc.status_code)

    normalized = parsed.normalized_name

    verdict = await PolicyEngine(session).is_name_blocked(ECOSYSTEM, normalized)
    if verdict.blocked:
        await _record_publish_denied(session, request, identity, parsed.name, verdict.reason)
        return upload_error(verdict.reason or "package is blocked", status.HTTP_403_FORBIDDEN)

    # Ownership before any mutation: the block below flips `is_local`, after
    # which the package is authoritative and never refreshed from upstream.
    try:
        grant = await ownership.authorize_publish(
            session,
            ECOSYSTEM,
            parsed.name,
            user_id=identity.user_id,
            is_admin=identity.is_admin and identity.has_scope("admin"),
        )
        await ownership.assert_not_retired(
            session, ECOSYSTEM, normalized, parsed.normalized_version
        )
    except ownership.PublishDenied as denied:
        await _record_publish_denied(session, request, identity, parsed.name, denied.reason)
        return upload_error(denied.reason, denied.status_code)

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

    normalized_version = parsed.normalized_version
    version_row = next(
        (v for v in package.versions if v.normalized_version == normalized_version), None
    )

    # PyPI never overwrites: a duplicate filename is an error.
    if version_row is not None:
        # An existing release that came from upstream is not somewhere to add
        # files. Only the filename was checked before, so a wheel with a
        # different platform tag attached itself to the genuine release -- and
        # pip prefers the more specific tag, so an exact pin installed it.
        if not version_row.is_local:
            reason = (
                f"{parsed.name} {parsed.version} is mirrored from an upstream "
                "registry; files cannot be added to it here."
            )
            await _record_publish_denied(
                session, request, identity, f"{parsed.name}=={parsed.version}", reason
            )
            return upload_error(reason, status.HTTP_403_FORBIDDEN)
        for existing in version_row.files:
            if existing.filename == parsed.filename:
                return upload_error(
                    f"File already exists: {parsed.filename}", status.HTTP_400_BAD_REQUEST
                )
        if parsed.filetype == "sdist" and any(
            f.packagetype == "sdist" for f in version_row.files
        ):
            return upload_error(
                f"Only one sdist may be uploaded per release ({parsed.version})",
                status.HTTP_400_BAD_REQUEST,
            )

    stored = await get_store().put_bytes(parsed.content)
    try:
        pypi_publish.verify_digests(parsed, stored)
    except pypi_publish.UploadError as exc:
        return upload_error(exc.message, exc.status_code)

    # Inline CVE gate before the file becomes resolvable.
    scan = await inline_scan(session, ECOSYSTEM, parsed.name, parsed.version)
    cve_verdict = await PolicyEngine(session).evaluate(
        ECOSYSTEM,
        normalized,
        parsed.version,
        max_cvss=scan.max_score,
        has_fix=scan.has_fix,
        scanned=scan.scanned,
    )
    if cve_verdict.blocked:
        # Capture the actor before the rollback expires the ORM objects the
        # Identity is holding.
        actor = (identity.user_id, identity.username)
        # Discard the package row and its `is_local` flip. Committing them on
        # a refused publish froze a cached project at its current releases, or
        # created an empty local one that answered 404 for everybody.
        await session.rollback()
        await _record_publish_denied(
            session,
            request,
            identity,
            f"{parsed.name}=={parsed.version}",
            cve_verdict.reason,
            extra={"max_cvss": scan.max_score},
            actor=actor,
        )
        return upload_error(
            cve_verdict.reason or "blocked by CVE policy", status.HTTP_403_FORBIDDEN
        )

    if version_row is None:
        version_row = PackageVersion(
            package_id=package.id,
            version=parsed.version,
            normalized_version=normalized_version,
            metadata_json=pypi_publish.metadata_from_upload(parsed),
            requires_python=parsed.requires_python,
            is_local=True,
            published_at=datetime.now(UTC),
            max_cvss=scan.max_score,
            scanned_at=datetime.now(UTC) if scan.scanned else None,
        )
        session.add(version_row)
        package.versions.append(version_row)
        await session.flush()

    blob = await session.get(Blob, stored.sha256)
    if blob is None:
        session.add(Blob(sha256=stored.sha256, size=stored.size, path=stored.path, refcount=1))
    else:
        blob.refcount += 1

    core_metadata = pypi_publish.extract_wheel_metadata(parsed.content, parsed.filename)

    session.add(
        PackageFile(
            version_id=version_row.id,
            filename=parsed.filename,
            blob_sha256=stored.sha256,
            size=stored.size,
            content_type=parsed.content_type,
            sha256=stored.sha256,
            sha1=stored.sha1,
            md5=stored.md5,
            blake2b_256=stored.blake2b_256,
            packagetype=parsed.filetype,
            python_version=parsed.pyversion,
            requires_python=parsed.requires_python,
            core_metadata={"_raw": core_metadata["_raw"]} if core_metadata else None,
            upload_time=datetime.now(UTC),
            cached_at=datetime.now(UTC),
        )
    )

    # A project is free to put an entire licence text in the License field, and
    # some do; bound it rather than letting the insert fail.
    package.description = packages.coerce_text(parsed.summary) or package.description
    package.author = packages.coerce_text(parsed.author, 512) or package.author
    package.homepage = packages.coerce_text(parsed.home_page, 1024) or package.homepage
    package.license = packages.coerce_text(parsed.license, 255) or package.license
    if parsed.keyword_list:
        package.keywords = packages.coerce_keywords(parsed.keyword_list)

    from ..core.naming import sort_pypi_versions

    ordered = sort_pypi_versions([v.version for v in package.versions])
    package.latest_version = ordered[-1] if ordered else parsed.version

    if scan.scanned and scan.cves:
        await OsvScanner(session).apply_to_version(version_row, scan, parsed.name)

    await audit.record_audit(
        session,
        audit.PACKAGE_PUBLISHED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="package",
        target_id=f"pypi:{parsed.name}",
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={
            "version": parsed.version,
            "filename": parsed.filename,
            "filetype": parsed.filetype,
            "ecosystem": "pypi",
        },
    )
    await session.commit()
    await packages.invalidate_package_cache("pypi", normalized)

    await _forward_to_publish_targets(session, parsed)

    # Warehouse returns a bare 200 on success; twine only checks the status.
    return PlainTextResponse("", status_code=status.HTTP_200_OK)


async def _forward_to_publish_targets(
    session: AsyncSession, parsed: pypi_publish.UploadRequest
) -> None:
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

    payload = {
        **{k: v for k, v in parsed.raw_fields.items() if isinstance(v, str)},
        "name": parsed.name,
        "version": parsed.version,
        "filetype": parsed.filetype,
        "content": (parsed.filename, parsed.content, parsed.content_type),
    }
    for upstream in targets:
        try:
            provider = build_provider(upstream)
            if not provider.supports_publish:
                continue
            ok, message = await provider.publish(payload, "pypi")
            if not ok:
                log.warning("mirror upload to %s failed: %s", upstream.name, message)
        except Exception:
            log.exception("mirror upload to %s raised", upstream.name)


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
async def _scan_new_versions(session: AsyncSession, package: Package) -> None:
    if not settings.osv_inline_scan:
        return
    unscanned = [v for v in package.versions if v.scanned_at is None]
    if not unscanned:
        return

    from ..core.naming import sort_pypi_versions

    ordering = {v: i for i, v in enumerate(sort_pypi_versions([v.version for v in unscanned]))}
    targets = sorted(unscanned, key=lambda v: ordering.get(v.version, 0), reverse=True)[:25]

    scanner = OsvScanner(session)
    try:
        results = await scanner.scan_versions(
            ECOSYSTEM, [(package.name, v.version) for v in targets]
        )
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
