"""Cargo endpoints.

Mounted at ``/cargo``, so clients configure (in ``.cargo/config.toml``):

    [source.crates-io]
    replace-with = "minireg"

    [source.minireg]
    registry = "sparse+http://minireg.example.com/cargo/index/"

Routes:

    GET /index/config.json                      registry configuration
    GET /index/{prefix}/{name}                  the crate's index file
    GET /api/v1/crates/{name}/{version}/download   the .crate artifact

This is a mirror: there is no publish, yank or owners surface, and
``config.json`` deliberately omits the ``api`` key that would advertise one.
Cargo's source-replacement mechanism -- the way a mirror is meant to be wired
in -- requires the replacement to serve content identical to crates.io anyway,
so it could not host a private crate even if we implemented publishing.
"""

from __future__ import annotations

import logging
import time

import orjson
from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..core.cache import cache_get_json, cache_set_json
from ..core.deps import Identity, client_ip, rate_limited_read
from ..core.naming import cargo_index_prefix, is_valid_cargo_name, normalize_cargo_name
from ..db import get_session
from ..models import Ecosystem, Package, PackageFile, PackageVersion
from ..services import artifacts, audit, cargo_render, packages
from ..services.osv import OsvScanner
from ..services.policy import PolicyEngine
from ..services.storage import get_store

log = logging.getLogger(__name__)
router = APIRouter(tags=["cargo"])

ECOSYSTEM = Ecosystem.cargo


def json_response(payload, status_code: int = 200) -> Response:
    return Response(
        content=orjson.dumps(payload), status_code=status_code, media_type="application/json"
    )


def cargo_error(message: str, status_code: int) -> Response:
    """Cargo surfaces a registry's error body when it is shaped like this, and
    prints a much less helpful generic failure otherwise."""
    return json_response({"errors": [{"detail": message}]}, status_code)


# --------------------------------------------------------------------------- #
# Index
# --------------------------------------------------------------------------- #
@router.get("/index/config.json")
async def index_config(identity: Identity = Depends(rate_limited_read)) -> Response:
    return json_response(cargo_render.render_config_json())


@router.get("/index/{index_path:path}")
async def index_file(
    index_path: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_read),
) -> Response:
    """Serve one crate's index file.

    The requested path encodes the crate name twice -- once in the shard prefix
    and once in the final segment -- and we verify they agree. Serving
    ``se/rd/tokio`` would otherwise populate a cache entry under a path no
    client will ever ask for again, and mask a client-side bug as a slow mirror.
    """
    name = index_path.rsplit("/", 1)[-1]
    if not name or not is_valid_cargo_name(name):
        return cargo_error("not found", status.HTTP_404_NOT_FOUND)

    normalized = normalize_cargo_name(name)
    if index_path != f"{cargo_index_prefix(normalized)}/{normalized}":
        return cargo_error("not found", status.HTTP_404_NOT_FOUND)

    policy = PolicyEngine(session)
    name_verdict = await policy.is_name_blocked(ECOSYSTEM, normalized)
    if name_verdict.blocked:
        return cargo_error(
            name_verdict.reason or "crate is blocked", status.HTTP_403_FORBIDDEN
        )

    cache_id = packages.cache_key("cargo", normalized, "index")
    cached = await cache_get_json(cache_id)
    if cached is not None:
        audit.record_download(
            audit.DownloadEvent(
                ecosystem="cargo",
                package_name=normalized,
                kind="metadata",
                user_id=identity.user_id,
                username=identity.username,
                ip=client_ip(request),
                user_agent=request.headers.get("user-agent"),
                cache_hit=True,
            )
        )
        return Response(content=cached["index"], media_type=cargo_render.INDEX_CONTENT_TYPE)

    lookup = await packages.fetch_package(session, ECOSYSTEM, normalized)
    if lookup.package is None:
        return cargo_error("not found", status.HTTP_404_NOT_FOUND)
    package = lookup.package

    await _scan_new_versions(session, package)
    blocked = await _blocked_versions(policy, package)

    audit.record_download(
        audit.DownloadEvent(
            ecosystem="cargo",
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

    body = cargo_render.render_index(package, blocked_versions=blocked)
    await cache_set_json(cache_id, {"index": body}, settings.meta_cache_ttl)
    return Response(content=body, media_type=cargo_render.INDEX_CONTENT_TYPE)


# --------------------------------------------------------------------------- #
# Artifacts
# --------------------------------------------------------------------------- #
async def _locate_file(
    session: AsyncSession, name: str, version: str
) -> tuple[Package, PackageVersion, PackageFile] | None:
    return await packages.locate_file(
        session, ECOSYSTEM, normalize_cargo_name(name), version=version
    )


@router.get("/api/v1/crates/{name}/{version}/download")
async def download(
    name: str,
    version: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(rate_limited_read),
) -> Response:
    started = time.perf_counter()

    if not is_valid_cargo_name(name):
        return cargo_error("not found", status.HTTP_404_NOT_FOUND)

    located = await _locate_file(session, name, version)
    if located is None:
        return cargo_error("not found", status.HTTP_404_NOT_FOUND)
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
                ecosystem="cargo",
                package_name=package.normalized_name,
                version=version_row.version,
                filename=file_row.filename,
                user_id=identity.user_id,
                username=identity.username,
                ip=client_ip(request),
                status=403,
            )
        )
        return cargo_error(verdict.reason or "crate is blocked", status.HTTP_403_FORBIDDEN)

    was_cached = bool(file_row.blob_sha256 and get_store().exists(file_row.blob_sha256))
    try:
        chunks, size, content_type = await artifacts.stream_artifact(session, file_row)
    except artifacts.DigestMismatch as exc:
        # cksum in the index is what cargo verifies against, and it is the same
        # digest we just failed on -- serving the bytes anyway would turn a
        # detectable mirror fault into a confusing client-side checksum error.
        log.error("digest mismatch serving %s: %s", file_row.filename, exc)
        return cargo_error(
            "artifact failed integrity verification", status.HTTP_502_BAD_GATEWAY
        )
    except artifacts.ArtifactError as exc:
        log.warning("artifact fetch failed: %s", exc)
        return cargo_error(str(exc), status.HTTP_502_BAD_GATEWAY)

    await packages.bump_download_counters(session, package.id, file_row.id)
    await session.commit()

    audit.record_download(
        audit.DownloadEvent(
            ecosystem="cargo",
            package_name=package.normalized_name,
            version=version_row.version,
            filename=file_row.filename,
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
        media_type=content_type or cargo_render.CRATE_CONTENT_TYPE,
        headers={
            "content-length": str(size),
            "cache-control": "public, max-age=31536000, immutable",
            "etag": f'"{file_row.blob_sha256}"',
            "content-disposition": f'attachment; filename="{file_row.filename}"',
        },
    )


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
async def _scan_new_versions(session: AsyncSession, package: Package) -> None:
    if not settings.osv_inline_scan:
        return
    unscanned = [v for v in package.versions if v.scanned_at is None]
    if not unscanned:
        return

    from ..core.naming import sort_versions_for

    ordering = {
        v: i for i, v in enumerate(sort_versions_for("cargo", [v.version for v in unscanned]))
    }
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
