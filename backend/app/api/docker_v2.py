"""The /v2 HTTP surface: OCI distribution spec 1.1.

One catch-all route per method dispatches on the path suffix, because image
names contain slashes and FastAPI path templates cannot express "anything,
then /manifests/<ref>". Every response carries the API version header, and
every error is an OCI error body.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..core.deps import client_ip, enforce_rate_limit
from ..core.metrics import bump
from ..db import get_session
from ..docker import push as push_ops
from ..docker import registry as reg
from ..docker import scanning
from ..docker.auth import (
    RegistryIdentity,
    authenticate_basic,
    can_read,
    issue_token,
    parse_scopes,
    push_problem,
    resolve_registry_identity,
    unauthorized,
)
from ..docker.errors import API_VERSION_HEADER, RegistryError
from ..docker.naming import Target, is_digest, parse_v2_path
from ..docker.policy import evaluate_pull, load_policy
from ..docker.store import FillFailed
from ..models import DockerManifest, DockerRepository
from ..services import audit

log = logging.getLogger(__name__)
router = APIRouter()

_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]


def _mirror_host(request: Request) -> bool:
    mirror = settings.docker_mirror_hostname
    return bool(mirror) and (request.headers.get("host") or "").lower() == mirror.lower()


def _headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    return {**API_VERSION_HEADER, **(extra or {})}


@router.api_route("/v2", methods=_METHODS, include_in_schema=False)
@router.api_route("/v2/", methods=_METHODS, include_in_schema=False)
@router.api_route("/v2/{path:path}", methods=_METHODS, include_in_schema=False)
async def v2(request: Request, path: str = "", session: AsyncSession = Depends(get_session)):
    head = request.method == "HEAD"
    try:
        if not settings.docker_enabled:
            raise RegistryError("UNSUPPORTED", "the container registry is disabled", status=404)
        parsed = parse_v2_path(path)
        if parsed is None:
            raise RegistryError("NAME_INVALID", f"unrecognised registry path /v2/{path}", status=404)
        if parsed.endpoint == "token":
            return await _token(request, session)
        ident = await resolve_registry_identity(session, request)
        await enforce_rate_limit(request, ident.as_identity(), bucket="docker")
        if parsed.endpoint == "base":
            return await _base(request, ident)
        if parsed.endpoint == "catalog":
            return await _catalog(request, session, ident)
        assert parsed.name is not None
        return await _dispatch(request, session, ident, parsed.endpoint, parsed.name, parsed.reference)
    except RegistryError as exc:
        with contextlib.suppress(Exception):
            await session.rollback()
        if exc.status >= 500:
            log.warning("/v2/%s -> %s %s", path, exc.status, exc.message)
        return exc.response(head=head)
    except Exception as exc:
        from fastapi import HTTPException

        with contextlib.suppress(Exception):
            await session.rollback()
        if isinstance(exc, HTTPException) and exc.status_code == 429:
            return RegistryError(
                "TOOMANYREQUESTS", "rate limit exceeded", headers=dict(exc.headers or {})
            ).response(head=head)
        raise


# --------------------------------------------------------------------------- #
# /v2/ and /v2/token
# --------------------------------------------------------------------------- #
async def _base(request: Request, ident: RegistryIdentity) -> Response:
    if ident.access is None and ident.anonymous:
        # Always challenge. A 200 here tells Docker "this registry never
        # wants credentials", and the push that follows then fails with an
        # unhelpful "no basic auth credentials".
        raise unauthorized(request)
    return JSONResponse({}, headers=_headers())


async def _token(request: Request, session: AsyncSession) -> Response:
    """Docker token endpoint (GET) and OAuth2 password grant (POST)."""
    scopes: list[str] = list(request.query_params.getlist("scope"))
    form_secret: str | None = None
    if request.method == "POST":
        form = await request.form()
        scopes.extend(str(v) for v in form.getlist("scope") if v)
        secret = form.get("password") or form.get("refresh_token")
        form_secret = str(secret) if secret else None
    ident = await authenticate_basic(session, request, secret=form_secret) or RegistryIdentity()
    await enforce_rate_limit(request, ident.as_identity(), bucket="docker-token")
    if ident.anonymous and not settings.allow_anonymous_read:
        raise unauthorized(request)

    access = []
    for kind, name, actions in parse_scopes(scopes):
        if kind != "repository":
            continue
        granted: set[str] = set()
        mirror = _mirror_host(request)
        try:
            target = await reg.resolve_target(session, name, mirror_host=mirror)
        except RegistryError:
            continue
        if "pull" in actions and can_read(ident):
            granted.add("pull")
        wants_write = actions & {"push", "delete"} and not mirror and target.local
        if wants_write and push_problem(ident, target.canonical) is None:
            repo = await reg.get_repo(session, target, create=False)
            owner_ok = repo is None or repo.owner_user_id in (None, ident.user_id) or (
                ident.user is not None and ident.user.is_admin
            )
            if owner_ok:
                granted |= actions & {"push", "delete"}
        if granted:
            access.append({"type": "repository", "name": name, "actions": sorted(granted)})
    token, ttl = issue_token(ident, access)
    if not ident.anonymous:
        bump("docker.token.issued", kind="user")
    body = {
        "token": token,
        "access_token": token,
        "expires_in": ttl,
        "issued_at": datetime.now(UTC).isoformat(),
    }
    await session.commit()
    return JSONResponse(body, headers={"Cache-Control": "no-store"})


async def _catalog(request: Request, session: AsyncSession, ident: RegistryIdentity) -> Response:
    if ident.anonymous:
        raise unauthorized(request, "the catalogue requires a login", scope="registry:catalog:*")
    n = _int_param(request, "n", 100, 1000)
    last = request.query_params.get("last")
    names = await reg.catalog(session, n=n, last=last)
    headers = _headers()
    if len(names) == n and names:
        headers["Link"] = f'</v2/_catalog?n={n}&last={quote(names[-1])}>; rel="next"'
    return JSONResponse({"repositories": names}, headers=headers)


def _int_param(request: Request, name: str, default: int, maximum: int) -> int:
    raw = request.query_params.get(name)
    if raw is None or raw == "":
        return default
    try:
        return max(0, min(int(raw), maximum))
    except ValueError as exc:
        raise RegistryError("UNSUPPORTED", f"invalid {name}", status=400) from exc


# --------------------------------------------------------------------------- #
# Access control
# --------------------------------------------------------------------------- #
def _require(request: Request, ident: RegistryIdentity, name: str, action: str, target: Target) -> None:
    scope = f"repository:{name}:{action}"
    if ident.access is not None:
        if action in ident.access.get(name, set()):
            return
        # A bearer token from our realm that does not cover this action:
        # send the client back for one that does.
        if ident.anonymous or action != "pull":
            raise unauthorized(request, f"token does not grant {action} on {name}", scope=scope)
    if action == "pull":
        if can_read(ident):
            return
        raise unauthorized(request, "authentication required to pull", scope=scope)
    problem = push_problem(ident, target.canonical)
    if problem is None:
        return
    if ident.anonymous:
        raise unauthorized(request, problem, scope=scope)
    raise RegistryError("DENIED", problem)


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #
async def _dispatch(
    request: Request,
    session: AsyncSession,
    ident: RegistryIdentity,
    endpoint: str,
    name: str,
    reference: str | None,
) -> Response:
    method = request.method
    mirror = _mirror_host(request)
    target = await reg.resolve_target(session, name, mirror_host=mirror)
    # An upload session is part of a push whatever the method: a GET on one
    # (the client asking how much it has sent) needs push rights too, and an
    # anonymous one gets a challenge rather than an ownership error.
    writing = method in ("POST", "PUT", "PATCH", "DELETE") or endpoint in ("upload", "upload_session")
    if writing and (mirror or not target.local):
        raise RegistryError(
            "DENIED",
            f"{target.canonical} is a cached upstream repository; images can only be "
            f"pushed under '{settings.docker_local_namespace}/'",
        )
    _require(request, ident, name, "push" if writing else "pull", target)

    if endpoint == "manifest":
        assert reference is not None
        if method in ("GET", "HEAD"):
            return await _get_manifest(request, session, ident, target, name, reference)
        if method == "PUT":
            return await _put_manifest(request, session, ident, target, name, reference)
        if method == "DELETE":
            return await _delete_manifest(request, session, ident, target, reference)
    elif endpoint == "blob":
        assert reference is not None
        if method in ("GET", "HEAD"):
            return await _get_blob(request, session, ident, target, name, reference)
        if method == "DELETE":
            repo = await _local_repo(session, target, ident, write=True)
            await push_ops.delete_blob(session, repo, reference)
            await session.commit()
            return Response(status_code=202, headers=_headers())
    elif endpoint == "upload" and method == "POST":
        return await _start_upload(request, session, ident, target, name)
    elif endpoint == "upload_session":
        assert reference is not None
        return await _upload_session(request, session, ident, target, name, reference)
    elif endpoint == "tags" and method == "GET":
        repo = await reg.get_repo(session, target, create=False)
        _check_quarantine(ident, repo)
        n_raw = request.query_params.get("n")
        n = _int_param(request, "n", 1000, 10000) if n_raw is not None else None
        tags = await reg.list_tags(session, target, repo, n=n, last=request.query_params.get("last"))
        headers = _headers()
        if n and len(tags) == n:
            headers["Link"] = f'</v2/{name}/tags/list?n={n}&last={quote(tags[-1])}>; rel="next"'
        return JSONResponse({"name": name, "tags": tags}, headers=headers)
    elif endpoint == "referrers" and method == "GET":
        assert reference is not None
        if not is_digest(reference):
            raise RegistryError("DIGEST_INVALID", "referrers are looked up by digest")
        repo = await reg.get_repo(session, target, create=False)
        artifact_type = request.query_params.get("artifactType")
        body = await reg.referrers(session, target, repo, reference, artifact_type)
        headers = _headers({"Content-Type": "application/vnd.oci.image.index.v1+json"})
        if artifact_type:
            headers["OCI-Filters-Applied"] = "artifactType"
        import orjson

        return Response(orjson.dumps(body), headers=headers, media_type=headers["Content-Type"])
    raise RegistryError("UNSUPPORTED", f"{method} is not supported here", status=405)


def _check_quarantine(ident: RegistryIdentity, repo: DockerRepository | None) -> None:
    if repo is not None and repo.quarantined and not ident.scanner:
        raise RegistryError(
            "DENIED",
            f"repository {repo.name} is quarantined"
            + (f": {repo.quarantine_reason}" if repo.quarantine_reason else ""),
        )


async def _local_repo(
    session: AsyncSession, target: Target, ident: RegistryIdentity, *, write: bool
) -> DockerRepository:
    if write:
        return await push_ops.repo_for_push(session, target, ident)
    repo = await reg.get_repo(session, target, create=False)
    if repo is None:
        raise RegistryError("NAME_UNKNOWN", f"repository {target.canonical} not found")
    return repo


def _log_download(
    request: Request,
    ident: RegistryIdentity,
    target: Target,
    *,
    reference: str | None,
    digest: str | None,
    kind: str,
    status: int,
    size: int = 0,
    cache_hit: bool = True,
    started: float | None = None,
) -> None:
    audit.record_download(
        audit.DownloadEvent(
            ecosystem="docker",
            package_name=target.canonical[:512],
            version=(reference or digest or "")[:128] or None,
            filename=digest,
            kind=kind,
            user_id=ident.user_id,
            username=ident.username,
            token_id=ident.token_id,
            ip=client_ip(request),
            user_agent=(request.headers.get("user-agent") or "")[:512] or None,
            bytes_sent=size,
            cache_hit=cache_hit,
            upstream_id=getattr(target.upstream, "id", None),
            status=status,
            duration_ms=int((time.perf_counter() - started) * 1000) if started else None,
        )
    )


# --------------------------------------------------------------------------- #
# Manifests
# --------------------------------------------------------------------------- #
async def _get_manifest(
    request: Request,
    session: AsyncSession,
    ident: RegistryIdentity,
    target: Target,
    name: str,
    reference: str,
) -> Response:
    started = time.perf_counter()
    head = request.method == "HEAD"
    repo = await reg.get_repo(session, target, create=not target.local)
    if repo is None:
        raise RegistryError("NAME_UNKNOWN", f"repository {target.canonical} not found")
    _check_quarantine(ident, repo)
    served = await reg.get_manifest(session, target, repo, reference, head=head)
    manifest = served.manifest

    if not ident.scanner:
        policy = await load_policy(session)
        pending = ("unscanned", "queued", "scanning")
        if manifest.kind == "image" and policy.scanning_enabled and not repo.quarantined:
            # Queue before judging: under strict mode (or for a pushed image)
            # an unscanned image is refused until its scan lands, so the scan
            # has to be queued by the very request that gets refused.
            await _maybe_scan(session, repo, manifest, policy)
            local = manifest.upstream_id is None
            hold_seconds = 0.0
            if manifest.scan_status in pending:
                if local and policy.push_require_scan:
                    # Pushed image: the scan is local and fast; wait for it.
                    hold_seconds = policy.hold_seconds or 15
                elif (
                    not local
                    and policy.hold_enabled
                    and manifest.total_size <= policy.hold_max_bytes
                ):
                    hold_seconds = policy.hold_seconds
            if hold_seconds:
                manifest = await _hold_for_scan(session, manifest, hold_seconds)
        verdict = await evaluate_pull(session, repo, manifest, policy)
        if not verdict.allowed:
            await _record_denial(request, session, ident, target, manifest, verdict.reason or "")
            _log_download(
                request, ident, target, reference=reference, digest=manifest.digest,
                kind="metadata", status=403 if verdict.code == "DENIED" else 503, started=started,
            )
            headers = {"Retry-After": str(verdict.retry_after)} if verdict.retry_after else None
            raise RegistryError(verdict.code, verdict.reason or "blocked by policy", headers=headers)
        await reg.touch(session, repo, manifest)
    await session.commit()

    _log_download(
        request, ident, target, reference=reference, digest=manifest.digest, kind="metadata",
        status=200, size=manifest.size, cache_hit=served.source in ("hit", "revalidated", "stale"),
        started=started,
    )
    headers = _headers(
        {
            "Docker-Content-Digest": manifest.digest,
            "Content-Type": manifest.media_type,
            "Content-Length": str(manifest.size),
            "ETag": f'"{manifest.digest}"',
            "X-Minireg-Cache": served.source,
        }
    )
    if head:
        return Response(status_code=200, headers=headers)
    return Response(served.body, status_code=200, headers=headers, media_type=manifest.media_type)


async def _maybe_scan(session: AsyncSession, repo: DockerRepository, manifest: DockerManifest, policy) -> None:
    if manifest.scan_status not in ("unscanned", "failed"):
        return
    if not policy.scan_on_pull and manifest.upstream_id is not None:
        return
    if not policy.scans_platform(manifest.platform):
        return
    priority = scanning.PRIORITY_PUSH if manifest.upstream_id is None else scanning.PRIORITY_PULL
    await scanning.enqueue(session, manifest, repo.name, reason="pull", priority=priority)
    await session.commit()


async def _hold_for_scan(session: AsyncSession, manifest: DockerManifest, seconds: float) -> DockerManifest:
    """Poll for the scan to land, up to ``seconds``."""
    await session.commit()
    deadline = time.monotonic() + max(0.0, seconds)
    job = (
        await session.execute(
            select(scanning.DockerScanJob).where(
                scanning.DockerScanJob.manifest_id == manifest.id,
                scanning.DockerScanJob.status == "queued",
            )
        )
    ).scalar_one_or_none()
    if job is not None and job.priority > scanning.PRIORITY_HOLD:
        job.priority = scanning.PRIORITY_HOLD
        await session.commit()
    bump("docker.scan.hold")
    while time.monotonic() < deadline:
        await asyncio.sleep(0.5)
        await session.refresh(manifest)
        if manifest.scan_status in ("scanned", "failed", "not_applicable"):
            bump("docker.scan.hold_resolved")
            return manifest
    bump("docker.scan.hold_timeout")
    return manifest


async def _record_denial(request, session, ident, target, manifest, reason: str) -> None:
    await audit.record_audit(
        session,
        audit.PACKAGE_BLOCKED,
        actor_user_id=ident.user_id,
        actor_username=ident.username,
        actor_type="token" if ident.token else "anonymous",
        target_type="image",
        target_id=f"{target.canonical}@{manifest.digest}"[:255],
        success=False,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={"ecosystem": "docker", "reason": reason, "digest": manifest.digest},
    )
    await session.commit()


async def _read_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise RegistryError("SIZE_INVALID", f"body is over the {limit} byte limit", status=413)
    buf = bytearray()
    async for chunk in request.stream():
        buf.extend(chunk)
        if len(buf) > limit:
            raise RegistryError("SIZE_INVALID", f"body is over the {limit} byte limit", status=413)
    return bytes(buf)


async def _put_manifest(
    request: Request,
    session: AsyncSession,
    ident: RegistryIdentity,
    target: Target,
    name: str,
    reference: str,
) -> Response:
    repo = await _local_repo(session, target, ident, write=True)
    body = await _read_body(request, settings.docker_max_manifest_bytes)
    manifest = await push_ops.put_manifest(
        session, target, repo, reference, body, request.headers.get("content-type"), ident
    )
    policy = await load_policy(session)
    if policy.scanning_enabled:
        await scanning.enqueue(session, manifest, repo.name, reason="push", priority=scanning.PRIORITY_PUSH)
    await audit.record_audit(
        session,
        "registry.docker.push",
        actor_user_id=ident.user_id,
        actor_username=ident.username,
        actor_type="token",
        target_type="image",
        target_id=f"{target.canonical}@{manifest.digest}"[:255],
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={
            "repository": target.canonical,
            "reference": reference,
            "digest": manifest.digest,
            "token_id": ident.token_id,
            "media_type": manifest.media_type,
        },
    )
    await session.commit()
    headers = _headers(
        {
            "Location": f"/v2/{name}/manifests/{manifest.digest}",
            "Docker-Content-Digest": manifest.digest,
        }
    )
    if manifest.subject_digest:
        headers["OCI-Subject"] = manifest.subject_digest
    return Response(status_code=201, headers=headers)


async def _delete_manifest(
    request: Request, session: AsyncSession, ident: RegistryIdentity, target: Target, reference: str
) -> Response:
    repo = await _local_repo(session, target, ident, write=True)
    if is_digest(reference):
        await push_ops.delete_manifest(session, repo, reference)
    else:
        await push_ops.delete_tag(session, repo, reference)
    await audit.record_audit(
        session,
        "registry.docker.delete",
        actor_user_id=ident.user_id,
        actor_username=ident.username,
        target_type="image",
        target_id=f"{target.canonical}:{reference}"[:255],
        ip=client_ip(request),
        detail={"repository": target.canonical, "reference": reference},
    )
    await session.commit()
    return Response(status_code=202, headers=_headers())


# --------------------------------------------------------------------------- #
# Blobs
# --------------------------------------------------------------------------- #
def _parse_range(value: str | None) -> tuple[int, int | None] | None:
    if not value or not value.startswith("bytes="):
        return None
    spec = value[6:].split(",")[0].strip()
    start_s, _, end_s = spec.partition("-")
    try:
        if start_s == "":
            return None  # suffix ranges: serve the whole blob
        start = int(start_s)
        end = int(end_s) if end_s else None
    except ValueError:
        return None
    if start < 0 or (end is not None and end < start):
        return None
    return start, end


async def _get_blob(
    request: Request,
    session: AsyncSession,
    ident: RegistryIdentity,
    target: Target,
    name: str,
    digest: str,
) -> Response:
    started = time.perf_counter()
    if not is_digest(digest):
        raise RegistryError("DIGEST_INVALID", f"unsupported digest {digest!r}")
    repo = await reg.get_repo(session, target, create=not target.local)
    if repo is None:
        raise RegistryError("NAME_UNKNOWN", f"repository {target.canonical} not found")
    _check_quarantine(ident, repo)

    if request.method == "HEAD":
        size = await reg.head_blob(session, target, repo, digest)
        await session.commit()
        return Response(
            status_code=200,
            headers=_headers(
                {
                    "Docker-Content-Digest": digest,
                    "Content-Length": str(size),
                    "Content-Type": "application/octet-stream",
                    "Accept-Ranges": "bytes",
                }
            ),
        )

    byte_range = _parse_range(request.headers.get("range"))
    blob = await reg.open_blob(session, target, repo, digest, byte_range=byte_range)
    await session.commit()
    headers = _headers(
        {
            "Docker-Content-Digest": digest,
            "Content-Type": "application/octet-stream",
            "Accept-Ranges": "bytes",
            "ETag": f'"{digest}"',
            "Cache-Control": "max-age=31536000, immutable",
        }
    )
    status = 200
    if blob.range is not None and blob.size is not None:
        start, end = blob.range
        headers["Content-Range"] = f"bytes {start}-{end}/{blob.size}"
        headers["Content-Length"] = str(end - start + 1)
        status = 206
    elif blob.size is not None:
        headers["Content-Length"] = str(blob.size)

    _log_download(
        request, ident, target, reference=None, digest=digest, kind="file", status=status,
        size=int(headers.get("Content-Length", 0)), cache_hit=blob.cached, started=started,
    )
    return StreamingResponse(_guarded(blob.chunks, digest), status_code=status, headers=headers)


async def _guarded(chunks: AsyncIterator[bytes], digest: str) -> AsyncIterator[bytes]:
    try:
        async for chunk in chunks:
            yield chunk
    except FillFailed as exc:
        # Headers are gone; the only signal left is a short body. The client
        # will see a truncated or digest-mismatched blob and retry.
        log.warning("aborting blob %s mid-stream: %s", digest, exc)
        bump("docker.blob.aborted")
        raise


# --------------------------------------------------------------------------- #
# Uploads
# --------------------------------------------------------------------------- #
def _upload_headers(name: str, upload_id: str, size: int) -> dict[str, str]:
    return _headers(
        {
            "Location": f"/v2/{name}/blobs/uploads/{upload_id}",
            "Docker-Upload-UUID": upload_id,
            "Range": f"0-{max(size - 1, 0)}",
            # No Content-Length here: the framework sets it from the actual
            # body. These headers also ride on a 416 error, whose body is
            # JSON; a hard-coded "0" there left the JSON on the kept-alive
            # connection, where the client read it as the start of the next
            # response.
        }
    )


async def _start_upload(
    request: Request, session: AsyncSession, ident: RegistryIdentity, target: Target, name: str
) -> Response:
    repo = await _local_repo(session, target, ident, write=True)
    mount = request.query_params.get("mount")
    source_name = request.query_params.get("from")
    if mount and is_digest(mount):
        source = None
        if source_name:
            try:
                src_target = await reg.resolve_target(session, source_name, mirror_host=False)
                allowed = ident.access is None or "pull" in ident.access.get(source_name, set())
                if allowed and can_read(ident):
                    source = await reg.get_repo(session, src_target, create=False)
            except RegistryError:
                source = None
        if await push_ops.mount_blob(session, repo, mount, source, ident):
            await session.commit()
            return Response(
                status_code=201,
                headers=_headers(
                    {"Location": f"/v2/{name}/blobs/{mount}", "Docker-Content-Digest": mount}
                ),
            )
    digest = request.query_params.get("digest")
    upload = await push_ops.start_upload(session, repo, ident)
    if digest:
        # Monolithic upload: the body is the whole blob.
        await get_store_append(request, upload.id)
        await push_ops.finish_upload(session, repo, upload, digest)
        await session.commit()
        return Response(
            status_code=201,
            headers=_headers({"Location": f"/v2/{name}/blobs/{digest}", "Docker-Content-Digest": digest}),
        )
    await session.commit()
    return Response(status_code=202, headers=_upload_headers(name, upload.id, 0))


async def get_store_append(request: Request, upload_id: str) -> int:
    from ..docker.store import get_oci_store

    return await get_oci_store().upload_append(
        upload_id, request.stream(), settings.docker_max_blob_bytes
    )


async def _upload_session(
    request: Request,
    session: AsyncSession,
    ident: RegistryIdentity,
    target: Target,
    name: str,
    upload_id: str,
) -> Response:
    from ..docker.store import get_oci_store

    repo = await _local_repo(session, target, ident, write=True)
    upload = await push_ops.get_upload(session, repo, upload_id)
    if upload.user_id is not None and upload.user_id != ident.user_id:
        raise RegistryError("BLOB_UPLOAD_UNKNOWN", "upload session not found")
    store = get_oci_store()
    method = request.method
    if method == "GET":
        size = store.upload_size(upload.id)
        return Response(status_code=204, headers=_upload_headers(name, upload.id, size))
    if method == "DELETE":
        store.upload_discard(upload.id)
        await session.delete(upload)
        await session.commit()
        return Response(status_code=204, headers=_headers())
    if method in ("PATCH", "PUT"):
        current = store.upload_size(upload.id)
        content_range = request.headers.get("content-range")
        if content_range and method == "PATCH":
            start = content_range.replace("bytes", "").strip().split("-")[0].strip()
            if not start.isdigit() or int(start) != current:
                raise RegistryError(
                    "RANGE_INVALID",
                    f"chunk starts at {start}; the upload has {current} bytes",
                    headers=_upload_headers(name, upload.id, current),
                )
        size = await get_store_append(request, upload.id)
        upload.size = size
        upload.updated_at = datetime.now(UTC)
        if method == "PATCH":
            await session.commit()
            return Response(status_code=202, headers=_upload_headers(name, upload.id, size))
        digest = request.query_params.get("digest")
        if not digest:
            raise RegistryError("DIGEST_INVALID", "PUT to finish an upload needs ?digest=")
        await push_ops.finish_upload(session, repo, upload, digest)
        await session.commit()
        return Response(
            status_code=201,
            headers=_headers({"Location": f"/v2/{name}/blobs/{digest}", "Docker-Content-Digest": digest}),
        )
    raise RegistryError("UNSUPPORTED", f"{method} is not supported on an upload", status=405)
