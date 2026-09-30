"""Pull-through and local image storage: the logic behind /v2.

Rate-limit economics drive most of this. Docker Hub counts a manifest GET
as a pull and does not count a HEAD, and every CI job, every
``imagePullPolicy: Always`` pod start and every ``docker pull`` resolves a
tag. So:

* a cached tag younger than DOCKER_TAG_TTL_SECONDS is answered locally;
* an older one is revalidated with a HEAD, and only a *changed* digest costs
  a GET -- by digest, once, however many clients asked;
* concurrent revalidations of one tag collapse into one (single flight);
* "not found" is remembered briefly, so a typo retried in a loop does not
  burn quota;
* when the upstream is unreachable, rate-limiting us, or erroring, the last
  good answer is served and the event counted. Without this a cache relays
  every upstream outage to every client.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..core.cache import cache_get_json, cache_set_json, herd_guard
from ..core.metrics import bump
from ..models import (
    DockerBlob,
    DockerManifest,
    DockerManifestRef,
    DockerRepoBlob,
    DockerRepoManifest,
    DockerRepository,
    DockerTag,
    Ecosystem,
    Upstream,
)
from . import manifest as mf
from .errors import RegistryError
from .naming import HUB_UPSTREAM_NAME, Target, is_digest, is_tag, route, valid_name
from .store import get_oci_store
from .upstream import (
    BlockedTarget,
    RegistryClient,
    UpstreamNotFound,
    UpstreamUnavailable,
)

log = logging.getLogger(__name__)

_clients: dict[tuple[int, str], RegistryClient] = {}


def client_for(upstream: Upstream) -> RegistryClient:
    """Clients are cached per upstream so bearer tokens are reused. Keyed on
    the row's config so an edited upstream gets a fresh client."""
    key = (upstream.id, f"{upstream.url}|{upstream.credential_enc}|{upstream.extra}")
    client = _clients.get(key)
    if client is None:
        for stale in [k for k in _clients if k[0] == upstream.id]:
            _clients.pop(stale, None)
        client = RegistryClient(upstream)
        _clients[key] = client
    return client


# --------------------------------------------------------------------------- #
# Routing
# --------------------------------------------------------------------------- #
_upstream_cache: tuple[float, dict[str, int], int | None] | None = None


async def docker_upstreams(session: AsyncSession) -> tuple[dict[str, Upstream], Upstream | None]:
    rows = (
        await session.execute(
            select(Upstream).where(
                Upstream.ecosystem == Ecosystem.docker, Upstream.enabled.is_(True)
            ).order_by(Upstream.tier, Upstream.priority, Upstream.id)
        )
    ).scalars().all()
    by_name = {u.name: u for u in rows}
    default = next((u for u in rows if (u.extra or {}).get("default")), None)
    if default is None:
        default = by_name.get(HUB_UPSTREAM_NAME)
    return by_name, default


async def resolve_target(session: AsyncSession, name: str, *, mirror_host: bool) -> Target:
    if not valid_name(name):
        raise RegistryError("NAME_INVALID", f"invalid repository name {name!r}")
    upstreams, default = await docker_upstreams(session)
    disabled = set(
        (
            await session.execute(
                select(Upstream.name).where(
                    Upstream.ecosystem == Ecosystem.docker, Upstream.enabled.is_(False)
                )
            )
        ).scalars().all()
    )
    try:
        target = route(
            name, upstreams, default_upstream=default, mirror_host=mirror_host, disabled=disabled
        )
    except LookupError as exc:
        raise RegistryError("NAME_UNKNOWN", str(exc)) from exc
    if not valid_name(target.canonical):
        raise RegistryError("NAME_INVALID", f"invalid repository name {target.canonical!r}")
    return target


async def get_repo(session: AsyncSession, target: Target, *, create: bool) -> DockerRepository | None:
    repo = (
        await session.execute(select(DockerRepository).where(DockerRepository.name == target.canonical))
    ).scalar_one_or_none()
    if repo is not None or not create:
        return repo
    repo = DockerRepository(
        name=target.canonical,
        upstream_id=getattr(target.upstream, "id", None),
        remote_name=target.remote,
        is_local=target.local,
    )
    try:
        async with session.begin_nested():
            session.add(repo)
            await session.flush()
    except IntegrityError:
        repo = (
            await session.execute(
                select(DockerRepository).where(DockerRepository.name == target.canonical)
            )
        ).scalar_one()
    return repo


# --------------------------------------------------------------------------- #
# Manifests
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class ServedManifest:
    manifest: DockerManifest
    body: bytes | None
    #: hit | revalidated | fetched | stale
    source: str
    tag: str | None = None


async def _manifest_row(session: AsyncSession, digest: str) -> DockerManifest | None:
    return (
        await session.execute(select(DockerManifest).where(DockerManifest.digest == digest))
    ).scalar_one_or_none()


async def _linked(session: AsyncSession, repo: DockerRepository, manifest: DockerManifest) -> bool:
    return (
        await session.execute(
            select(DockerRepoManifest.id).where(
                DockerRepoManifest.repository_id == repo.id,
                DockerRepoManifest.manifest_id == manifest.id,
            )
        )
    ).first() is not None


async def link(session: AsyncSession, repo: DockerRepository, manifest: DockerManifest) -> None:
    if await _linked(session, repo, manifest):
        return
    try:
        async with session.begin_nested():
            session.add(DockerRepoManifest(repository_id=repo.id, manifest_id=manifest.id))
            await session.flush()
    except IntegrityError:
        pass


async def store_manifest(
    session: AsyncSession,
    body: bytes,
    content_type: str | None,
    *,
    expected_digest: str | None,
    upstream_id: int | None,
    pushed_by: int | None = None,
) -> DockerManifest:
    """Record a manifest by its exact bytes, returning the (possibly
    pre-existing) row."""
    parsed = mf.parse(body, content_type)
    store = get_oci_store()
    digest = await store.put_bytes(body, expected=expected_digest)
    existing = await _manifest_row(session, digest)
    if existing is not None:
        return existing

    platform = None
    kind = parsed.kind
    if not parsed.is_index:
        # The index that named this child already recorded its platform, and
        # whether it is a BuildKit attestation rather than a runnable image.
        # Clients fetch the index first, so this is the common order.
        parent_ref = (
            await session.execute(
                select(DockerManifestRef)
                .where(DockerManifestRef.digest == digest, DockerManifestRef.ref_type == "manifest")
                .limit(1)
            )
        ).scalar_one_or_none()
        if parent_ref is not None:
            platform = parent_ref.platform
            if mf.is_attestation_entry(parent_ref):
                kind = "attestation"
                platform = None

    row = DockerManifest(
        digest=digest,
        media_type=parsed.media_type,
        size=len(body),
        is_index=parsed.is_index,
        kind=kind,
        artifact_type=parsed.artifact_type,
        config_digest=parsed.config_digest,
        config_media_type=parsed.config_media_type,
        platform=platform,
        total_size=parsed.total_size,
        layer_count=parsed.layer_count,
        subject_digest=parsed.subject_digest,
        annotations=parsed.annotations,
        upstream_id=upstream_id,
        pushed_by_user_id=pushed_by,
        scan_status="unscanned" if kind == "image" else "not_applicable",
    )
    try:
        async with session.begin_nested():
            session.add(row)
            await session.flush()
            for ref in parsed.refs:
                session.add(
                    DockerManifestRef(
                        manifest_id=row.id,
                        ref_type=ref.ref_type,
                        digest=ref.digest,
                        media_type=ref.media_type,
                        size=ref.size,
                        position=ref.position,
                        platform=ref.platform,
                        annotations=ref.annotations,
                    )
                )
            await session.flush()
    except IntegrityError:
        existing = await _manifest_row(session, digest)
        if existing is None:
            raise
        return existing
    if parsed.is_index:
        # Children fetched earlier (by digest) learn their platform now.
        for ref in parsed.refs:
            if ref.platform:
                await session.execute(
                    update(DockerManifest)
                    .where(DockerManifest.digest == ref.digest, DockerManifest.platform.is_(None))
                    .values(platform=ref.platform)
                )
            if mf.is_attestation_entry(ref):
                await session.execute(
                    update(DockerManifest)
                    .where(DockerManifest.digest == ref.digest)
                    .values(kind="attestation", scan_status="not_applicable")
                )
    bump("docker.manifest.stored")
    return row


def _neg_key(target: Target, reference: str) -> str:
    return f"docker:neg:{target.canonical}:{reference}"


_local_neg: dict[str, float] = {}


async def _negative_hit(target: Target, reference: str) -> bool:
    key = _neg_key(target, reference)
    if (_local_neg.get(key) or 0) > time.monotonic():
        return True
    return bool(await cache_get_json(key))


async def _remember_missing(target: Target, reference: str) -> None:
    ttl = settings.docker_negative_cache_ttl_seconds
    if ttl <= 0:
        return
    key = _neg_key(target, reference)
    _local_neg[key] = time.monotonic() + ttl
    if len(_local_neg) > 20000:
        now = time.monotonic()
        for k in [k for k, v in _local_neg.items() if v < now]:
            _local_neg.pop(k, None)
    await cache_set_json(key, {"missing": True}, ttl)


def _unavailable(exc: UpstreamUnavailable | BlockedTarget, what: str) -> RegistryError:
    if isinstance(exc, BlockedTarget):
        return RegistryError("DENIED", f"refused to contact the upstream: {exc}", status=502)
    if exc.status == 429:
        headers = {"Retry-After": exc.retry_after} if exc.retry_after else {}
        return RegistryError(
            "TOOMANYREQUESTS",
            f"the upstream is rate limiting this registry and {what} is not cached yet",
            headers=headers,
        )
    return RegistryError(
        "UNAVAILABLE", f"the upstream is unavailable and {what} is not cached: {exc}", status=502
    )


async def get_manifest(
    session: AsyncSession,
    target: Target,
    repo: DockerRepository,
    reference: str,
    *,
    head: bool,
) -> ServedManifest:
    if is_digest(reference):
        return await _manifest_by_digest(session, target, repo, reference, head=head)
    if not is_tag(reference):
        # Not a valid tag, so no such manifest can exist here: the spec
        # answers that as "unknown" (404), not as a malformed request. It is
        # also never forwarded upstream.
        raise RegistryError("MANIFEST_UNKNOWN", f"no manifest {reference[:140]!r}: not a valid tag or digest")
    return await _manifest_by_tag(session, target, repo, reference, head=head)


async def _body(manifest: DockerManifest, head: bool) -> bytes | None:
    if head:
        return None
    body = await get_oci_store().read_bytes(manifest.digest)
    if body is None:
        raise RegistryError("MANIFEST_UNKNOWN", f"manifest {manifest.digest} bytes are missing")
    return body


async def _manifest_by_digest(
    session: AsyncSession, target: Target, repo: DockerRepository, digest: str, *, head: bool
) -> ServedManifest:
    row = await _manifest_row(session, digest)
    store = get_oci_store()
    have_bytes = row is not None and store.exists(digest)
    if have_bytes and await _linked(session, repo, row):
        return ServedManifest(row, await _body(row, head), "hit")
    if target.local:
        raise RegistryError("MANIFEST_UNKNOWN", f"manifest {digest} is not in {target.canonical}")

    # Known digest, not yet seen in this repository: content is verified by
    # digest either way, but make the upstream confirm the repository has it
    # so one repository cannot be used to serve another's images.
    client = client_for(target.upstream)
    if await _negative_hit(target, digest):
        raise RegistryError("MANIFEST_UNKNOWN", f"manifest {digest} not found upstream")
    try:
        async with herd_guard(f"docker-mf:{target.canonical}:{digest}", ttl=60):
            row = await _manifest_row(session, digest)
            if row is not None and store.exists(digest) and await _linked(session, repo, row):
                return ServedManifest(row, await _body(row, head), "hit")
            await session.commit()  # no transaction held across the network
            resp = await client.manifest(target.remote, digest)
            if resp.body is None:
                raise RegistryError("MANIFEST_UNKNOWN", "upstream returned no manifest body")
            row = await store_manifest(
                session, resp.body, resp.media_type, expected_digest=digest, upstream_id=target.upstream.id
            )
            await link(session, repo, row)
            await session.commit()
            bump("docker.manifest", result="fetched")
            return ServedManifest(row, None if head else resp.body, "fetched")
    except UpstreamNotFound as exc:
        await _remember_missing(target, digest)
        raise RegistryError("MANIFEST_UNKNOWN", f"manifest {digest} not found upstream") from exc
    except (UpstreamUnavailable, BlockedTarget) as exc:
        if have_bytes and row is not None:
            # Same bytes, verified by digest; serve rather than fail.
            await link(session, repo, row)
            await session.commit()
            bump("docker.manifest", result="stale")
            return ServedManifest(row, await _body(row, head), "stale")
        raise _unavailable(exc, f"manifest {digest}") from exc


async def _tag_row(session: AsyncSession, repo: DockerRepository, tag: str) -> DockerTag | None:
    return (
        await session.execute(
            select(DockerTag).where(DockerTag.repository_id == repo.id, DockerTag.tag == tag)
        )
    ).scalar_one_or_none()


def _fresh(tag: DockerTag) -> bool:
    checked = tag.checked_at
    if checked.tzinfo is None:
        checked = checked.replace(tzinfo=UTC)
    return datetime.now(UTC) - checked < timedelta(seconds=settings.docker_tag_ttl_seconds)


async def set_tag(
    session: AsyncSession, repo: DockerRepository, tag: str, manifest: DockerManifest, *, user_id=None
) -> None:
    row = await _tag_row(session, repo, tag)
    now = datetime.now(UTC)
    if row is None:
        try:
            async with session.begin_nested():
                session.add(
                    DockerTag(
                        repository_id=repo.id,
                        tag=tag,
                        manifest_id=manifest.id,
                        checked_at=now,
                        pushed_by_user_id=user_id,
                    )
                )
                await session.flush()
            return
        except IntegrityError:
            row = await _tag_row(session, repo, tag)
            if row is None:
                raise
    row.manifest_id = manifest.id
    row.checked_at = now
    if user_id is not None:
        row.pushed_by_user_id = user_id


async def _manifest_by_tag(
    session: AsyncSession, target: Target, repo: DockerRepository, tag: str, *, head: bool, force: bool = False
) -> ServedManifest:
    row = await _tag_row(session, repo, tag)
    if row is not None:
        manifest = await session.get(DockerManifest, row.manifest_id)
        usable = manifest is not None and (target.local or (not force and _fresh(row)))
        if usable and get_oci_store().exists(manifest.digest):
            bump("docker.manifest", result="hit")
            return ServedManifest(manifest, await _body(manifest, head), "hit", tag)
    if target.local:
        raise RegistryError("MANIFEST_UNKNOWN", f"{target.canonical}:{tag} not found")
    if row is None and await _negative_hit(target, tag):
        raise RegistryError("MANIFEST_UNKNOWN", f"{target.canonical}:{tag} not found upstream")

    async with herd_guard(f"docker-tag:{target.canonical}:{tag}", ttl=60):
        # A peer may have revalidated while we waited.
        await session.commit()
        row = await _tag_row(session, repo, tag)
        if row is not None:
            await session.refresh(row)
            manifest = await session.get(DockerManifest, row.manifest_id)
            if manifest is not None and not force and _fresh(row) and get_oci_store().exists(manifest.digest):
                bump("docker.manifest", result="hit")
                return ServedManifest(manifest, await _body(manifest, head), "hit", tag)
        return await _revalidate(session, target, repo, tag, row, head=head)


async def _revalidate(
    session: AsyncSession,
    target: Target,
    repo: DockerRepository,
    tag: str,
    row: DockerTag | None,
    *,
    head: bool,
) -> ServedManifest:
    client = client_for(target.upstream)
    cached = await session.get(DockerManifest, row.manifest_id) if row is not None else None
    store = get_oci_store()
    # No transaction held across the network (see open_blob).
    await session.commit()
    try:
        if cached is not None and store.exists(cached.digest):
            probe = await client.manifest(target.remote, tag, head=True)
            if probe.digest and probe.digest == cached.digest:
                row.checked_at = datetime.now(UTC)
                await session.commit()
                bump("docker.manifest", result="revalidated")
                return ServedManifest(cached, await _body(cached, head), "revalidated", tag)
            if probe.digest:
                known = await _manifest_row(session, probe.digest)
                if known is not None and store.exists(known.digest):
                    # Moved to a digest we already hold (another repo, or a
                    # rollback): no GET needed.
                    await link(session, repo, known)
                    await set_tag(session, repo, tag, known)
                    await session.commit()
                    bump("docker.manifest", result="revalidated")
                    return ServedManifest(known, await _body(known, head), "revalidated", tag)
        # Cold, or the tag moved: one GET. By digest when the HEAD gave us
        # one, so the bytes we store are exactly the ones we verify.
        resp = await client.manifest(target.remote, tag)
        if resp.body is None:
            raise UpstreamUnavailable(f"{client.name}: empty manifest")
        expected = resp.digest if resp.digest and is_digest(resp.digest) else None
        manifest = await store_manifest(
            session, resp.body, resp.media_type, expected_digest=expected, upstream_id=target.upstream.id
        )
        await link(session, repo, manifest)
        await set_tag(session, repo, tag, manifest)
        await session.commit()
        bump("docker.manifest", result="fetched")
        return ServedManifest(manifest, None if head else resp.body, "fetched", tag)
    except UpstreamNotFound as exc:
        if row is not None:
            await session.delete(row)
            await session.commit()
        await _remember_missing(target, tag)
        raise RegistryError("MANIFEST_UNKNOWN", f"{target.canonical}:{tag} not found upstream") from exc
    except (UpstreamUnavailable, BlockedTarget) as exc:
        if cached is not None and store.exists(cached.digest):
            bump("docker.manifest", result="stale")
            bump("docker.serve_stale", upstream=client.name)
            log.warning(
                "serving cached %s:%s (%s) because the upstream failed: %s",
                target.canonical,
                tag,
                cached.digest,
                exc,
            )
            return ServedManifest(cached, await _body(cached, head), "stale", tag)
        raise _unavailable(exc, f"{target.canonical}:{tag}") from exc


async def refresh_tag(session: AsyncSession, target: Target, repo: DockerRepository, tag: str) -> ServedManifest:
    """Revalidate now, ignoring the TTL (watch list, admin refresh)."""
    return await _manifest_by_tag(session, target, repo, tag, head=True, force=True)


async def touch(session: AsyncSession, repo: DockerRepository, manifest: DockerManifest) -> None:
    """Record a pull. Batched writes would be cheaper; a manifest pull is
    rare enough next to blob traffic that one UPDATE is acceptable."""
    now = datetime.now(UTC)
    await session.execute(
        update(DockerRepoManifest)
        .where(DockerRepoManifest.repository_id == repo.id, DockerRepoManifest.manifest_id == manifest.id)
        .values(last_pulled_at=now, pull_count=DockerRepoManifest.pull_count + 1)
    )
    await session.execute(
        update(DockerManifest).where(DockerManifest.id == manifest.id).values(last_accessed_at=now)
    )
    await session.execute(
        update(DockerRepository)
        .where(DockerRepository.id == repo.id)
        .values(last_pulled_at=now, pull_count=DockerRepository.pull_count + 1)
    )


# --------------------------------------------------------------------------- #
# Blobs
# --------------------------------------------------------------------------- #
async def known_blob_size(session: AsyncSession, digest: str) -> int | None:
    blob = await session.get(DockerBlob, digest)
    if blob is not None:
        return blob.size
    return (
        await session.execute(
            select(DockerManifestRef.size).where(DockerManifestRef.digest == digest).limit(1)
        )
    ).scalar_one_or_none()


async def blob_in_repo(session: AsyncSession, repo: DockerRepository, digest: str) -> bool:
    """Whether ``digest`` belongs to this repository (pushed/mounted into it,
    or referenced by one of its manifests or their children)."""
    if (
        await session.execute(
            select(DockerRepoBlob.id).where(
                DockerRepoBlob.repository_id == repo.id, DockerRepoBlob.digest == digest
            )
        )
    ).first():
        return True
    manifest_ids = select(DockerRepoManifest.manifest_id).where(
        DockerRepoManifest.repository_id == repo.id
    )
    child_digests = select(DockerManifestRef.digest).where(
        DockerManifestRef.manifest_id.in_(manifest_ids), DockerManifestRef.ref_type == "manifest"
    )
    child_ids = select(DockerManifest.id).where(DockerManifest.digest.in_(child_digests))
    return (
        await session.execute(
            select(DockerManifestRef.id)
            .where(
                DockerManifestRef.digest == digest,
                or_(
                    DockerManifestRef.manifest_id.in_(manifest_ids),
                    DockerManifestRef.manifest_id.in_(child_ids),
                ),
            )
            .limit(1)
        )
    ).first() is not None


async def _record_blob(digest: str, size: int, upstream_id: int | None, media_type: str | None) -> None:
    from ..db import session_scope

    try:
        async with session_scope() as s:
            if await s.get(DockerBlob, digest) is None:
                s.add(DockerBlob(digest=digest, size=size, upstream_id=upstream_id, media_type=media_type))
    except IntegrityError:
        pass


@dataclass(slots=True)
class BlobResponse:
    chunks: AsyncIterator[bytes]
    size: int | None
    #: (start, end) inclusive when a range is being served.
    range: tuple[int, int] | None = None
    cached: bool = True


async def open_blob(
    session: AsyncSession,
    target: Target,
    repo: DockerRepository,
    digest: str,
    *,
    byte_range: tuple[int, int | None] | None = None,
) -> BlobResponse:
    store = get_oci_store()
    if store.exists(digest):
        if target.local and not await blob_in_repo(session, repo, digest):
            raise RegistryError("BLOB_UNKNOWN", f"blob {digest} is not in {target.canonical}")
        size = store.size_of(digest) or 0
        await session.execute(
            update(DockerBlob).where(DockerBlob.digest == digest).values(last_accessed_at=datetime.now(UTC))
        )
        if byte_range is not None:
            start, end = byte_range
            end = size - 1 if end is None or end >= size else end
            if start >= size or start > end:
                raise RegistryError(
                    "RANGE_INVALID",
                    f"range {start}-{end} is outside a {size} byte blob",
                    headers={"Content-Range": f"bytes */{size}"},
                )
            return BlobResponse(store.iter_file(digest, start, end), size, (start, end))
        bump("docker.blob", result="hit")
        return BlobResponse(store.iter_file(digest), size)

    if target.local:
        raise RegistryError("BLOB_UNKNOWN", f"blob {digest} is not in {target.canonical}")

    client = client_for(target.upstream)
    expected = await known_blob_size(session, digest)
    media_type = (
        await session.execute(
            select(DockerManifestRef.media_type).where(DockerManifestRef.digest == digest).limit(1)
        )
    ).scalar_one_or_none()
    upstream_id = target.upstream.id
    # End the transaction before touching the network. Opening the upstream
    # stream (token exchange, redirect, first byte) or waiting on another
    # request's download can take far longer than Postgres lets a
    # transaction sit idle; it then kills the connection under this request.
    await session.commit()

    async def opener():
        return await client.blob_stream(target.remote, digest)

    async def on_complete(d: str, size: int) -> None:
        await _record_blob(d, size, upstream_id, media_type)

    try:
        chunks = await store.fill_and_stream(
            digest, opener, expected_size=expected, on_complete=on_complete
        )
    except UpstreamNotFound as exc:
        raise RegistryError("BLOB_UNKNOWN", f"blob {digest} not found upstream") from exc
    except (UpstreamUnavailable, BlockedTarget) as exc:
        raise _unavailable(exc, f"blob {digest}") from exc
    bump("docker.blob", result="fetched")
    # A Range request against a blob still being filled gets the whole blob
    # with a 200, which every client handles.
    return BlobResponse(chunks, expected, None, cached=False)


async def head_blob(
    session: AsyncSession, target: Target, repo: DockerRepository, digest: str
) -> int:
    store = get_oci_store()
    size = store.size_of(digest)
    if size is not None:
        if target.local and not await blob_in_repo(session, repo, digest):
            raise RegistryError("BLOB_UNKNOWN", f"blob {digest} is not in {target.canonical}")
        return size
    if target.local:
        raise RegistryError("BLOB_UNKNOWN", f"blob {digest} is not in {target.canonical}")
    known = await known_blob_size(session, digest)
    if known is not None:
        return known
    # Unknown to us: ask the upstream without downloading.
    client = client_for(target.upstream)
    try:
        resp = await client._send(
            "HEAD", client.url_for(target.remote, f"blobs/{digest}"), remote=target.remote, purpose="blob"
        )
        await resp.aclose()
        client._raise_for(resp, f"blob {digest}", client.name)
        return int(resp.headers.get("content-length") or 0)
    except UpstreamNotFound as exc:
        raise RegistryError("BLOB_UNKNOWN", f"blob {digest} not found upstream") from exc
    except (UpstreamUnavailable, BlockedTarget) as exc:
        raise _unavailable(exc, f"blob {digest}") from exc


async def prefetch_image(session: AsyncSession, target: Target, manifest: DockerManifest) -> int:
    """Fill every layer of an image manifest (watch list, pull-time hold)."""
    if target.local or manifest.is_index:
        return 0
    refs = (
        await session.execute(
            select(DockerManifestRef).where(
                DockerManifestRef.manifest_id == manifest.id,
                DockerManifestRef.ref_type.in_(("blob", "config")),
            )
        )
    ).scalars().all()
    repo = await get_repo(session, target, create=True)
    fetched = 0

    async def one(digest: str) -> None:
        nonlocal fetched
        if get_oci_store().exists(digest):
            return
        resp = await open_blob(session, target, repo, digest)
        async for _ in resp.chunks:
            pass
        fetched += 1

    sem = asyncio.Semaphore(4)

    async def bounded(digest: str) -> None:
        async with sem:
            with contextlib.suppress(Exception):
                await one(digest)

    await asyncio.gather(*(bounded(r.digest) for r in refs))
    return fetched


# --------------------------------------------------------------------------- #
# Tags / referrers / catalogue
# --------------------------------------------------------------------------- #
async def list_tags(
    session: AsyncSession, target: Target, repo: DockerRepository | None, *, n: int | None, last: str | None
) -> list[str]:
    tags: list[str] = []
    if target.local:
        if repo is None:
            raise RegistryError("NAME_UNKNOWN", f"repository {target.canonical} not found")
    else:
        key = f"docker:tags:{target.canonical}"
        cached = await cache_get_json(key)
        if cached is not None:
            tags = cached
        else:
            try:
                tags = await client_for(target.upstream).tags(target.remote)
                await cache_set_json(key, tags, 300)
            except UpstreamNotFound as exc:
                raise RegistryError("NAME_UNKNOWN", f"repository {target.canonical} not found upstream") from exc
            except (UpstreamUnavailable, BlockedTarget):
                bump("docker.serve_stale", upstream=target.upstream_name or "?")
                tags = []
    if repo is not None:
        local_tags = (
            await session.execute(select(DockerTag.tag).where(DockerTag.repository_id == repo.id))
        ).scalars().all()
        tags = list(set(tags) | set(local_tags))
    tags.sort()
    if last:
        tags = [t for t in tags if t > last]
    if n is not None:
        tags = tags[: max(0, n)]
    return tags


async def referrers(
    session: AsyncSession, target: Target, repo: DockerRepository | None, digest: str, artifact_type: str | None
) -> dict:
    manifests: list[dict] = []
    if not target.local:
        # Clients (containerd, docker buildx, cosign) ask for referrers on
        # every pull. Without this cache each warm pull still cost an
        # upstream round trip and a token exchange. Referrers of a digest
        # change only when someone attaches a signature or SBOM, so the tag
        # TTL is fresh enough; a failed lookup is cached briefly as empty.
        key = f"docker:referrers:{target.upstream.name}:{target.remote}:{digest}"
        cached = await cache_get_json(key)
        if cached is not None:
            manifests.extend(cached)
        else:
            ttl = settings.docker_tag_ttl_seconds
            try:
                raw = await client_for(target.upstream).referrers(target.remote, digest)
            except (UpstreamUnavailable, BlockedTarget, UpstreamNotFound):
                raw = None
                ttl = settings.docker_negative_cache_ttl_seconds
            if raw:
                import orjson

                with contextlib.suppress(Exception):
                    doc = orjson.loads(raw)
                    for entry in doc.get("manifests") or []:
                        if isinstance(entry, dict) and is_digest(str(entry.get("digest"))):
                            manifests.append(entry)
            await cache_set_json(key, manifests[:256], ttl)
    if repo is not None:
        rows = (
            await session.execute(
                select(DockerManifest)
                .join(DockerRepoManifest, DockerRepoManifest.manifest_id == DockerManifest.id)
                .where(
                    DockerRepoManifest.repository_id == repo.id,
                    DockerManifest.subject_digest == digest,
                )
            )
        ).scalars().all()
        seen = {m.get("digest") for m in manifests}
        for row in rows:
            if row.digest in seen:
                continue
            entry = {"mediaType": row.media_type, "digest": row.digest, "size": row.size}
            at = row.artifact_type or row.config_media_type
            if at:
                entry["artifactType"] = at
            if row.annotations:
                entry["annotations"] = row.annotations
            manifests.append(entry)
    if artifact_type:
        manifests = [m for m in manifests if m.get("artifactType") == artifact_type]
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": manifests,
    }


async def catalog(session: AsyncSession, *, n: int, last: str | None) -> list[str]:
    stmt = select(DockerRepository.name).where(DockerRepository.indexed_only.is_(False))
    if last:
        stmt = stmt.where(DockerRepository.name > last)
    return list((await session.execute(stmt.order_by(DockerRepository.name).limit(n))).scalars().all())


# --------------------------------------------------------------------------- #
# Storage accounting / eviction
# --------------------------------------------------------------------------- #
async def usage(session: AsyncSession) -> dict[str, int]:
    blob_bytes, blob_count = (
        await session.execute(select(func.coalesce(func.sum(DockerBlob.size), 0), func.count()).select_from(DockerBlob))
    ).one()
    local_bytes = (
        await session.execute(
            select(func.coalesce(func.sum(DockerBlob.size), 0)).where(DockerBlob.is_local.is_(True))
        )
    ).scalar_one()
    manifest_bytes, manifest_count = (
        await session.execute(
            select(func.coalesce(func.sum(DockerManifest.size), 0), func.count()).select_from(DockerManifest)
        )
    ).one()
    repos = (await session.execute(select(func.count()).select_from(DockerRepository))).scalar_one()
    return {
        "blob_bytes": int(blob_bytes or 0),
        "blob_count": int(blob_count or 0),
        "local_blob_bytes": int(local_bytes or 0),
        "manifest_bytes": int(manifest_bytes or 0),
        "manifest_count": int(manifest_count or 0),
        "repository_count": int(repos or 0),
        "total_bytes": int(blob_bytes or 0) + int(manifest_bytes or 0),
    }
