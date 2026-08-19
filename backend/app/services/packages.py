"""Package persistence and the read path shared by both registries.

Read path for a metadata request:

    Redis (rendered doc)  ->  Postgres (packages/versions/files)
      ->  upstream resolver  ->  persist  ->  render  ->  Redis

Locally published content short-circuits at the Postgres step and never
consults an upstream.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer, selectinload

from ..config import settings
from ..core.cache import cache_delete_prefix, herd_guard
from ..core.naming import (
    normalize_name_for,
    normalize_npm_name,
    normalize_pypi_name,
    normalize_pypi_version,
)
from ..models import DistTag, Ecosystem, Package, PackageFile, PackageVersion, Upstream
from ..upstreams.base import RemotePackage
from .resolver import Resolver, ResolveResult

log = logging.getLogger(__name__)


def cache_key(ecosystem: str, name: str, suffix: str = "") -> str:
    return f"pkg:{ecosystem}:{name}{(':' + suffix) if suffix else ''}"



# Column widths for the fields upstreams populate. Values are truncated to fit
# rather than allowed to fail the insert: a registry that 500s because some
# package put a whole licence text in a field is worse than one that stores the
# first 255 characters of it.
_TEXT_LIMITS = {"license": 255, "author": 512, "homepage": 1024, "latest_version": 128}


def coerce_text(value, limit: int | None = None) -> str | None:
    """Flatten an upstream field into something a text column will accept.

    Registry metadata is not schema-enforced and the shapes drift over time.
    npm's ``license`` is a plain SPDX string today, but older packages carry
    ``{"type": "MIT", "url": ...}`` or a ``licenses`` array of those, and PyPI
    projects occasionally paste an entire licence into the field. Passing any
    of that straight to a VARCHAR column raises a driver-level DataError, which
    surfaces as a 500 on both the packument *and* every tarball under it --
    one badly shaped field takes the whole package offline.
    """
    if value is None:
        return None
    if isinstance(value, str):
        text = value
    elif isinstance(value, dict):
        # {"type": "MIT", "url": ...} and friends.
        text = value.get("type") or value.get("name") or value.get("license") or ""
        if not isinstance(text, str):
            text = ""
    elif isinstance(value, (list, tuple)):
        parts = [coerce_text(item) for item in value]
        text = ", ".join(part for part in parts if part)
    elif isinstance(value, (int, float, bool)):
        text = str(value)
    else:
        return None

    text = text.strip()
    if not text:
        return None
    return text[:limit] if limit else text


def coerce_keywords(value) -> list[str]:
    """Keywords are a list by convention, but a string in the wild."""
    if isinstance(value, str):
        return [k.strip() for k in value.replace(",", " ").split() if k.strip()]
    if isinstance(value, (list, tuple)):
        return [k for k in (coerce_text(item) for item in value) if k]
    return []


@dataclass(slots=True)
class PackageLookup:
    package: Package | None
    fresh: bool
    from_upstream: bool = False
    upstream: Upstream | None = None


async def get_package_row(
    session: AsyncSession, ecosystem: Ecosystem, normalized_name: str, *, load_files: bool = True
) -> Package | None:
    stmt = select(Package).where(
        Package.ecosystem == ecosystem, Package.normalized_name == normalized_name
    )
    if load_files:
        stmt = stmt.options(
            selectinload(Package.versions).selectinload(PackageVersion.files),
            selectinload(Package.dist_tags),
        )
    else:
        stmt = stmt.options(selectinload(Package.dist_tags))
    return (await session.execute(stmt)).scalar_one_or_none()


def is_stale(package: Package) -> bool:
    """A package that has any locally published version is authoritative and
    never stale. Otherwise it goes stale on the metadata TTL."""
    if package.is_local:
        return False
    if package.cached_at is None:
        return True
    cached = package.cached_at
    if cached.tzinfo is None:
        cached = cached.replace(tzinfo=UTC)
    return datetime.now(UTC) - cached > timedelta(seconds=settings.meta_cache_ttl)


async def persist_remote_package(
    session: AsyncSession,
    ecosystem: Ecosystem,
    remote: RemotePackage,
    upstream: Upstream | None,
    *,
    requested_name: str | None = None,
) -> Package:
    """Upsert a resolved upstream document into the local tables.

    Locally published versions are never overwritten by upstream data -- a
    private package that shadows a public one keeps its own content.
    """
    display_name = remote.name or requested_name or ""
    normalized = normalize_name_for(ecosystem.value, display_name)

    package = await get_package_row(session, ecosystem, normalized)
    if package is None:
        package = Package(
            ecosystem=ecosystem,
            name=display_name,
            normalized_name=normalized,
            origin_upstream_id=upstream.id if upstream else None,
        )
        # Initialise the collections so SQLAlchemy treats them as loaded.
        # Touching an unloaded relationship on a brand-new instance would
        # trigger a lazy load, which is illegal on an async session.
        package.versions = []
        package.dist_tags = []
        session.add(package)
        try:
            await session.flush()
        except IntegrityError:
            # Another request created it concurrently; adopt theirs.
            await session.rollback()
            package = await get_package_row(session, ecosystem, normalized)
            if package is None:
                raise

    package.description = coerce_text(remote.description) or package.description
    package.author = coerce_text(remote.author, _TEXT_LIMITS["author"]) or package.author
    package.homepage = coerce_text(remote.homepage, _TEXT_LIMITS["homepage"]) or package.homepage
    package.license = coerce_text(remote.license, _TEXT_LIMITS["license"]) or package.license
    keywords = coerce_keywords(remote.keywords)
    if keywords:
        package.keywords = keywords
    package.cached_document = remote.raw or package.cached_document
    package.cached_etag = remote.etag
    package.cached_at = datetime.now(UTC)

    existing_versions = {v.normalized_version: v for v in package.versions}

    for remote_version in remote.versions:
        norm_version = (
            normalize_pypi_version(remote_version.version)
            if ecosystem == Ecosystem.pypi
            else remote_version.version
        )
        version_row = existing_versions.get(norm_version)
        if version_row is None:
            version_row = PackageVersion(
                package_id=package.id,
                version=remote_version.version,
                normalized_version=norm_version,
                upstream_id=upstream.id if upstream else None,
            )
            # Mark the collection loaded; reading it on a pending instance
            # would otherwise emit a lazy SELECT, which an async session
            # cannot service from inside this coroutine.
            version_row.files = []
            session.add(version_row)
            package.versions.append(version_row)
            existing_versions[norm_version] = version_row
        elif version_row.is_local:
            # Never let an upstream clobber something published here.
            continue

        version_row.metadata_json = remote_version.metadata or version_row.metadata_json
        version_row.requires_python = remote_version.requires_python or version_row.requires_python
        version_row.deprecated = remote_version.deprecated
        if isinstance(remote_version.yanked, str):
            version_row.yanked = True
            version_row.yanked_reason = remote_version.yanked
        else:
            version_row.yanked = bool(remote_version.yanked)
        version_row.published_at = remote_version.published_at or version_row.published_at

        await session.flush()

        existing_files = {f.filename: f for f in version_row.files}
        for remote_file in remote_version.files:
            file_row = existing_files.get(remote_file.filename)
            if file_row is None:
                file_row = PackageFile(
                    version_id=version_row.id, filename=remote_file.filename
                )
                session.add(file_row)
                version_row.files.append(file_row)
                existing_files[remote_file.filename] = file_row
            elif file_row.blob_sha256:
                # Already cached locally: the artifact is immutable, so only
                # refresh the pointer metadata, never the digests.
                file_row.upstream_url = remote_file.url or file_row.upstream_url
                continue

            file_row.upstream_url = remote_file.url
            file_row.upstream_id = remote_file.upstream_id or (upstream.id if upstream else None)
            file_row.size = remote_file.size or file_row.size
            file_row.requires_python = remote_file.requires_python
            file_row.packagetype = remote_file.packagetype
            file_row.python_version = remote_file.python_version
            file_row.content_type = remote_file.content_type
            file_row.upload_time = remote_file.upload_time or file_row.upload_time
            if isinstance(remote_file.core_metadata, dict):
                file_row.core_metadata = remote_file.core_metadata
            elif remote_file.core_metadata:
                file_row.core_metadata = {"available": True}
            if isinstance(remote_file.yanked, str):
                file_row.yanked = True
                file_row.yanked_reason = remote_file.yanked
            else:
                file_row.yanked = bool(remote_file.yanked)

            for algorithm, digest in (remote_file.hashes or {}).items():
                if algorithm == "sha256":
                    file_row.sha256 = digest
                elif algorithm == "sha1":
                    file_row.sha1 = digest
                elif algorithm == "md5":
                    file_row.md5 = digest
                elif algorithm in ("blake2b_256", "blake2b"):
                    file_row.blake2b_256 = digest
                elif algorithm == "integrity":
                    file_row.integrity = digest

    # dist-tags (npm). Local tags win over upstream.
    if remote.dist_tags:
        existing_tags = {t.tag: t for t in package.dist_tags}
        for tag, version in remote.dist_tags.items():
            row = existing_tags.get(tag)
            if row is None:
                row = DistTag(package_id=package.id, tag=tag, version=version)
                session.add(row)
                package.dist_tags.append(row)
            elif not package.is_local:
                row.version = version
        package.latest_version = (
            coerce_text(remote.dist_tags.get("latest"), _TEXT_LIMITS["latest_version"])
            or package.latest_version
        )

    if package.latest_version is None and package.versions:
        package.latest_version = _derive_latest(ecosystem, package)

    await session.flush()
    return package


def _derive_latest(ecosystem: Ecosystem, package: Package) -> str | None:
    from ..core.naming import max_semver, sort_pypi_versions

    versions = [v.version for v in package.versions if not v.yanked]
    if not versions:
        versions = [v.version for v in package.versions]
    if not versions:
        return None
    if ecosystem == Ecosystem.npm:
        return max_semver(versions)
    ordered = sort_pypi_versions(versions)
    return ordered[-1] if ordered else None


async def fetch_package(
    session: AsyncSession,
    ecosystem: Ecosystem,
    name: str,
    *,
    allow_upstream: bool = True,
    force_refresh: bool = False,
) -> PackageLookup:
    """Return a package, consulting upstreams when the local copy is stale."""
    normalized = normalize_name_for(ecosystem.value, name)
    package = await get_package_row(session, ecosystem, normalized)

    if package is not None and package.is_local:
        return PackageLookup(package=package, fresh=True)
    if package is not None and not force_refresh and not is_stale(package):
        return PackageLookup(package=package, fresh=True)
    if not allow_upstream:
        return PackageLookup(package=package, fresh=package is not None)

    # Collapse concurrent cold-cache fetches for the same package.
    async with herd_guard(cache_key(ecosystem.value, normalized, "fetch"), ttl=30):
        # Re-check: another waiter may have refreshed it while we queued.
        package = await get_package_row(session, ecosystem, normalized)
        if package is not None and not force_refresh and not is_stale(package):
            return PackageLookup(package=package, fresh=True)

        resolver = Resolver(session)
        result: ResolveResult | None = await resolver.resolve(ecosystem, name)
        if result is None:
            # Upstreams do not have it. A stale local copy is better than a 404.
            if package is not None:
                return PackageLookup(package=package, fresh=False)
            return PackageLookup(package=None, fresh=False)

        package = await persist_remote_package(
            session, ecosystem, result.package, result.upstream, requested_name=name
        )
        await session.commit()
        await invalidate_package_cache(ecosystem.value, normalized)
        return PackageLookup(
            package=package, fresh=True, from_upstream=True, upstream=result.upstream
        )


async def invalidate_package_cache(ecosystem: str, normalized_name: str) -> None:
    await cache_delete_prefix(cache_key(ecosystem, normalized_name))


async def bump_download_counters(
    session: AsyncSession, package_id: int, file_id: int | None = None
) -> None:
    """Counter increments are done with a targeted UPDATE rather than an ORM
    read-modify-write, so concurrent downloads do not lose counts."""
    from sqlalchemy import update

    await session.execute(
        update(Package)
        .where(Package.id == package_id)
        .values(download_count=Package.download_count + 1)
    )
    if file_id is not None:
        await session.execute(
            update(PackageFile)
            .where(PackageFile.id == file_id)
            .values(download_count=PackageFile.download_count + 1)
        )


async def search_local(
    session: AsyncSession,
    ecosystem: Ecosystem | None,
    query: str,
    *,
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[Package], int]:
    """Substring search over the local index, ranked by exact match then
    downloads. Backed by the pg_trgm GIN index."""
    pattern = f"%{query.lower()}%"
    conditions = [Package.normalized_name.ilike(pattern)]
    if query:
        conditions.append(Package.description.ilike(pattern))

    from sqlalchemy import or_

    # Search results render summary fields only. Leaving cached_document in
    # means one page of hits can carry hundreds of MB of packument JSON.
    stmt = select(Package).options(defer(Package.cached_document)).where(or_(*conditions))
    count_stmt = select(func.count(Package.id)).where(or_(*conditions))
    if ecosystem is not None:
        stmt = stmt.where(Package.ecosystem == ecosystem)
        count_stmt = count_stmt.where(Package.ecosystem == ecosystem)

    total = (await session.execute(count_stmt)).scalar_one()
    stmt = stmt.order_by(
        (Package.normalized_name == query.lower()).desc(),
        Package.download_count.desc(),
        Package.normalized_name.asc(),
    ).limit(limit).offset(offset)
    return list((await session.execute(stmt)).scalars().all()), total


def normalized_for(ecosystem: Ecosystem, name: str) -> str:
    return (
        normalize_pypi_name(name) if ecosystem == Ecosystem.pypi else normalize_npm_name(name)
    )
