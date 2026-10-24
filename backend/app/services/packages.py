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

from sqlalchemy import delete as sa_delete
from sqlalchemy import func, or_, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import update as sa_update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer, selectinload
from sqlalchemy.orm.attributes import set_committed_value

from ..config import settings
from ..core.cache import cache_delete_prefix, cache_get_json, cache_set_json, herd_guard
from ..core.naming import (
    normalize_name_for,
    normalize_pypi_version,
)
from ..models import DistTag, Ecosystem, Package, PackageFile, PackageVersion, Upstream
from ..upstreams.base import RemotePackage
from ..upstreams.revalidation import Validators, bound_prefix
from .resolver import Resolver, ResolveResult, TierUnavailable

log = logging.getLogger(__name__)


def _escape_like(value: str) -> str:
    """Neutralise LIKE/ILIKE metacharacters in user input."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


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
    session: AsyncSession,
    ecosystem: Ecosystem,
    normalized_name: str,
    *,
    load_files: bool = True,
    with_documents: bool = False,
) -> Package | None:
    """Load one package with its tags, and its versions and files when
    ``load_files`` is set.

    Lean by default: ``Package.cached_document`` (the whole upstream
    packument -- 37 MB for vite) and every ``PackageVersion.metadata_json``
    are deferred, and touching either on the result raises on an async
    session rather than silently loading it. Only the renderers need them;
    they get them through :func:`fetch_package`, which asks for
    ``with_documents=True``. Ownership checks, tag edits, deprecations,
    unpublishes and the refresh path itself read names, versions and flags.
    """
    stmt = select(Package).where(
        Package.ecosystem == ecosystem, Package.normalized_name == normalized_name
    )
    if not with_documents:
        stmt = stmt.options(defer(Package.cached_document, raiseload=True))
    if load_files:
        versions = selectinload(Package.versions)
        if not with_documents:
            versions = versions.options(
                defer(PackageVersion.metadata_json, raiseload=True),
                selectinload(PackageVersion.files),
            )
        else:
            versions = versions.selectinload(PackageVersion.files)
        stmt = stmt.options(versions, selectinload(Package.dist_tags))
    else:
        stmt = stmt.options(selectinload(Package.dist_tags))
    package = (await session.execute(stmt)).scalar_one_or_none()
    if package is not None and with_documents:
        await ensure_documents(session, package)
    return package


async def ensure_documents(session: AsyncSession, package: Package) -> None:
    """Load whichever of the heavy columns this instance does not hold yet.

    An instance already in the session's identity map keeps the attributes
    it was first loaded with -- a later query that asks for the documents
    does not fill in ones an earlier lean query deferred -- and the refresh
    path deliberately leaves unchanged versions' metadata unloaded. Rather
    than reload everything with ``populate_existing``, fetch exactly the
    missing values and install them as committed state.
    """
    state = sa_inspect(package)
    if "cached_document" in state.unloaded and package.id is not None:
        document = (
            await session.execute(select(Package.cached_document).where(Package.id == package.id))
        ).scalar_one_or_none()
        set_committed_value(package, "cached_document", document)
    if "versions" in state.unloaded:
        return
    missing = {
        v.id: v
        for v in package.versions
        if v.id is not None and "metadata_json" in sa_inspect(v).unloaded
    }
    if not missing:
        return
    rows = await session.execute(
        select(PackageVersion.id, PackageVersion.metadata_json).where(
            PackageVersion.package_id == package.id
        )
    )
    for version_id, metadata in rows:
        row = missing.get(version_id)
        if row is not None:
            set_committed_value(row, "metadata_json", metadata if metadata is not None else {})


def _expired(cached_at: datetime | None) -> bool:
    if cached_at is None:
        return True
    if cached_at.tzinfo is None:
        cached_at = cached_at.replace(tzinfo=UTC)
    return datetime.now(UTC) - cached_at > timedelta(seconds=settings.meta_cache_ttl)


def is_stale(package: Package) -> bool:
    """A package that has any locally published version is authoritative and
    never stale. Otherwise it goes stale on the metadata TTL."""
    if package.is_local:
        return False
    return _expired(package.cached_at)


@dataclass(slots=True)
class _Freshness:
    id: int
    is_local: bool
    cached_at: datetime | None
    cached_etag: str | None

    @property
    def stale(self) -> bool:
        return not self.is_local and _expired(self.cached_at)


async def _probe(session: AsyncSession, ecosystem: Ecosystem, normalized: str) -> _Freshness | None:
    """The four columns the freshness decision needs, and nothing else.

    Deciding whether to refresh used to load the whole package graph,
    packument included, and then the refresh loaded it all again under the
    herd lock -- two full deserialisations of a document that was about to
    be replaced.
    """
    row = (
        await session.execute(
            select(Package.id, Package.is_local, Package.cached_at, Package.cached_etag).where(
                Package.ecosystem == ecosystem, Package.normalized_name == normalized
            )
        )
    ).first()
    return _Freshness(*row) if row is not None else None


class UpstreamNameMismatch(Exception):
    """An upstream returned a document for a different package."""


def _same(current, new) -> bool:
    if isinstance(current, datetime) and isinstance(new, datetime):
        # SQLite hands back naive datetimes for timezone-aware columns; an
        # equality test across that boundary is always False and would
        # rewrite every row on every refresh.
        if current.tzinfo is None:
            current = current.replace(tzinfo=UTC)
        if new.tzinfo is None:
            new = new.replace(tzinfo=UTC)
    return current == new


def _set(obj, attr: str, value) -> bool:
    """Assign only when the value differs; report whether it did."""
    if _same(getattr(obj, attr), value):
        return False
    setattr(obj, attr, value)
    return True


def _normalized_version(ecosystem: Ecosystem, version: str) -> str:
    return normalize_pypi_version(version) if ecosystem == Ecosystem.pypi else version


def _apply_file(file_row: PackageFile, remote_file, upstream_id: int | None) -> bool:
    """Copy one upstream file's fields onto its row. Returns whether anything
    changed."""
    changed = False
    source = remote_file.upstream_id or upstream_id
    if file_row.blob_sha256:
        # Already cached locally: the artifact is immutable, so only refresh
        # the pointer metadata, never the digests. The source moves with the
        # pointer -- otherwise a file re-sourced from a live upstream still
        # looks like it belongs to the one it first came from.
        changed |= _set(file_row, "upstream_url", remote_file.url or file_row.upstream_url)
        if source is not None:
            changed |= _set(file_row, "upstream_id", source)
        return changed

    changed |= _set(file_row, "upstream_url", remote_file.url)
    changed |= _set(file_row, "upstream_id", source)
    changed |= _set(file_row, "size", remote_file.size or file_row.size)
    changed |= _set(file_row, "requires_python", remote_file.requires_python)
    changed |= _set(file_row, "packagetype", remote_file.packagetype)
    changed |= _set(file_row, "python_version", remote_file.python_version)
    changed |= _set(file_row, "content_type", remote_file.content_type)
    changed |= _set(file_row, "upload_time", remote_file.upload_time or file_row.upload_time)
    if isinstance(remote_file.core_metadata, dict):
        changed |= _set(file_row, "core_metadata", remote_file.core_metadata)
    elif remote_file.core_metadata:
        changed |= _set(file_row, "core_metadata", {"available": True})
    if isinstance(remote_file.yanked, str):
        changed |= _set(file_row, "yanked", True)
        changed |= _set(file_row, "yanked_reason", remote_file.yanked)
    else:
        changed |= _set(file_row, "yanked", bool(remote_file.yanked))

    for algorithm, digest in (remote_file.hashes or {}).items():
        column = _HASH_COLUMNS.get(algorithm)
        if column:
            changed |= _set(file_row, column, digest)
    return changed


_HASH_COLUMNS = {
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
    "blake2b_256": "blake2b_256",
    "blake2b": "blake2b_256",
    "integrity": "integrity",
}


async def persist_remote_package(
    session: AsyncSession,
    ecosystem: Ecosystem,
    remote: RemotePackage,
    upstream: Upstream | None,
    *,
    requested_name: str | None = None,
    validators: Validators | None = None,
) -> Package:
    """Upsert a resolved upstream document into the local tables.

    Locally published versions are never overwritten by upstream data -- a
    private package that shadows a public one keeps its own content.

    Only what changed is written. A refresh used to rewrite every version's
    ``metadata_json`` and flush once per version -- 5,600 round trips and as
    many JSON rewrites for playwright, every TTL, to record nothing new.
    Existing versions are loaded without their metadata; one whose mutable
    fields (deprecation, yanking, requires-python, publication time, source
    or files) are unchanged keeps the metadata it has, and everything is
    flushed once at the end. Per-version documents are treated as immutable
    otherwise, which is how npm, PyPI and the cargo index all behave: a
    published version's content does not change, only those flags do.
    """
    display_name = remote.name or requested_name or ""
    normalized = normalize_name_for(ecosystem.value, display_name)

    # The row is keyed on the name the *upstream* declared, so an upstream
    # that answered a request for `some-package` with a document named
    # `@corp/internal-lib` wrote its versions into the internal package's row
    # -- with attacker-chosen tarball URLs and matching digests, which then
    # verify, because both sides came from the same place. Answer for the name
    # you were asked about or the answer is discarded.
    if requested_name:
        expected = normalize_name_for(ecosystem.value, requested_name)
        if expected != normalized:
            raise UpstreamNameMismatch(
                f"upstream answered a request for '{requested_name}' with a document "
                f"named '{display_name}'"
            )

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

    _set(package, "description", coerce_text(remote.description) or package.description)
    _set(package, "author", coerce_text(remote.author, _TEXT_LIMITS["author"]) or package.author)
    _set(
        package,
        "homepage",
        coerce_text(remote.homepage, _TEXT_LIMITS["homepage"]) or package.homepage,
    )
    _set(package, "license", coerce_text(remote.license, _TEXT_LIMITS["license"]) or package.license)
    keywords = coerce_keywords(remote.keywords)
    if keywords:
        _set(package, "keywords", keywords)
    if remote.raw:
        # Written without reading the old one: comparing would mean loading
        # a second copy of a document that can be tens of megabytes.
        package.cached_document = remote.raw
    package.cached_etag = validators.encode() if validators else None
    package.cached_at = datetime.now(UTC)

    existing_versions = {v.normalized_version: v for v in package.versions}
    default_source = upstream.id if upstream else None

    for remote_version in remote.versions:
        norm_version = _normalized_version(ecosystem, remote_version.version)
        # The version's source is where its files came from. In a merged PyPI
        # document that need not be the upstream the merge is attributed to.
        source = next(
            (f.upstream_id for f in remote_version.files if f.upstream_id), default_source
        )
        version_row = existing_versions.get(norm_version)
        is_new = version_row is None
        if is_new:
            version_row = PackageVersion(
                package_id=package.id,
                version=remote_version.version,
                normalized_version=norm_version,
                upstream_id=source,
                metadata_json=remote_version.metadata or {},
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

        changed = False
        if not is_new and source is not None:
            changed |= _set(version_row, "upstream_id", source)
        changed |= _set(
            version_row,
            "requires_python",
            remote_version.requires_python or version_row.requires_python,
        )
        changed |= _set(version_row, "deprecated", remote_version.deprecated)
        if isinstance(remote_version.yanked, str):
            changed |= _set(version_row, "yanked", True)
            changed |= _set(version_row, "yanked_reason", remote_version.yanked)
        else:
            changed |= _set(version_row, "yanked", bool(remote_version.yanked))
        changed |= _set(
            version_row,
            "published_at",
            remote_version.published_at or version_row.published_at,
        )

        existing_files = {f.filename: f for f in version_row.files}
        for remote_file in remote_version.files:
            file_row = existing_files.get(remote_file.filename)
            if file_row is None:
                file_row = PackageFile(filename=remote_file.filename)
                # Appending through the relationship sets version_id at
                # flush, so a new version needs no flush of its own first.
                version_row.files.append(file_row)
                existing_files[remote_file.filename] = file_row
                changed = True
            changed |= _apply_file(file_row, remote_file, default_source)

        if is_new or not remote_version.metadata:
            continue
        if changed:
            # Something about this version moved upstream (npm deprecation
            # lives in the version document, cargo's yank flag in the index
            # line), so its stored document is replaced too.
            version_row.metadata_json = remote_version.metadata
        elif "metadata_json" in sa_inspect(version_row).unloaded:
            # Unchanged: nothing to write, and the document the caller is
            # about to render is the one in hand. Installing it as committed
            # state means the stored copy never has to be read back.
            set_committed_value(version_row, "metadata_json", remote_version.metadata)

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
                _set(row, "version", version)
        _set(
            package,
            "latest_version",
            coerce_text(remote.dist_tags.get("latest"), _TEXT_LIMITS["latest_version"])
            or package.latest_version,
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
    if ecosystem == Ecosystem.pypi:
        ordered = sort_pypi_versions(versions)
        return ordered[-1] if ordered else None
    # npm and cargo are both semver 2.0.0, and both want the highest *stable*
    # release rather than the highest version outright -- a crate sitting on a
    # long run of `-alpha` publishes should still present its last release as
    # latest.
    return max_semver(versions)


# --------------------------------------------------------------------------- #
# Provenance pruning
# --------------------------------------------------------------------------- #
async def prune_unsourced(
    session: AsyncSession,
    ecosystem: Ecosystem,
    package: Package,
    *,
    answer: RemotePackage | None = None,
    answered_tier: int | None = None,
) -> bool:
    """Drop upstream versions and files nothing may serve any more.

    Versions used to be permanent once persisted. Deleting a compromised
    upstream left every version it had supplied in the packument and the
    simple page, and an internal tier that recovered from an outage never
    displaced what a public tier had answered in the meantime. A non-local
    version or file goes when its source upstream is

    * no longer a source for this name -- deleted, or no longer claiming it
      (``resolver.live_sources``; a disabled upstream is paused, not gone); or
    * ranked below the tier that just answered, and absent from that answer
      (``answer``/``answered_tier``, given only after a successful resolve).

    It stays when its source is merely unhealthy or unreachable: an outage is
    not a configuration change, and serving what we hold through one is the
    point of the cache. It also stays when the answering tier itself simply
    no longer lists it, which is the existing serve-what-we-have behaviour
    for upstream deletions. Locally published versions are never touched,
    and rows with no recorded source are left alone, since nothing says where
    they came from.

    Returns whether anything was removed.
    """
    from ..models import PackageVulnerability
    from .artifacts import purge_file
    from .resolver import live_sources

    live = await live_sources(session, ecosystem, package.normalized_name)
    if answer is not None and not answer.versions:
        # A tier that answers 200 with nothing (an empty simple page, a
        # proxy with no copy yet) says nothing about what lower tiers hold;
        # displacing on it would purge every cached lower-tier file.
        answer = None
        answered_tier = None
    present_versions: set[str] | None = None
    present_files: set[str] | None = None
    if answer is not None:
        present_versions = {_normalized_version(ecosystem, v.version) for v in answer.versions}
        present_files = {f.filename for v in answer.versions for f in v.files}

    def displaced(source: int | None, present: bool) -> bool:
        if source is None:
            return False
        if source not in live:
            return True
        if present or answered_tier is None or present_versions is None:
            return False
        return live[source] > answered_tier

    doomed_versions: list[PackageVersion] = []
    doomed_files: list[tuple[PackageVersion, PackageFile]] = []
    for version_row in package.versions:
        if version_row.is_local:
            continue
        if version_row.files:
            dead = [
                f
                for f in version_row.files
                if displaced(
                    f.upstream_id, present_files is None or f.filename in present_files
                )
            ]
            if len(dead) == len(version_row.files):
                doomed_versions.append(version_row)
            elif dead:
                doomed_files.extend((version_row, f) for f in dead)
        elif displaced(
            version_row.upstream_id,
            present_versions is None or version_row.normalized_version in present_versions,
        ):
            doomed_versions.append(version_row)

    if not doomed_versions and not doomed_files:
        return False

    # Validators bound to an upstream whose rows were just removed would let
    # a later 304 from it "confirm" a document missing those rows.
    removed_sources = {f.upstream_id for _, f in doomed_files} | {
        v.upstream_id for v in doomed_versions
    } | {f.upstream_id for v in doomed_versions for f in v.files}
    bound = Validators.decode(package.cached_etag)
    if bound is not None and bound.upstream_id in removed_sources:
        package.cached_etag = None

    for version_row, file_row in doomed_files:
        await purge_file(session, file_row)
        version_row.files.remove(file_row)
        await session.delete(file_row)
        if version_row.upstream_id not in live:
            survivor = next((f.upstream_id for f in version_row.files if f.upstream_id), None)
            if survivor is not None:
                version_row.upstream_id = survivor

    removed = {v.version for v in doomed_versions}
    if doomed_versions:
        for version_row in doomed_versions:
            for file_row in version_row.files:
                await purge_file(session, file_row)
        ids = [v.id for v in doomed_versions if v.id is not None]
        if ids:
            # ON DELETE CASCADE covers this on Postgres; be explicit so the
            # result does not depend on the backend enforcing foreign keys.
            await session.execute(
                sa_delete(PackageVulnerability).where(PackageVulnerability.version_id.in_(ids))
            )
        for version_row in doomed_versions:
            package.versions.remove(version_row)
            await session.delete(version_row)

        log.warning(
            "pruned %d version(s) of %s:%s whose source upstream may no longer serve them",
            len(doomed_versions),
            ecosystem.value,
            package.normalized_name,
        )
        # Tags must not point at what was just removed.
        for tag in list(package.dist_tags):
            if tag.version in removed:
                if tag.tag == "latest" and package.versions:
                    tag.version = _derive_latest(ecosystem, package) or tag.version
                else:
                    package.dist_tags.remove(tag)
                    await session.delete(tag)
        if package.latest_version in removed:
            package.latest_version = _derive_latest(ecosystem, package)

    await session.flush()
    return True


async def fetch_package(
    session: AsyncSession,
    ecosystem: Ecosystem,
    name: str,
    *,
    allow_upstream: bool = True,
    force_refresh: bool = False,
    with_documents: bool = True,
) -> PackageLookup:
    """Return a package, consulting upstreams when the local copy is stale.

    The package comes back with its documents loaded (the renderers need
    them) unless ``with_documents=False``. Freshness is decided from a
    column-only probe, so a refresh deserialises the stored document at most
    once, after the refresh, and not at all when the caller does not want it.
    """
    normalized = normalize_name_for(ecosystem.value, name)

    async def load() -> Package | None:
        return await get_package_row(session, ecosystem, normalized, with_documents=with_documents)

    probe = await _probe(session, ecosystem, normalized)
    if probe is not None and (probe.is_local or (not force_refresh and not probe.stale)):
        return PackageLookup(package=await load(), fresh=True)
    if not allow_upstream:
        package = await load() if probe is not None else None
        return PackageLookup(package=package, fresh=package is not None)

    # A name nothing has: remember that briefly. Typos, private scopes that
    # only exist on someone else's machine and probes otherwise walk every
    # tier on every request, and the herd guard only collapses the concurrent
    # ones. META_NEGATIVE_CACHE_TTL existed as a setting but was never read.
    miss_key = cache_key(ecosystem.value, normalized, "miss")
    if probe is None and not force_refresh and await cache_get_json(miss_key):
        return PackageLookup(package=None, fresh=False)

    # End the transaction before queueing on the herd lock or going to the
    # network: either can take longer than Postgres lets a transaction sit
    # idle (60 s), and a killed connection fails the whole request. The
    # session stays usable; the next statement opens a new transaction.
    await session.commit()

    # Collapse concurrent cold-cache fetches for the same package.
    async with herd_guard(cache_key(ecosystem.value, normalized, "fetch"), ttl=30):
        # Re-check: another waiter may have refreshed it while we queued.
        probe = await _probe(session, ecosystem, normalized)
        if probe is not None and not force_refresh and not probe.stale:
            return PackageLookup(package=await load(), fresh=True)

        validators = None
        if probe is not None and not force_refresh:
            validators = Validators.decode(probe.cached_etag)

        # Commits again once it has read the upstream list, before any
        # upstream request.
        resolver = Resolver(session, end_transaction=True)
        try:
            result: ResolveResult | None = await resolver.resolve(
                ecosystem, name, validators=validators
            )
        except TierUnavailable as exc:
            # A tier failed rather than answering "not found". Serve what we
            # have; do not let a lower tier take the name.
            log.warning("resolution incomplete for %s:%s -- %s", ecosystem.value, name, exc)
            package = await _settle(session, ecosystem, normalized, with_documents)
            return PackageLookup(package=package, fresh=False)

        if result is None:
            # Upstreams do not have it. A stale local copy is better than a 404.
            #
            # The resolver records upstream health on the ORM objects, and on
            # this path nothing else commits -- so during a full outage the
            # failure counter never reached the threshold, the circuit breaker
            # never tripped, and every request kept paying three retries per
            # upstream while holding a pooled connection. _settle commits.
            package = await _settle(session, ecosystem, normalized, with_documents)
            if package is not None:
                return PackageLookup(package=package, fresh=False)
            await cache_set_json(miss_key, {"miss": True}, settings.meta_negative_cache_ttl)
            return PackageLookup(package=None, fresh=False)

        if result.not_modified:
            # 304: what we hold is current. Restart the TTL without touching
            # the document, the versions or the validators.
            await session.execute(
                sa_update(Package)
                .where(Package.id == probe.id)
                .values(cached_at=datetime.now(UTC))
                .execution_options(synchronize_session=False)
            )
            package = await _settle(session, ecosystem, normalized, with_documents)
            return PackageLookup(package=package, fresh=True, upstream=result.upstream)

        try:
            package = await persist_remote_package(
                session,
                ecosystem,
                result.package,
                result.upstream,
                requested_name=name,
                validators=result.validators,
            )
        except UpstreamNameMismatch as exc:
            log.warning("discarding upstream response: %s", exc)
            await session.rollback()
            return PackageLookup(package=None, fresh=False)
        await prune_unsourced(
            session, ecosystem, package, answer=result.package, answered_tier=result.tier
        )
        upstream = result.upstream
        await session.commit()
        await invalidate_package_cache(ecosystem.value, normalized)
        if with_documents:
            await ensure_documents(session, package)
        return PackageLookup(package=package, fresh=True, from_upstream=True, upstream=upstream)


async def _settle(
    session: AsyncSession, ecosystem: Ecosystem, normalized: str, with_documents: bool
) -> Package | None:
    """Finish a refresh that produced no new document: drop whatever has
    lost its source, commit (which also records upstream health), and load
    what is left to serve.

    A non-local package with nothing left is reported as absent rather than
    served as an empty shell.
    """
    package = await get_package_row(session, ecosystem, normalized)
    pruned = package is not None and await prune_unsourced(session, ecosystem, package)
    await session.commit()
    if pruned:
        await invalidate_package_cache(ecosystem.value, normalized)
    if package is None or (not package.is_local and not package.versions):
        return None
    if with_documents:
        await ensure_documents(session, package)
    return package


# --------------------------------------------------------------------------- #
# Upstream configuration changes
# --------------------------------------------------------------------------- #
async def retire_upstream_content(session: AsyncSession, upstream: Upstream) -> int:
    """Remove every cached version and file whose only source is ``upstream``.

    Called when an upstream is deleted (disabling is a pause and keeps
    everything). Marking packages stale is
    not enough on its own: a client installing from a lockfile asks for the
    tarball directly and never re-reads the metadata, so a compromised
    upstream's cached artifacts would keep being served. Locally published
    versions are never touched. Blobs are released through the orphan sweep,
    which reconciles reference counts.

    Bulk SQL rather than the ORM: an upstream can be the source of a whole
    ecosystem's worth of rows, and none of them need loading to be deleted.
    Returns the number of versions removed.
    """
    from ..models import PackageVulnerability

    if upstream.ecosystem == Ecosystem.docker or upstream.id is None:
        return 0
    uid = upstream.id
    upstream_versions = select(PackageVersion.id).where(PackageVersion.is_local.is_(False))
    from_upstream = select(PackageFile.version_id).where(PackageFile.upstream_id == uid)
    other_files = (
        select(PackageFile.id)
        .where(
            PackageFile.version_id == PackageVersion.id,
            or_(PackageFile.upstream_id != uid, PackageFile.upstream_id.is_(None)),
        )
        .exists()
    )
    doomed = list(
        (
            await session.execute(
                select(PackageVersion.id).where(
                    PackageVersion.is_local.is_(False),
                    or_(PackageVersion.upstream_id == uid, PackageVersion.id.in_(from_upstream)),
                    ~other_files,
                )
            )
        ).scalars()
    )
    affected: set[int] = set()
    for start in range(0, len(doomed), 500):
        chunk = doomed[start : start + 500]
        affected.update(
            (
                await session.execute(
                    select(PackageVersion.package_id).where(PackageVersion.id.in_(chunk)).distinct()
                )
            ).scalars()
        )
        await session.execute(
            sa_delete(PackageVulnerability).where(PackageVulnerability.version_id.in_(chunk))
        )
        await session.execute(sa_delete(PackageFile).where(PackageFile.version_id.in_(chunk)))
        await session.execute(sa_delete(PackageVersion).where(PackageVersion.id.in_(chunk)))

    # Versions that survive because another upstream also supplies them lose
    # just this upstream's files, and stop being attributed to it.
    await session.execute(
        sa_delete(PackageFile)
        .where(PackageFile.upstream_id == uid, PackageFile.version_id.in_(upstream_versions))
        .execution_options(synchronize_session=False)
    )
    await session.execute(
        sa_update(PackageVersion)
        .where(PackageVersion.upstream_id == uid, PackageVersion.is_local.is_(False))
        .values(
            upstream_id=select(func.min(PackageFile.upstream_id))
            .where(PackageFile.version_id == PackageVersion.id)
            .scalar_subquery()
        )
        .execution_options(synchronize_session=False)
    )
    # Tags and latest_version must not name what was just removed; the next
    # refresh (the ecosystem is marked stale) re-derives them.
    affected_ids = sorted(affected)
    for start in range(0, len(affected_ids), 500):
        chunk = affected_ids[start : start + 500]
        await session.execute(
            sa_delete(DistTag)
            .where(
                DistTag.package_id.in_(chunk),
                ~select(PackageVersion.id)
                .where(
                    PackageVersion.package_id == DistTag.package_id,
                    PackageVersion.version == DistTag.version,
                )
                .exists(),
            )
            .execution_options(synchronize_session=False)
        )
        await session.execute(
            sa_update(Package)
            .where(
                Package.id.in_(chunk),
                ~select(PackageVersion.id)
                .where(
                    PackageVersion.package_id == Package.id,
                    PackageVersion.version == Package.latest_version,
                )
                .exists(),
            )
            .values(latest_version=None)
            .execution_options(synchronize_session=False)
        )
    # A 304 from this upstream's validators would otherwise "confirm" a
    # document whose versions were just removed.
    await session.execute(
        sa_update(Package)
        .where(Package.cached_etag.startswith(bound_prefix(uid), autoescape=True))
        .values(cached_etag=None)
        .execution_options(synchronize_session=False)
    )
    if doomed:
        log.warning(
            "upstream %s retired: removed %d cached version(s) it alone supplied",
            upstream.name,
            len(doomed),
        )
    return len(doomed)


async def mark_ecosystem_stale(
    session: AsyncSession, ecosystem: Ecosystem, *, forget_validators_of: int | None = None
) -> None:
    """Make every upstream-sourced package in ``ecosystem`` refresh on its
    next request, so a change to the upstream set is reflected in what is
    served instead of waiting out each package's TTL.

    ``forget_validators_of`` drops conditional-request validators issued by
    that upstream: after its URL or credentials change, a 304 from it says
    nothing about the document we hold. (A cleared ``cached_at`` already
    bypasses validators bound to an upstream that is no longer consulted.)
    """
    if ecosystem == Ecosystem.docker:
        return
    await session.execute(
        sa_update(Package)
        .where(Package.ecosystem == ecosystem, Package.is_local.is_(False))
        .values(cached_at=None)
        .execution_options(synchronize_session=False)
    )
    if forget_validators_of is not None:
        await session.execute(
            sa_update(Package)
            .where(
                Package.ecosystem == ecosystem,
                Package.cached_etag.startswith(
                    bound_prefix(forget_validators_of), autoescape=True
                ),
            )
            .values(cached_etag=None)
            .execution_options(synchronize_session=False)
        )


async def invalidate_ecosystem_cache(ecosystem: Ecosystem) -> None:
    """Drop every rendered document and negative-cache entry for an
    ecosystem, plus search results, which can name upstream packages.

    Run after the commit that changed the upstream set, or a request racing
    it can re-cache the old answer.
    """
    if ecosystem == Ecosystem.docker:
        return
    # Includes `pkg:{eco}:{name}:miss`: a name that missed before an
    # upstream was added must not stay missing for the negative TTL.
    await cache_delete_prefix(f"pkg:{ecosystem.value}:")
    await cache_delete_prefix("search:")


async def locate_file(
    session: AsyncSession,
    ecosystem: Ecosystem,
    normalized_name: str,
    *,
    filename: str | None = None,
    version: str | None = None,
) -> tuple[Package, PackageVersion, PackageFile] | None:
    """Find one artifact without dragging the package's whole document graph.

    The download routes used to go through :func:`fetch_package`, which eager
    loads every version and every file and, crucially, the ``Package`` entity
    itself -- and that carries ``cached_document``, the entire upstream
    packument (18 MB for playwright, 37 MB for vite). Twenty concurrent CI
    fetches of one tarball therefore deserialised hundreds of megabytes of
    JSON to find a single row, inside a 1.5 GB container. That is the exit-137
    signature the project has already been bitten by once, reachable from
    ordinary installs rather than a batch job.

    Only the columns the download path reads are selected. On a genuine cold
    miss it falls back to a full resolve -- at which point the packument has
    to be parsed anyway -- and then re-runs the narrow query.
    """
    found = await _locate_file_row(session, ecosystem, normalized_name, filename, version)
    if found is not None:
        return found

    # Nothing local. Someone may be fetching an artifact URL without having
    # asked for the metadata first, which is legitimate.
    lookup = await fetch_package(session, ecosystem, normalized_name, with_documents=False)
    if lookup.package is None:
        return None
    return await _locate_file_row(session, ecosystem, normalized_name, filename, version)


async def _locate_file_row(
    session: AsyncSession,
    ecosystem: Ecosystem,
    normalized_name: str,
    filename: str | None,
    version: str | None,
) -> tuple[Package, PackageVersion, PackageFile] | None:
    stmt = (
        select(Package, PackageVersion, PackageFile)
        .join(PackageVersion, PackageVersion.package_id == Package.id)
        .join(PackageFile, PackageFile.version_id == PackageVersion.id)
        .where(Package.ecosystem == ecosystem, Package.normalized_name == normalized_name)
        .options(
            defer(Package.cached_document),
            defer(PackageVersion.metadata_json),
        )
        .limit(1)
    )
    if filename is not None:
        stmt = stmt.where(PackageFile.filename == filename)
    if version is not None:
        stmt = stmt.where(PackageVersion.version == version)
    row = (await session.execute(stmt)).first()
    if row is None:
        return None
    return row[0], row[1], row[2]


async def invalidate_package_cache(ecosystem: str, normalized_name: str) -> None:
    # Trailing separator: without it, refreshing `react` also dropped every
    # cached document for `react-dom`, `react-router` and friends.
    await cache_delete_prefix(f"{cache_key(ecosystem, normalized_name)}:")


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
    # Escape the wildcards, or `%a%b%c%d%e%f%` from any logged-in user turns
    # an indexed prefix search into a scan of every description in the table.
    pattern = f"%{_escape_like(query.lower())}%"
    conditions = [Package.normalized_name.ilike(pattern, escape="\\")]
    if query:
        conditions.append(Package.description.ilike(pattern, escape="\\"))

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
    return normalize_name_for(ecosystem.value, name)
