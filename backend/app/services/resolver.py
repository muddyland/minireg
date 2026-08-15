"""Tiered upstream resolution.

Routing rules
-------------
1. Local (published-here) content always wins. It is authoritative and never
   goes to the network.
2. Upstreams are grouped by ``tier`` and tiers are consumed in ascending order.
   A tier is fully exhausted before the next is attempted.
3. Within a tier, upstreams are raced concurrently by default -- the first
   success wins and the losers are cancelled. With ``UPSTREAM_TIER_PARALLEL``
   off they are tried sequentially by ``priority``.
4. A 404 from an upstream is authoritative *for that upstream only*; we keep
   walking. Only when every tier is exhausted do we return "not found".
5. Repeatedly failing upstreams are marked unhealthy and skipped, with a
   probe letting them recover.

Merging
-------
For PyPI, a project can legitimately exist in several upstreams (an internal
GitLab index plus public PyPI). We merge file lists across the *winning tier*
so a private package that shadows a public one still resolves, with earlier
tiers taking precedence on filename collisions.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import Ecosystem, Upstream, UpstreamKind
from ..upstreams.base import (
    RemotePackage,
    RemoteVersion,
    SearchHit,
    UpstreamError,
    UpstreamNotFound,
    UpstreamProvider,
)
from ..upstreams.gitlab_provider import GitLabNpmProvider, GitLabPyPIProvider
from ..upstreams.npm_provider import NpmProvider
from ..upstreams.pypi_provider import PyPIProvider

log = logging.getLogger(__name__)

PROVIDERS: dict[UpstreamKind, type[UpstreamProvider]] = {
    UpstreamKind.npm: NpmProvider,
    UpstreamKind.pypi: PyPIProvider,
    UpstreamKind.gitlab_npm: GitLabNpmProvider,
    UpstreamKind.gitlab_pypi: GitLabPyPIProvider,
}

# An upstream is quarantined after this many consecutive failures.
FAILURE_THRESHOLD = 5
# ...and re-probed this often while quarantined.
PROBE_INTERVAL_SECONDS = 120


def build_provider(upstream: Upstream) -> UpstreamProvider:
    cls = PROVIDERS.get(upstream.kind)
    if cls is None:
        raise UpstreamError(f"unsupported upstream kind: {upstream.kind}")
    return cls(upstream)


@dataclass(slots=True)
class ResolveResult:
    package: RemotePackage
    upstream: Upstream
    tier: int


async def load_upstreams(
    session: AsyncSession, ecosystem: Ecosystem, *, enabled_only: bool = True
) -> list[Upstream]:
    stmt = select(Upstream).where(Upstream.ecosystem == ecosystem)
    if enabled_only:
        stmt = stmt.where(Upstream.enabled.is_(True))
    stmt = stmt.order_by(Upstream.tier.asc(), Upstream.priority.asc(), Upstream.id.asc())
    return list((await session.execute(stmt)).scalars().all())


def group_by_tier(upstreams: list[Upstream]) -> list[tuple[int, list[Upstream]]]:
    tiers: dict[int, list[Upstream]] = defaultdict(list)
    for up in upstreams:
        tiers[up.tier].append(up)
    return [(tier, tiers[tier]) for tier in sorted(tiers)]


def is_quarantined(upstream: Upstream) -> bool:
    """Skip an upstream that keeps failing, but let a probe through
    periodically so recovery is automatic."""
    if upstream.healthy or upstream.consecutive_failures < FAILURE_THRESHOLD:
        return False
    if upstream.last_check_at is None:
        return False
    last = upstream.last_check_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    return (datetime.now(UTC) - last).total_seconds() < PROBE_INTERVAL_SECONDS


class Resolver:
    """Resolves a package name across the configured upstream tiers."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def resolve(
        self, ecosystem: Ecosystem, name: str, *, merge_tier: bool | None = None
    ) -> ResolveResult | None:
        upstreams = await load_upstreams(self.session, ecosystem)
        if not upstreams:
            return None
        # PyPI merges by default because the Simple API is file-oriented and a
        # project's files can legitimately be split across indexes. npm does
        # not: a packument is a single authoritative document.
        if merge_tier is None:
            merge_tier = ecosystem == Ecosystem.pypi

        for tier, group in group_by_tier(upstreams):
            candidates = [u for u in group if not is_quarantined(u)]
            if not candidates:
                continue

            results = await self._query_tier(candidates, name, collect_all=merge_tier)
            if not results:
                continue
            if len(results) == 1 or not merge_tier:
                package, upstream = results[0]
                self.tag_files_with_upstream(package, upstream)
                return ResolveResult(package=package, upstream=upstream, tier=tier)

            merged = self._merge(results)
            return ResolveResult(package=merged, upstream=results[0][1], tier=tier)
        return None

    async def _query_tier(
        self, candidates: list[Upstream], name: str, *, collect_all: bool
    ) -> list[tuple[RemotePackage, Upstream]]:
        if not settings.upstream_tier_parallel:
            out: list[tuple[RemotePackage, Upstream]] = []
            for upstream in candidates:
                pkg = await self._query_one(upstream, name)
                if pkg is not None:
                    out.append((pkg, upstream))
                    if not collect_all:
                        break
            return out

        async def query(upstream: Upstream) -> tuple[RemotePackage | None, Upstream]:
            # Carry the upstream through with the result so completion order
            # never has to be correlated back to an input.
            return await self._query_one(upstream, name), upstream

        tasks = [asyncio.create_task(query(u)) for u in candidates]
        found: list[tuple[RemotePackage, Upstream]] = []
        try:
            for completed in asyncio.as_completed(tasks):
                package, upstream = await completed
                if package is None:
                    continue
                found.append((package, upstream))
                if not collect_all:
                    break
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        # Preserve configured priority order rather than completion order, so
        # merging is deterministic run to run.
        order = {u.id: i for i, u in enumerate(candidates)}
        found.sort(key=lambda pair: order.get(pair[1].id, 999))
        return found

    async def _query_one(self, upstream: Upstream, name: str) -> RemotePackage | None:
        provider = build_provider(upstream)
        try:
            package = await provider.fetch_package(name)
        except UpstreamNotFound:
            await self._mark_healthy(upstream)
            return None
        except asyncio.CancelledError:
            raise
        except UpstreamError as exc:
            await self._mark_failure(upstream, str(exc))
            return None
        except Exception as exc:
            log.exception("upstream %s raised unexpectedly", upstream.name)
            await self._mark_failure(upstream, repr(exc))
            return None
        await self._mark_healthy(upstream)
        return package

    def _merge(self, results: list[tuple[RemotePackage, Upstream]]) -> RemotePackage:
        """Union file lists; earlier (higher-priority) entries win collisions."""
        base, base_upstream = results[0]
        merged = RemotePackage(
            name=base.name,
            dist_tags=dict(base.dist_tags),
            description=base.description,
            author=base.author,
            homepage=base.homepage,
            license=base.license,
            keywords=list(base.keywords),
            readme=base.readme,
            time=dict(base.time),
            raw=base.raw,
            etag=None,  # a merged document has no single upstream ETag
            upstream_id=base_upstream.id,
            upstream_name=base_upstream.name,
        )

        by_version: dict[str, RemoteVersion] = {}
        # Filenames are globally unique within a project, so one set is enough
        # to give the first (highest-priority) contributor the win.
        claimed_files: set[str] = set()

        for package, upstream in results:
            if not merged.description and package.description:
                merged.description = package.description
            for tag, version in package.dist_tags.items():
                merged.dist_tags.setdefault(tag, version)
            for key, value in package.time.items():
                merged.time.setdefault(key, value)

            for version in package.versions:
                target = by_version.get(version.version)
                if target is None:
                    target = RemoteVersion(
                        version=version.version,
                        metadata=dict(version.metadata),
                        files=[],
                        deprecated=version.deprecated,
                        yanked=version.yanked,
                        requires_python=version.requires_python,
                        published_at=version.published_at,
                    )
                    by_version[version.version] = target
                elif not target.metadata and version.metadata:
                    target.metadata = dict(version.metadata)

                for file in version.files:
                    if file.filename in claimed_files:
                        continue
                    claimed_files.add(file.filename)
                    file.upstream_id = upstream.id
                    target.files.append(file)
                    if file.requires_python and not target.requires_python:
                        target.requires_python = file.requires_python

        # Re-derive yanked state after merging: a version is yanked only when
        # every surviving file is yanked.
        for version in by_version.values():
            if version.files:
                version.yanked = (
                    next(
                        (f.yanked for f in version.files if isinstance(f.yanked, str) and f.yanked),
                        True,
                    )
                    if all(bool(f.yanked) for f in version.files)
                    else False
                )

        merged.versions = list(by_version.values())
        return merged

    @staticmethod
    def tag_files_with_upstream(package: RemotePackage, upstream: Upstream) -> None:
        """Stamp every file with its origin so artifact fetches pick the right
        credentials. ``_merge`` does this itself; single-upstream results need
        it applied after the fact."""
        for version in package.versions:
            for file in version.files:
                if file.upstream_id is None:
                    file.upstream_id = upstream.id

    # -- health bookkeeping ------------------------------------------------- #
    async def _mark_failure(self, upstream: Upstream, error: str) -> None:
        upstream.consecutive_failures = (upstream.consecutive_failures or 0) + 1
        upstream.last_error = error[:2000]
        upstream.last_check_at = datetime.now(UTC)
        if upstream.consecutive_failures >= FAILURE_THRESHOLD:
            upstream.healthy = False
        log.warning("upstream %s failed (%d): %s", upstream.name, upstream.consecutive_failures, error)

    async def _mark_healthy(self, upstream: Upstream) -> None:
        if upstream.consecutive_failures or not upstream.healthy:
            upstream.consecutive_failures = 0
            upstream.healthy = True
            upstream.last_error = None
        upstream.last_check_at = datetime.now(UTC)

    # -- search ------------------------------------------------------------- #
    async def search_upstreams(
        self, ecosystem: Ecosystem, query: str, size: int = 20
    ) -> list[SearchHit]:
        """Fan out to every search-capable upstream, dedup by name, keep the
        first (highest-tier) occurrence."""
        upstreams = await load_upstreams(self.session, ecosystem)
        providers = []
        for upstream in upstreams:
            if is_quarantined(upstream):
                continue
            try:
                provider = build_provider(upstream)
            except UpstreamError:
                continue
            if provider.supports_search or provider.supports_indexing:
                providers.append(provider)
        if not providers:
            return []

        async def run(p: UpstreamProvider) -> list[SearchHit]:
            # A slow or search-less upstream must never hold up the response.
            try:
                return await asyncio.wait_for(p.search(query, size=size), timeout=8.0)
            except Exception:
                return []

        batches = await asyncio.gather(*(run(p) for p in providers))
        seen: set[str] = set()
        merged: list[SearchHit] = []
        for batch in batches:
            for hit in batch:
                key = hit.name.lower()
                if key in seen:
                    continue
                seen.add(key)
                merged.append(hit)
        merged.sort(key=lambda h: h.score, reverse=True)
        return merged[:size]
