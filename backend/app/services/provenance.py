"""Where did this package come from?

A package can legitimately be served by more than one upstream:

* PyPI results are merged across a tier, so files for one project genuinely
  arrive from several indexes at once.
* An npm packument is fetched from a single upstream per request, but over time
  different versions can land from different upstreams -- tier 1 being down for
  an hour is enough.
* A package published here can also exist upstream, in which case the local
  copy wins but the upstream one is still worth linking to.

This module reads the provenance we already record on the package, version, and
file rows and turns it into a list of links.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Package, Upstream
from .resolver import build_provider

log = logging.getLogger(__name__)


async def package_upstreams(session: AsyncSession, package: Package) -> list[dict]:
    """Return one entry per upstream that has contributed to this package.

    ``package`` must have ``versions`` (and their ``files``) loaded; this issues
    exactly one extra query, for the upstream rows themselves.
    """
    version_counts: dict[int, int] = defaultdict(int)
    file_counts: dict[int, int] = defaultdict(int)

    for version in package.versions:
        if version.upstream_id:
            version_counts[version.upstream_id] += 1
        for file in version.files:
            if file.upstream_id:
                file_counts[file.upstream_id] += 1

    ids = set(version_counts) | set(file_counts)
    if package.origin_upstream_id:
        ids.add(package.origin_upstream_id)

    entries: list[dict] = []

    # Locally published content has no upstream, but saying so is the whole
    # point of the panel -- otherwise a private package looks like it has no
    # source at all.
    if package.is_local:
        local_versions = sum(1 for v in package.versions if v.is_local)
        entries.append(
            {
                "id": None,
                "name": "Published here",
                "kind": "local",
                "tier": 0,
                "enabled": True,
                "healthy": True,
                "is_origin": not package.origin_upstream_id,
                "versions": local_versions,
                "files": sum(len(v.files) for v in package.versions if v.is_local),
                "web_url": None,
                "index_url": None,
            }
        )

    if not ids:
        return entries

    rows = (
        await session.execute(select(Upstream).where(Upstream.id.in_(ids)))
    ).scalars().all()
    by_id = {u.id: u for u in rows}

    for upstream_id in ids:
        upstream = by_id.get(upstream_id)
        if upstream is None:
            # Upstream was deleted; the packages it fetched are still here.
            entries.append(
                {
                    "id": upstream_id,
                    "name": "(deleted upstream)",
                    "kind": None,
                    "tier": None,
                    "enabled": False,
                    "healthy": False,
                    "is_origin": upstream_id == package.origin_upstream_id,
                    "versions": version_counts.get(upstream_id, 0),
                    "files": file_counts.get(upstream_id, 0),
                    "web_url": None,
                    "index_url": None,
                }
            )
            continue

        web_url = index_url = None
        try:
            provider = build_provider(upstream)
            index_url = provider.package_index_url(package.name)
            web_url = provider.package_web_url(package.name)
        except Exception:
            log.warning("could not build links for upstream %s", upstream.name, exc_info=True)

        entries.append(
            {
                "id": upstream.id,
                "name": upstream.name,
                "kind": upstream.kind.value,
                "tier": upstream.tier,
                "enabled": upstream.enabled,
                "healthy": upstream.healthy,
                "is_origin": upstream.id == package.origin_upstream_id,
                "versions": version_counts.get(upstream.id, 0),
                "files": file_counts.get(upstream.id, 0),
                "web_url": web_url,
                "index_url": index_url,
            }
        )

    # Tier order, so the upstream that actually answers first is listed first.
    entries.sort(key=lambda e: (e["tier"] if e["tier"] is not None else 999, e["name"]))
    return entries
