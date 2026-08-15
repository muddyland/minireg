"""npm packument rendering.

The registry API has two documents, distinguished by the Accept header:

* **full** -- ``application/json``. Everything: hoisted latest-version fields,
  ``time``, ``readme``, ``_id``/``_rev``, complete version objects.
* **abbreviated** -- ``application/vnd.npm.install-v1+json``. A strict subset,
  and the fields are *whitelisted*: anything not on npm's list is dropped.
  This is what ``npm install`` requests, and it is where most of the bandwidth
  saving lives.

Every ``dist.tarball`` is rewritten to point at this registry so the client
comes back to us for bytes instead of leaking to the upstream.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from ..config import settings
from ..core.naming import max_semver, npm_tarball_filename
from ..models import Package, PackageVersion

# The abbreviated document permits exactly these keys inside each version.
# Source: npm/registry docs/responses/package-metadata.md
ABBREVIATED_VERSION_KEYS = frozenset(
    {
        "name",
        "version",
        "deprecated",
        "dependencies",
        "acceptDependencies",
        "optionalDependencies",
        "devDependencies",
        "bundleDependencies",
        "peerDependencies",
        "peerDependenciesMeta",
        "bin",
        "directories",
        "dist",
        "engines",
        "_hasShrinkwrap",
        "hasInstallScript",
        "funding",
        "cpu",
        "os",
    }
)

ABBREVIATED_CONTENT_TYPE = "application/vnd.npm.install-v1+json"
FULL_CONTENT_TYPE = "application/json"


def wants_abbreviated(accept: str | None) -> bool:
    """npm sends ``Accept: application/vnd.npm.install-v1+json; q=1.0,
    application/json; q=0.8, */*``. Presence of the install-v1 type wins."""
    if not accept:
        return False
    return "application/vnd.npm.install-v1+json" in accept.lower()


def tarball_url(package_name: str, version: str, filename: str | None = None) -> str:
    """``{base}/npm/{name}/-/{filename}`` -- npm's canonical tarball path.

    The name keeps its slash for scoped packages here (npm does not encode it
    in the tarball path, only in the packument path).
    """
    name_part = "/".join(quote(segment, safe="") for segment in package_name.split("/"))
    fname = filename or npm_tarball_filename(package_name, version)
    return f"{settings.npm_base}/{name_part}/-/{quote(fname, safe='')}"


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    # npm uses millisecond precision with a Z suffix.
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _dist_for(package: Package, version_row: PackageVersion) -> dict[str, Any]:
    """Build the ``dist`` object, rewriting the tarball URL to point here."""
    original = (version_row.metadata_json or {}).get("dist") or {}
    file_row = next(iter(version_row.files), None)

    dist: dict[str, Any] = {
        k: v
        for k, v in original.items()
        # These we always own; the rest (fileCount, unpackedSize, signatures,
        # npm-signature, attestations) pass through untouched.
        if k not in ("tarball", "shasum", "integrity")
    }
    dist["tarball"] = tarball_url(
        package.name, version_row.version, file_row.filename if file_row else None
    )

    shasum = (file_row.sha1 if file_row else None) or original.get("shasum")
    if shasum:
        dist["shasum"] = shasum
    integrity = (file_row.integrity if file_row else None) or original.get("integrity")
    if integrity:
        dist["integrity"] = integrity
    return dist


def render_version(
    package: Package, version_row: PackageVersion, *, abbreviated: bool
) -> dict[str, Any]:
    base = dict(version_row.metadata_json or {})
    base.setdefault("name", package.name)
    base["version"] = version_row.version
    base["dist"] = _dist_for(package, version_row)

    if version_row.deprecated:
        base["deprecated"] = version_row.deprecated

    if not abbreviated:
        base.setdefault("_id", f"{package.name}@{version_row.version}")
        return base

    # Whitelist filter. npm clients rely on absent keys, not null ones.
    return {k: v for k, v in base.items() if k in ABBREVIATED_VERSION_KEYS}


def _dist_tags(package: Package) -> dict[str, str]:
    tags = {t.tag: t.version for t in package.dist_tags}
    if "latest" not in tags:
        derived = package.latest_version or max_semver([v.version for v in package.versions])
        if derived:
            tags["latest"] = derived
    return tags


def _time_map(package: Package) -> dict[str, str]:
    """``time`` maps each version to its publish timestamp, plus the special
    ``created`` and ``modified`` keys."""
    times: dict[str, str] = {}
    stamps: list[datetime] = []
    for version_row in package.versions:
        when = version_row.published_at or version_row.first_seen_at
        rendered = _iso(when)
        if rendered:
            times[version_row.version] = rendered
        if when:
            stamps.append(when.replace(tzinfo=UTC) if when.tzinfo is None else when)

    created = min(stamps) if stamps else package.first_seen_at
    modified = max(stamps) if stamps else package.updated_at
    if created:
        times["created"] = _iso(created)
    if modified:
        times["modified"] = _iso(modified)
    return times


def render_packument(package: Package, *, abbreviated: bool) -> dict[str, Any]:
    versions = sorted(package.versions, key=lambda v: v.version)
    rendered_versions = {
        v.version: render_version(package, v, abbreviated=abbreviated) for v in versions
    }
    dist_tags = _dist_tags(package)

    if abbreviated:
        # Exactly four top-level keys; nothing else is permitted.
        modified = _time_map(package).get("modified") or _iso(package.updated_at)
        return {
            "name": package.name,
            "modified": modified,
            "dist-tags": dist_tags,
            "versions": rendered_versions,
        }

    doc: dict[str, Any] = {
        "_id": package.name,
        "_rev": f"{len(versions)}-{int((package.updated_at or package.first_seen_at).timestamp())}",
        "name": package.name,
        "dist-tags": dist_tags,
        "versions": rendered_versions,
        "time": _time_map(package),
    }

    # Fields hoisted from the `latest` version, per the full-packument format.
    latest = dist_tags.get("latest")
    latest_meta = (rendered_versions.get(latest) or {}) if latest else {}
    cached = package.cached_document or {}

    for field in (
        "description",
        "homepage",
        "keywords",
        "repository",
        "author",
        "bugs",
        "license",
        "contributors",
        "maintainers",
        "readmeFilename",
    ):
        value = cached.get(field, latest_meta.get(field))
        if value is not None:
            doc[field] = value

    doc.setdefault("description", package.description or "")
    if package.homepage and "homepage" not in doc:
        doc["homepage"] = package.homepage
    if package.license and "license" not in doc:
        doc["license"] = package.license
    if package.keywords and "keywords" not in doc:
        doc["keywords"] = package.keywords

    readme = cached.get("readme") or latest_meta.get("readme")
    if readme:
        doc["readme"] = readme
    if cached.get("users"):
        doc["users"] = cached["users"]

    return doc


def render_version_document(package: Package, version_row: PackageVersion) -> dict[str, Any]:
    """``GET /:package/:version`` returns a bare version object, not a packument."""
    doc = render_version(package, version_row, abbreviated=False)
    doc.setdefault("_id", f"{package.name}@{version_row.version}")
    if package.description and "description" not in doc:
        doc["description"] = package.description
    return doc


def render_search_response(
    hits: list[dict], total: int, *, time: datetime | None = None
) -> dict[str, Any]:
    """``GET /-/v1/search`` response envelope.

    Each object carries ``package``, ``score`` (with ``detail``), and
    ``searchScore``. Clients read ``objects[].package`` and tolerate flat
    scores, but npm's own UI reads the detail breakdown, so we emit it.
    """
    return {
        "objects": hits,
        "total": total,
        "time": (time or datetime.now(UTC)).strftime("%a %b %d %Y %H:%M:%S GMT+0000 (UTC)"),
    }


def build_search_object(
    *,
    name: str,
    version: str | None,
    description: str | None,
    keywords: list[str] | None,
    author: str | None,
    date: datetime | None,
    score: float,
    publisher: str | None = None,
) -> dict[str, Any]:
    normalized = max(0.0, min(1.0, score))
    return {
        "package": {
            "name": name,
            "version": version or "0.0.0",
            "description": description or "",
            "keywords": keywords or [],
            "date": _iso(date),
            "links": {"npm": f"{settings.npm_base}/{quote(name, safe='@/')}"},
            **({"author": {"name": author}} if author else {}),
            **({"publisher": {"username": publisher}} if publisher else {}),
            "maintainers": [],
        },
        "score": {
            "final": normalized,
            "detail": {
                "quality": normalized,
                "popularity": normalized,
                "maintenance": normalized,
            },
        },
        "searchScore": score,
    }
