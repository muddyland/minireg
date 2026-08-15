"""npm registry upstream provider.

Speaks the CommonJS-era registry API: a packument at ``/{name}``, tarballs at
whatever ``dist.tarball`` points to, and search at ``/-/v1/search``.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from ..core.naming import npm_name_to_path
from .base import (
    RemoteFile,
    RemotePackage,
    RemoteVersion,
    SearchHit,
    UpstreamError,
    UpstreamNotFound,
    UpstreamProvider,
)

log = logging.getLogger(__name__)

# Asking for the abbreviated document cuts a large packument (react is ~1MB
# full, ~200KB abbreviated) dramatically. We ask for the full document anyway
# because we must be able to re-serve full packuments 1:1 to clients that
# request them, and we cannot synthesize the hoisted fields from abbreviated.
FULL_ACCEPT = "application/json"
ABBREVIATED_ACCEPT = "application/vnd.npm.install-v1+json"


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class NpmProvider(UpstreamProvider):
    supports_indexing = False  # the public registry has no full-list endpoint
    supports_search = True

    def package_url(self, name: str) -> str:
        """Packument URL. Subclasses (GitLab) override the addressing scheme."""
        return f"{self.base_url}/{npm_name_to_path(name)}"

    #: Hosts whose web UI we can address without being told.
    PUBLIC_WEB = {
        "registry.npmjs.org": "https://www.npmjs.com/package/{name}",
        "registry.yarnpkg.com": "https://www.npmjs.com/package/{name}",
    }

    def package_index_url(self, name: str) -> str:
        return self.package_url(name)

    def default_web_url(self, name: str) -> str | None:
        from urllib.parse import urlsplit

        host = urlsplit(self.base_url).netloc.lower()
        template = self.PUBLIC_WEB.get(host)
        return template.format(name=name) if template else None

    async def fetch_package(self, name: str) -> RemotePackage:
        url = self.package_url(name)
        resp = await self.request("GET", url, headers={"accept": FULL_ACCEPT})
        if resp.status_code == 404:
            raise UpstreamNotFound(f"{self.name}: {name} not found")
        if resp.status_code in (401, 403):
            raise UpstreamError(f"{self.name}: unauthorized ({resp.status_code})")
        if resp.status_code >= 400:
            raise UpstreamError(f"{self.name}: HTTP {resp.status_code}")

        try:
            doc = resp.json()
        except ValueError as exc:
            raise UpstreamError(f"{self.name}: invalid JSON packument") from exc
        if not isinstance(doc, dict) or "versions" not in doc:
            raise UpstreamError(f"{self.name}: malformed packument")

        return self.parse_packument(doc, etag=resp.headers.get("etag"))

    def parse_packument(self, doc: dict, etag: str | None = None) -> RemotePackage:
        name = doc.get("name") or ""
        times = doc.get("time") or {}
        versions: list[RemoteVersion] = []

        for version, vdoc in (doc.get("versions") or {}).items():
            if not isinstance(vdoc, dict):
                continue
            dist = vdoc.get("dist") or {}
            tarball = dist.get("tarball")
            files: list[RemoteFile] = []
            if tarball:
                hashes: dict[str, str] = {}
                if dist.get("shasum"):
                    hashes["sha1"] = dist["shasum"]
                integrity = dist.get("integrity")
                files.append(
                    RemoteFile(
                        filename=tarball.rsplit("/", 1)[-1],
                        url=tarball,
                        hashes=hashes,
                        # dist.unpackedSize is the *uncompressed* tree size, not
                        # the tarball size, so it is not a Content-Length. Real
                        # size is recorded when we first cache the artifact.
                        size=None,
                        content_type="application/octet-stream",
                    )
                )
                if integrity:
                    files[0].hashes["integrity"] = integrity

            deprecated = vdoc.get("deprecated")
            versions.append(
                RemoteVersion(
                    version=version,
                    metadata=vdoc,
                    files=files,
                    deprecated=deprecated if isinstance(deprecated, str) else None,
                    published_at=_parse_time(times.get(version)),
                )
            )

        latest_meta: dict = {}
        dist_tags = doc.get("dist-tags") or {}
        latest = dist_tags.get("latest")
        if latest:
            latest_meta = (doc.get("versions") or {}).get(latest) or {}

        author = doc.get("author") or latest_meta.get("author")
        if isinstance(author, dict):
            author = author.get("name")

        return RemotePackage(
            name=name,
            versions=versions,
            dist_tags=dict(dist_tags),
            description=doc.get("description") or latest_meta.get("description"),
            author=author if isinstance(author, str) else None,
            homepage=doc.get("homepage") or latest_meta.get("homepage"),
            license=doc.get("license") or latest_meta.get("license"),
            keywords=doc.get("keywords") or latest_meta.get("keywords") or [],
            readme=doc.get("readme"),
            time={k: v for k, v in times.items() if isinstance(v, str)},
            raw=doc,
            etag=etag,
            upstream_id=self.id,
            upstream_name=self.name,
        )

    async def search(self, query: str, size: int = 20, offset: int = 0) -> list[SearchHit]:
        url = f"{self.base_url}/-/v1/search"
        try:
            resp = await self.request(
                "GET", url, params={"text": query, "size": min(size, 250), "from": offset}
            )
        except UpstreamError:
            return []
        if resp.status_code != 200:
            return []
        try:
            data = resp.json()
        except ValueError:
            return []

        hits: list[SearchHit] = []
        for obj in data.get("objects") or []:
            pkg = obj.get("package") or {}
            if not pkg.get("name"):
                continue
            author = pkg.get("author")
            if isinstance(author, dict):
                author = author.get("name")
            hits.append(
                SearchHit(
                    name=pkg["name"],
                    version=pkg.get("version"),
                    description=pkg.get("description"),
                    keywords=pkg.get("keywords") or [],
                    author=author if isinstance(author, str) else None,
                    date=_parse_time(pkg.get("date")),
                    links=pkg.get("links") or {},
                    score=float(obj.get("searchScore") or 0.0),
                )
            )
        return hits

    async def health_check(self) -> tuple[bool, str | None]:
        try:
            resp = await self.request("GET", f"{self.base_url}/-/ping", retries=0)
            if resp.status_code < 400:
                return True, None
            # Not every registry implements /-/ping; fall back to a known package.
            resp = await self.request("GET", f"{self.base_url}/npm", retries=0)
            return resp.status_code < 500, (
                None if resp.status_code < 500 else f"HTTP {resp.status_code}"
            )
        except UpstreamError as exc:
            return False, str(exc)
