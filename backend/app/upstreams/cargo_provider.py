"""crates.io sparse-index upstream provider.

Speaks the sparse HTTP registry protocol (RFC 2789), which is what cargo has
used by default since 1.70 and what ``sparse+https://`` selects:

    GET {index}/config.json      -- the download URL template
    GET {index}/{prefix}/{name}  -- one JSON object per line, one line per version

The index is *version*-oriented, unlike PyPI's file-oriented Simple API, so
there is no filename parsing to do: each line already names its version and
carries the artifact's sha256 in ``cksum``.

The older git index is not supported. Cloning a repository the size of the
crates.io index -- and keeping it fetched -- is a different operational shape
than an HTTP cache, and every registry worth mirroring now serves sparse.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

import orjson

from ..core.naming import cargo_crate_filename, cargo_index_path, normalize_cargo_name
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

CRATE_CONTENT_TYPE = "application/x-tar"

def _parse_pubtime(value: Any) -> datetime | None:
    """crates.io stamps each index entry with a ``pubtime``.

    It is an extension rather than part of the sparse-index specification, so
    a registry that omits it is not malformed -- the version simply has no
    known publication date and the UI shows none.
    """
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


#: Substituted into a registry's ``dl`` template. A registry that uses none of
#: them gets ``/{crate}/{version}/download`` appended instead, per the spec.
_DL_MARKERS = ("{crate}", "{version}", "{prefix}", "{lowerprefix}", "{sha256-checksum}")


class CargoProvider(UpstreamProvider):
    #: The sparse index has no endpoint that enumerates every crate. crates.io
    #: publishes a database dump for that, which is not something to pull
    #: through a request path.
    supports_indexing = False
    supports_search = True

    PUBLIC_WEB: ClassVar[dict[str, str]] = {
        "index.crates.io": "https://crates.io/crates/{name}",
        "static.crates.io": "https://crates.io/crates/{name}",
    }

    #: Registries whose sparse index lives on a different host from their web
    #: API, so ``search`` knows where to look without being configured.
    PUBLIC_API: ClassVar[dict[str, str]] = {
        "index.crates.io": "https://crates.io",
        "static.crates.io": "https://crates.io",
    }

    def __init__(self, upstream) -> None:
        super().__init__(upstream)
        # Cached after the first config.json fetch; the document is tiny and
        # effectively static, and every artifact URL is rendered from it.
        self._config: dict[str, Any] | None = None

    # -- addressing --------------------------------------------------------- #
    def index_url(self, name: str) -> str:
        return f"{self.base_url}/{cargo_index_path(name)}"

    def package_index_url(self, name: str) -> str:
        return self.index_url(name)

    def default_web_url(self, name: str) -> str | None:
        host = urlsplit(self.base_url).netloc.lower()
        template = self.PUBLIC_WEB.get(host)
        return template.format(name=name) if template else None

    def api_base(self) -> str | None:
        """Base URL of the registry's web API, used only for search."""
        configured = (self.upstream.extra or {}).get("api_url")
        if configured:
            return str(configured).rstrip("/")
        host = urlsplit(self.base_url).netloc.lower()
        return self.PUBLIC_API.get(host)

    # -- index config ------------------------------------------------------- #
    async def registry_config(self) -> dict[str, Any]:
        """``config.json`` from the index root.

        A missing or unparseable config is not fatal: we fall back to the
        conventional ``{index}/{crate}/{version}/download`` shape, which is what
        a registry serving no template would resolve to anyway.
        """
        if self._config is not None:
            return self._config
        try:
            resp = await self.request("GET", f"{self.base_url}/config.json")
            if resp.status_code < 400:
                doc = orjson.loads(resp.content)
                if isinstance(doc, dict):
                    self._config = doc
                    return doc
        except (UpstreamError, orjson.JSONDecodeError, ValueError):
            log.debug("no usable config.json on %s", self.name, exc_info=True)
        self._config = {}
        return self._config

    def download_url(self, dl_template: str, name: str, version: str, cksum: str | None) -> str:
        """Render a registry's ``dl`` template for one version.

        Per the cargo book: if the template contains none of the markers, the
        path ``/{crate}/{version}/download`` is appended to it.
        """
        base = dl_template.rstrip("/")
        if not any(marker in base for marker in _DL_MARKERS):
            return f"{base}/{quote(name, safe='')}/{quote(version, safe='')}/download"

        lowered = normalize_cargo_name(name)
        prefix = cargo_index_path(name).rsplit("/", 1)[0]
        return (
            base.replace("{crate}", name)
            .replace("{version}", version)
            # `prefix` and `lowerprefix` differ only for a registry that allows
            # uppercase in names; ours are already normalized, so both resolve
            # to the same lowercased shards.
            .replace("{lowerprefix}", prefix)
            .replace("{prefix}", prefix)
            .replace("{sha256-checksum}", cksum or "")
            .replace("{lowername}", lowered)
        )

    # -- fetch -------------------------------------------------------------- #
    async def fetch_package(self, name: str) -> RemotePackage:
        url = self.index_url(name)
        resp = await self.request("GET", url, headers={"accept": "text/plain"})
        if resp.status_code == 404:
            raise UpstreamNotFound(f"{self.name}: {name} not found")
        if resp.status_code in (401, 403):
            raise UpstreamError(f"{self.name}: unauthorized ({resp.status_code})")
        if resp.status_code >= 400:
            raise UpstreamError(f"{self.name}: HTTP {resp.status_code}")

        config = await self.registry_config()
        dl_template = config.get("dl") or self.base_url

        entries = self._parse_index(resp.text)
        if not entries:
            # An index file that exists but holds no parseable line is not the
            # same as a 404, but it is equally unusable -- treat it as absent so
            # the resolver keeps walking the remaining tiers.
            raise UpstreamNotFound(f"{self.name}: {name} has no index entries")

        display_name = entries[0].get("name") or name
        versions: list[RemoteVersion] = []
        for entry in entries:
            version = entry.get("vers")
            if not isinstance(version, str) or not version:
                continue
            cksum = entry.get("cksum") if isinstance(entry.get("cksum"), str) else None
            filename = cargo_crate_filename(display_name, version)
            versions.append(
                RemoteVersion(
                    version=version,
                    # The index line *is* the per-version metadata: deps,
                    # features, links, rust-version. Keeping it whole means the
                    # index we re-serve is byte-equivalent in content to the one
                    # upstream serves, which is what checksum verification on
                    # the client side assumes.
                    metadata=entry,
                    files=[
                        RemoteFile(
                            filename=filename,
                            url=self.download_url(dl_template, display_name, version, cksum),
                            hashes={"sha256": cksum.lower()} if cksum else {},
                            content_type=CRATE_CONTENT_TYPE,
                            packagetype="crate",
                        )
                    ],
                    yanked=bool(entry.get("yanked")),
                    published_at=_parse_pubtime(entry.get("pubtime")),
                )
            )

        return RemotePackage(
            name=display_name,
            versions=versions,
            # The sparse index carries no description, author or license -- it
            # is a resolution index, not a catalogue. Those fields come from the
            # web API when one is reachable, and are otherwise left empty rather
            # than guessed at.
            raw={"index": entries},
            etag=resp.headers.get("etag"),
            upstream_id=self.id,
            upstream_name=self.name,
        )

    @staticmethod
    def _parse_index(body: str) -> list[dict]:
        """Newline-delimited JSON, one object per published version.

        A malformed line is skipped rather than failing the crate: the index is
        append-only and a single bad record must not make every version of a
        crate unresolvable.
        """
        entries: list[dict] = []
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = orjson.loads(line)
            except orjson.JSONDecodeError:
                log.warning("skipping unparseable index line")
                continue
            if isinstance(obj, dict):
                entries.append(obj)
        return entries

    # -- search ------------------------------------------------------------- #
    async def search(self, query: str, size: int = 20, offset: int = 0) -> list[SearchHit]:
        api = self.api_base()
        if not api:
            return []
        try:
            resp = await self.request(
                "GET",
                f"{api}/api/v1/crates",
                params={"q": query, "per_page": min(size, 100)},
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
        for crate in data.get("crates") or []:
            if not isinstance(crate, dict) or not crate.get("name"):
                continue
            hits.append(
                SearchHit(
                    name=crate["name"],
                    version=crate.get("max_stable_version") or crate.get("max_version"),
                    description=crate.get("description"),
                    keywords=[k for k in (crate.get("keywords") or []) if isinstance(k, str)],
                    links={"homepage": crate["homepage"]} if crate.get("homepage") else {},
                    # crates.io returns results already ranked but scores them
                    # by exact-match weighting we cannot reproduce; downloads
                    # are the closest stable proxy for merging across upstreams.
                    score=float(crate.get("downloads") or 0.0),
                )
            )
        return hits

    # -- health ------------------------------------------------------------- #
    async def health_check(self) -> tuple[bool, str | None]:
        try:
            resp = await self.request("GET", f"{self.base_url}/config.json", retries=0)
            if resp.status_code < 400:
                return True, None
            # Not every sparse index exposes config.json to anonymous callers;
            # a known-good crate proves the index is answering either way.
            resp = await self.request("GET", self.index_url("serde"), retries=0)
            return resp.status_code < 500, (
                None if resp.status_code < 500 else f"HTTP {resp.status_code}"
            )
        except UpstreamError as exc:
            return False, str(exc)
