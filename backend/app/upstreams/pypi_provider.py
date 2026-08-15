"""PyPI Simple-API upstream provider.

Prefers the PEP 691 JSON API and falls back to PEP 503 HTML when an upstream
(devpi, an old Artifactory, a plain directory listing) only speaks HTML.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from html.parser import HTMLParser
from typing import ClassVar
from urllib.parse import unquote, urljoin

from ..core.naming import normalize_pypi_name, parse_dist_filename
from .base import (
    RemoteFile,
    RemotePackage,
    RemoteVersion,
    UpstreamError,
    UpstreamNotFound,
    UpstreamProvider,
)

log = logging.getLogger(__name__)

# Ask for the newest JSON we understand, then JSON 1.0, then HTML.
SIMPLE_ACCEPT = (
    "application/vnd.pypi.simple.v1+json;q=1.0, "
    "application/vnd.pypi.simple.v1+html;q=0.2, "
    "text/html;q=0.01"
)


class _SimpleHTMLParser(HTMLParser):
    """PEP 503 HTML anchor scraper, extended with PEP 592/658/714 attributes."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        attributes = dict(attrs)
        href = attributes.get("href")
        if not href:
            return
        self._current = {
            "href": href,
            "requires_python": attributes.get("data-requires-python"),
            # PEP 592: presence of the attribute means yanked; its value is the
            # reason, and an empty value still means yanked.
            "yanked": attributes.get("data-yanked"),
            "yanked_present": "data-yanked" in attributes,
            # PEP 714: data-core-metadata is the current spelling;
            # data-dist-info-metadata is the deprecated alias we still accept.
            "core_metadata": attributes.get("data-core-metadata")
            or attributes.get("data-dist-info-metadata"),
            "gpg_sig": attributes.get("data-gpg-sig"),
            "text": "",
        }
        self.links.append(self._current)

    def handle_data(self, data):
        if self._current is not None:
            self._current["text"] += data

    def handle_endtag(self, tag):
        if tag == "a":
            self._current = None


_HASH_FRAGMENT_RE = re.compile(r"#(?P<alg>[a-z0-9_]+)=(?P<digest>[a-fA-F0-9]+)$")


def _split_hash_fragment(url: str) -> tuple[str, dict[str, str]]:
    """PEP 503 puts the digest in the URL fragment: ``...whl#sha256=abc``."""
    m = _HASH_FRAGMENT_RE.search(url)
    if not m:
        return url, {}
    return url[: m.start()], {m.group("alg").lower(): m.group("digest").lower()}


def _parse_upload_time(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _coerce_core_metadata(value) -> bool | dict | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value or None
    if isinstance(value, dict):
        return value or True
    if isinstance(value, str):
        # HTML attribute form: "true" or "sha256=<digest>"
        if value.lower() in ("true", ""):
            return True
        if "=" in value:
            alg, _, digest = value.partition("=")
            return {alg.lower(): digest}
        return True
    return None


class PyPIProvider(UpstreamProvider):
    supports_indexing = True

    def project_url(self, name: str) -> str:
        # PEP 503 requires the normalized name and a trailing slash.
        return f"{self.base_url}/{normalize_pypi_name(name)}/"

    PUBLIC_WEB: ClassVar[dict[str, str]] = {
        "pypi.org": "https://pypi.org/project/{normalized_name}/",
        "test.pypi.org": "https://test.pypi.org/project/{normalized_name}/",
    }

    def package_index_url(self, name: str) -> str:
        return self.project_url(name)

    def default_web_url(self, name: str) -> str | None:
        from urllib.parse import urlsplit

        host = urlsplit(self.base_url).netloc.lower()
        template = self.PUBLIC_WEB.get(host)
        if not template:
            return None
        return template.format(normalized_name=normalize_pypi_name(name))

    async def fetch_package(self, name: str) -> RemotePackage:
        url = self.project_url(name)
        resp = await self.request("GET", url, headers={"accept": SIMPLE_ACCEPT})
        if resp.status_code == 404:
            raise UpstreamNotFound(f"{self.name}: {name} not found")
        if resp.status_code >= 400:
            raise UpstreamError(f"{self.name}: HTTP {resp.status_code}")

        content_type = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
        if content_type == "application/vnd.pypi.simple.v1+json" or content_type == "application/json":
            files, versions_hint, raw = self._parse_json(resp.json(), url)
        else:
            files, versions_hint, raw = self._parse_html(resp.text, url)

        return self._assemble(name, files, versions_hint, raw, resp.headers.get("etag"))

    # -- parsing ------------------------------------------------------------ #
    def _parse_json(self, doc: dict, base: str) -> tuple[list[RemoteFile], list[str], dict]:
        files: list[RemoteFile] = []
        for entry in doc.get("files") or []:
            filename = entry.get("filename")
            href = entry.get("url")
            if not filename or not href:
                continue
            absolute = urljoin(base, href)
            absolute, frag_hashes = _split_hash_fragment(absolute)
            hashes = {k.lower(): v.lower() for k, v in (entry.get("hashes") or {}).items()}
            hashes.update(frag_hashes)

            yanked = entry.get("yanked", False)
            parsed = parse_dist_filename(filename)
            files.append(
                RemoteFile(
                    filename=filename,
                    url=absolute,
                    hashes=hashes,
                    size=entry.get("size"),
                    requires_python=entry.get("requires-python"),
                    yanked=yanked if isinstance(yanked, (bool, str)) else False,
                    core_metadata=_coerce_core_metadata(
                        entry.get("core-metadata", entry.get("dist-info-metadata"))
                    ),
                    upload_time=_parse_upload_time(entry.get("upload-time")),
                    packagetype=parsed[2] if parsed else None,
                    python_version=self._python_version_for(filename, parsed),
                )
            )
        # PEP 700 versions key, when the upstream provides it.
        versions = [v for v in (doc.get("versions") or []) if isinstance(v, str)]
        return files, versions, doc

    def _parse_html(self, html: str, base: str) -> tuple[list[RemoteFile], list[str], dict]:
        parser = _SimpleHTMLParser()
        parser.feed(html)
        files: list[RemoteFile] = []
        for link in parser.links:
            absolute = urljoin(base, link["href"])
            absolute, hashes = _split_hash_fragment(absolute)
            filename = (link["text"] or "").strip() or unquote(absolute.rsplit("/", 1)[-1])
            if not filename:
                continue
            yanked: bool | str = False
            if link["yanked_present"]:
                yanked = link["yanked"] or True
            parsed = parse_dist_filename(filename)
            files.append(
                RemoteFile(
                    filename=filename,
                    url=absolute,
                    hashes=hashes,
                    requires_python=link["requires_python"],
                    yanked=yanked,
                    core_metadata=_coerce_core_metadata(link["core_metadata"]),
                    packagetype=parsed[2] if parsed else None,
                    python_version=self._python_version_for(filename, parsed),
                )
            )
        return files, [], {}

    @staticmethod
    def _python_version_for(filename: str, parsed: tuple | None) -> str | None:
        """PyPI's ``python_version`` field: ``source`` for sdists, else the wheel
        python tag."""
        if not parsed:
            return None
        if parsed[2] == "sdist":
            return "source"
        if filename.endswith(".whl"):
            parts = filename[: -len(".whl")].split("-")
            if len(parts) >= 3:
                return parts[-3]
        return None

    def _assemble(
        self,
        name: str,
        files: list[RemoteFile],
        versions_hint: list[str],
        raw: dict,
        etag: str | None,
    ) -> RemotePackage:
        """Group flat file lists into versions, which is the shape the rest of
        the system stores. The Simple API is file-oriented, not version-oriented,
        so the version has to come out of the filename."""
        by_version: dict[str, RemoteVersion] = {}
        for file in files:
            parsed = parse_dist_filename(file.filename)
            version = parsed[1] if parsed else "0.0.0+unknown"
            rv = by_version.get(version)
            if rv is None:
                rv = RemoteVersion(version=version, files=[])
                by_version[version] = rv
            rv.files.append(file)
            if file.requires_python and not rv.requires_python:
                rv.requires_python = file.requires_python
            if file.upload_time and (rv.published_at is None or file.upload_time < rv.published_at):
                rv.published_at = file.upload_time

        # A version is yanked only when every one of its files is yanked.
        for rv in by_version.values():
            if rv.files and all(bool(f.yanked) for f in rv.files):
                reasons = [f.yanked for f in rv.files if isinstance(f.yanked, str) and f.yanked]
                rv.yanked = reasons[0] if reasons else True

        # PEP 700 allows versions with no files; keep them visible.
        for version in versions_hint:
            by_version.setdefault(version, RemoteVersion(version=version, files=[]))

        return RemotePackage(
            name=raw.get("name") or name,
            versions=list(by_version.values()),
            raw=raw,
            etag=etag,
            upstream_id=self.id,
            upstream_name=self.name,
        )

    # -- indexing / health -------------------------------------------------- #
    async def list_packages(self) -> list[str]:
        resp = await self.request(
            "GET", f"{self.base_url}/", headers={"accept": SIMPLE_ACCEPT}
        )
        if resp.status_code >= 400:
            raise UpstreamError(f"{self.name}: HTTP {resp.status_code}")
        content_type = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
        if "json" in content_type:
            return [
                p["name"]
                for p in (resp.json().get("projects") or [])
                if isinstance(p, dict) and p.get("name")
            ]
        parser = _SimpleHTMLParser()
        parser.feed(resp.text)
        return [(link["text"] or "").strip() for link in parser.links if (link["text"] or "").strip()]

    async def health_check(self) -> tuple[bool, str | None]:
        try:
            resp = await self.request(
                "GET", f"{self.base_url}/pip/", headers={"accept": SIMPLE_ACCEPT}, retries=0
            )
            return resp.status_code < 500, (
                None if resp.status_code < 500 else f"HTTP {resp.status_code}"
            )
        except UpstreamError as exc:
            return False, str(exc)
