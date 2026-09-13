"""PyPI Simple API rendering.

Specs implemented
-----------------
PEP 503  base HTML Simple API and name normalization
PEP 592  ``yanked`` / ``data-yanked``
PEP 629  ``pypi:repository-version`` meta tag / ``meta.api-version``
PEP 658  ``.metadata`` sidecar files
PEP 691  JSON Simple API
PEP 700  ``versions`` key, mandatory ``size``, optional ``upload-time``
PEP 714  ``core-metadata`` (with the ``dist-info-metadata`` alias retained)

We advertise API version 1.1, which is exactly the feature set above. Digests
go in the URL fragment for HTML (PEP 503) and in the ``hashes`` object for JSON
(PEP 691); pip verifies both.
"""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape
from typing import Any
from urllib.parse import quote

from ..config import settings
from ..core.naming import normalize_pypi_name, sort_pypi_versions
from ..models import Package, PackageFile, PackageVersion

API_VERSION = "1.1"

JSON_CONTENT_TYPE = "application/vnd.pypi.simple.v1+json"
HTML_CONTENT_TYPE = "application/vnd.pypi.simple.v1+html"
LEGACY_HTML_CONTENT_TYPE = "text/html"


def select_content_type(accept: str | None, format_param: str | None = None) -> str:
    """PEP 691 content negotiation.

    ``?format=`` wins when present (PEP 691 permits it), then the Accept
    header by q-value, then HTML as the default for bare browsers and old pip.
    """
    if format_param:
        normalized = format_param.strip().lower()
        if normalized in (JSON_CONTENT_TYPE, "json", "application/json"):
            return JSON_CONTENT_TYPE
        if normalized in (HTML_CONTENT_TYPE, "html", "text/html"):
            return HTML_CONTENT_TYPE

    if not accept:
        return HTML_CONTENT_TYPE

    best_type = LEGACY_HTML_CONTENT_TYPE
    best_q = -1.0
    for chunk in accept.split(","):
        parts = [p.strip() for p in chunk.split(";")]
        media = parts[0].lower()
        quality = 1.0
        for param in parts[1:]:
            if param.startswith("q="):
                try:
                    quality = float(param[2:])
                except ValueError:
                    quality = 0.0
        if quality <= best_q:
            continue
        if media in (JSON_CONTENT_TYPE, "application/vnd.pypi.simple.latest+json"):
            best_type, best_q = JSON_CONTENT_TYPE, quality
        elif media in (HTML_CONTENT_TYPE, "application/vnd.pypi.simple.latest+html") or media in (LEGACY_HTML_CONTENT_TYPE, "*/*"):
            best_type, best_q = HTML_CONTENT_TYPE, quality
    return best_type


def wants_json(accept: str | None, format_param: str | None = None) -> bool:
    return select_content_type(accept, format_param) == JSON_CONTENT_TYPE


# --------------------------------------------------------------------------- #
# URLs
# --------------------------------------------------------------------------- #
def file_url(project_name: str, filename: str) -> str:
    """``{base}/pypi/files/{project}/{filename}``."""
    return (
        f"{settings.pypi_base}/files/"
        f"{quote(normalize_pypi_name(project_name), safe='')}/{quote(filename, safe='')}"
    )


def metadata_url(project_name: str, filename: str) -> str:
    """PEP 658 sidecar: the file URL with ``.metadata`` appended."""
    return file_url(project_name, filename) + ".metadata"


def project_url(project_name: str) -> str:
    return f"{settings.pypi_base}/simple/{quote(normalize_pypi_name(project_name), safe='')}/"


# --------------------------------------------------------------------------- #
# Field helpers
# --------------------------------------------------------------------------- #
def _yanked_value(file_row: PackageFile) -> bool | str:
    """PEP 592: ``false``, ``true``, or a reason string."""
    if not file_row.yanked:
        return False
    return file_row.yanked_reason or True


def _core_metadata_value(file_row: PackageFile) -> bool | dict | None:
    """PEP 714: ``true`` or ``{alg: digest}``; omitted when unavailable."""
    value = file_row.core_metadata
    if not value:
        return None
    if isinstance(value, dict):
        digests = {k: v for k, v in value.items() if k != "available" and isinstance(v, str)}
        return digests or True
    return True


def _hashes_for(file_row: PackageFile) -> dict[str, str]:
    hashes: dict[str, str] = {}
    if file_row.sha256:
        hashes["sha256"] = file_row.sha256
    if file_row.blake2b_256:
        hashes["blake2b_256"] = file_row.blake2b_256
    if file_row.md5:
        hashes["md5"] = file_row.md5
    return hashes


def _upload_time(file_row: PackageFile) -> str | None:
    """PEP 700 format: ``yyyy-mm-ddThh:mm:ssZ``, UTC."""
    when = file_row.upload_time
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# JSON (PEP 691 + PEP 700)
# --------------------------------------------------------------------------- #
def render_project_json(
    package: Package, *, excluded_versions: set[str] | None = None
) -> dict[str, Any]:
    excluded = excluded_versions or set()
    files: list[dict[str, Any]] = []
    versions: list[str] = []

    for version_row in package.versions:
        if version_row.version in excluded:
            continue
        versions.append(version_row.version)
        for file_row in version_row.files:
            entry: dict[str, Any] = {
                "filename": file_row.filename,
                "url": file_url(package.name, file_row.filename),
                # PEP 691 requires the key even when we have no digest.
                "hashes": _hashes_for(file_row),
                # PEP 700 makes size mandatory.
                "size": file_row.size or 0,
            }
            requires_python = file_row.requires_python or version_row.requires_python
            if requires_python:
                entry["requires-python"] = requires_python

            yanked = _yanked_value(file_row)
            if yanked is not False:
                entry["yanked"] = yanked

            core_metadata = _core_metadata_value(file_row)
            if core_metadata is not None:
                entry["core-metadata"] = core_metadata
                # PEP 714 keeps the old key for clients that predate the rename.
                entry["dist-info-metadata"] = core_metadata

            upload_time = _upload_time(file_row)
            if upload_time:
                entry["upload-time"] = upload_time

            files.append(entry)

    return {
        "meta": {"api-version": API_VERSION},
        "name": normalize_pypi_name(package.name),
        "files": files,
        "versions": sort_pypi_versions(versions),
    }


def render_index_json(names: list[str]) -> dict[str, Any]:
    return {
        "meta": {"api-version": API_VERSION},
        "projects": [{"name": normalize_pypi_name(name)} for name in names],
    }


# --------------------------------------------------------------------------- #
# HTML (PEP 503 + PEP 592 + PEP 629 + PEP 714)
# --------------------------------------------------------------------------- #
def _anchor_attributes(package: Package, version_row: PackageVersion, file_row: PackageFile) -> str:
    attributes: list[str] = []

    requires_python = file_row.requires_python or version_row.requires_python
    if requires_python:
        # PEP 503 requires this attribute value be HTML-escaped; `>` and `<`
        # are extremely common in specifiers, so this is not optional.
        attributes.append(f'data-requires-python="{escape(requires_python, quote=True)}"')

    yanked = _yanked_value(file_row)
    if yanked is True:
        attributes.append("data-yanked=\"\"")
    elif isinstance(yanked, str):
        attributes.append(f'data-yanked="{escape(yanked, quote=True)}"')

    core_metadata = _core_metadata_value(file_row)
    if core_metadata is not None:
        if isinstance(core_metadata, dict):
            algorithm, digest = next(iter(core_metadata.items()))
            value = f"{algorithm}={digest}"
        else:
            value = "true"
        attributes.append(f'data-core-metadata="{escape(value, quote=True)}"')
        attributes.append(f'data-dist-info-metadata="{escape(value, quote=True)}"')

    return (" " + " ".join(attributes)) if attributes else ""


def render_project_html(package: Package, *, excluded_versions: set[str] | None = None) -> str:
    excluded = excluded_versions or set()
    normalized = normalize_pypi_name(package.name)
    lines = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "  <head>",
        f'    <meta name="pypi:repository-version" content="{API_VERSION}">',
        f"    <title>Links for {escape(normalized)}</title>",
        "  </head>",
        "  <body>",
        f"    <h1>Links for {escape(normalized)}</h1>",
    ]

    for version_row in package.versions:
        if version_row.version in excluded:
            continue
        for file_row in version_row.files:
            url = file_url(package.name, file_row.filename)
            # PEP 503: the digest goes in the URL fragment.
            if file_row.sha256:
                url = f"{url}#sha256={file_row.sha256}"
            attributes = _anchor_attributes(package, version_row, file_row)
            lines.append(
                f'    <a href="{escape(url, quote=True)}"{attributes}>'
                f"{escape(file_row.filename)}</a><br>"
            )

    lines += ["  </body>", "</html>", ""]
    return "\n".join(lines)


def render_index_html(names: list[str]) -> str:
    lines = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "  <head>",
        f'    <meta name="pypi:repository-version" content="{API_VERSION}">',
        "    <title>Simple index</title>",
        "  </head>",
        "  <body>",
    ]
    for name in names:
        normalized = normalize_pypi_name(name)
        lines.append(
            f'    <a href="{escape(normalized, quote=True)}/">{escape(normalized)}</a><br>'
        )
    lines += ["  </body>", "</html>", ""]
    return "\n".join(lines)


def render_json_api_project(
    package: Package, *, excluded_versions: set[str] | None = None
) -> dict[str, Any]:
    """Warehouse-compatible ``/pypi/{name}/json``.

    Not a PEP, but pervasive in tooling, so we serve a faithful subset.

    ``excluded_versions`` carries the policy verdict, exactly as the simple
    index does. A blocked release is omitted entirely rather than marked,
    because this document is a list of things you can install.
    """
    excluded = excluded_versions or set()
    visible = [v for v in package.versions if v.version not in excluded]
    latest = package.latest_version
    if latest in excluded:
        latest = sort_pypi_versions([v.version for v in visible])[-1] if visible else None
    latest_row = next((v for v in visible if v.version == latest), None)
    metadata = (latest_row.metadata_json if latest_row else {}) or {}

    releases: dict[str, list[dict]] = {}
    for version_row in visible:
        releases[version_row.version] = [
            {
                "filename": f.filename,
                "url": file_url(package.name, f.filename),
                "packagetype": f.packagetype,
                "python_version": f.python_version,
                "requires_python": f.requires_python,
                "size": f.size or 0,
                "digests": _hashes_for(f),
                "yanked": bool(f.yanked),
                "yanked_reason": f.yanked_reason,
                "upload_time_iso_8601": _upload_time(f),
            }
            for f in version_row.files
        ]

    return {
        "info": {
            "name": package.name,
            "version": latest,
            "summary": package.description or metadata.get("summary"),
            "home_page": package.homepage,
            "author": package.author,
            "license": package.license,
            "requires_python": latest_row.requires_python if latest_row else None,
            "keywords": ",".join(package.keywords or []),
            "package_url": project_url(package.name),
            "yanked": bool(latest_row.yanked) if latest_row else False,
        },
        "last_serial": 0,
        "releases": releases,
        "urls": releases.get(latest or "", []),
        "vulnerabilities": [],
    }


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
