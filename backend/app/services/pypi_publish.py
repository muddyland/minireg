"""PyPI legacy upload (``twine upload``) parsing and validation.

twine POSTs ``multipart/form-data`` to the upload endpoint with
``:action=file_upload``, the distribution as the ``content`` part, and the
package's core metadata flattened into form fields.

Warehouse's own rules that we reproduce:

* the filename must agree with the ``name`` and ``version`` fields
* every digest the client supplies must match the bytes received
* only one sdist per release
* re-uploading an existing filename is rejected (PyPI never overwrites)
"""

from __future__ import annotations

import logging
import re
import zipfile
from dataclasses import dataclass, field
from email.parser import Parser
from io import BytesIO
from typing import Any

from ..core.naming import (
    is_valid_pypi_name,
    normalize_pypi_name,
    normalize_pypi_version,
    parse_dist_filename,
)

log = logging.getLogger(__name__)

VALID_FILETYPES = {"sdist", "bdist_wheel", "bdist_egg", "bdist_wininst", "bdist_dumb"}

# Warehouse's allowed distribution extensions.
ALLOWED_EXTENSIONS = (".tar.gz", ".zip", ".whl", ".egg")

MAX_FILE_BYTES = 1024 * 1024 * 1024

# Fields that may appear more than once in the form.
MULTIVALUED = {
    "classifiers",
    "requires_dist",
    "provides_dist",
    "obsoletes_dist",
    "requires_external",
    "project_urls",
    "supported_platform",
    "platform",
    "license_file",
    "dynamic",
}

_FILENAME_RE = re.compile(r"^[A-Za-z0-9._+!-]+$")


class UploadError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


@dataclass(slots=True)
class UploadRequest:
    name: str
    version: str
    filename: str
    content: bytes
    filetype: str
    pyversion: str | None = None
    metadata_version: str | None = None
    summary: str | None = None
    description: str | None = None
    description_content_type: str | None = None
    author: str | None = None
    author_email: str | None = None
    maintainer: str | None = None
    maintainer_email: str | None = None
    license: str | None = None
    keywords: str | None = None
    home_page: str | None = None
    requires_python: str | None = None
    classifiers: list[str] = field(default_factory=list)
    requires_dist: list[str] = field(default_factory=list)
    project_urls: list[str] = field(default_factory=list)
    md5_digest: str | None = None
    sha256_digest: str | None = None
    blake2_256_digest: str | None = None
    content_type: str = "application/octet-stream"
    raw_fields: dict[str, Any] = field(default_factory=dict)

    @property
    def normalized_name(self) -> str:
        return normalize_pypi_name(self.name)

    @property
    def normalized_version(self) -> str:
        return normalize_pypi_version(self.version)

    @property
    def keyword_list(self) -> list[str]:
        if not self.keywords:
            return []
        return [k.strip() for k in re.split(r"[,\s]+", self.keywords) if k.strip()]


def _single(form: dict[str, Any], key: str) -> str | None:
    value = form.get(key)
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    text = str(value).strip()
    # Warehouse treats the literal "UNKNOWN" as absent.
    return None if text in ("", "UNKNOWN") else text


def _multi(form: dict[str, Any], key: str) -> list[str]:
    value = form.get(key)
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [str(value).strip()] if str(value).strip() else []


def parse_upload(
    form: dict[str, Any], filename: str, content: bytes, content_type: str
) -> UploadRequest:
    """Validate a legacy upload form and return a normalized request."""
    action = _single(form, ":action") or _single(form, "action")
    if action and action not in ("file_upload", "submit"):
        raise UploadError(f"unsupported :action '{action}'")

    name = _single(form, "name")
    version = _single(form, "version")
    if not name:
        raise UploadError("'name' is required")
    if not version:
        raise UploadError("'version' is required")
    if not is_valid_pypi_name(name):
        raise UploadError(f"'{name}' is not a valid project name (PEP 508)")

    if not filename:
        raise UploadError("no filename supplied for the uploaded content")
    if not _FILENAME_RE.match(filename):
        raise UploadError(f"invalid characters in filename '{filename}'")
    if not filename.endswith(ALLOWED_EXTENSIONS):
        raise UploadError(
            f"unsupported distribution type for '{filename}'; "
            f"expected one of {', '.join(ALLOWED_EXTENSIONS)}"
        )
    if not content:
        raise UploadError("uploaded file is empty")
    if len(content) > MAX_FILE_BYTES:
        raise UploadError("uploaded file exceeds the size limit", status_code=413)

    filetype = _single(form, "filetype")
    parsed = parse_dist_filename(filename)
    if parsed is None:
        raise UploadError(f"could not parse project name and version from '{filename}'")
    file_name_part, file_version_part, inferred_type = parsed
    filetype = filetype or inferred_type
    if filetype not in VALID_FILETYPES:
        raise UploadError(f"invalid filetype '{filetype}'")

    # The filename is the authority pip trusts, so it must agree with the form.
    if normalize_pypi_name(file_name_part) != normalize_pypi_name(name):
        raise UploadError(
            f"filename '{filename}' does not match the declared project name '{name}'"
        )
    if normalize_pypi_version(file_version_part) != normalize_pypi_version(version):
        raise UploadError(
            f"filename '{filename}' does not match the declared version '{version}'"
        )

    return UploadRequest(
        name=name,
        version=version,
        filename=filename,
        content=content,
        filetype=filetype,
        pyversion=_single(form, "pyversion") or ("source" if filetype == "sdist" else None),
        metadata_version=_single(form, "metadata_version"),
        summary=_single(form, "summary"),
        description=_single(form, "description"),
        description_content_type=_single(form, "description_content_type"),
        author=_single(form, "author"),
        author_email=_single(form, "author_email"),
        maintainer=_single(form, "maintainer"),
        maintainer_email=_single(form, "maintainer_email"),
        license=_single(form, "license") or _single(form, "license_expression"),
        keywords=_single(form, "keywords"),
        home_page=_single(form, "home_page"),
        requires_python=_single(form, "requires_python"),
        classifiers=_multi(form, "classifiers"),
        requires_dist=_multi(form, "requires_dist"),
        project_urls=_multi(form, "project_urls"),
        md5_digest=(_single(form, "md5_digest") or "").lower() or None,
        sha256_digest=(_single(form, "sha256_digest") or "").lower() or None,
        blake2_256_digest=(_single(form, "blake2_256_digest") or "").lower() or None,
        content_type=content_type or "application/octet-stream",
        raw_fields={k: v for k, v in form.items() if k != "content"},
    )


def verify_digests(request: UploadRequest, stored) -> None:
    """Every digest the client declared must match what we received."""
    for label, declared, actual in (
        ("md5", request.md5_digest, stored.md5),
        ("sha256", request.sha256_digest, stored.sha256),
        ("blake2_256", request.blake2_256_digest, stored.blake2b_256),
    ):
        if declared and declared != actual.lower():
            raise UploadError(
                f"{label} digest mismatch: client declared {declared}, "
                f"server computed {actual}"
            )


#: Nothing legitimate puts a megabyte of core metadata in a wheel, and
#: `ZipFile.read` will happily inflate whatever the central directory claims.
MAX_METADATA_BYTES = 4 * 1024 * 1024


def _read_metadata_member(archive: zipfile.ZipFile) -> str | None:
    """Read `*.dist-info/METADATA` with a bound on the inflated size."""
    candidates = [
        info
        for info in archive.infolist()
        if info.filename.endswith(".dist-info/METADATA") and info.filename.count("/") == 1
    ]
    if not candidates:
        return None
    info = candidates[0]
    # Trust the header enough to reject early, then bound the actual read so a
    # lying header cannot turn a 5 MB wheel into a 4 GB allocation.
    if info.file_size > MAX_METADATA_BYTES:
        return None
    with archive.open(info) as handle:
        data = handle.read(MAX_METADATA_BYTES + 1)
    if len(data) > MAX_METADATA_BYTES:
        return None
    return data.decode("utf-8", "replace")


def extract_wheel_metadata_from_path(path, filename: str) -> dict[str, Any] | None:
    """Same as :func:`extract_wheel_metadata`, reading the zip from disk.

    Used on the PEP 658 read path, where the wheel is already a blob on the
    filesystem: `zipfile` seeks to the central directory and inflates one
    member, so a 900 MB wheel costs a few kilobytes of memory instead of being
    loaded whole.
    """
    if not str(filename).endswith(".whl"):
        return None
    try:
        with zipfile.ZipFile(path) as archive:
            raw = _read_metadata_member(archive)
    except (zipfile.BadZipFile, KeyError, OSError):
        return None
    if raw is None:
        return None
    return _parse_metadata(raw)


def extract_wheel_metadata(content: bytes, filename: str) -> dict[str, Any] | None:
    """Pull ``*.dist-info/METADATA`` out of a wheel.

    Enables PEP 658: pip can then fetch metadata without downloading the wheel,
    which is a large win for resolution.
    """
    if not filename.endswith(".whl"):
        return None
    try:
        with zipfile.ZipFile(BytesIO(content)) as archive:
            raw = _read_metadata_member(archive)
    except (zipfile.BadZipFile, KeyError, OSError):
        return None
    if raw is None:
        return None
    return _parse_metadata(raw)


def _parse_metadata(raw: str) -> dict[str, Any]:
    message = Parser().parsestr(raw)
    metadata: dict[str, Any] = {"_raw": raw}
    for key in message:
        values = message.get_all(key) or []
        normalized = key.lower().replace("-", "_")
        metadata[normalized] = values if len(values) > 1 else values[0]
    return metadata


def metadata_from_upload(request: UploadRequest) -> dict[str, Any]:
    """Core metadata as a dict, for storage on the version row."""
    return {
        "metadata_version": request.metadata_version,
        "name": request.name,
        "version": request.version,
        "summary": request.summary,
        "description_content_type": request.description_content_type,
        "author": request.author,
        "author_email": request.author_email,
        "maintainer": request.maintainer,
        "maintainer_email": request.maintainer_email,
        "license": request.license,
        "keywords": request.keyword_list,
        "home_page": request.home_page,
        "requires_python": request.requires_python,
        "classifiers": request.classifiers,
        "requires_dist": request.requires_dist,
        "project_urls": request.project_urls,
        "filetype": request.filetype,
        "pyversion": request.pyversion,
    }
