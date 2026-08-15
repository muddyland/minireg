"""npm publish document handling.

``npm publish`` sends a single PUT to ``/{package}`` carrying a CouchDB-style
document: the whole packument plus the tarball inlined under ``_attachments``
as base64. The same endpoint is reused by ``npm deprecate`` (a document with
``deprecated`` set on versions and no attachment) and by ``npm unpublish``.

We therefore have to classify the intent from the document's shape.
"""

from __future__ import annotations

import base64
import binascii
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..core.naming import is_valid_npm_name, is_valid_semver, npm_tarball_filename

log = logging.getLogger(__name__)

# npm's own cap; anything larger is almost certainly a mistake.
MAX_ATTACHMENT_BYTES = 1024 * 1024 * 1024


class PublishError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


@dataclass(slots=True)
class Attachment:
    filename: str
    data: bytes
    content_type: str
    declared_length: int | None = None


@dataclass(slots=True)
class PublishRequest:
    """A parsed and validated npm publish document."""

    name: str
    versions: dict[str, dict] = field(default_factory=dict)
    dist_tags: dict[str, str] = field(default_factory=dict)
    attachments: dict[str, Attachment] = field(default_factory=dict)
    access: str | None = None
    readme: str | None = None
    description: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    #: "publish" | "deprecate" | "unpublish"
    intent: str = "publish"
    #: Versions whose `deprecated` field changed, for the deprecate intent.
    deprecations: dict[str, str] = field(default_factory=dict)

    @property
    def new_versions(self) -> list[str]:
        return list(self.versions)


def _decode_attachment(filename: str, spec: dict) -> Attachment:
    data = spec.get("data")
    if not isinstance(data, str):
        raise PublishError(f"attachment '{filename}' has no data")
    try:
        # validate=True so silently-truncated base64 is caught here rather than
        # producing a corrupt tarball.
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PublishError(f"attachment '{filename}' is not valid base64") from exc

    if len(raw) > MAX_ATTACHMENT_BYTES:
        raise PublishError(f"attachment '{filename}' exceeds the size limit", status_code=413)

    declared = spec.get("length")
    if isinstance(declared, int) and declared != len(raw):
        raise PublishError(
            f"attachment '{filename}' length mismatch: declared {declared}, got {len(raw)}"
        )

    return Attachment(
        filename=filename,
        data=raw,
        content_type=spec.get("content_type") or "application/octet-stream",
        declared_length=declared if isinstance(declared, int) else None,
    )


def parse_publish_document(doc: Any, path_name: str) -> PublishRequest:
    """Validate an incoming publish document and classify its intent."""
    if not isinstance(doc, dict):
        raise PublishError("publish body must be a JSON object")

    name = doc.get("name") or doc.get("_id") or path_name
    if not isinstance(name, str) or not name:
        raise PublishError("publish document has no package name")
    if name != path_name:
        raise PublishError(
            f"package name '{name}' does not match the request path '{path_name}'"
        )

    valid, reason = is_valid_npm_name(name)
    if not valid:
        raise PublishError(f"invalid package name: {reason}")

    versions = doc.get("versions")
    if versions is not None and not isinstance(versions, dict):
        raise PublishError("'versions' must be an object")
    versions = versions or {}

    for version, meta in versions.items():
        if not is_valid_semver(version):
            raise PublishError(f"'{version}' is not a valid semver version")
        if not isinstance(meta, dict):
            raise PublishError(f"version '{version}' metadata must be an object")
        declared = meta.get("version")
        if declared is not None and declared != version:
            raise PublishError(
                f"version key '{version}' does not match its metadata version '{declared}'"
            )

    dist_tags = doc.get("dist-tags") or {}
    if not isinstance(dist_tags, dict):
        raise PublishError("'dist-tags' must be an object")
    for tag, version in dist_tags.items():
        if not isinstance(version, str):
            raise PublishError(f"dist-tag '{tag}' must map to a version string")
        if is_valid_semver(tag):
            # npm forbids this: a tag that parses as a version makes
            # `npm install pkg@1.0.0` ambiguous.
            raise PublishError(f"dist-tag '{tag}' must not be a valid semver version")

    raw_attachments = doc.get("_attachments") or {}
    if not isinstance(raw_attachments, dict):
        raise PublishError("'_attachments' must be an object")
    attachments = {
        filename: _decode_attachment(filename, spec)
        for filename, spec in raw_attachments.items()
        if isinstance(spec, dict) and spec.get("data")
    }

    deprecations = {
        version: meta["deprecated"]
        for version, meta in versions.items()
        if isinstance(meta.get("deprecated"), str)
    }

    # Intent: an attachment means new bytes are being published. No attachment
    # but versions present means a metadata-only edit (deprecate/undeprecate).
    if attachments:
        intent = "publish"
    elif versions:
        intent = "deprecate"
    else:
        intent = "unpublish"

    return PublishRequest(
        name=name,
        versions=versions,
        dist_tags=dict(dist_tags),
        attachments=attachments,
        access=doc.get("access"),
        readme=doc.get("readme") if isinstance(doc.get("readme"), str) else None,
        description=doc.get("description") if isinstance(doc.get("description"), str) else None,
        raw=doc,
        intent=intent,
        deprecations=deprecations,
    )


def match_attachment(request: PublishRequest, version: str) -> Attachment | None:
    """Find the tarball belonging to a version.

    npm names it ``{unscoped-name}-{version}.tgz``, but we also accept a
    ``dist.tarball`` basename because some clients and proxies differ.
    """
    expected = npm_tarball_filename(request.name, version)
    if expected in request.attachments:
        return request.attachments[expected]

    meta = request.versions.get(version) or {}
    tarball = (meta.get("dist") or {}).get("tarball")
    if isinstance(tarball, str):
        basename = tarball.rsplit("/", 1)[-1]
        if basename in request.attachments:
            return request.attachments[basename]

    # Single-version publish with an oddly named attachment: unambiguous.
    if len(request.attachments) == 1 and len(request.versions) == 1:
        return next(iter(request.attachments.values()))
    return None


def publish_ok_response(name: str, version: str | None = None) -> dict:
    """The success envelope npm expects. ``ok`` may be a string; the CLI prints
    it verbatim on success."""
    return {
        "ok": True,
        "id": name,
        "rev": f"{int(datetime.now(UTC).timestamp())}-{version or 'meta'}",
        "success": True,
    }
