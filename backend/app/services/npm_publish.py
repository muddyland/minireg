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
import io
import logging
import tarfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..config import settings
from ..core.naming import is_valid_npm_name, is_valid_semver, npm_tarball_filename
from .storage import Digests

log = logging.getLogger(__name__)

# npm's own cap; anything larger is almost certainly a mistake.
# Mirrors the transport-level cap in main.limit_body_size. Kept as a second
# line of defence for a chunked request, which carries no Content-Length.
MAX_ATTACHMENT_BYTES = settings.max_publish_bytes


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


# --------------------------------------------------------------------------- #
# Tarball checks that run before a single byte is stored
# --------------------------------------------------------------------------- #
def digest_tarball(data: bytes) -> Digests:
    """Every digest the publish path checks or records, from bytes in memory."""
    digests = Digests()
    digests.update(data)
    return digests


def verify_declared_digests(version: str, meta: dict, digests: Digests) -> None:
    """Reject a publish whose ``dist`` disagrees with its own tarball.

    ``shasum`` and ``integrity`` are both optional, and the values we serve
    are always recomputed from the stored bytes. A declared value that does
    not match is still refused rather than silently corrected: it means the
    client packed one thing and uploaded another, and the user should hear
    about it at publish time, not when a lockfile written against the
    declared digest fails with EINTEGRITY.
    """
    declared = meta.get("dist") or {}
    if not isinstance(declared, dict):
        return

    shasum = declared.get("shasum")
    actual_sha1 = digests.sha1.hexdigest()
    if isinstance(shasum, str) and shasum and shasum.lower() != actual_sha1:
        raise PublishError(
            f"shasum mismatch for {version}: declared {shasum}, got {actual_sha1}"
        )

    integrity = declared.get("integrity")
    if not isinstance(integrity, str) or not integrity.strip():
        return
    actual = {
        "sha512": digests.sha512.digest(),
        "sha256": digests.sha256.digest(),
        "sha1": digests.sha1.digest(),
    }
    for token in integrity.split():
        algorithm, sep, rest = token.partition("-")
        if not sep or algorithm not in actual:
            # An algorithm we do not compute (sha384) proves nothing either way.
            continue
        encoded = rest.split("?", 1)[0]
        try:
            claimed = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            claimed = b""
        if claimed != actual[algorithm]:
            expected = "sha512-" + base64.b64encode(actual["sha512"]).decode()
            raise PublishError(
                f"integrity mismatch for {version}: declared {token}, got {expected}"
            )


#: Lifecycle scripts that make npm run code at install time.
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")
#: Most tar members we look at for ``binding.gyp`` before giving up.
_MAX_TAR_MEMBERS = 10_000


def tarball_has_binding_gyp(data: bytes) -> bool:
    """Whether the package root holds ``binding.gyp``.

    npm runs ``node-gyp rebuild`` for such a package even with no install
    script declared, and the public registry counts it as one. The tarball is
    already in memory; this reads member headers in stream mode and stops at
    the first hit. A tarball we cannot read answers False -- the metadata
    flag is not the place to refuse a publish.
    """
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|*") as archive:
            for count, member in enumerate(archive):
                if count >= _MAX_TAR_MEMBERS:
                    return False
                parts = [p for p in member.name.split("/") if p and p != "."]
                # npm packs everything under one top-level directory,
                # conventionally `package/`.
                if len(parts) == 2 and parts[1] == "binding.gyp" and member.isfile():
                    return True
    except (tarfile.TarError, OSError, EOFError, ValueError):
        return False
    return False


def has_install_script(meta: dict, data: bytes) -> bool:
    scripts = meta.get("scripts")
    if isinstance(scripts, dict) and any(
        isinstance(scripts.get(name), str) and scripts[name].strip()
        for name in INSTALL_SCRIPTS
    ):
        return True
    return tarball_has_binding_gyp(data)


def annotate_install_script(meta: dict, data: bytes) -> None:
    """Set ``hasInstallScript`` the way the public registry does.

    Computed, never taken from the client: it is the flag the abbreviated
    packument uses to tell an installer that this version runs code, so a
    publisher must not be able to clear it. Absent rather than false when
    there is nothing to run, matching registry.npmjs.org.
    """
    if has_install_script(meta, data):
        meta["hasInstallScript"] = True
    else:
        meta.pop("hasInstallScript", None)
