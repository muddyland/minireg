"""Parse and classify manifests.

The digest is over the raw bytes, which are stored and served untouched;
this only reads them to learn what they reference, how big the image is,
and what kind of thing it is. Anything that is not a manifest a client can
run -- an attestation, a cosign signature, an SBOM, a Helm chart -- is
recorded and served but not scanned, so the scanner never fails on it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..config import settings
from .errors import RegistryError
from .naming import is_digest

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_V1 = (
    "application/vnd.docker.distribution.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v1+prettyjws",
)

INDEX_TYPES = {OCI_INDEX, DOCKER_LIST}
IMAGE_TYPES = {OCI_MANIFEST, DOCKER_MANIFEST}
MANIFEST_TYPES = INDEX_TYPES | IMAGE_TYPES

#: Config media types of a runnable image. Anything else is an artifact.
IMAGE_CONFIG_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
#: BuildKit marks attestation manifests in an index with this annotation and
#: an "unknown/unknown" platform.
ATTESTATION_ANNOTATION = "vnd.docker.reference.type"


@dataclass(slots=True)
class Ref:
    ref_type: str  # blob | config | manifest
    digest: str
    media_type: str | None
    size: int
    position: int
    platform: str | None = None
    annotations: dict = field(default_factory=dict)


@dataclass(slots=True)
class ParsedManifest:
    media_type: str
    is_index: bool
    kind: str  # image | index | attestation | artifact | signature
    refs: list[Ref]
    config_digest: str | None = None
    config_media_type: str | None = None
    artifact_type: str | None = None
    subject_digest: str | None = None
    annotations: dict = field(default_factory=dict)
    total_size: int = 0
    layer_count: int = 0

    @property
    def scannable(self) -> bool:
        return self.kind == "image"


def platform_string(p: dict | None) -> str | None:
    if not isinstance(p, dict):
        return None
    os_ = p.get("os")
    arch = p.get("architecture")
    if not os_ or not arch:
        return None
    s = f"{os_}/{arch}"
    if p.get("variant"):
        s += f"/{p['variant']}"
    return s[:64]


def _descriptor(d, what: str) -> tuple[str, str | None, int]:
    if not isinstance(d, dict):
        raise RegistryError("MANIFEST_INVALID", f"{what} is not a descriptor")
    digest = d.get("digest")
    if not isinstance(digest, str) or not is_digest(digest):
        raise RegistryError("MANIFEST_INVALID", f"{what} has an unsupported or malformed digest")
    size = d.get("size")
    if not isinstance(size, int) or size < 0:
        raise RegistryError("MANIFEST_INVALID", f"{what} has no valid size")
    media_type = d.get("mediaType")
    return digest, media_type if isinstance(media_type, str) else None, size


def parse(body: bytes, content_type: str | None) -> ParsedManifest:
    if len(body) > settings.docker_max_manifest_bytes:
        raise RegistryError(
            "MANIFEST_INVALID", f"manifest exceeds the {settings.docker_max_manifest_bytes} byte limit"
        )
    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise RegistryError("MANIFEST_INVALID", "manifest is not valid JSON") from exc
    if not isinstance(doc, dict):
        raise RegistryError("MANIFEST_INVALID", "manifest is not a JSON object")

    media_type = doc.get("mediaType") or (content_type or "").split(";")[0].strip()
    if media_type in DOCKER_V1 or doc.get("schemaVersion") == 1:
        raise RegistryError(
            "MANIFEST_INVALID",
            "schema 1 manifests are not supported (deprecated by Docker, unverifiable layers)",
        )
    if not media_type:
        # OCI allows an absent mediaType; infer from shape.
        media_type = OCI_INDEX if "manifests" in doc else OCI_MANIFEST
    if media_type not in MANIFEST_TYPES:
        raise RegistryError("MANIFEST_INVALID", f"unsupported manifest media type {media_type!r}")
    if doc.get("schemaVersion") != 2:
        raise RegistryError("MANIFEST_INVALID", "schemaVersion must be 2")

    raw_annotations = doc.get("annotations")
    annotations: dict = raw_annotations if isinstance(raw_annotations, dict) else {}
    subject = doc.get("subject")
    subject_digest = None
    if subject is not None:
        subject_digest, _, _ = _descriptor(subject, "subject")
    artifact_type = doc.get("artifactType") if isinstance(doc.get("artifactType"), str) else None

    refs: list[Ref] = []
    if media_type in INDEX_TYPES:
        entries = doc.get("manifests")
        if not isinstance(entries, list):
            raise RegistryError("MANIFEST_INVALID", "index has no manifests list")
        if len(entries) > settings.docker_max_index_entries:
            raise RegistryError(
                "MANIFEST_INVALID",
                f"index lists {len(entries)} manifests, over the "
                f"{settings.docker_max_index_entries} limit",
            )
        for i, entry in enumerate(entries):
            digest, mt, size = _descriptor(entry, f"manifests[{i}]")
            ann = _annotations(entry)
            refs.append(
                Ref("manifest", digest, mt, size, i, platform_string(entry.get("platform")), ann)
            )
        return ParsedManifest(
            media_type=media_type,
            is_index=True,
            kind="index",
            refs=refs,
            artifact_type=artifact_type,
            subject_digest=subject_digest,
            annotations=annotations,
        )

    config_digest, config_mt, config_size = _descriptor(doc.get("config"), "config")
    refs.append(Ref("config", config_digest, config_mt, config_size, 0))
    layers = doc.get("layers")
    if layers is None:
        layers = []
    if not isinstance(layers, list):
        raise RegistryError("MANIFEST_INVALID", "layers is not a list")
    if len(layers) > 1000:
        raise RegistryError("MANIFEST_INVALID", "manifest lists more than 1000 layers")
    total = config_size
    for i, layer in enumerate(layers):
        digest, mt, size = _descriptor(layer, f"layers[{i}]")
        if isinstance(layer, dict) and isinstance(layer.get("urls"), list) and layer["urls"]:
            # Foreign layers (Windows base images) point at URLs we would
            # have to fetch from wherever the manifest says. Not supported.
            raise RegistryError(
                "MANIFEST_INVALID",
                "manifests with foreign-URL layers are not supported",
            )
        ann = _annotations(layer)
        refs.append(Ref("blob", digest, mt, size, i + 1, annotations=ann))
        total += size

    kind = "image"
    if artifact_type or (config_mt and config_mt not in IMAGE_CONFIG_TYPES):
        kind = "artifact"
    if subject_digest:
        kind = "signature" if _looks_like_signature(artifact_type, config_mt, refs) else "artifact"
    if annotations.get(ATTESTATION_ANNOTATION) or any(
        r.media_type == "application/vnd.in-toto+json" for r in refs
    ):
        kind = "attestation"
    return ParsedManifest(
        media_type=media_type,
        is_index=False,
        kind=kind,
        refs=refs,
        config_digest=config_digest,
        config_media_type=config_mt,
        artifact_type=artifact_type,
        subject_digest=subject_digest,
        annotations=annotations,
        total_size=total,
        layer_count=len(refs) - 1,
    )


def _annotations(d) -> dict:
    value = d.get("annotations") if isinstance(d, dict) else None
    return value if isinstance(value, dict) else {}


def _looks_like_signature(artifact_type, config_mt, refs) -> bool:
    hints = (artifact_type or "") + (config_mt or "")
    hints += "".join(r.media_type or "" for r in refs)
    return any(s in hints for s in ("cosign", "sigstore", "notary", "signature"))


def is_attestation_entry(ref: Ref) -> bool:
    """An index entry that is a BuildKit attestation rather than a platform."""
    return ref.annotations.get(ATTESTATION_ANNOTATION) == "attestation-manifest" or (
        ref.platform in ("unknown/unknown",)
    )
