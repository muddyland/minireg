"""Image names, references, and how a /v2 path is routed.

Clients cannot use a path prefix, so every image lives at the root of the
host. The first path segment decides where a name goes:

* the local namespace (``local`` by default): images pushed here;
* the name of a Docker upstream: that upstream, with the rest of the path as
  the remote repository (``quay/prometheus/busybox`` -> quay.io
  ``prometheus/busybox``);
* ``dockerhub``: always Docker Hub, the escape hatch for a Hub namespace
  that an upstream name would otherwise shadow;
* anything else: the default upstream, Docker Hub, with a one-segment name
  expanded the way the docker CLI does it (``alpine`` -> ``library/alpine``).

Everything is stored under one canonical name, ``<upstream>/<remote>`` or
``local/<rest>``, so ``alpine``, ``library/alpine`` and
``dockerhub/library/alpine`` are one repository rather than three copies.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

from ..config import settings

# OCI distribution-spec grammar. A component is lowercase alphanumerics
# joined by a single separator run; a name is components joined by "/".
_COMPONENT = r"[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*"
NAME_RE = re.compile(rf"^{_COMPONENT}(?:/{_COMPONENT})*$")
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
# Only sha256. The spec allows sha512 but no client in practice produces it,
# and accepting an algorithm we do not verify would be worse than refusing.
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
UPSTREAM_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
#: Longest repository name accepted. Postgres column is 512; the spec's own
#: guidance is that 255 is the practical ceiling across registries.
MAX_NAME_LENGTH = 255

HUB_UPSTREAM_NAME = "dockerhub"


def is_digest(ref: str) -> bool:
    return bool(DIGEST_RE.match(ref))


def is_tag(ref: str) -> bool:
    return bool(TAG_RE.match(ref))


def valid_name(name: str) -> bool:
    return 0 < len(name) <= MAX_NAME_LENGTH and bool(NAME_RE.match(name))


# --------------------------------------------------------------------------- #
# Upstream presets
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class Preset:
    name: str
    label: str
    url: str
    #: Hosts a layer download may be redirected to. fnmatch patterns. These
    #: were observed against the live registries; a registry that moves its
    #: CDN shows up as a refused redirect naming the new host.
    blob_hosts: tuple[str, ...] = ()
    #: Token realms credentials may be sent to, besides the registry itself.
    auth_hosts: tuple[str, ...] = ()
    #: Docker Hub expands one-segment names under library/.
    library_prefix: bool = False
    note: str = ""


PRESETS: dict[str, Preset] = {
    p.name: p
    for p in (
        Preset(
            name=HUB_UPSTREAM_NAME,
            label="Docker Hub",
            url="https://registry-1.docker.io",
            blob_hosts=("production.cloudfront.docker.com", "*.cloudfront.docker.com"),
            auth_hosts=("auth.docker.io",),
            library_prefix=True,
            note=(
                "Rate-limits image pulls per account, and per IP address when "
                "anonymous. Give it the credentials of a dedicated account."
            ),
        ),
        Preset(
            name="ghcr",
            label="GitHub (ghcr.io)",
            url="https://ghcr.io",
            blob_hosts=("pkg-containers.githubusercontent.com",),
            note="Also serves the Trivy vulnerability database the scanner uses.",
        ),
        Preset(
            name="quay",
            label="Quay",
            url="https://quay.io",
            blob_hosts=("cdn*.quay.io",),
        ),
        Preset(
            name="k8s",
            label="registry.k8s.io",
            url="https://registry.k8s.io",
            # registry.k8s.io redirects to the nearest Artifact Registry or
            # S3 mirror, so this is a family of hosts rather than one.
            blob_hosts=(
                "*-docker.pkg.dev",
                "cdn.registry.k8s.io",
                "prod-registry-k8s-io-*.s3.dualstack.*.amazonaws.com",
                "storage.googleapis.com",
            ),
        ),
        Preset(
            name="ecr-public",
            label="AWS Public ECR",
            url="https://public.ecr.aws",
            blob_hosts=("*.cloudfront.net",),
        ),
        Preset(
            name="gcr-mirror",
            label="Google mirror (mirror.gcr.io)",
            url="https://mirror.gcr.io",
            blob_hosts=("storage.googleapis.com",),
            library_prefix=True,
            note="Google's cache of Docker Hub's official images.",
        ),
    )
}


def reserved_names() -> set[str]:
    """Names no upstream may take.

    An upstream name rewires every pull whose first path segment matches it,
    so these cannot be a warning an admin clicks through: ``library`` would
    capture every official image, the local namespace would let an upstream
    answer for images pushed here, and a preset name pointed somewhere else
    is exactly the confusion attack presets exist to prevent.
    """
    return {
        settings.docker_local_namespace,
        "library",
        "v2",
        "token",
        "_catalog",
        HUB_UPSTREAM_NAME,
        *PRESETS,
    }


def upstream_name_problem(name: str, url: str) -> str | None:
    """Why ``name`` cannot be a Docker upstream pointing at ``url``, or None."""
    if not UPSTREAM_NAME_RE.match(name):
        return (
            "a Docker upstream name becomes the first path segment of every image "
            "it serves, so it must be lowercase letters, digits and hyphens"
        )
    preset = PRESETS.get(name)
    if preset is not None:
        if _same_registry(preset.url, url):
            return None
        return f"'{name}' is reserved for the {preset.label} preset ({preset.url})"
    if name in reserved_names():
        return f"'{name}' is a reserved name"
    return None


def _same_registry(a: str, b: str) -> bool:
    from urllib.parse import urlsplit

    return (urlsplit(a).hostname or "").lower() == (urlsplit(b).hostname or "").lower()


def host_matches(host: str, patterns) -> bool:
    host = host.lower()
    return any(fnmatch.fnmatchcase(host, p.lower()) for p in patterns if p)


# --------------------------------------------------------------------------- #
# Routing
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class Target:
    """Where one image name resolves to."""

    canonical: str
    #: The upstream row, or None for a local repository.
    upstream: Any | None = None
    #: The repository name on the upstream.
    remote: str | None = None
    local: bool = False
    #: Names a client used that differ from ``canonical``; informational.
    aliases: list[str] = field(default_factory=list)

    @property
    def upstream_name(self) -> str | None:
        return getattr(self.upstream, "name", None)


def library_expand(upstream, remote: str) -> str:
    """Docker Hub's one-segment names live under library/."""
    if "/" in remote:
        return remote
    if upstream_uses_library(upstream):
        return f"library/{remote}"
    return remote


def upstream_uses_library(upstream) -> bool:
    extra = getattr(upstream, "extra", None) or {}
    if "library_prefix" in extra:
        return bool(extra["library_prefix"])
    preset = PRESETS.get(getattr(upstream, "name", ""))
    if preset is not None:
        return preset.library_prefix
    from urllib.parse import urlsplit

    host = (urlsplit(getattr(upstream, "url", "")).hostname or "").lower()
    return host in ("registry-1.docker.io", "index.docker.io", "docker.io", "mirror.gcr.io")


def route(
    name: str,
    upstreams: dict[str, Any],
    *,
    default_upstream: Any | None,
    mirror_host: bool = False,
    disabled: frozenset[str] | set[str] = frozenset(),
) -> Target:
    """Resolve a client-supplied image name.

    ``upstreams`` maps enabled Docker upstream names to rows.
    ``mirror_host`` is set when the request arrived on the Docker Hub mirror
    hostname, where every name is a Docker Hub name.

    ``disabled`` holds the names of configured-but-disabled upstreams. Their
    prefix is refused rather than falling through to Docker Hub: with `ghcr`
    switched off, `ghcr/aquasecurity/trivy` would otherwise be fetched from
    whoever registered the `ghcr` namespace on Hub.

    Raises ``LookupError`` when the name cannot go anywhere (no default
    upstream configured and no prefix matched).
    """
    local_ns = settings.docker_local_namespace
    first, _, rest = name.partition("/")

    if mirror_host:
        hub = upstreams.get(HUB_UPSTREAM_NAME) or default_upstream
        if hub is None:
            raise LookupError("no Docker Hub upstream is configured")
        remote = library_expand(hub, name)
        return Target(canonical=f"{hub.name}/{remote}", upstream=hub, remote=remote)

    if first == local_ns:
        if not rest:
            raise LookupError(f"'{local_ns}' alone is not a repository")
        return Target(canonical=name, local=True)

    if rest and first in disabled and first not in upstreams:
        raise LookupError(f"upstream '{first}' is disabled")

    if rest and first in upstreams:
        upstream = upstreams[first]
        remote = library_expand(upstream, rest)
        return Target(canonical=f"{upstream.name}/{remote}", upstream=upstream, remote=remote)

    if default_upstream is None:
        raise LookupError(
            "no upstream matches this name and no default (Docker Hub) upstream is configured"
        )
    remote = library_expand(default_upstream, name)
    return Target(
        canonical=f"{default_upstream.name}/{remote}",
        upstream=default_upstream,
        remote=remote,
    )


# --------------------------------------------------------------------------- #
# /v2 path parsing
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class V2Path:
    endpoint: str  # base|manifest|blob|upload|upload_session|tags|referrers|catalog|token
    name: str | None = None
    reference: str | None = None


_PATTERNS = (
    # Order matters: uploads before blobs, since a name may not end in
    # "blobs" but an upload path always contains "/blobs/uploads".
    ("upload", re.compile(r"^(?P<name>.+)/blobs/uploads/?$")),
    ("upload_session", re.compile(r"^(?P<name>.+)/blobs/uploads/(?P<ref>[A-Za-z0-9-]+)$")),
    ("blob", re.compile(r"^(?P<name>.+)/blobs/(?P<ref>[^/]+)$")),
    ("manifest", re.compile(r"^(?P<name>.+)/manifests/(?P<ref>[^/]+)$")),
    ("tags", re.compile(r"^(?P<name>.+)/tags/list$")),
    ("referrers", re.compile(r"^(?P<name>.+)/referrers/(?P<ref>[^/]+)$")),
)


def parse_v2_path(path: str) -> V2Path | None:
    """Split what follows ``/v2/``. Names contain slashes, so the endpoint is
    found by its suffix, matching greedily from the left so the *last*
    ``/manifests/`` (say) is the separator."""
    if path in ("", "/"):
        return V2Path("base")
    if path == "_catalog":
        return V2Path("catalog")
    if path == "token":
        return V2Path("token")
    for endpoint, pattern in _PATTERNS:
        m = pattern.match(path)
        if m:
            return V2Path(endpoint, m.group("name"), m.groupdict().get("ref"))
    return None
