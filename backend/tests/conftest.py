import os
import tempfile
from datetime import UTC, datetime

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("PUBLIC_URL", "http://registry.test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-long-enough-32")
os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:1/0")
os.environ.setdefault("OSV_ENABLED", "false")
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
# Artifact fetches are restricted to an allowlist of hosts, because the URL
# comes out of upstream metadata and is attacker-chosen when an upstream is
# hostile. The mock upstreams below serve their files from separate CDN hosts,
# exactly as the real registries do, so those hosts are declared here the way
# an operator would declare them in .env.
os.environ.setdefault(
    "UPSTREAM_ARTIFACT_HOSTS",
    "registry.npmjs.org,files.pythonhosted.org,static.crates.io,"
    "upstream.test,fallback.test,static.upstream.test,files.upstream.test,"
    "cdn.upstream.test,internal.test",
)
os.environ.setdefault("UPSTREAM_ALLOW_PRIVATE_ADDRESSES", "true")

from app.models import DistTag, Ecosystem, Package, PackageFile, PackageVersion
from app.services.storage import BlobStore, set_store


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """Fail fast if a test tries to reach the network for real.

    Everything outbound is supposed to be mocked with respx, which intercepts
    above the socket layer and so is unaffected by this. A call that gets
    past respx used to leave the suite waiting on connect timeouts and
    retries -- a publish now checks whether the name already resolves
    upstream, and three provenance tests configure `.example` upstreams and
    then publish. On a developer machine DNS says NXDOMAIN instantly and
    nobody notices; on a CI network that blackholes instead, the same tests
    hung for twenty-five minutes.

    Failing loudly, naming the host, is much easier to act on than a hang.
    """
    import ipaddress
    import socket

    real_getaddrinfo = socket.getaddrinfo

    def guard(host, *args, **kwargs):
        name = host.decode() if isinstance(host, bytes) else host
        if name in ("localhost", "", None):
            return real_getaddrinfo(host, *args, **kwargs)
        try:
            # A literal address resolves locally without touching the network,
            # and the SSRF guard's own tests hand it link-local literals on
            # purpose. Only names need blocking.
            ipaddress.ip_address(name)
        except ValueError:
            raise RuntimeError(
                f"this test tried to resolve {name!r} for real. Mock it with "
                "respx, or arrange the test so it does not reach the network."
            ) from None
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", guard)


@pytest.fixture
def blob_store(tmp_path):
    store = BlobStore(str(tmp_path / "blobs"))
    store.ensure_dirs()
    set_store(store)
    yield store
    set_store(None)  # type: ignore[arg-type]


@pytest.fixture
def tmp_storage():
    with tempfile.TemporaryDirectory() as path:
        store = BlobStore(path)
        store.ensure_dirs()
        set_store(store)
        yield store
    set_store(None)  # type: ignore[arg-type]


def make_package(
    name="lodash",
    ecosystem=Ecosystem.npm,
    versions=(("4.17.21", {}),),
    dist_tags=None,
    **kwargs,
):
    """Build a detached Package graph for renderer tests (no DB needed)."""
    now = datetime(2024, 3, 1, 12, 0, 0, tzinfo=UTC)
    package = Package(
        id=1,
        ecosystem=ecosystem,
        name=name,
        normalized_name=name.lower(),
        first_seen_at=now,
        updated_at=now,
        download_count=0,
        blocked=False,
        is_local=False,
        keywords=[],
        **kwargs,
    )
    package.versions = []
    package.dist_tags = []

    for index, (version, meta) in enumerate(versions, start=1):
        version_row = PackageVersion(
            id=index,
            package_id=1,
            version=version,
            normalized_version=version,
            metadata_json=dict(meta),
            yanked=False,
            is_local=False,
            published_at=now,
            first_seen_at=now,
        )
        version_row.files = []
        package.versions.append(version_row)

    if dist_tags:
        for tag, version in dist_tags.items():
            package.dist_tags.append(DistTag(id=len(package.dist_tags) + 1, package_id=1, tag=tag, version=version))
        package.latest_version = dist_tags.get("latest")
    return package


def add_file(version_row, filename, **kwargs):
    file_row = PackageFile(
        id=len(version_row.files) + 1,
        version_id=version_row.id,
        filename=filename,
        content_type=kwargs.pop("content_type", "application/octet-stream"),
        yanked=kwargs.pop("yanked", False),
        download_count=0,
        **kwargs,
    )
    version_row.files.append(file_row)
    return file_row
