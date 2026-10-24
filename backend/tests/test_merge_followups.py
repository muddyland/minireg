"""Fixes that only became visible once the review branches were merged."""

from types import SimpleNamespace

import pytest
import respx

from app.api import cargo, npm, pypi

from .test_integration import app_client, auth  # noqa: F401
from .test_npm_protocol import audited  # noqa: F401
from .test_proxy import mock_npm_upstream


@pytest.mark.parametrize("module", [npm, pypi, cargo])
def test_artifact_etag_never_renders_none(module):
    # Mid-download streams have no blob digest yet.
    streaming = SimpleNamespace(blob_sha256=None, sha256=None)
    assert module._artifact_etag(streaming) == {}

    recorded = SimpleNamespace(blob_sha256=None, sha256="ab" * 32)
    assert module._artifact_etag(recorded) == {"etag": f'"{"ab" * 32}"'}

    cached = SimpleNamespace(blob_sha256="cd" * 32, sha256="ab" * 32)
    assert module._artifact_etag(cached) == {"etag": f'"{"cd" * 32}"'}


async def test_admin_rescore_invalidates_packages_whose_score_moved(app_client, monkeypatch):  # noqa: F811
    """A rescore changes max_cvss, which the CVSS policy reads, so the
    rendered documents for that package must be dropped after the commit."""
    from app import db as db_module
    from app.models import (
        Ecosystem,
        Package,
        PackageVersion,
        PackageVulnerability,
        Vulnerability,
    )
    from app.services import osv

    async with db_module.session_scope() as session:
        moved = Package(ecosystem=Ecosystem.npm, name="moved", normalized_name="moved")
        still = Package(ecosystem=Ecosystem.npm, name="still", normalized_name="still")
        session.add_all([moved, still])
        await session.flush()
        v_moved = PackageVersion(package_id=moved.id, version="1.0.0", normalized_version="1.0.0", max_cvss=None)
        v_still = PackageVersion(package_id=still.id, version="1.0.0", normalized_version="1.0.0", max_cvss=None)
        session.add_all([v_moved, v_still])
        await session.flush()
        # A stored record whose vector scores 9.8, but whose version rows
        # never got the denormalised max_cvss.
        raw = {
            "id": "GHSA-test-0001",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ],
        }
        session.add(
            Vulnerability(
                id="GHSA-test-0001", cve_id="CVE-2026-0001", ecosystem=Ecosystem.npm, raw=raw
            )
        )
        await session.flush()
        session.add(PackageVulnerability(version_id=v_moved.id, vulnerability_id="GHSA-test-0001"))

    invalidated: list[set] = []

    async def capture(targets):
        invalidated.append(set(targets))

    monkeypatch.setattr(osv, "invalidate_rendered_documents", capture)

    response = await app_client.post(
        "/api/admin/rescore", headers=auth(app_client, "admin")
    )
    assert response.status_code == 200, response.text
    assert response.json()["versions_updated"] == 1
    assert invalidated == [{("npm", "moved")}]


@respx.mock
async def test_package_page_for_an_uncached_package_loads_lean(app_client):  # noqa: F811
    """The package page's cold path fetches from upstream with the heavy
    columns deferred (raiseload). Nothing it renders may touch them."""
    from app import db as db_module
    from app.models import Ecosystem, Upstream, UpstreamKind

    async with db_module.session_scope() as session:
        session.add(
            Upstream(
                name="mock-npm",
                ecosystem=Ecosystem.npm,
                kind=UpstreamKind.npm,
                url="https://upstream.test",
                tier=1,
                enabled=True,
            )
        )
    mock_npm_upstream()
    response = await app_client.get("/api/packages/npm/leftpad", headers=auth(app_client, "reader"))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["name"] == "leftpad"
    assert {v["version"] for v in body["versions"]} == {"1.0.0", "1.1.0"}


# --------------------------------------------------------------------------- #
# Package upstreams honour HTTP(S)_PROXY / NO_PROXY again
# --------------------------------------------------------------------------- #
@pytest.fixture
def https_proxy_env(monkeypatch):
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.internal:3128")
    monkeypatch.setenv("NO_PROXY", "gitlab.internal.test")


def test_proxy_for_follows_the_environment(https_proxy_env):
    from app.upstreams import netguard

    assert netguard.proxy_for("https://registry.npmjs.org/leftpad") == "http://proxy.internal:3128"
    assert netguard.proxy_for("https://gitlab.internal.test/api") is None
    assert netguard.proxy_for("http://plain.example/x") is None


async def test_pinned_client_routes_proxied_urls_through_the_proxy(https_proxy_env):
    import httpx

    from app.upstreams import netguard

    client = netguard.pinned_client(
        netguard.PinnedBackend(),
        verify=True,
        timeout=httpx.Timeout(5),
        max_connections=4,
        max_keepalive=2,
    )
    try:
        proxied = client._transport_for_url(httpx.URL("https://registry.npmjs.org/x"))
        direct = client._transport_for_url(httpx.URL("https://gitlab.internal.test/x"))
        assert proxied is not client._transport
        assert direct is client._transport
    finally:
        await client.aclose()


async def test_guard_allows_a_proxied_name_it_cannot_resolve(https_proxy_env, monkeypatch):
    from app.config import settings
    from app.upstreams import netguard

    monkeypatch.setattr(settings, "upstream_allow_private_addresses", False)

    async def no_dns(host, port):
        raise OSError("no resolver in a proxy-only network")

    monkeypatch.setattr(netguard, "resolve_host", no_dns)
    backend = netguard.PinnedBackend()
    await netguard.guard_url(
        "https://registry.npmjs.org/leftpad",
        upstream_url="https://registry.npmjs.org",
        backend=backend,
    )
    assert backend.pins == {}  # the proxy resolves it; nothing to pin


async def test_guard_still_refuses_a_proxied_name_that_resolves_privately(
    https_proxy_env, monkeypatch
):
    from app.config import settings
    from app.upstreams import netguard

    monkeypatch.setattr(settings, "upstream_allow_private_addresses", False)

    async def private(host, port):
        return ["10.1.2.3"]

    monkeypatch.setattr(netguard, "resolve_host", private)
    with pytest.raises(netguard.BlockedUrl):
        await netguard.guard_url(
            "https://registry.npmjs.org/leftpad",
            upstream_url="https://registry.npmjs.org",
            backend=netguard.PinnedBackend(),
        )


@respx.mock
async def test_stale_dist_tag_refresh_does_not_select_the_packument(audited):  # noqa: F811
    """A stale dist-tag request refreshes from upstream, but the handler
    only reads tags: the refresh must not load the stored packument."""
    import httpx
    from sqlalchemy import update

    from app import db as db_module
    from app.models import Ecosystem, Package, Upstream, UpstreamKind

    from .test_npm_protocol import VERSION_COUNT
    from .test_query_footprint import SqlRecorder

    async with db_module.session_scope() as session:
        session.add(
            Upstream(
                name="mock-npm", ecosystem=Ecosystem.npm, kind=UpstreamKind.npm,
                url="https://upstream.test", tier=1, enabled=True,
            )
        )
        await session.execute(
            update(Package).where(Package.name == "playwright").values(cached_at=None)
        )
    versions = {
        f"1.0.{i}": {
            "name": "playwright",
            "version": f"1.0.{i}",
            "dist": {"tarball": f"https://upstream.test/playwright/-/playwright-1.0.{i}.tgz",
                     "shasum": "0" * 40},
        }
        for i in range(VERSION_COUNT)
    }
    respx.get("https://upstream.test/playwright").mock(
        return_value=httpx.Response(
            200,
            json={"name": "playwright", "dist-tags": {"latest": f"1.0.{VERSION_COUNT - 1}"},
                  "versions": versions},
        )
    )
    with SqlRecorder() as sql:
        tags = await audited.get(
            "/npm/-/package/playwright/dist-tags", headers=auth(audited, "reader")
        )
    assert tags.status_code == 200, tags.text
    assert not sql.selects_touching("cached_document"), sql.selects_touching("cached_document")
    assert not sql.selects_touching("metadata_json"), sql.selects_touching("metadata_json")
