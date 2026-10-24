"""Fixes that only became visible once the review branches were merged."""

from types import SimpleNamespace

import pytest
import respx

from app.api import cargo, npm, pypi

from .test_integration import app_client, auth  # noqa: F401
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
