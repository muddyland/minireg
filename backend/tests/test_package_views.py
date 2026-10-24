"""The read-only package views: per-version policy on the user-facing page,
the admin package detail's query footprint, and the dashboard counts."""

from datetime import UTC, datetime

import pytest_asyncio

from app import db as db_module
from app.models import DockerRepository, Ecosystem, Package, PackageVersion

from .test_integration import app_client, auth  # noqa: F401  (fixture import)
from .test_query_footprint import SqlRecorder


@pytest_asyncio.fixture
async def widget(app_client):  # noqa: F811
    """npm `widget` 1.0.0-1.0.3; 1.0.1 carries a critical CVE score."""
    async with db_module.session_scope() as session:
        package = Package(
            ecosystem=Ecosystem.npm,
            name="widget",
            normalized_name="widget",
            latest_version="1.0.3",
            keywords=[],
            is_local=False,
            cached_document={"versions": {"pad": "x" * 4096}},
        )
        session.add(package)
        await session.flush()
        for i in range(4):
            session.add(
                PackageVersion(
                    package_id=package.id,
                    version=f"1.0.{i}",
                    normalized_version=f"1.0.{i}",
                    max_cvss=9.8 if i == 1 else None,
                    scanned_at=datetime.now(UTC),
                    metadata_json={"pad": "y" * 512},
                )
            )
        app_client.package_id = package.id  # type: ignore[attr-defined]
    return app_client


def _versions(body: dict) -> dict[str, dict]:
    return {v["version"]: v for v in body["versions"]}


class TestPackagePageShowsVersionBlocks:
    async def test_cve_and_version_range_blocks_are_reported_to_non_admins(self, widget):
        admin = auth(widget, "admin")
        response = await widget.put(
            "/api/admin/settings/cve-policy",
            json={"enabled": True, "min_score": 7.0, "max_score": 10.0},
            headers=admin,
        )
        assert response.status_code == 200
        response = await widget.post(
            "/api/admin/rules",
            json={
                "pattern": "widget",
                "action": "block",
                "version_spec": "1.0.0",
                "reason": "broken release",
            },
            headers=admin,
        )
        assert response.status_code == 201

        response = await widget.get("/api/packages/npm/widget", headers=auth(widget, "reader"))
        assert response.status_code == 200
        body = response.json()
        # A version-scoped rule does not block the package as a whole.
        assert body["blocked"] is False
        versions = _versions(body)
        assert versions["1.0.0"]["blocked"] is True
        assert versions["1.0.0"]["block_reason"] == "broken release"
        assert versions["1.0.1"]["blocked"] is True
        assert "CVSS 9.8" in versions["1.0.1"]["block_reason"]
        for allowed in ("1.0.2", "1.0.3"):
            assert versions[allowed]["blocked"] is False
            assert versions[allowed]["block_reason"] is None

    async def test_unblocked_package_reports_every_version_allowed(self, widget):
        response = await widget.get("/api/packages/npm/widget", headers=auth(widget, "reader"))
        assert response.status_code == 200
        assert not any(v["blocked"] for v in response.json()["versions"])

    async def test_name_block_still_reported_at_package_level(self, widget):
        await widget.post(
            "/api/admin/rules",
            json={"pattern": "widget", "action": "block", "reason": "abandoned"},
            headers=auth(widget, "admin"),
        )
        response = await widget.get("/api/packages/npm/widget", headers=auth(widget, "reader"))
        body = response.json()
        assert body["blocked"] is True and body["block_reason"] == "abandoned"
        assert all(v["block_reason"] == "abandoned" for v in body["versions"])


class TestAdminPackageDetailFootprint:
    async def test_admin_package_detail_does_not_select_blobs(self, widget):
        with SqlRecorder() as sql:
            response = await widget.get(
                f"/api/admin/packages/{widget.package_id}", headers=auth(widget, "admin")
            )
        assert response.status_code == 200
        assert len(response.json()["versions"]) == 4
        sql.assert_no_heavy_columns("admin package detail")


class TestDashboardCounts:
    async def test_every_package_ecosystem_and_images_are_counted(self, widget):
        async with db_module.session_scope() as session:
            session.add(
                Package(
                    ecosystem=Ecosystem.cargo,
                    name="serde",
                    normalized_name="serde",
                    keywords=[],
                    is_local=False,
                )
            )
            session.add_all(
                [
                    DockerRepository(name="hub/library/alpine"),
                    DockerRepository(name="local/team/app", is_local=True),
                    DockerRepository(name="gitlab/listed", indexed_only=True),
                ]
            )

        response = await widget.get("/api/admin/stats/overview", headers=auth(widget, "admin"))
        assert response.status_code == 200
        body = response.json()
        assert body["packages"]["npm"] == 1
        assert body["packages"]["pypi"] == 0
        assert body["packages"]["cargo"] == 1
        assert "docker" not in body["packages"]
        assert body["images"]["repositories"] == 2
        assert body["images"]["local"] == 1
        assert body["images"]["tags"] == 0
