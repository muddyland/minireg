"""Guards against re-introducing the query shape that OOM-killed the server.

`packages.cached_document` holds a whole upstream packument -- 18MB for
playwright, 37MB for vite -- and `package_versions.metadata_json` holds one
per version. Selecting the ORM *entity* on a joined, multi-row query pulls
those blobs once per row and deserialises each into Python objects, so a
200-row batch could drag several GB into a 4GB container and get it killed by
the kernel with nothing written to the application log.

These tests assert on the SQL the server actually emits, because the bug was
invisible at the Python level: the handlers read only `name` and `version`,
and looked entirely reasonable.
"""


import pytest_asyncio
from sqlalchemy import event

from app import db as db_module
from app.models import Ecosystem, Package, PackageVersion

from .test_integration import app_client, auth  # noqa: F401  (fixture import)

HEAVY_COLUMNS = ("cached_document", "metadata_json")

# Big enough that a regression is unmistakable in memory terms, small enough
# to keep the test fast.
BIG_PACKUMENT = {"versions": {f"1.0.{i}": {"pad": "x" * 512} for i in range(200)}}
VERSION_COUNT = 300


class SqlRecorder:
    """Captures every statement the engine executes."""

    def __init__(self):
        self.statements: list[str] = []

    def __enter__(self):
        self._sync = db_module.get_engine().sync_engine
        event.listen(self._sync, "before_cursor_execute", self._on_execute)
        return self

    def __exit__(self, *exc):
        event.remove(self._sync, "before_cursor_execute", self._on_execute)
        return False

    def _on_execute(self, conn, cursor, statement, params, context, executemany):
        self.statements.append(statement)

    def selects_touching(self, column: str) -> list[str]:
        return [
            s for s in self.statements
            if s.lstrip().upper().startswith("SELECT") and column in s
        ]

    def assert_no_heavy_columns(self, context: str) -> None:
        for column in HEAVY_COLUMNS:
            offenders = self.selects_touching(column)
            assert not offenders, (
                f"{context} selected {column}, which carries whole packuments "
                f"and will exhaust memory on real data:\n  " + "\n  ".join(offenders)
            )


@pytest_asyncio.fixture
async def seeded(app_client):  # noqa: F811
    """One package with a fat packument and many versions -- i.e. playwright."""
    async with db_module.session_scope() as session:
        package = Package(
            ecosystem=Ecosystem.npm,
            name="playwright",
            normalized_name="playwright",
            description="browser automation",
            latest_version=f"1.0.{VERSION_COUNT - 1}",
            keywords=[],
            is_local=False,
            cached_document=BIG_PACKUMENT,
        )
        session.add(package)
        await session.flush()
        for i in range(VERSION_COUNT):
            session.add(
                PackageVersion(
                    package_id=package.id,
                    version=f"1.0.{i}",
                    normalized_version=f"1.0.{i}",
                    metadata_json={"name": "playwright", "pad": "y" * 512},
                )
            )
    return app_client


class TestNoPackumentInMultiRowQueries:
    async def test_local_search_does_not_select_packuments(self, seeded):
        with SqlRecorder() as sql:
            response = await seeded.get(
                "/api/search", params={"q": "play"}, headers=auth(seeded, "reader")
            )
        assert response.status_code == 200
        assert response.json()["results"][0]["name"] == "playwright"
        sql.assert_no_heavy_columns("local search")

    async def test_package_detail_does_not_select_packuments(self, seeded):
        with SqlRecorder() as sql:
            response = await seeded.get(
                "/api/packages/npm/playwright", headers=auth(seeded, "reader")
            )
        assert response.status_code == 200
        body = response.json()
        # The view must still be complete -- deferring must not drop data.
        assert len(body["versions"]) == VERSION_COUNT
        sql.assert_no_heavy_columns("package detail")

    async def test_npm_search_does_not_select_packuments(self, seeded):
        with SqlRecorder() as sql:
            response = await seeded.get(
                "/npm/-/v1/search", params={"text": "play"}, headers=auth(seeded, "reader")
            )
        assert response.status_code == 200
        sql.assert_no_heavy_columns("npm search")

    async def test_admin_scan_trigger_does_not_select_packuments(self, seeded):
        with SqlRecorder() as sql:
            response = await seeded.post(
                "/api/admin/scan", params={"limit": 50}, headers=auth(seeded, "admin")
            )
        assert response.status_code == 200
        sql.assert_no_heavy_columns("admin scan trigger")


class TestCliAuditFootprint:
    """The audit endpoint was the worst offender: it filtered on package name
    only, so auditing one version of playwright loaded every version row the
    registry held -- each carrying a copy of the packument."""

    async def test_audit_does_not_select_packuments(self, seeded):
        with SqlRecorder() as sql:
            response = await seeded.post(
                "/api/cli/audit",
                json={
                    "ecosystem": "npm",
                    "packages": [{"name": "playwright", "version": "1.0.7"}],
                    "scan_unknown": False,
                },
                headers=auth(seeded, "reader"),
            )
        assert response.status_code == 200
        sql.assert_no_heavy_columns("cli audit")

    async def test_audit_filters_on_the_requested_versions(self, seeded):
        with SqlRecorder() as sql:
            response = await seeded.post(
                "/api/cli/audit",
                json={
                    "ecosystem": "npm",
                    "packages": [{"name": "playwright", "version": "1.0.7"}],
                    "scan_unknown": False,
                },
                headers=auth(seeded, "reader"),
            )
        assert response.status_code == 200
        joined = [
            s for s in sql.statements
            if "package_versions" in s and "packages" in s and "JOIN" in s.upper()
        ]
        assert joined, "expected the audit to join packages to package_versions"
        assert any("package_versions.version IN" in s for s in joined), (
            "audit must constrain the join to the requested versions; without it, "
            "auditing one version of a package loads every version row it has:\n  "
            + "\n  ".join(joined)
        )


class TestHousekeepingRefreshFootprint:
    async def test_background_refresh_batch_does_not_select_packuments(self, seeded):
        """The hourly CVE refresh in main.housekeeping_loop, run directly."""
        from datetime import UTC, datetime, timedelta

        from sqlalchemy import select
        from sqlalchemy.orm import defer

        cutoff = datetime.now(UTC) - timedelta(days=1)
        with SqlRecorder() as sql:
            async with db_module.session_scope() as session:
                rows = (
                    await session.execute(
                        select(Package.ecosystem, Package.name, PackageVersion)
                        .join(PackageVersion, PackageVersion.package_id == Package.id)
                        .options(defer(PackageVersion.metadata_json))
                        .where(
                            (PackageVersion.scanned_at.is_(None))
                            | (PackageVersion.scanned_at < cutoff)
                        )
                        .order_by(PackageVersion.scanned_at.asc().nullsfirst())
                        .limit(200)
                    )
                ).all()
        assert len(rows) == 200
        # Everything the scan needs is present without the blobs.
        eco, name, version = rows[0]
        assert eco == Ecosystem.npm and name == "playwright" and version.version
        sql.assert_no_heavy_columns("housekeeping CVE refresh")

    async def test_housekeeping_loop_query_matches_this_shape(self):
        """Ties the test above to the real source, so editing one fails the other."""
        import inspect

        from app.main import _cve_refresh_task

        source = inspect.getsource(_cve_refresh_task)
        assert "select(Package.ecosystem, Package.name, PackageVersion)" in source, (
            "the CVE refresh no longer selects scalar package columns; "
            "selecting the Package entity re-introduces the OOM"
        )
        assert "defer(PackageVersion.metadata_json)" in source
