"""OSV scanning against a real database and a mocked OSV API.

These exercise ``OsvScanner.scan_versions`` end to end -- querybatch, the
per-advisory detail fetch, the upsert and ``apply_to_version`` -- because the
failures they guard against live in how those pieces hand results to each
other, not in any one function.

``DOCKER_TEST_DATABASE_URL`` runs them against PostgreSQL, as the Docker
tests do.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
import respx
from sqlalchemy import func, select

from app import db as db_module
from app.config import settings
from app.models import Ecosystem, Package, PackageVersion, PackageVulnerability, Vulnerability
from app.services import osv
from app.services.osv import OsvScanner
from app.services.policy import CvePolicy

OSV = "https://api.osv.dev"
CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
MEDIUM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"  # 6.1


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch):
    pg_url = os.environ.get("DOCKER_TEST_DATABASE_URL")
    if pg_url:
        db_module.init_engine(pg_url)
        from app.models import Base

        async with db_module.get_engine().begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    else:
        db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'osv.db'}")
    await db_module.create_schema()
    monkeypatch.setattr(settings, "osv_enabled", True)
    monkeypatch.setattr(settings, "osv_api_url", OSV)
    # Retries are part of what is tested; their waits are not.
    monkeypatch.setattr(osv, "_FETCH_RETRY_DELAYS", (0.0, 0.0))
    yield
    await db_module.dispose_engine()


async def seed_version(name: str, version: str, **columns) -> int:
    async with db_module.session_scope() as session:
        package = (
            await session.execute(
                select(Package).where(Package.ecosystem == Ecosystem.npm, Package.name == name)
            )
        ).scalar_one_or_none()
        if package is None:
            package = Package(
                ecosystem=Ecosystem.npm, name=name, normalized_name=name, keywords=[]
            )
            session.add(package)
            await session.flush()
        row = PackageVersion(
            package_id=package.id, version=version, normalized_version=version, **columns
        )
        session.add(row)
        await session.flush()
        return row.id


async def seed_advisory(osv_id: str, *, score, modified: datetime, raw: dict, link_to=()):
    async with db_module.session_scope() as session:
        session.add(
            Vulnerability(
                id=osv_id,
                cve_id=osv_id,
                ecosystem=Ecosystem.npm,
                cvss_score=score,
                severity_label=osv.severity_label(score),
                modified=modified,
                raw=raw,
                fetched_at=datetime.now(UTC),
            )
        )
        await session.flush()
        for version_id in link_to:
            session.add(PackageVulnerability(version_id=version_id, vulnerability_id=osv_id))


def aware(value):
    """SQLite returns naive timestamps; they were written as UTC."""
    return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


def record(osv_id, *, package="evil", vector=None, fixed=None, modified="2026-01-01T00:00:00Z"):
    events = [{"introduced": "0"}]
    if fixed:
        events.append({"fixed": fixed})
    rec = {
        "id": osv_id,
        "aliases": [],
        "modified": modified,
        "summary": f"advisory {osv_id}",
        "affected": [
            {"package": {"name": package, "ecosystem": "npm"},
             "ranges": [{"type": "SEMVER", "events": events}]}
        ],
    }
    if vector:
        rec["severity"] = [{"type": "CVSS_V3", "score": vector}]
    return rec


def querybatch(router, *answers):
    """Answer querybatch with one ``[(id, modified), ...]`` list per query."""
    router.post(f"{OSV}/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {"vulns": [{"id": i, "modified": m} for i, m in ids]} if ids else {}
                    for ids in answers
                ]
            },
        )
    )


async def scan(name, version):
    async with db_module.session_scope() as session:
        row = (
            await session.execute(
                select(PackageVersion)
                .join(Package, Package.id == PackageVersion.package_id)
                .where(Package.name == name, PackageVersion.version == version)
            )
        ).scalar_one()
        return await OsvScanner(session).scan_and_apply(Ecosystem.npm, row, name)


async def version_state(version_id):
    async with db_module.session_scope() as session:
        row = await session.get(PackageVersion, version_id)
        links = (
            await session.execute(
                select(PackageVulnerability.vulnerability_id).where(
                    PackageVulnerability.version_id == version_id
                )
            )
        ).scalars().all()
        return row.max_cvss, row.has_fix, row.scanned_at, sorted(links)


# --------------------------------------------------------------------------- #
# A detail fetch that fails is not "no advisory"
# --------------------------------------------------------------------------- #
class TestHydrationFailure:
    async def test_unfetchable_advisory_leaves_the_version_unscanned(self, db):
        await seed_version("evil", "1.0.0")
        with respx.mock(assert_all_called=False) as router:
            querybatch(router, [("MAL-2026-1", "2026-01-01T00:00:00Z")])
            detail = router.get(f"{OSV}/v1/vulns/MAL-2026-1").mock(
                return_value=httpx.Response(429)
            )
            result = await scan("evil", "1.0.0")

        assert detail.call_count == 3  # first try plus two retries
        assert result.scanned is False
        # Fail-closed now applies, as policy.md promises.
        policy = CvePolicy(enabled=True, min_score=7.0, block_unscored=True)
        assert policy.blocks(result.max_score, scanned=result.scanned)

    async def test_failed_rescan_keeps_the_verdict_an_earlier_scan_found(self, db):
        stamp = datetime.now(UTC) - timedelta(days=1)
        version_id = await seed_version(
            "evil", "1.0.0", max_cvss=10.0, scanned_at=stamp
        )
        await seed_advisory(
            "MAL-2026-1",
            score=10.0,
            modified=datetime(2026, 1, 1, tzinfo=UTC),
            raw=record("MAL-2026-1"),
            link_to=[version_id],
        )
        with respx.mock(assert_all_called=False) as router:
            # A second advisory appeared and its detail fetch times out.
            querybatch(
                router,
                [("MAL-2026-1", "2026-01-01T00:00:00Z"), ("GHSA-new", "2026-02-01T00:00:00Z")],
            )
            router.get(f"{OSV}/v1/vulns/GHSA-new").mock(
                side_effect=httpx.ReadTimeout("slow")
            )
            result = await scan("evil", "1.0.0")

        assert result.scanned is False
        max_cvss, _fix, scanned_at, links = await version_state(version_id)
        assert max_cvss == 10.0
        assert links == ["MAL-2026-1"]
        assert aware(scanned_at) == stamp

    async def test_a_429_that_clears_is_retried_into_a_real_answer(self, db):
        await seed_version("evil", "1.0.0")
        with respx.mock(assert_all_called=False) as router:
            querybatch(router, [("GHSA-a", "2026-01-01T00:00:00Z")])
            router.get(f"{OSV}/v1/vulns/GHSA-a").mock(
                side_effect=[
                    httpx.Response(429, headers={"retry-after": "0"}),
                    httpx.Response(200, json=record("GHSA-a", vector=CRITICAL)),
                ]
            )
            result = await scan("evil", "1.0.0")
        assert result.scanned is True
        assert result.max_score == pytest.approx(9.8)

    async def test_a_record_filtered_on_purpose_is_still_clean(self, db, monkeypatch):
        """OSV_CVE_ONLY dropping a record is a decision, not a failure."""
        monkeypatch.setattr(settings, "osv_cve_only", True)
        await seed_version("evil", "1.0.0")
        with respx.mock(assert_all_called=False) as router:
            querybatch(router, [("GHSA-nocve", "2026-01-01T00:00:00Z")])
            router.get(f"{OSV}/v1/vulns/GHSA-nocve").mock(
                return_value=httpx.Response(200, json=record("GHSA-nocve", vector=CRITICAL))
            )
            result = await scan("evil", "1.0.0")
        assert result.scanned is True
        assert result.cves == []
        assert result.max_score == 0.0

    async def test_refresh_pass_does_not_reselect_a_version_osv_would_not_answer(
        self, db, monkeypatch
    ):
        from app import main

        monkeypatch.setattr(settings, "osv_batch_size", 2)
        await seed_version("evil", "1.0.0")
        await seed_version("good", "1.0.0")
        await seed_version("good", "2.0.0")
        asked: list[list[str]] = []

        def answer(request):
            import json

            queries = json.loads(request.content)["queries"]
            asked.append([q["package"]["name"] for q in queries])
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": "MAL-2026-1", "modified": "2026-01-01T00:00:00Z"}]}
                        if q["package"]["name"] == "evil"
                        else {}
                        for q in queries
                    ]
                },
            )

        with respx.mock(assert_all_called=False) as router:
            router.post(f"{OSV}/v1/querybatch").mock(side_effect=answer)
            router.get(f"{OSV}/v1/vulns/MAL-2026-1").mock(return_value=httpx.Response(503))
            await main._cve_refresh_task()

        assert sum(names.count("evil") for names in asked) == 1
        async with db_module.session_scope() as session:
            unscanned = (
                await session.execute(
                    select(func.count()).where(PackageVersion.scanned_at.is_(None))
                )
            ).scalar_one()
        assert unscanned == 1  # evil, left for the next pass


# --------------------------------------------------------------------------- #
# Stored advisories follow OSV's edits
# --------------------------------------------------------------------------- #
class TestStoredAdvisoryRefresh:
    async def test_a_modified_advisory_is_refetched_and_reaches_every_linked_version(self, db):
        stamp = datetime.now(UTC) - timedelta(hours=1)
        scanned_id = await seed_version("lib", "1.0.0")
        other_id = await seed_version("lib", "0.9.0", max_cvss=6.1, scanned_at=stamp)
        await seed_advisory(
            "GHSA-up",
            score=6.1,
            modified=datetime(2026, 1, 1, tzinfo=UTC),
            raw=record("GHSA-up", package="lib", vector=MEDIUM),
            link_to=[other_id],
        )
        with respx.mock(assert_all_called=False) as router:
            querybatch(router, [("GHSA-up", "2026-03-01T00:00:00Z")])
            detail = router.get(f"{OSV}/v1/vulns/GHSA-up").mock(
                return_value=httpx.Response(
                    200,
                    json=record(
                        "GHSA-up",
                        package="lib",
                        vector=CRITICAL,
                        fixed="1.0.1",
                        modified="2026-03-01T00:00:00Z",
                    ),
                )
            )
            result = await scan("lib", "1.0.0")

        assert detail.called
        assert result.max_score == pytest.approx(9.8)
        assert result.has_fix is True
        # The version that was not part of this scan carries the new score
        # too: the policy reads the version's column, not the advisory.
        max_cvss, has_fix, _at, links = await version_state(other_id)
        assert max_cvss == pytest.approx(9.8)
        assert has_fix is True
        assert links == ["GHSA-up"]
        max_cvss, *_ = await version_state(scanned_id)
        assert max_cvss == pytest.approx(9.8)
        async with db_module.session_scope() as session:
            stored = await session.get(Vulnerability, "GHSA-up")
            assert stored.cvss_score == pytest.approx(9.8)
            assert aware(stored.modified) == datetime(2026, 3, 1, tzinfo=UTC)
            link = (
                await session.execute(
                    select(PackageVulnerability).where(
                        PackageVulnerability.version_id == other_id
                    )
                )
            ).scalar_one()
            assert link.fixed_version == "1.0.1"

    async def test_an_unchanged_advisory_is_not_refetched(self, db):
        await seed_version("lib", "1.0.0")
        await seed_advisory(
            "GHSA-same",
            score=6.1,
            modified=datetime(2026, 1, 1, tzinfo=UTC),
            raw=record("GHSA-same", package="lib", vector=MEDIUM),
        )
        with respx.mock(assert_all_called=False) as router:
            querybatch(router, [("GHSA-same", "2026-01-01T00:00:00Z")])
            detail = router.get(f"{OSV}/v1/vulns/GHSA-same").mock(
                return_value=httpx.Response(500)
            )
            result = await scan("lib", "1.0.0")
        assert not detail.called
        assert result.scanned is True
        assert result.max_score == pytest.approx(6.1)

    async def test_an_old_copy_without_a_reported_modified_time_expires(self, db):
        await seed_version("lib", "1.0.0")
        await seed_advisory(
            "GHSA-old",
            score=None,
            modified=datetime(2020, 1, 1, tzinfo=UTC),
            raw=record("GHSA-old", package="lib"),
        )
        async with db_module.session_scope() as session:
            row = await session.get(Vulnerability, "GHSA-old")
            row.fetched_at = datetime.now(UTC) - timedelta(days=400)
        with respx.mock(assert_all_called=False) as router:
            querybatch(router, [("GHSA-old", None)])
            router.get(f"{OSV}/v1/vulns/GHSA-old").mock(
                return_value=httpx.Response(
                    200, json=record("GHSA-old", package="lib", vector=CRITICAL)
                )
            )
            result = await scan("lib", "1.0.0")
        assert result.max_score == pytest.approx(9.8)

    async def test_a_failed_refetch_falls_back_to_the_stored_copy(self, db):
        await seed_version("lib", "1.0.0")
        await seed_advisory(
            "GHSA-up",
            score=6.1,
            modified=datetime(2026, 1, 1, tzinfo=UTC),
            raw=record("GHSA-up", package="lib", vector=MEDIUM),
        )
        with respx.mock(assert_all_called=False) as router:
            querybatch(router, [("GHSA-up", "2026-03-01T00:00:00Z")])
            router.get(f"{OSV}/v1/vulns/GHSA-up").mock(return_value=httpx.Response(503))
            result = await scan("lib", "1.0.0")
        assert result.scanned is True
        assert result.max_score == pytest.approx(6.1)


# --------------------------------------------------------------------------- #
# "No advisories" is told apart from "advisories scoring 0.0"
# --------------------------------------------------------------------------- #
class TestAdvisoryPresence:
    async def _verdict(self, version_id, policy):
        from app.models import Setting
        from app.services.policy import KEY_CVE_POLICY, PolicyEngine

        async with db_module.session_scope() as session:
            await session.merge(Setting(key=KEY_CVE_POLICY, value=policy))
        async with db_module.session_scope() as session:
            row = await session.get(PackageVersion, version_id)
            engine = PolicyEngine(session)
            return await engine.evaluate(
                "npm",
                "lib",
                row.version,
                max_cvss=row.max_cvss,
                has_fix=row.has_fix,
                scanned=bool(row.scanned_at),
                has_advisories=row.has_advisories,
            )

    async def test_scan_records_whether_anything_was_found(self, db):
        clean_id = await seed_version("lib", "1.0.0")
        zero_id = await seed_version("lib", "2.0.0")
        no_impact = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        with respx.mock(assert_all_called=False) as router:
            router.post(f"{OSV}/v1/querybatch").mock(
                side_effect=[
                    httpx.Response(200, json={"results": [{}]}),
                    httpx.Response(
                        200,
                        json={"results": [{"vulns": [{"id": "GHSA-zero", "modified": None}]}]},
                    ),
                ]
            )
            router.get(f"{OSV}/v1/vulns/GHSA-zero").mock(
                return_value=httpx.Response(
                    200, json=record("GHSA-zero", package="lib", vector=no_impact)
                )
            )
            await scan("lib", "1.0.0")
            await scan("lib", "2.0.0")

        policy = {"enabled": True, "min_score": 0.0, "max_score": 10.0}
        async with db_module.session_scope() as session:
            clean = await session.get(PackageVersion, clean_id)
            zero = await session.get(PackageVersion, zero_id)
            assert (clean.max_cvss, clean.has_advisories) == (0.0, False)
            assert (zero.max_cvss, zero.has_advisories) == (0.0, True)
        assert (await self._verdict(clean_id, policy)).allowed
        assert (await self._verdict(zero_id, policy)).blocked

    async def test_upgrade_backfills_versions_scanned_before_the_column(self, db):
        version_id = await seed_version(
            "lib", "1.0.0", max_cvss=0.0, scanned_at=datetime.now(UTC)
        )
        clean_id = await seed_version("lib", "2.0.0", max_cvss=0.0, scanned_at=datetime.now(UTC))
        await seed_advisory(
            "GHSA-zero",
            score=0.0,
            modified=datetime(2026, 1, 1, tzinfo=UTC),
            raw=record("GHSA-zero", package="lib"),
            link_to=[version_id],
        )
        await db_module.create_schema()  # what every start runs
        await db_module.create_schema()  # and again: idempotent
        async with db_module.session_scope() as session:
            assert (await session.get(PackageVersion, version_id)).has_advisories is True
            assert (await session.get(PackageVersion, clean_id)).has_advisories is False


class TestCvePolicyDefaults:
    def test_a_fresh_install_blocks_high_and_critical(self):
        for policy in (CvePolicy(), CvePolicy.from_dict(None), CvePolicy.from_dict({})):
            assert policy.enabled is True
            assert policy.block_malware is True
            assert policy.blocks(7.5, scanned=True)
            assert policy.blocks(9.8, scanned=True)
            assert not policy.blocks(6.9, scanned=True)
            assert not policy.blocks(0.0, scanned=True, has_advisories=False)

    def test_a_saved_policy_keeps_its_choice(self):
        policy = CvePolicy.from_dict({"enabled": False, "min_score": 9.0, "max_score": 10.0})
        assert policy.enabled is False
        assert not policy.blocks(9.8, scanned=True)

    async def test_the_settings_api_reports_the_defaults(self, db):
        from app.api.admin.management import CvePolicyUpdate

        assert CvePolicy(**CvePolicyUpdate().model_dump()) == CvePolicy()


class TestCvePolicyZeroRange:
    def test_clean_is_never_in_range(self):
        policy = CvePolicy(enabled=True, min_score=0.0, max_score=10.0, block_unscored=True)
        assert not policy.blocks(0.0, scanned=True, has_advisories=False)
        assert not policy.blocks(0.0, scanned=True)  # callers that cannot tell
        assert policy.blocks(0.0, scanned=True, has_advisories=True)
        assert policy.blocks(5.0, scanned=True, has_advisories=False)
        assert policy.blocks(None, scanned=True)
        assert policy.blocks(None, scanned=False)


# --------------------------------------------------------------------------- #
# Malicious-package advisories
# --------------------------------------------------------------------------- #
class TestMaliciousFlag:
    async def test_scan_flags_malware_and_the_policy_blocks_it_without_a_fix(self, db):
        from app.models import Setting
        from app.services.policy import KEY_CVE_POLICY, PolicyEngine

        version_id = await seed_version("evil", "1.0.0")
        with respx.mock(assert_all_called=False) as router:
            querybatch(router, [("MAL-2026-7", "2026-01-01T00:00:00Z")])
            router.get(f"{OSV}/v1/vulns/MAL-2026-7").mock(
                return_value=httpx.Response(200, json=record("MAL-2026-7"))
            )
            result = await scan("evil", "1.0.0")
        assert result.malicious is True
        assert result.has_fix is False

        async with db_module.session_scope() as session:
            session.add(
                Setting(
                    key=KEY_CVE_POLICY,
                    value={"enabled": True, "min_score": 7.0, "max_score": 10.0,
                           "require_fix_available": True},
                )
            )
        async with db_module.session_scope() as session:
            row = await session.get(PackageVersion, version_id)
            assert row.is_malicious is True
            verdict = await PolicyEngine(session).evaluate(
                "npm",
                "evil",
                row.version,
                max_cvss=row.max_cvss,
                has_fix=row.has_fix,
                scanned=bool(row.scanned_at),
                has_advisories=row.has_advisories,
                malicious=row.is_malicious,
            )
        assert verdict.blocked

    async def _malware_verdict(self, policy_value):
        from app.models import Setting
        from app.services.policy import KEY_CVE_POLICY, PolicyEngine

        if policy_value is not None:
            async with db_module.session_scope() as session:
                session.add(Setting(key=KEY_CVE_POLICY, value=policy_value))
        async with db_module.session_scope() as session:
            return await PolicyEngine(session).evaluate(
                "npm", "evil", "1.0.0", max_cvss=None, scanned=True,
                has_advisories=True, malicious=True,
            )

    async def test_malware_is_blocked_on_a_fresh_install(self, db):
        # No policy ever saved: the out-of-the-box posture.
        verdict = await self._malware_verdict(None)
        assert verdict.blocked
        assert verdict.source == "malware"

    async def test_malware_stays_blocked_with_the_cve_policy_off(self, db):
        # A policy saved before the malware switch existed, with the score
        # policy disabled: that used to serve malware.
        verdict = await self._malware_verdict(
            {"enabled": False, "min_score": 7.0, "max_score": 10.0}
        )
        assert verdict.blocked
        assert verdict.source == "malware"

    async def test_malware_is_served_only_when_explicitly_allowed(self, db):
        verdict = await self._malware_verdict(
            {"enabled": False, "min_score": 7.0, "max_score": 10.0, "block_malware": False}
        )
        assert verdict.allowed

    async def test_a_cached_malicious_record_still_flags_the_version(self, db):
        await seed_version("evil", "2.0.0")
        await seed_advisory(
            "MAL-2026-7",
            score=10.0,
            modified=datetime(2026, 1, 1, tzinfo=UTC),
            raw=record("MAL-2026-7"),
        )
        with respx.mock(assert_all_called=False) as router:
            querybatch(router, [("MAL-2026-7", "2026-01-01T00:00:00Z")])
            result = await scan("evil", "2.0.0")
        assert result.malicious is True

    async def test_upgrade_backfills_malicious_versions(self, db):
        bad = await seed_version("evil", "1.0.0", max_cvss=10.0, scanned_at=datetime.now(UTC))
        other = await seed_version("lib", "1.0.0", max_cvss=9.8, scanned_at=datetime.now(UTC))
        await seed_advisory(
            "MAL-2026-7", score=10.0, modified=datetime(2026, 1, 1, tzinfo=UTC),
            raw=record("MAL-2026-7"), link_to=[bad],
        )
        await seed_advisory(
            "GHSA-x", score=9.8, modified=datetime(2026, 1, 1, tzinfo=UTC),
            raw=record("GHSA-x", package="lib", vector=CRITICAL), link_to=[other],
        )
        await db_module.create_schema()
        async with db_module.session_scope() as session:
            assert (await session.get(PackageVersion, bad)).is_malicious is True
            assert (await session.get(PackageVersion, other)).is_malicious is False
