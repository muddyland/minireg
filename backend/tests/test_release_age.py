"""The hold on new releases (release-age policy).

A release a public upstream published less than ``min_days`` ago is not
served: most malicious releases are found and pulled within that window. These
tests drive the real proxy path -- packument, version document, dist-tags and
tarball -- against a mocked upstream, because a hold that only one of those
paths enforced would be no hold at all.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import httpx
import pytest_asyncio
import respx
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update

from app import db as db_module
from app.models import (
    Ecosystem,
    Package,
    PackageRule,
    PackageVersion,
    PackageVulnerability,
    RuleAction,
    Setting,
    Upstream,
    UpstreamKind,
    Vulnerability,
    upstream_is_public,
)
from app.services.policy import (
    KEY_RELEASE_AGE,
    PolicyEngine,
    ReleaseAgePolicy,
    invalidate_policy_cache,
)
from app.services.storage import BlobStore, set_store

TARBALL = b"pretend-this-is-a-gzipped-npm-tarball" * 10
TARBALL_SHA1 = hashlib.sha1(TARBALL).hexdigest()
WHEEL = b"pretend-this-is-a-python-wheel" * 10
WHEEL_SHA256 = hashlib.sha256(WHEEL).hexdigest()


def _iso(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def packument(new_age: timedelta = timedelta(days=1)) -> dict:
    """leftpad 1.0.0 (years old) and 1.1.0 (published ``new_age`` ago)."""
    fresh = datetime.now(UTC) - new_age

    def version(v: str) -> dict:
        return {
            "name": "leftpad",
            "version": v,
            "dist": {
                "shasum": TARBALL_SHA1,
                "tarball": f"https://upstream.test/leftpad/-/leftpad-{v}.tgz",
            },
        }

    return {
        "_id": "leftpad",
        "name": "leftpad",
        "dist-tags": {"latest": "1.1.0"},
        "time": {
            "created": "2019-06-01T00:00:00.000Z",
            "1.0.0": "2020-01-01T00:00:00.000Z",
            "1.1.0": _iso(fresh),
        },
        "versions": {"1.0.0": version("1.0.0"), "1.1.0": version("1.1.0")},
    }


def mock_npm(new_age: timedelta = timedelta(days=1)) -> None:
    respx.get("https://upstream.test/leftpad").mock(
        return_value=httpx.Response(200, json=packument(new_age))
    )
    for v in ("1.0.0", "1.1.0"):
        respx.get(f"https://upstream.test/leftpad/-/leftpad-{v}.tgz").mock(
            return_value=httpx.Response(200, content=TARBALL)
        )


def mock_pypi() -> None:
    fresh = datetime.now(UTC) - timedelta(hours=6)
    files = []
    for v, when in (("1.0.0", datetime(2020, 1, 1, tzinfo=UTC)), ("2.0.0", fresh)):
        files.append(
            {
                "filename": f"widget-{v}-py3-none-any.whl",
                "url": f"https://files.upstream.test/widget-{v}-py3-none-any.whl",
                "hashes": {"sha256": WHEEL_SHA256},
                "size": len(WHEEL),
                "upload-time": _iso(when),
            }
        )
        respx.get(f"https://files.upstream.test/widget-{v}-py3-none-any.whl").mock(
            return_value=httpx.Response(200, content=WHEEL)
        )
    respx.get("https://pypi.upstream.test/simple/widget/").mock(
        return_value=httpx.Response(
            200,
            json={
                "meta": {"api-version": "1.1"},
                "name": "widget",
                "versions": ["1.0.0", "2.0.0"],
                "files": files,
            },
            headers={"content-type": "application/vnd.pypi.simple.v1+json"},
        )
    )


@pytest_asyncio.fixture
async def client(tmp_path):
    from app.main import app

    db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'hold.db'}")
    await db_module.create_schema()
    store = BlobStore(str(tmp_path / "storage"))
    store.ensure_dirs()
    set_store(store)
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
        session.add(
            Upstream(
                name="mock-pypi",
                ecosystem=Ecosystem.pypi,
                kind=UpstreamKind.pypi,
                url="https://pypi.upstream.test/simple",
                tier=1,
                enabled=True,
            )
        )
    await invalidate_policy_cache()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://registry.test") as c:
        yield c
    await db_module.dispose_engine()
    set_store(None)  # type: ignore[arg-type]


async def set_hold(**values) -> None:
    async with db_module.session_scope() as session:
        row = await session.get(Setting, KEY_RELEASE_AGE)
        value = {**ReleaseAgePolicy().to_dict(), **values}
        if row is None:
            session.add(Setting(key=KEY_RELEASE_AGE, value=value))
        else:
            row.value = value
    await invalidate_policy_cache()


async def add_rule(**columns) -> None:
    async with db_module.session_scope() as session:
        session.add(PackageRule(**columns))
    await invalidate_policy_cache()


# --------------------------------------------------------------------------- #
# The policy object
# --------------------------------------------------------------------------- #
class TestReleaseAgePolicy:
    def test_on_by_default_for_three_days(self):
        for policy in (ReleaseAgePolicy(), ReleaseAgePolicy.from_dict(None)):
            assert policy.enabled is True
            assert policy.min_days == 3
            assert policy.exempt_security_fixes is True

    def test_held_until(self):
        now = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
        policy = ReleaseAgePolicy(min_days=3)
        published = now - timedelta(days=1)
        assert policy.held_until(published, now) == published + timedelta(days=3)
        assert policy.held_until(now - timedelta(days=3, seconds=1), now) is None
        assert policy.held_until(None, now) is None
        assert ReleaseAgePolicy(enabled=False).held_until(published, now) is None
        # A naive timestamp is read as UTC rather than crashing the request.
        assert policy.held_until(published.replace(tzinfo=None), now) is not None
        # A publication time in the future is held, not waved through.
        assert policy.held_until(now + timedelta(days=30), now) is not None

    def test_gitlab_upstreams_are_private_by_default(self):
        assert upstream_is_public(Upstream(kind=UpstreamKind.npm, is_public=None))
        assert not upstream_is_public(Upstream(kind=UpstreamKind.gitlab_npm, is_public=None))
        assert not upstream_is_public(Upstream(kind=UpstreamKind.gitlab_pypi, is_public=None))
        assert upstream_is_public(Upstream(kind=UpstreamKind.gitlab_npm, is_public=True))
        assert not upstream_is_public(Upstream(kind=UpstreamKind.npm, is_public=False))

    async def test_local_and_unknown_age_versions_are_never_held(self, client):
        fresh = datetime.now(UTC) - timedelta(hours=1)
        async with db_module.session_scope() as session:
            engine = PolicyEngine(session)
            held = await engine.evaluate("npm", "x", "1.0.0", published_at=fresh)
            assert held.blocked and held.source == "release_age"
            assert (
                await engine.evaluate("npm", "x", "1.0.0", published_at=fresh, is_local=True)
            ).allowed
            assert (await engine.evaluate("npm", "x", "1.0.0", published_at=None)).allowed


# --------------------------------------------------------------------------- #
# npm, end to end
# --------------------------------------------------------------------------- #
class TestNpmHold:
    @respx.mock
    async def test_a_new_release_is_hidden_and_latest_falls_back(self, client):
        mock_npm()
        doc = (await client.get("/npm/leftpad")).json()
        assert sorted(doc["versions"]) == ["1.0.0"]
        assert doc["dist-tags"]["latest"] == "1.0.0"

        tags = (await client.get("/npm/-/package/leftpad/dist-tags")).json()
        assert tags["latest"] == "1.0.0"

    @respx.mock
    async def test_the_tarball_and_version_document_are_refused_with_a_reason(self, client):
        mock_npm()
        await client.get("/npm/leftpad")
        response = await client.get("/npm/leftpad/-/leftpad-1.1.0.tgz")
        assert response.status_code == 403
        message = response.json()["error"]
        assert message.startswith("held back: 1.1.0 was published")
        assert "3 days after publication" in message
        assert "Use an earlier version" in message
        assert (await client.get("/npm/leftpad/1.1.0")).status_code == 403
        # The old release is unaffected.
        assert (await client.get("/npm/leftpad/-/leftpad-1.0.0.tgz")).status_code == 200

    @respx.mock
    async def test_a_release_older_than_the_hold_is_served(self, client):
        mock_npm(new_age=timedelta(days=4))
        doc = (await client.get("/npm/leftpad")).json()
        assert sorted(doc["versions"]) == ["1.0.0", "1.1.0"]
        assert (await client.get("/npm/leftpad/-/leftpad-1.1.0.tgz")).status_code == 200

    @respx.mock
    async def test_a_longer_hold_covers_more(self, client):
        mock_npm(new_age=timedelta(days=4))
        await set_hold(min_days=7)
        doc = (await client.get("/npm/leftpad")).json()
        assert sorted(doc["versions"]) == ["1.0.0"]

    @respx.mock
    async def test_switching_the_hold_off_serves_everything(self, client):
        mock_npm()
        await set_hold(enabled=False)
        doc = (await client.get("/npm/leftpad")).json()
        assert sorted(doc["versions"]) == ["1.0.0", "1.1.0"]

    @respx.mock
    async def test_an_exempt_rule_skips_the_hold(self, client):
        mock_npm()
        await add_rule(pattern="leftpad", action=RuleAction.exempt, reason="we trust it")
        doc = (await client.get("/npm/leftpad")).json()
        assert sorted(doc["versions"]) == ["1.0.0", "1.1.0"]
        assert (await client.get("/npm/leftpad/-/leftpad-1.1.0.tgz")).status_code == 200

    @respx.mock
    async def test_a_version_scoped_exemption_covers_only_its_versions(self, client):
        mock_npm()
        await add_rule(pattern="leftpad", action=RuleAction.exempt, version_spec="<1.1.0")
        doc = (await client.get("/npm/leftpad")).json()
        assert sorted(doc["versions"]) == ["1.0.0"]

    @respx.mock
    async def test_an_exemption_never_overrides_a_block(self, client):
        mock_npm()
        await add_rule(pattern="leftpad", action=RuleAction.exempt)
        await add_rule(pattern="leftpad", action=RuleAction.block, version_spec="1.1.0")
        doc = (await client.get("/npm/leftpad")).json()
        assert sorted(doc["versions"]) == ["1.0.0"]

    @respx.mock
    async def test_a_private_upstream_is_not_held(self, client):
        mock_npm()
        async with db_module.session_scope() as session:
            await session.execute(update(Upstream).values(is_public=False))
        await invalidate_policy_cache()
        doc = (await client.get("/npm/leftpad")).json()
        assert sorted(doc["versions"]) == ["1.0.0", "1.1.0"]

    @respx.mock
    async def test_the_fix_for_a_cve_is_served_straight_away(self, client):
        mock_npm()
        await client.get("/npm/leftpad")
        async with db_module.session_scope() as session:
            old = (
                await session.execute(
                    select(PackageVersion)
                    .join(Package)
                    .where(Package.normalized_name == "leftpad", PackageVersion.version == "1.0.0")
                )
            ).scalar_one()
            session.add(
                Vulnerability(
                    id="GHSA-test-fix", cve_id="CVE-2026-0001", ecosystem=Ecosystem.npm
                )
            )
            await session.flush()
            session.add(
                PackageVulnerability(
                    version_id=old.id, vulnerability_id="GHSA-test-fix", fixed_version="1.1.0"
                )
            )
        await invalidate_policy_cache()
        doc = (await client.get("/npm/leftpad")).json()
        assert "1.1.0" in doc["versions"]
        assert (await client.get("/npm/leftpad/-/leftpad-1.1.0.tgz")).status_code == 200

        # ...unless the operator turned that exemption off.
        await set_hold(exempt_security_fixes=False)
        assert (await client.get("/npm/leftpad/-/leftpad-1.1.0.tgz")).status_code == 403


# --------------------------------------------------------------------------- #
# PyPI, end to end
# --------------------------------------------------------------------------- #
class TestPypiHold:
    @respx.mock
    async def test_a_new_release_is_left_out_of_the_simple_index(self, client):
        mock_pypi()
        response = await client.get(
            "/pypi/simple/widget/", headers={"accept": "application/vnd.pypi.simple.v1+json"}
        )
        assert response.status_code == 200
        filenames = [f["filename"] for f in response.json()["files"]]
        assert filenames == ["widget-1.0.0-py3-none-any.whl"]

        response = await client.get("/pypi/files/widget/widget-2.0.0-py3-none-any.whl")
        assert response.status_code == 403
        assert response.text.startswith("held back: 2.0.0 was published")
        old = await client.get("/pypi/files/widget/widget-1.0.0-py3-none-any.whl")
        assert old.status_code == 200


# --------------------------------------------------------------------------- #
# cargo, end to end
# --------------------------------------------------------------------------- #
class TestCargoHold:
    @respx.mock
    async def test_a_new_release_is_left_out_of_the_sparse_index(self, client):
        import json

        async with db_module.session_scope() as session:
            session.add(
                Upstream(
                    name="mock-cargo",
                    ecosystem=Ecosystem.cargo,
                    kind=UpstreamKind.cargo,
                    url="https://index.upstream.test",
                    tier=1,
                    enabled=True,
                )
            )
        await invalidate_policy_cache()
        fresh = (datetime.now(UTC) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines = [
            {"name": "serde", "vers": v, "deps": [], "cksum": "a" * 64, "features": {},
             "yanked": False, **({"pubtime": when} if when else {})}
            for v, when in (("1.0.0", None), ("1.0.1", "2024-05-06T12:00:00Z"), ("1.0.2", fresh))
        ]
        respx.get("https://index.upstream.test/config.json").mock(
            return_value=httpx.Response(200, json={"dl": "https://static.upstream.test/api/v1/crates"})
        )
        respx.get("https://index.upstream.test/se/rd/serde").mock(
            return_value=httpx.Response(200, text="\n".join(json.dumps(x) for x in lines))
        )
        response = await client.get("/cargo/index/se/rd/serde")
        assert response.status_code == 200
        yanked = {
            entry["vers"]: entry["yanked"]
            for entry in (json.loads(line) for line in response.text.splitlines() if line)
        }
        # Blocked crate versions are served as yanked, so cargo never selects
        # them for a new resolution. An entry without pubtime predates the
        # field, so it is old: not held.
        assert yanked == {"1.0.0": False, "1.0.1": False, "1.0.2": True}
        download = await client.get("/cargo/api/v1/crates/serde/1.0.2/download")
        assert download.status_code == 403
        assert "held back" in download.text
