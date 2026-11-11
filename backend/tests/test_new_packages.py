"""The new-package guard.

Attackers publish under names people mistype (typosquatting) and names AI
assistants invent when they hallucinate a dependency (slopsquatting), then
wait. Such a name is almost always days or weeks old, so a package that first
appeared on a public registry less than ``min_days`` ago is refused.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import respx
from sqlalchemy import select, update

from app import db as db_module
from app.models import (
    Ecosystem,
    Package,
    PackageVersion,
    RuleAction,
    Setting,
    Upstream,
    UpstreamKind,
)
from app.services.packages import first_published_at
from app.services.policy import (
    KEY_NEW_PACKAGES,
    NewPackagePolicy,
    invalidate_policy_cache,
)
from app.upstreams.base import RemotePackage, RemoteVersion
from tests.test_release_age import TARBALL, TARBALL_SHA1, WHEEL, WHEEL_SHA256, add_rule, client  # noqa: F401


def _iso(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def mock_npm(name: str, created_days_ago: float, versions: dict[str, float]) -> None:
    """A package created ``created_days_ago`` with releases ``{version: days_ago}``."""
    now = datetime.now(UTC)
    doc = {
        "_id": name,
        "name": name,
        "dist-tags": {"latest": max(versions)},
        "time": {
            "created": _iso(now - timedelta(days=created_days_ago)),
            **{v: _iso(now - timedelta(days=d)) for v, d in versions.items()},
        },
        "versions": {
            v: {
                "name": name,
                "version": v,
                "dist": {
                    "shasum": TARBALL_SHA1,
                    "tarball": f"https://upstream.test/{name}/-/{name}-{v}.tgz",
                },
            }
            for v in versions
        },
    }
    respx.get(f"https://upstream.test/{name}").mock(return_value=httpx.Response(200, json=doc))
    for v in versions:
        respx.get(f"https://upstream.test/{name}/-/{name}-{v}.tgz").mock(
            return_value=httpx.Response(200, content=TARBALL)
        )


async def set_guard(**values) -> None:
    async with db_module.session_scope() as session:
        row = await session.get(Setting, KEY_NEW_PACKAGES)
        value = {**NewPackagePolicy().to_dict(), **values}
        if row is None:
            session.add(Setting(key=KEY_NEW_PACKAGES, value=value))
        else:
            row.value = value
    await invalidate_policy_cache()


class TestFirstPublished:
    def test_npm_created_wins(self):
        remote = RemotePackage(
            name="x",
            time={"created": "2019-06-01T00:00:00.000Z"},
            versions=[RemoteVersion("1.0.0", published_at=datetime(2026, 1, 1, tzinfo=UTC))],
        )
        assert first_published_at(remote) == datetime(2019, 6, 1, tzinfo=UTC)

    def test_oldest_release_when_every_release_is_dated(self):
        remote = RemotePackage(
            name="x",
            versions=[
                RemoteVersion("1.0.1", published_at=datetime(2026, 2, 1, tzinfo=UTC)),
                RemoteVersion("1.0.0", published_at=datetime(2026, 1, 1, tzinfo=UTC)),
            ],
        )
        assert first_published_at(remote) == datetime(2026, 1, 1, tzinfo=UTC)

    def test_an_undated_release_means_unknown_not_new(self):
        # A crate whose first releases predate crates.io's `pubtime`.
        remote = RemotePackage(
            name="x",
            versions=[
                RemoteVersion("0.1.0", published_at=None),
                RemoteVersion("2.0.0", published_at=datetime.now(UTC)),
            ],
        )
        assert first_published_at(remote) is None
        assert first_published_at(RemotePackage(name="x")) is None

    def test_the_policy_defaults(self):
        policy = NewPackagePolicy.from_dict(None)
        assert policy.enabled is True and policy.min_days == 30
        now = datetime(2026, 11, 11, tzinfo=UTC)
        assert policy.new_until(now - timedelta(days=29), now) is not None
        assert policy.new_until(now - timedelta(days=31), now) is None
        assert policy.new_until(None, now) is None
        assert NewPackagePolicy(enabled=False).new_until(now, now) is None


class TestNpmGuard:
    @respx.mock
    async def test_a_new_package_is_refused_with_a_reason(self, client):  # noqa: F811
        mock_npm("reqeusts-helper", created_days_ago=6, versions={"1.0.0": 6, "1.0.1": 5})
        response = await client.get("/npm/reqeusts-helper")
        assert response.status_code == 403
        message = response.json()["error"]
        assert message.startswith("blocked as a new package: reqeusts-helper first appeared")
        assert "at least 30 days old" in message
        assert "check this is the package you meant" in message

        tarball = await client.get("/npm/reqeusts-helper/-/reqeusts-helper-1.0.0.tgz")
        assert tarball.status_code == 403
        assert "new package" in tarball.json()["error"]

    @respx.mock
    async def test_an_established_package_is_not_affected(self, client):  # noqa: F811
        # Created years ago; a release from last week is past the 3-day hold.
        mock_npm("leftpad", created_days_ago=2000, versions={"1.0.0": 2000, "1.1.0": 7})
        doc = (await client.get("/npm/leftpad")).json()
        assert sorted(doc["versions"]) == ["1.0.0", "1.1.0"]

    @respx.mock
    async def test_an_exempt_rule_lets_it_through(self, client):  # noqa: F811
        mock_npm("our-new-tool", created_days_ago=6, versions={"1.0.0": 6})
        await add_rule(pattern="our-new-tool", action=RuleAction.exempt, reason="ours")
        response = await client.get("/npm/our-new-tool")
        assert response.status_code == 200
        assert sorted(response.json()["versions"]) == ["1.0.0"]

    @respx.mock
    async def test_switching_the_guard_off_serves_it(self, client):  # noqa: F811
        mock_npm("brand-new", created_days_ago=6, versions={"1.0.0": 6})
        await set_guard(enabled=False)
        assert (await client.get("/npm/brand-new")).status_code == 200

    @respx.mock
    async def test_a_shorter_window(self, client):  # noqa: F811
        mock_npm("brand-new", created_days_ago=10, versions={"1.0.0": 10})
        await set_guard(min_days=7)
        assert (await client.get("/npm/brand-new")).status_code == 200

    @respx.mock
    async def test_a_private_upstream_is_not_guarded(self, client):  # noqa: F811
        mock_npm("brand-new", created_days_ago=6, versions={"1.0.0": 6})
        async with db_module.session_scope() as session:
            await session.execute(update(Upstream).values(is_public=False))
        await invalidate_policy_cache()
        assert (await client.get("/npm/brand-new")).status_code == 200

    @respx.mock
    async def test_a_package_whose_only_release_is_held_says_so(self, client):  # noqa: F811
        # Not a new package -- the name is old -- but every release it has
        # left is inside the hold. The 403 must say why, not "blocked".
        mock_npm("revived", created_days_ago=2000, versions={"2.0.0": 1})
        response = await client.get("/npm/revived")
        assert response.status_code == 403
        assert response.json()["error"].startswith("held back: 2.0.0 was published")


class TestPypiGuard:
    @respx.mock
    async def test_a_new_project_is_refused_with_a_reason(self, client):  # noqa: F811
        when = datetime.now(UTC) - timedelta(days=4)
        respx.get("https://pypi.upstream.test/simple/hallucinated-utils/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "meta": {"api-version": "1.1"},
                    "name": "hallucinated-utils",
                    "versions": ["0.1.0"],
                    "files": [
                        {
                            "filename": "hallucinated_utils-0.1.0-py3-none-any.whl",
                            "url": "https://files.upstream.test/hu-0.1.0.whl",
                            "hashes": {"sha256": WHEEL_SHA256},
                            "size": len(WHEEL),
                            "upload-time": _iso(when),
                        }
                    ],
                },
                headers={"content-type": "application/vnd.pypi.simple.v1+json"},
            )
        )
        response = await client.get("/pypi/simple/hallucinated-utils/")
        assert response.status_code == 403
        assert response.text.startswith(
            "blocked as a new package: hallucinated-utils first appeared"
        )


class TestCargoGuard:
    async def _crate(self, client, entries):  # noqa: F811
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
        respx.get("https://index.upstream.test/config.json").mock(
            return_value=httpx.Response(
                200, json={"dl": "https://static.upstream.test/api/v1/crates"}
            )
        )
        lines = [
            {
                "name": "fresh",
                "vers": v,
                "deps": [],
                "cksum": "a" * 64,
                "features": {},
                "yanked": False,
                **({"pubtime": when} if when else {}),
            }
            for v, when in entries
        ]
        respx.get("https://index.upstream.test/fr/es/fresh").mock(
            return_value=httpx.Response(200, text="\n".join(json.dumps(x) for x in lines))
        )
        response = await client.get("/cargo/index/fr/es/fresh")
        assert response.status_code == 200
        return {
            e["vers"]: e["yanked"]
            for e in (json.loads(line) for line in response.text.splitlines() if line)
        }

    @respx.mock
    async def test_a_new_crate_is_served_as_yanked(self, client):  # noqa: F811
        ten = (datetime.now(UTC) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert await self._crate(client, [("0.1.0", ten)]) == {"0.1.0": True}
        download = await client.get("/cargo/api/v1/crates/fresh/0.1.0/download")
        assert download.status_code == 403
        assert "new package" in download.text

    @respx.mock
    async def test_a_crate_older_than_pubtime_is_not_new(self, client):  # noqa: F811
        ten = (datetime.now(UTC) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert await self._crate(client, [("0.1.0", None), ("0.2.0", ten)]) == {
            "0.1.0": False,
            "0.2.0": False,
        }


class TestBackfill:
    async def test_cached_packages_get_a_first_published_date_on_upgrade(self, client):  # noqa: F811
        old = datetime(2021, 5, 1, tzinfo=UTC)
        async with db_module.session_scope() as session:
            dated = Package(ecosystem=Ecosystem.npm, name="dated", normalized_name="dated")
            undated = Package(ecosystem=Ecosystem.npm, name="undated", normalized_name="undated")
            session.add_all([dated, undated])
            await session.flush()
            for package, stamps in ((dated, [old, old + timedelta(days=9)]), (undated, [old, None])):
                for i, stamp in enumerate(stamps):
                    session.add(
                        PackageVersion(
                            package_id=package.id,
                            version=f"1.0.{i}",
                            normalized_version=f"1.0.{i}",
                            published_at=stamp,
                        )
                    )
        await db_module.create_schema()  # what every start runs
        await db_module.create_schema()  # idempotent
        async with db_module.session_scope() as session:
            rows = dict(
                (await session.execute(select(Package.name, Package.first_published_at))).all()
            )
        assert rows["dated"].replace(tzinfo=UTC) == old
        assert rows["undated"] is None
