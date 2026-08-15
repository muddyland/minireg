"""Version-scoped block rules, end to end.

Verifies that an npm rule's `version_spec` is interpreted as a real semver
range (not a glob) all the way through the policy engine and the registry
endpoints, and that PyPI keeps PEP 440 semantics.
"""

import base64

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import db as db_module
from app.core.security import generate_token, hash_password
from app.models import ApiToken, Ecosystem, PackageRule, RuleAction, User
from app.services.policy import _matches_version, invalidate_policy_cache
from app.services.storage import BlobStore, set_store


class TestMatchesVersionNpm:
    """Unit-level: the predicate the policy engine actually calls."""

    @pytest.mark.parametrize(
        "spec,version,expected",
        [
            # Exact
            ("3.3.6", "3.3.6", True),
            ("3.3.6", "3.3.5", False),
            # Comparators -- the case globs could not express at all
            ("<4.17.21", "4.17.20", True),
            ("<4.17.21", "4.17.21", False),
            ("<4.17.21", "3.0.0", True),
            (">=1.0.0", "1.0.0", True),
            (">=1.0.0", "0.9.9", False),
            # Compound (AND)
            (">=3.0.0 <3.0.2", "3.0.1", True),
            (">=3.0.0 <3.0.2", "3.0.2", False),
            (">=3.0.0 <3.0.2", "2.9.9", False),
            # Union (OR)
            ("<2.6.9 || >=3.0.0 <3.0.2", "2.6.8", True),
            ("<2.6.9 || >=3.0.0 <3.0.2", "3.0.1", True),
            ("<2.6.9 || >=3.0.0 <3.0.2", "2.7.0", False),
            # Caret / tilde
            ("^1.2.3", "1.9.0", True),
            ("^1.2.3", "2.0.0", False),
            ("~1.2.3", "1.2.9", True),
            ("~1.2.3", "1.3.0", False),
            # X-ranges (also valid globs, so these must not regress)
            ("1.2.x", "1.2.7", True),
            ("1.2.x", "1.3.0", False),
            ("1.x", "1.99.99", True),
            ("1.x", "2.0.0", False),
            # Hyphen
            ("1.0.0 - 2.0.0", "1.5.0", True),
            ("1.0.0 - 2.0.0", "2.0.1", False),
            # Wildcards
            ("*", "9.9.9", True),
        ],
    )
    def test_npm_ranges(self, spec, version, expected):
        assert _matches_version(spec, "npm", version) is expected

    def test_prereleases_are_blocked_inclusively(self):
        # A block list must not leak a prerelease of a version it blocks, even
        # though npm's install-time default would skip it.
        assert _matches_version("<4.17.21", "npm", "4.17.20-rc.1") is True
        assert _matches_version(">=1.0.0 <2.0.0", "npm", "1.5.0-beta.1") is True
        assert _matches_version("1.x", "npm", "1.0.0-alpha") is True

    def test_prerelease_outside_the_range_still_does_not_match(self):
        assert _matches_version("<4.17.21", "npm", "5.0.0-rc.1") is False

    def test_unparseable_spec_falls_back_to_glob(self):
        # Preserves rules written before ranges were understood, and supports
        # patterns semver has no syntax for.
        assert _matches_version("*-nightly*", "npm", "1.2.3-nightly.4") is True
        assert _matches_version("*-nightly*", "npm", "1.2.3") is False

    def test_no_spec_matches_everything(self):
        assert _matches_version(None, "npm", "1.2.3") is True
        assert _matches_version("", "npm", "1.2.3") is True

    def test_spec_without_a_version_does_not_match(self):
        # Package-level question against a version-scoped rule.
        assert _matches_version("<2.0.0", "npm", None) is False


class TestMatchesVersionPypi:
    @pytest.mark.parametrize(
        "spec,version,expected",
        [
            ("==1.2.3", "1.2.3", True),
            ("==1.2.3", "1.2.4", False),
            ("<2.0", "1.9.9", True),
            ("<2.0", "2.0", False),
            (">=1.0,<2.0", "1.5", True),
            (">=1.0,<2.0", "2.1", False),
            ("~=1.4.2", "1.4.5", True),
            ("~=1.4.2", "1.5.0", False),
            ("!=1.2.3", "1.2.4", True),
        ],
    )
    def test_pep440_specifiers(self, spec, version, expected):
        assert _matches_version(spec, "pypi", version) is expected

    def test_prereleases_included(self):
        assert _matches_version("<2.0", "pypi", "1.9.9rc1") is True


# --------------------------------------------------------------------------- #
# End to end
# --------------------------------------------------------------------------- #
@pytest_asyncio.fixture
async def client(tmp_path):
    from app.main import app

    db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'vp.db'}")
    await db_module.create_schema()
    store = BlobStore(str(tmp_path / "storage"))
    store.ensure_dirs()
    set_store(store)

    async with db_module.session_scope() as session:
        admin = User(
            username="admin",
            password_hash=hash_password("admin-password-1234"),
            is_admin=True,
            can_publish=True,
        )
        session.add(admin)
        await session.flush()
        full, prefix, token_hash = generate_token()
        session.add(
            ApiToken(
                user_id=admin.id,
                name="t",
                prefix=prefix,
                token_hash=token_hash,
                scopes=["read", "publish", "admin"],
            )
        )
    await invalidate_policy_cache()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://registry.test"
    ) as c:
        c.headers.update({"authorization": f"Bearer {full}"})
        yield c

    await db_module.dispose_engine()
    set_store(None)  # type: ignore[arg-type]


def publish_body(name, version):
    tarball = f"tarball-for-{name}-{version}".encode()
    return {
        "name": name,
        "dist-tags": {"latest": version},
        "versions": {version: {"name": name, "version": version, "dist": {}}},
        "_attachments": {
            f"{name}-{version}.tgz": {
                "content_type": "application/octet-stream",
                "data": base64.b64encode(tarball).decode(),
                "length": len(tarball),
            }
        },
    }


async def add_rule(pattern, version_spec, ecosystem=Ecosystem.npm):
    async with db_module.session_scope() as session:
        session.add(
            PackageRule(
                ecosystem=ecosystem,
                pattern=pattern,
                action=RuleAction.block,
                version_spec=version_spec,
                reason=f"blocked {pattern}@{version_spec}",
            )
        )
    await invalidate_policy_cache()


class TestVersionScopedBlockingEndToEnd:
    async def test_only_the_matching_versions_are_hidden(self, client):
        for version in ("4.17.19", "4.17.20", "4.17.21", "5.0.0"):
            await client.put("/npm/lodash", json=publish_body("lodash", version))

        await add_rule("lodash", "<4.17.21")

        doc = (await client.get("/npm/lodash")).json()
        assert "4.17.19" not in doc["versions"]
        assert "4.17.20" not in doc["versions"]
        assert "4.17.21" in doc["versions"]
        assert "5.0.0" in doc["versions"]

    async def test_blocked_version_tarball_is_403(self, client):
        for version in ("1.0.0", "2.0.0"):
            await client.put("/npm/thing", json=publish_body("thing", version))
        await add_rule("thing", "<2.0.0")

        blocked = await client.get("/npm/thing/-/thing-1.0.0.tgz")
        allowed = await client.get("/npm/thing/-/thing-2.0.0.tgz")
        assert blocked.status_code == 403
        assert allowed.status_code == 200

    async def test_blocked_version_document_is_403(self, client):
        for version in ("1.0.0", "2.0.0"):
            await client.put("/npm/thing", json=publish_body("thing", version))
        await add_rule("thing", "<2.0.0")

        assert (await client.get("/npm/thing/1.0.0")).status_code == 403
        assert (await client.get("/npm/thing/2.0.0")).status_code == 200

    async def test_compound_range_blocks_a_window(self, client):
        for version in ("3.3.5", "3.3.6", "3.3.7"):
            await client.put("/npm/event-stream", json=publish_body("event-stream", version))
        await add_rule("event-stream", ">=3.3.6 <3.3.7")

        doc = (await client.get("/npm/event-stream")).json()
        assert "3.3.6" not in doc["versions"]
        assert "3.3.5" in doc["versions"]
        assert "3.3.7" in doc["versions"]

    async def test_union_range_blocks_two_windows(self, client):
        for version in ("2.6.8", "2.6.9", "3.0.1", "3.0.2"):
            await client.put("/npm/axios", json=publish_body("axios", version))
        await add_rule("axios", "<2.6.9 || >=3.0.0 <3.0.2")

        doc = (await client.get("/npm/axios")).json()
        assert "2.6.8" not in doc["versions"]
        assert "3.0.1" not in doc["versions"]
        assert "2.6.9" in doc["versions"]
        assert "3.0.2" in doc["versions"]

    async def test_latest_is_repointed_past_a_blocked_range(self, client):
        for version in ("1.0.0", "2.0.0", "3.0.0"):
            await client.put("/npm/lib", json=publish_body("lib", version))
        await add_rule("lib", ">=2.0.0")

        doc = (await client.get("/npm/lib")).json()
        assert doc["dist-tags"]["latest"] == "1.0.0"
        assert doc["dist-tags"]["latest"] in doc["versions"]

    async def test_publishing_a_blocked_version_is_refused(self, client):
        await add_rule("newpkg", ">=2.0.0")
        allowed = await client.put("/npm/newpkg", json=publish_body("newpkg", "1.0.0"))
        blocked = await client.put("/npm/newpkg", json=publish_body("newpkg", "2.0.0"))
        assert allowed.status_code == 201
        assert blocked.status_code == 403

    async def test_package_level_rule_still_blocks_the_whole_package(self, client):
        await client.put("/npm/gone", json=publish_body("gone", "1.0.0"))
        await add_rule("gone", None)
        assert (await client.get("/npm/gone")).status_code == 403


class TestRuleValidationApi:
    async def test_valid_npm_range_is_accepted_and_expanded(self, client):
        response = await client.post(
            "/api/admin/rules",
            json={
                "pattern": "lodash",
                "action": "block",
                "ecosystem": "npm",
                "version_spec": "^1.2.3",
            },
        )
        assert response.status_code == 201
        assert response.json()["version_spec_expanded"] == ">=1.2.3 <2.0.0-0"

    async def test_invalid_npm_range_is_rejected_with_guidance(self, client):
        response = await client.post(
            "/api/admin/rules",
            json={
                "pattern": "lodash",
                "action": "block",
                "ecosystem": "npm",
                "version_spec": "not a range",
            },
        )
        assert response.status_code == 400
        assert "not a valid npm version range" in response.json()["detail"]

    async def test_invalid_pypi_specifier_is_rejected(self, client):
        response = await client.post(
            "/api/admin/rules",
            json={
                "pattern": "django",
                "action": "block",
                "ecosystem": "pypi",
                "version_spec": "^1.2.3",
            },
        )
        assert response.status_code == 400
        assert "PEP 440" in response.json()["detail"]

    async def test_valid_pypi_specifier_is_accepted(self, client):
        response = await client.post(
            "/api/admin/rules",
            json={
                "pattern": "django",
                "action": "block",
                "ecosystem": "pypi",
                "version_spec": "<2.0",
            },
        )
        assert response.status_code == 201

    async def test_dry_run_reports_a_version_scoped_rule(self, client):
        await client.post(
            "/api/admin/rules",
            json={
                "pattern": "lodash",
                "action": "block",
                "ecosystem": "npm",
                "version_spec": "<4.17.21",
                "reason": "CVE-2021-23337",
            },
        )
        blocked = await client.post(
            "/api/admin/rules/test?ecosystem=npm&name=lodash&version=4.17.20"
        )
        allowed = await client.post(
            "/api/admin/rules/test?ecosystem=npm&name=lodash&version=4.17.21"
        )
        assert blocked.json()["allowed"] is False
        assert blocked.json()["reason"] == "CVE-2021-23337"
        assert allowed.json()["allowed"] is True
