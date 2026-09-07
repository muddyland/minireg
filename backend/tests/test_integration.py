"""End-to-end tests against a live app instance backed by SQLite.

These exercise the real routing, auth, policy, publish, and rendering paths --
the parts unit tests of pure functions cannot cover.
"""

import base64

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import db as db_module
from app.core.security import generate_token
from app.models import ApiToken, Ecosystem, PackageRule, RuleAction, Setting, User
from app.services.policy import KEY_ALLOWLIST_MODE, KEY_CVE_POLICY, invalidate_policy_cache
from app.services.storage import BlobStore, set_store


@pytest_asyncio.fixture
async def app_client(tmp_path):
    """A fresh app + database per test."""
    from app.core.security import hash_password
    from app.main import app

    # A file-backed database, not ":memory:": with NullPool every connection
    # would otherwise get its own private, empty in-memory database.
    db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
    await db_module.create_schema()

    store = BlobStore(str(tmp_path / "storage"))
    store.ensure_dirs()
    set_store(store)

    async with db_module.session_scope() as session:
        admin = User(
            username="admin",
            email="admin@test",
            password_hash=hash_password("admin-password-1234"),
            is_admin=True,
            can_publish=True,
        )
        publisher = User(
            username="publisher",
            email="pub@test",
            password_hash=hash_password("publisher-password-1"),
            is_admin=False,
            can_publish=True,
        )
        reader = User(
            username="reader",
            email="reader@test",
            password_hash=hash_password("reader-password-12345"),
            is_admin=False,
            can_publish=False,
        )
        session.add_all([admin, publisher, reader])
        await session.flush()

        tokens = {}
        for user, scopes in (
            (admin, ["read", "publish", "admin"]),
            (publisher, ["read", "publish"]),
            (reader, ["read"]),
        ):
            full, prefix, token_hash = generate_token()
            session.add(
                ApiToken(
                    user_id=user.id,
                    name=f"{user.username}-token",
                    prefix=prefix,
                    token_hash=token_hash,
                    scopes=scopes,
                )
            )
            tokens[user.username] = full

    await invalidate_policy_cache()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://registry.test") as client:
        client.tokens = tokens  # type: ignore[attr-defined]
        yield client

    await db_module.dispose_engine()
    set_store(None)  # type: ignore[arg-type]


def auth(client, username="publisher"):
    return {"authorization": f"Bearer {client.tokens[username]}"}


def basic_auth(client, username="publisher"):
    raw = base64.b64encode(f"__token__:{client.tokens[username]}".encode()).decode()
    return {"authorization": f"Basic {raw}"}


def npm_publish_body(name="test-pkg", version="1.0.0", tarball=b"tarball-content"):
    return {
        "_id": name,
        "name": name,
        "description": "a test package",
        "dist-tags": {"latest": version},
        "versions": {
            version: {
                "name": name,
                "version": version,
                "description": "a test package",
                "dependencies": {"left-pad": "^1.0.0"},
                "main": "index.js",
                "dist": {"tarball": f"http://x/{name}/-/{name}-{version}.tgz"},
            }
        },
        "_attachments": {
            f"{name}-{version}.tgz": {
                "content_type": "application/octet-stream",
                "data": base64.b64encode(tarball).decode(),
                "length": len(tarball),
            }
        },
    }


# --------------------------------------------------------------------------- #
class TestServiceEndpoints:
    async def test_health(self, app_client):
        response = await app_client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_npm_ping(self, app_client):
        response = await app_client.get("/npm/-/ping")
        assert response.status_code == 200
        assert response.json() == {}

    async def test_npm_whoami_anonymous(self, app_client):
        assert (await app_client.get("/npm/-/whoami")).status_code == 401

    async def test_npm_whoami_with_token(self, app_client):
        response = await app_client.get("/npm/-/whoami", headers=auth(app_client))
        assert response.status_code == 200
        assert response.json() == {"username": "publisher"}

    async def test_npm_legacy_login_is_rejected_with_guidance(self, app_client):
        response = await app_client.put(
            "/npm/-/user/org.couchdb.user:someone", json={"name": "someone", "password": "x"}
        )
        assert response.status_code == 401
        assert "API token" in response.json()["error"]


class TestAuthentication:
    async def test_login_and_me(self, app_client):
        response = await app_client.post(
            "/api/auth/login", json={"username": "admin", "password": "admin-password-1234"}
        )
        assert response.status_code == 200
        assert response.json()["user"]["is_admin"] is True

        me = await app_client.get("/api/auth/me")
        assert me.status_code == 200
        assert me.json()["user"]["username"] == "admin"

    async def test_login_with_wrong_password(self, app_client):
        response = await app_client.post(
            "/api/auth/login", json={"username": "admin", "password": "wrong"}
        )
        assert response.status_code == 401
        # Must not disclose whether the account exists.
        assert response.json()["detail"] == "invalid username or password"

    async def test_login_unknown_user_same_message(self, app_client):
        response = await app_client.post(
            "/api/auth/login", json={"username": "nobody", "password": "wrong"}
        )
        assert response.json()["detail"] == "invalid username or password"

    async def test_basic_auth_with_token_works(self, app_client):
        response = await app_client.get("/npm/-/whoami", headers=basic_auth(app_client))
        assert response.status_code == 200

    async def test_invalid_token_is_anonymous(self, app_client):
        response = await app_client.get(
            "/npm/-/whoami", headers={"authorization": "Bearer mrg_deadbeef_nope"}
        )
        assert response.status_code == 401

    async def test_admin_endpoint_requires_admin(self, app_client):
        response = await app_client.get("/api/admin/users", headers=auth(app_client, "publisher"))
        assert response.status_code == 403

    async def test_admin_endpoint_allows_admin(self, app_client):
        response = await app_client.get("/api/admin/users", headers=auth(app_client, "admin"))
        assert response.status_code == 200
        assert len(response.json()["users"]) == 3


class TestNpmPublishFlow:
    async def test_publish_requires_authentication(self, app_client):
        response = await app_client.put("/npm/test-pkg", json=npm_publish_body())
        assert response.status_code == 401

    async def test_publish_requires_publish_permission(self, app_client):
        response = await app_client.put(
            "/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client, "reader")
        )
        assert response.status_code == 403

    async def test_publish_succeeds(self, app_client):
        response = await app_client.put(
            "/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client)
        )
        assert response.status_code == 201
        assert response.json()["ok"] is True

    async def test_published_packument_is_servable(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        response = await app_client.get("/npm/test-pkg")
        assert response.status_code == 200
        doc = response.json()
        assert doc["name"] == "test-pkg"
        assert "1.0.0" in doc["versions"]
        assert doc["dist-tags"]["latest"] == "1.0.0"
        assert doc["versions"]["1.0.0"]["dist"]["tarball"].startswith("http://registry.test/npm/")

    async def test_abbreviated_packument(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        response = await app_client.get(
            "/npm/test-pkg", headers={"accept": "application/vnd.npm.install-v1+json"}
        )
        assert response.status_code == 200
        assert set(response.json()) == {"name", "modified", "dist-tags", "versions"}
        assert "application/vnd.npm.install-v1+json" in response.headers["content-type"]

    async def test_tarball_roundtrip(self, app_client):
        payload = b"the-actual-tarball-bytes"
        await app_client.put(
            "/npm/test-pkg", json=npm_publish_body(tarball=payload), headers=auth(app_client)
        )
        response = await app_client.get("/npm/test-pkg/-/test-pkg-1.0.0.tgz")
        assert response.status_code == 200
        assert response.content == payload
        assert response.headers["cache-control"] == "public, max-age=31536000, immutable"

    async def test_republishing_same_version_conflicts(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        response = await app_client.put(
            "/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client)
        )
        assert response.status_code == 409
        assert "cannot publish over" in response.json()["error"].lower()

    async def test_version_document(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        response = await app_client.get("/npm/test-pkg/1.0.0")
        assert response.status_code == 200
        assert response.json()["version"] == "1.0.0"
        assert "versions" not in response.json()

    async def test_latest_tag_resolves(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        response = await app_client.get("/npm/test-pkg/latest")
        assert response.status_code == 200
        assert response.json()["version"] == "1.0.0"

    async def test_scoped_package_publish_and_fetch(self, app_client):
        body = npm_publish_body(name="@scope/thing")
        body["_attachments"] = {"thing-1.0.0.tgz": body["_attachments"].pop("@scope/thing-1.0.0.tgz")}
        response = await app_client.put(
            "/npm/@scope%2fthing", json=body, headers=auth(app_client)
        )
        assert response.status_code == 201

        # Both the encoded and unencoded forms must resolve to the same package.
        for path in ("/npm/@scope%2fthing", "/npm/@scope/thing"):
            got = await app_client.get(path)
            assert got.status_code == 200, path
            assert got.json()["name"] == "@scope/thing"

    async def test_dist_tags_endpoints(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        await app_client.put(
            "/npm/test-pkg", json=npm_publish_body(version="2.0.0"), headers=auth(app_client)
        )

        response = await app_client.get("/npm/-/package/test-pkg/dist-tags")
        assert response.status_code == 200
        assert response.json()["latest"] == "2.0.0"

        response = await app_client.put(
            "/npm/-/package/test-pkg/dist-tags/beta",
            content='"1.0.0"',
            headers=auth(app_client),
        )
        assert response.status_code == 200
        assert (await app_client.get("/npm/-/package/test-pkg/dist-tags")).json()["beta"] == "1.0.0"

        response = await app_client.delete(
            "/npm/-/package/test-pkg/dist-tags/beta", headers=auth(app_client)
        )
        assert response.status_code == 200
        assert "beta" not in (await app_client.get("/npm/-/package/test-pkg/dist-tags")).json()

    async def test_cannot_delete_latest_tag(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        response = await app_client.delete(
            "/npm/-/package/test-pkg/dist-tags/latest", headers=auth(app_client)
        )
        assert response.status_code == 400

    async def test_unknown_package_is_404(self, app_client):
        assert (await app_client.get("/npm/does-not-exist")).status_code == 404


class TestPypiPublishFlow:
    def _upload(self, name="my-package", version="1.0.0", filename=None, content=b"wheel-bytes"):
        filename = filename or f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
        return (
            {
                ":action": "file_upload",
                "protocol_version": "1",
                "name": name,
                "version": version,
                "filetype": "bdist_wheel",
                "pyversion": "py3",
                "metadata_version": "2.1",
                "summary": "A test package",
            },
            {"content": (filename, content, "application/octet-stream")},
        )

    async def test_upload_requires_auth(self, app_client):
        data, files = self._upload()
        response = await app_client.post("/pypi/legacy/", data=data, files=files)
        assert response.status_code == 401

    async def test_upload_succeeds(self, app_client):
        data, files = self._upload()
        response = await app_client.post(
            "/pypi/legacy/", data=data, files=files, headers=basic_auth(app_client)
        )
        assert response.status_code == 200

    async def test_simple_index_html(self, app_client):
        data, files = self._upload()
        await app_client.post(
            "/pypi/legacy/", data=data, files=files, headers=basic_auth(app_client)
        )
        response = await app_client.get("/pypi/simple/my-package/")
        assert response.status_code == 200
        assert "pypi:repository-version" in response.text
        assert "my_package-1.0.0-py3-none-any.whl" in response.text
        assert "#sha256=" in response.text

    async def test_simple_index_json(self, app_client):
        data, files = self._upload()
        await app_client.post(
            "/pypi/legacy/", data=data, files=files, headers=basic_auth(app_client)
        )
        response = await app_client.get(
            "/pypi/simple/my-package/",
            headers={"accept": "application/vnd.pypi.simple.v1+json"},
        )
        assert response.status_code == 200
        doc = response.json()
        assert doc["meta"]["api-version"] == "1.1"
        assert doc["name"] == "my-package"
        assert doc["versions"] == ["1.0.0"]
        assert doc["files"][0]["size"] == len(b"wheel-bytes")

    async def test_non_normalized_url_redirects(self, app_client):
        response = await app_client.get("/pypi/simple/My.Package/", follow_redirects=False)
        assert response.status_code == 301
        assert response.headers["location"].endswith("/pypi/simple/my-package/")

    async def test_file_download_roundtrip(self, app_client):
        payload = b"the-wheel-bytes-here"
        data, files = self._upload(content=payload)
        await app_client.post(
            "/pypi/legacy/", data=data, files=files, headers=basic_auth(app_client)
        )
        response = await app_client.get(
            "/pypi/files/my-package/my_package-1.0.0-py3-none-any.whl"
        )
        assert response.status_code == 200
        assert response.content == payload

    async def test_duplicate_filename_rejected(self, app_client):
        data, files = self._upload()
        await app_client.post(
            "/pypi/legacy/", data=data, files=files, headers=basic_auth(app_client)
        )
        data, files = self._upload()
        response = await app_client.post(
            "/pypi/legacy/", data=data, files=files, headers=basic_auth(app_client)
        )
        assert response.status_code == 400
        assert "already exists" in response.text

    async def test_only_one_sdist_per_release(self, app_client):
        for filename in ("my_package-1.0.0.tar.gz", "my_package-1.0.0.zip"):
            data, files = self._upload(filename=filename)
            data["filetype"] = "sdist"
            response = await app_client.post(
                "/pypi/legacy/", data=data, files=files, headers=basic_auth(app_client)
            )
        assert response.status_code == 400
        assert "Only one sdist" in response.text

    async def test_filename_mismatch_rejected(self, app_client):
        data, files = self._upload(filename="other_package-1.0.0-py3-none-any.whl")
        response = await app_client.post(
            "/pypi/legacy/", data=data, files=files, headers=basic_auth(app_client)
        )
        assert response.status_code == 400
        assert "does not match the declared project name" in response.text

    async def test_index_lists_project(self, app_client):
        data, files = self._upload()
        await app_client.post(
            "/pypi/legacy/", data=data, files=files, headers=basic_auth(app_client)
        )
        response = await app_client.get(
            "/pypi/simple/", headers={"accept": "application/vnd.pypi.simple.v1+json"}
        )
        assert response.status_code == 200
        assert {"name": "my-package"} in response.json()["projects"]


class TestBlockList:
    async def _add_rule(self, pattern, action=RuleAction.block, ecosystem=None, version_spec=None):
        async with db_module.session_scope() as session:
            session.add(
                PackageRule(
                    ecosystem=ecosystem,
                    pattern=pattern,
                    action=action,
                    version_spec=version_spec,
                    reason=f"test rule for {pattern}",
                )
            )
        await invalidate_policy_cache()

    async def test_blocked_package_metadata_is_403(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        await self._add_rule("test-pkg")
        response = await app_client.get("/npm/test-pkg")
        assert response.status_code == 403
        assert "test rule" in response.json()["error"]

    async def test_blocked_package_tarball_is_403(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        await self._add_rule("test-pkg")
        response = await app_client.get("/npm/test-pkg/-/test-pkg-1.0.0.tgz")
        assert response.status_code == 403

    async def test_glob_pattern_blocks(self, app_client):
        await app_client.put(
            "/npm/evil-thing", json=npm_publish_body(name="evil-thing"), headers=auth(app_client)
        )
        await self._add_rule("evil-*")
        assert (await app_client.get("/npm/evil-thing")).status_code == 403

    async def test_block_prevents_publishing(self, app_client):
        await self._add_rule("banned-pkg")
        response = await app_client.put(
            "/npm/banned-pkg", json=npm_publish_body(name="banned-pkg"), headers=auth(app_client)
        )
        assert response.status_code == 403

    async def test_pypi_block(self, app_client):
        data, files = TestPypiPublishFlow()._upload()
        await app_client.post(
            "/pypi/legacy/", data=data, files=files, headers=basic_auth(app_client)
        )
        await self._add_rule("my-package", ecosystem=Ecosystem.pypi)
        assert (await app_client.get("/pypi/simple/my-package/")).status_code == 403

    async def test_ecosystem_scoped_rule_does_not_leak(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        # A PyPI-scoped rule must not block the npm package of the same name.
        await self._add_rule("test-pkg", ecosystem=Ecosystem.pypi)
        assert (await app_client.get("/npm/test-pkg")).status_code == 200

    async def test_allow_rule_never_overrides_a_block(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        await self._add_rule("test-pkg", action=RuleAction.block)
        await self._add_rule("test-pkg", action=RuleAction.allow)
        # The block list is always enforced.
        assert (await app_client.get("/npm/test-pkg")).status_code == 403


class TestAllowlistMode:
    async def _set_allowlist(self, enabled):
        async with db_module.session_scope() as session:
            existing = await session.get(Setting, KEY_ALLOWLIST_MODE)
            if existing:
                existing.value = {"enabled": enabled}
            else:
                session.add(Setting(key=KEY_ALLOWLIST_MODE, value={"enabled": enabled}))
        await invalidate_policy_cache()

    async def test_allowlist_mode_denies_unlisted(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        await self._set_allowlist(True)
        assert (await app_client.get("/npm/test-pkg")).status_code == 403

    async def test_allowlist_mode_permits_listed(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        await self._set_allowlist(True)
        async with db_module.session_scope() as session:
            session.add(PackageRule(pattern="test-pkg", action=RuleAction.allow))
        await invalidate_policy_cache()
        assert (await app_client.get("/npm/test-pkg")).status_code == 200


class TestCvePolicy:
    async def _set_policy(self, **kwargs):
        payload = {
            "enabled": True,
            "min_score": 7.0,
            "max_score": 10.0,
            "block_unscored": False,
            "require_fix_available": False,
            **kwargs,
        }
        async with db_module.session_scope() as session:
            existing = await session.get(Setting, KEY_CVE_POLICY)
            if existing:
                existing.value = payload
            else:
                session.add(Setting(key=KEY_CVE_POLICY, value=payload))
        await invalidate_policy_cache()

    async def _set_version_score(self, score):
        from sqlalchemy import update

        from app.models import PackageVersion

        async with db_module.session_scope() as session:
            from datetime import UTC, datetime

            await session.execute(
                update(PackageVersion).values(max_cvss=score, scanned_at=datetime.now(UTC))
            )

    async def test_version_in_blocked_range_is_hidden(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        await self._set_policy(min_score=7.0, max_score=10.0)
        await self._set_version_score(9.8)
        response = await app_client.get("/npm/test-pkg")
        # Every version is blocked, so the whole package is refused.
        assert response.status_code == 403

    async def test_version_below_range_is_served(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        await self._set_policy(min_score=9.0, max_score=10.0)
        await self._set_version_score(5.0)
        assert (await app_client.get("/npm/test-pkg")).status_code == 200

    async def test_range_upper_bound_is_respected(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        # Block only medium severity; a critical package passes this rule.
        await self._set_policy(min_score=4.0, max_score=6.9)
        await self._set_version_score(9.8)
        assert (await app_client.get("/npm/test-pkg")).status_code == 200

    async def test_blocked_version_tarball_is_403(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        await self._set_policy(min_score=7.0, max_score=10.0)
        await self._set_version_score(9.8)
        assert (await app_client.get("/npm/test-pkg/-/test-pkg-1.0.0.tgz")).status_code == 403

    async def test_disabled_policy_serves_everything(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        await self._set_policy(enabled=False)
        await self._set_version_score(10.0)
        assert (await app_client.get("/npm/test-pkg")).status_code == 200

    async def _score_one_version(self, version, score):
        from datetime import UTC, datetime

        from sqlalchemy import update

        from app.models import PackageVersion

        async with db_module.session_scope() as session:
            await session.execute(
                update(PackageVersion)
                .where(PackageVersion.version == version)
                .values(max_cvss=score, scanned_at=datetime.now(UTC))
            )

    async def test_only_affected_versions_are_hidden(self, app_client):
        # The realistic case: one bad version among several good ones.
        for version in ("1.0.0", "1.0.1", "2.0.0"):
            await app_client.put(
                "/npm/test-pkg",
                json=npm_publish_body(version=version),
                headers=auth(app_client),
            )
        await self._set_policy(min_score=9.0, max_score=10.0)
        await self._score_one_version("1.0.1", 9.8)
        await self._score_one_version("1.0.0", 2.0)
        await self._score_one_version("2.0.0", None)

        doc = (await app_client.get("/npm/test-pkg")).json()
        assert "1.0.1" not in doc["versions"], "the 9.8 version must be filtered out"
        assert "1.0.0" in doc["versions"], "a 2.0 version is below the block range"
        assert "2.0.0" in doc["versions"], "an unaffected version stays"

    async def test_latest_is_repointed_when_it_is_blocked(self, app_client):
        for version in ("1.0.0", "2.0.0"):
            await app_client.put(
                "/npm/test-pkg",
                json=npm_publish_body(version=version),
                headers=auth(app_client),
            )
        await self._set_policy(min_score=9.0, max_score=10.0)
        await self._score_one_version("2.0.0", 9.9)
        await self._score_one_version("1.0.0", 1.0)

        doc = (await app_client.get("/npm/test-pkg")).json()
        # `latest` pointed at 2.0.0; with it blocked, clients must still get a
        # resolvable tag rather than a dangling one.
        assert doc["dist-tags"]["latest"] == "1.0.0"
        assert doc["dist-tags"]["latest"] in doc["versions"]


class TestAuditLog:
    async def test_login_is_audited(self, app_client):
        await app_client.post(
            "/api/auth/login", json={"username": "admin", "password": "admin-password-1234"}
        )
        response = await app_client.get(
            "/api/admin/audit?action=auth.login", headers=auth(app_client, "admin")
        )
        assert response.status_code == 200
        actions = [e["action"] for e in response.json()["entries"]]
        assert "auth.login.success" in actions

    async def test_failed_login_is_audited(self, app_client):
        await app_client.post(
            "/api/auth/login", json={"username": "admin", "password": "nope"}
        )
        response = await app_client.get(
            "/api/admin/audit?action=auth.login", headers=auth(app_client, "admin")
        )
        entries = response.json()["entries"]
        assert any(e["action"] == "auth.login.failed" and not e["success"] for e in entries)

    async def test_publish_is_audited(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        response = await app_client.get(
            "/api/admin/audit?action=registry.publish", headers=auth(app_client, "admin")
        )
        entries = response.json()["entries"]
        assert any(e["target_id"] == "npm:test-pkg" for e in entries)

    async def test_admin_action_is_audited(self, app_client):
        await app_client.post(
            "/api/admin/rules",
            json={"pattern": "bad-*", "action": "block", "reason": "test"},
            headers=auth(app_client, "admin"),
        )
        response = await app_client.get(
            "/api/admin/audit?action=admin.rule", headers=auth(app_client, "admin")
        )
        assert any(e["action"] == "admin.rule.created" for e in response.json()["entries"])


class TestAdminApi:
    async def test_stats_overview(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        response = await app_client.get(
            "/api/admin/stats/overview", headers=auth(app_client, "admin")
        )
        assert response.status_code == 200
        body = response.json()
        assert body["packages"]["npm"] == 1
        assert body["users"]["total"] == 3

    async def test_storage_stats(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        response = await app_client.get(
            "/api/admin/stats/storage", headers=auth(app_client, "admin")
        )
        assert response.status_code == 200
        assert response.json()["blobs"]["count"] == 1

    async def test_rule_crud(self, app_client):
        created = await app_client.post(
            "/api/admin/rules",
            json={"pattern": "evil-*", "action": "block", "reason": "malware"},
            headers=auth(app_client, "admin"),
        )
        assert created.status_code == 201
        rule_id = created.json()["id"]

        listed = await app_client.get("/api/admin/rules", headers=auth(app_client, "admin"))
        assert any(r["id"] == rule_id for r in listed.json()["rules"])

        deleted = await app_client.delete(
            f"/api/admin/rules/{rule_id}", headers=auth(app_client, "admin")
        )
        assert deleted.status_code == 200

    async def test_rule_dry_run(self, app_client):
        await app_client.post(
            "/api/admin/rules",
            json={"pattern": "evil-*", "action": "block", "reason": "malware"},
            headers=auth(app_client, "admin"),
        )
        response = await app_client.post(
            "/api/admin/rules/test?ecosystem=npm&name=evil-thing",
            headers=auth(app_client, "admin"),
        )
        assert response.status_code == 200
        assert response.json()["allowed"] is False
        assert response.json()["source"] == "block_rule"

    async def test_upstream_crud(self, app_client):
        created = await app_client.post(
            "/api/admin/upstreams",
            json={
                "name": "npmjs",
                "ecosystem": "npm",
                "kind": "npm",
                "url": "https://registry.npmjs.org",
                "tier": 1,
                "credential": "super-secret-token",
            },
            headers=auth(app_client, "admin"),
        )
        assert created.status_code == 201
        body = created.json()
        assert body["has_credential"] is True
        # The credential itself must never be returned.
        assert "super-secret-token" not in created.text

    async def test_cve_policy_roundtrip(self, app_client):
        response = await app_client.put(
            "/api/admin/settings/cve-policy",
            json={"enabled": True, "min_score": 7.0, "max_score": 10.0},
            headers=auth(app_client, "admin"),
        )
        assert response.status_code == 200
        settings_response = await app_client.get(
            "/api/admin/settings", headers=auth(app_client, "admin")
        )
        assert settings_response.json()["cve_policy"]["enabled"] is True

    async def test_cve_policy_rejects_inverted_range(self, app_client):
        response = await app_client.put(
            "/api/admin/settings/cve-policy",
            json={"enabled": True, "min_score": 9.0, "max_score": 2.0},
            headers=auth(app_client, "admin"),
        )
        assert response.status_code == 400

    async def test_cannot_remove_last_admin(self, app_client):
        users = (await app_client.get("/api/admin/users", headers=auth(app_client, "admin"))).json()
        admin_id = next(u["id"] for u in users["users"] if u["username"] == "admin")
        response = await app_client.patch(
            f"/api/admin/users/{admin_id}",
            json={"is_admin": False},
            headers=auth(app_client, "admin"),
        )
        assert response.status_code == 400


class TestTokenManagement:
    async def test_create_and_use_token(self, app_client):
        await app_client.post(
            "/api/auth/login", json={"username": "publisher", "password": "publisher-password-1"}
        )
        created = await app_client.post(
            "/api/auth/tokens", json={"name": "ci", "scopes": ["read", "publish"]}
        )
        assert created.status_code == 201
        token = created.json()["token"]

        response = await app_client.get(
            "/npm/-/whoami", headers={"authorization": f"Bearer {token}"}
        )
        assert response.json() == {"username": "publisher"}

    async def test_non_admin_cannot_mint_admin_token(self, app_client):
        await app_client.post(
            "/api/auth/login", json={"username": "publisher", "password": "publisher-password-1"}
        )
        response = await app_client.post(
            "/api/auth/tokens", json={"name": "escalate", "scopes": ["admin"]}
        )
        assert response.status_code == 403

    async def test_reader_cannot_mint_publish_token(self, app_client):
        await app_client.post(
            "/api/auth/login", json={"username": "reader", "password": "reader-password-12345"}
        )
        response = await app_client.post(
            "/api/auth/tokens", json={"name": "sneaky", "scopes": ["publish"]}
        )
        assert response.status_code == 403

    async def test_revoked_token_stops_working(self, app_client):
        await app_client.post(
            "/api/auth/login", json={"username": "publisher", "password": "publisher-password-1"}
        )
        created = await app_client.post("/api/auth/tokens", json={"name": "temp"})
        token = created.json()["token"]
        await app_client.delete(f"/api/auth/tokens/{created.json()['id']}")

        response = await app_client.get(
            "/npm/-/whoami", headers={"authorization": f"Bearer {token}"}
        )
        assert response.status_code == 401


class TestClientConfig:
    async def test_config_uses_public_url(self, app_client):
        response = await app_client.get("/api/client-config", headers=auth(app_client))
        assert response.status_code == 200
        body = response.json()
        assert body["npm"]["registry"] == "http://registry.test/npm/"
        assert body["pip"]["index_url"] == "http://registry.test/pypi/simple/"
        assert body["twine"]["repository_url"] == "http://registry.test/pypi/legacy/"
        assert "registry.test/npm/:_authToken" in body["npm"]["npmrc"]

    async def test_cargo_stanza_is_client_ready(self, app_client):
        """The Client setup page renders these keys directly, so the contract
        matters as much as the values. Both the `sparse+` prefix and the
        trailing slash are load-bearing: without the prefix cargo tries to git
        clone the index, and without the slash it joins the shard paths against
        the parent segment and every crate 404s."""
        body = (
            await app_client.get("/api/client-config", headers=auth(app_client))
        ).json()
        cargo = body["cargo"]
        assert cargo["registry"] == "sparse+http://registry.test/cargo/index/"

        assert set(cargo) >= {"registry", "config_toml", "config_path", "commands", "note"}

        # It has to be a source replacement, not a plain [registries] entry --
        # only replacement redirects crates.io deps without editing Cargo.toml.
        assert "[source.crates-io]" in cargo["config_toml"]
        assert 'replace-with = "minireg"' in cargo["config_toml"]
        assert cargo["registry"] in cargo["config_toml"]

        # No token belongs in it: reads are anonymous and cargo only sends
        # credentials to an index declaring auth-required.
        assert "token" not in cargo["config_toml"].lower()


class TestUserSearch:
    async def test_search_finds_published_package(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        response = await app_client.get("/api/search?q=test", headers=auth(app_client, "reader"))
        assert response.status_code == 200
        assert any(r["name"] == "test-pkg" for r in response.json()["results"])

    async def test_search_requires_login(self, app_client):
        assert (await app_client.get("/api/search?q=test")).status_code == 401

    async def test_blocked_package_hidden_from_regular_users(self, app_client):
        await app_client.put("/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client))
        async with db_module.session_scope() as session:
            session.add(PackageRule(pattern="test-pkg", action=RuleAction.block, reason="nope"))
        await invalidate_policy_cache()

        response = await app_client.get("/api/search?q=test", headers=auth(app_client, "reader"))
        assert not any(r["name"] == "test-pkg" for r in response.json()["results"])

        # Admins still see it, flagged as blocked.
        response = await app_client.get("/api/search?q=test", headers=auth(app_client, "admin"))
        hit = next(r for r in response.json()["results"] if r["name"] == "test-pkg")
        assert hit["blocked"] is True
