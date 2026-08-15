"""CLI backend: device-authorization login, audit, and distribution.

Also covers the CLI's own lockfile parsers, which are pure functions in the
shipped script.
"""

import base64
import importlib.util
import json
import pathlib
import sys
from datetime import UTC, datetime, timedelta

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import db as db_module
from app.core.security import generate_token, hash_password
from app.models import ApiToken, DeviceAuthorization, Ecosystem, PackageRule, RuleAction, User
from app.services.policy import invalidate_policy_cache
from app.services.storage import BlobStore, set_store

# Import the shipped CLI as a module so its parsers are tested as-published.
CLI_PATH = pathlib.Path(__file__).resolve().parents[2] / "cli" / "minireg.py"
_spec = importlib.util.spec_from_file_location("minireg_cli", CLI_PATH)
cli = importlib.util.module_from_spec(_spec)
sys.modules["minireg_cli"] = cli
_spec.loader.exec_module(cli)


@pytest_asyncio.fixture
async def client(tmp_path):
    from app.main import app

    db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'cli.db'}")
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
        reader = User(
            username="reader",
            password_hash=hash_password("reader-password-1234"),
            is_admin=False,
            can_publish=False,
        )
        session.add_all([admin, reader])
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
        c.admin_token = full  # type: ignore[attr-defined]
        yield c

    await db_module.dispose_engine()
    set_store(None)  # type: ignore[arg-type]


def admin_auth(client):
    return {"authorization": f"Bearer {client.admin_token}"}


async def login_session(client, username="admin", password="admin-password-1234"):
    return await client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )


# --------------------------------------------------------------------------- #
class TestDeviceFlow:
    async def test_start_returns_codes_and_urls(self, client):
        response = await client.post(
            "/api/cli/auth/start", json={"hostname": "laptop", "platform": "Linux"}
        )
        assert response.status_code == 201
        body = response.json()
        assert len(body["device_code"]) > 20
        assert len(body["user_code"]) == 9  # XXXX-XXXX
        assert body["verification_url"].endswith("/cli-login")
        assert body["user_code"] in body["verification_url_complete"]
        assert body["interval"] >= 1

    async def test_start_needs_no_authentication(self, client):
        # The whole point is that the CLI has no credential yet.
        assert (await client.post("/api/cli/auth/start", json={})).status_code == 201

    async def test_poll_is_pending_before_approval(self, client):
        start = (await client.post("/api/cli/auth/start", json={})).json()
        response = await client.post(
            "/api/cli/auth/poll", json={"device_code": start["device_code"]}
        )
        assert response.status_code == 200
        assert response.json()["status"] == "authorization_pending"

    async def test_unknown_device_code_is_rejected(self, client):
        response = await client.post("/api/cli/auth/poll", json={"device_code": "nope"})
        assert response.status_code == 400
        assert response.json()["detail"] == "expired_token"

    async def test_full_approval_hands_over_a_working_token(self, client):
        start = (await client.post("/api/cli/auth/start", json={"hostname": "laptop"})).json()

        await login_session(client)
        pending = await client.get(f"/api/cli/auth/pending/{start['user_code']}")
        assert pending.status_code == 200
        assert pending.json()["hostname"] == "laptop"

        approve = await client.post(
            "/api/cli/auth/approve",
            json={"user_code": start["user_code"], "approve": True, "scopes": ["read"]},
        )
        assert approve.status_code == 200
        assert approve.json()["approved"] is True

        polled = await client.post(
            "/api/cli/auth/poll", json={"device_code": start["device_code"]}
        )
        assert polled.status_code == 200
        body = polled.json()
        assert body["status"] == "complete"
        assert body["username"] == "admin"

        # The handed-over token must actually authenticate.
        whoami = await client.get(
            "/npm/-/whoami", headers={"authorization": f"Bearer {body['token']}"}
        )
        assert whoami.json() == {"username": "admin"}

    async def test_token_is_handed_over_exactly_once(self, client):
        start = (await client.post("/api/cli/auth/start", json={})).json()
        await login_session(client)
        await client.post("/api/cli/auth/approve", json={"user_code": start["user_code"]})

        first = await client.post(
            "/api/cli/auth/poll", json={"device_code": start["device_code"]}
        )
        assert first.json()["status"] == "complete"

        second = await client.post(
            "/api/cli/auth/poll", json={"device_code": start["device_code"]}
        )
        assert second.status_code == 400

    async def test_user_code_is_accepted_case_and_dash_insensitively(self, client):
        start = (await client.post("/api/cli/auth/start", json={})).json()
        mangled = start["user_code"].replace("-", "").lower()
        await login_session(client)
        approve = await client.post("/api/cli/auth/approve", json={"user_code": mangled})
        assert approve.status_code == 200

    async def test_denial_stops_the_flow(self, client):
        start = (await client.post("/api/cli/auth/start", json={})).json()
        await login_session(client)
        await client.post(
            "/api/cli/auth/approve", json={"user_code": start["user_code"], "approve": False}
        )
        polled = await client.post(
            "/api/cli/auth/poll", json={"device_code": start["device_code"]}
        )
        assert polled.status_code == 403
        assert polled.json()["detail"] == "access_denied"

    async def test_approval_requires_a_logged_in_person(self, client):
        start = (await client.post("/api/cli/auth/start", json={})).json()
        response = await client.post(
            "/api/cli/auth/approve", json={"user_code": start["user_code"]}
        )
        assert response.status_code == 401

    async def test_expired_code_cannot_be_approved(self, client):
        start = (await client.post("/api/cli/auth/start", json={})).json()
        async with db_module.session_scope() as session:
            from sqlalchemy import update

            await session.execute(
                update(DeviceAuthorization).values(
                    expires_at=datetime.now(UTC) - timedelta(minutes=1)
                )
            )
        await login_session(client)
        response = await client.post(
            "/api/cli/auth/approve", json={"user_code": start["user_code"]}
        )
        assert response.status_code == 404

    async def test_double_approval_is_rejected(self, client):
        start = (await client.post("/api/cli/auth/start", json={})).json()
        await login_session(client)
        await client.post("/api/cli/auth/approve", json={"user_code": start["user_code"]})
        again = await client.post(
            "/api/cli/auth/approve", json={"user_code": start["user_code"]}
        )
        assert again.status_code == 409

    async def test_token_never_exceeds_the_approvers_authority(self, client):
        start = (await client.post("/api/cli/auth/start", json={})).json()
        # A read-only user approving with admin+publish requested.
        await login_session(client, "reader", "reader-password-1234")
        approve = await client.post(
            "/api/cli/auth/approve",
            json={"user_code": start["user_code"], "scopes": ["read", "publish", "admin"]},
        )
        assert approve.json()["scopes"] == ["read"]

    async def test_approval_is_audited(self, client):
        start = (await client.post("/api/cli/auth/start", json={"hostname": "laptop"})).json()
        await login_session(client)
        await client.post("/api/cli/auth/approve", json={"user_code": start["user_code"]})

        entries = (
            await client.get("/api/admin/audit?action=auth.cli", headers=admin_auth(client))
        ).json()["entries"]
        assert any(e["action"] == "auth.cli.approved" for e in entries)
        approved = next(e for e in entries if e["action"] == "auth.cli.approved")
        assert approved["detail"]["hostname"] == "laptop"

    async def test_device_code_is_not_stored_in_plaintext(self, client):
        start = (await client.post("/api/cli/auth/start", json={})).json()
        async with db_module.session_scope() as session:
            from sqlalchemy import select

            record = (await session.execute(select(DeviceAuthorization))).scalar_one()
            assert record.device_code_hash != start["device_code"]
            assert len(record.device_code_hash) == 64


# --------------------------------------------------------------------------- #
class TestAuditEndpoint:
    def _publish(self, name, version):
        tarball = f"{name}-{version}".encode()
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

    async def test_requires_authentication(self, client):
        response = await client.post(
            "/api/cli/audit", json={"ecosystem": "npm", "packages": [{"name": "x", "version": "1"}]}
        )
        assert response.status_code == 401

    async def test_empty_request_is_fine(self, client):
        response = await client.post(
            "/api/cli/audit", json={"ecosystem": "npm", "packages": []}, headers=admin_auth(client)
        )
        assert response.status_code == 200
        assert response.json()["findings"] == []

    async def test_clean_project_has_no_findings(self, client):
        await client.put("/npm/safe", json=self._publish("safe", "1.0.0"), headers=admin_auth(client))
        response = await client.post(
            "/api/cli/audit",
            json={
                "ecosystem": "npm",
                "packages": [{"name": "safe", "version": "1.0.0"}],
                "scan_unknown": False,
            },
            headers=admin_auth(client),
        )
        assert response.json()["findings"] == []
        assert response.json()["checked"] == 1

    async def test_blocked_package_is_reported(self, client):
        await client.put(
            "/npm/bad", json=self._publish("bad", "1.0.0"), headers=admin_auth(client)
        )
        async with db_module.session_scope() as session:
            session.add(
                PackageRule(
                    ecosystem=Ecosystem.npm,
                    pattern="bad",
                    action=RuleAction.block,
                    reason="not allowed here",
                )
            )
        await invalidate_policy_cache()

        response = await client.post(
            "/api/cli/audit",
            json={
                "ecosystem": "npm",
                "packages": [{"name": "bad", "version": "1.0.0"}],
                "scan_unknown": False,
            },
            headers=admin_auth(client),
        )
        findings = response.json()["findings"]
        assert len(findings) == 1
        assert findings[0]["blocked"] is True
        assert findings[0]["block_reason"] == "not allowed here"

    async def test_version_scoped_block_only_hits_that_version(self, client):
        for version in ("1.0.0", "2.0.0"):
            await client.put(
                "/npm/lib", json=self._publish("lib", version), headers=admin_auth(client)
            )
        async with db_module.session_scope() as session:
            session.add(
                PackageRule(
                    ecosystem=Ecosystem.npm,
                    pattern="lib",
                    action=RuleAction.block,
                    version_spec="<2.0.0",
                    reason="upgrade to 2.x",
                )
            )
        await invalidate_policy_cache()

        response = await client.post(
            "/api/cli/audit",
            json={
                "ecosystem": "npm",
                "packages": [
                    {"name": "lib", "version": "1.0.0"},
                    {"name": "lib", "version": "2.0.0"},
                ],
                "scan_unknown": False,
            },
            headers=admin_auth(client),
        )
        findings = {f["version"]: f for f in response.json()["findings"]}
        assert findings["1.0.0"]["blocked"] is True
        assert "2.0.0" not in findings

    async def test_unknown_packages_are_reported_as_unscanned(self, client):
        response = await client.post(
            "/api/cli/audit",
            json={
                "ecosystem": "npm",
                "packages": [{"name": "never-seen", "version": "9.9.9"}],
                "scan_unknown": False,
            },
            headers=admin_auth(client),
        )
        body = response.json()
        assert body["unscanned_total"] == 1
        assert body["unscanned"][0]["name"] == "never-seen"

    async def test_cves_are_reported_with_scores(self, client):
        await client.put(
            "/npm/vuln", json=self._publish("vuln", "1.0.0"), headers=admin_auth(client)
        )
        async with db_module.session_scope() as session:
            from sqlalchemy import select, update

            from app.models import PackageVersion, PackageVulnerability, Vulnerability

            session.add(
                Vulnerability(
                    id="GHSA-test-0001",
                    cve_id="CVE-2024-00001",
                    ecosystem=Ecosystem.npm,
                    summary="Test issue",
                    cvss_score=9.8,
                    severity_label="critical",
                )
            )
            await session.flush()
            version = (await session.execute(select(PackageVersion))).scalars().first()
            session.add(
                PackageVulnerability(
                    version_id=version.id,
                    vulnerability_id="GHSA-test-0001",
                    fixed_version="1.0.1",
                )
            )
            await session.execute(
                update(PackageVersion)
                .where(PackageVersion.id == version.id)
                .values(max_cvss=9.8, scanned_at=datetime.now(UTC))
            )

        response = await client.post(
            "/api/cli/audit",
            json={
                "ecosystem": "npm",
                "packages": [{"name": "vuln", "version": "1.0.0"}],
                "scan_unknown": False,
            },
            headers=admin_auth(client),
        )
        finding = response.json()["findings"][0]
        assert finding["max_cvss"] == 9.8
        cve = finding["cves"][0]
        assert cve["cve_id"] == "CVE-2024-00001"
        assert cve["severity"] == "critical"
        assert cve["fixed_version"] == "1.0.1"


# --------------------------------------------------------------------------- #
class TestDistribution:
    async def test_download_serves_the_cli(self, client):
        response = await client.get("/api/cli/download")
        assert response.status_code == 200
        assert "minireg" in response.headers["content-disposition"]
        assert response.text.startswith("#!/usr/bin/env python3")
        assert "def cmd_audit" in response.text

    async def test_install_script_bakes_in_the_registry_url(self, client):
        response = await client.get("/api/cli/install.sh")
        assert response.status_code == 200
        assert 'REGISTRY="http://registry.test"' in response.text
        assert "/api/cli/download" in response.text

    async def test_downloaded_cli_is_valid_python(self, client):
        import ast

        source = (await client.get("/api/cli/download")).text
        ast.parse(source)  # must not raise


# --------------------------------------------------------------------------- #
class TestCliLockfileParsers:
    """The parsers ship inside the CLI, so they are tested from the real file."""

    def test_package_lock_v3(self, tmp_path):
        path = tmp_path / "package-lock.json"
        path.write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "myapp", "version": "1.0.0"},
                        "node_modules/lodash": {"version": "4.17.21"},
                        "node_modules/express": {"version": "4.18.2"},
                    },
                }
            )
        )
        found = {(p["name"], p["version"]) for p in cli.parse_package_lock(path)}
        assert ("lodash", "4.17.21") in found
        assert ("express", "4.18.2") in found
        # The project itself is not a dependency.
        assert not any(n == "myapp" for n, _ in found)

    def test_package_lock_v1(self, tmp_path):
        path = tmp_path / "package-lock.json"
        path.write_text(
            json.dumps(
                {
                    "lockfileVersion": 1,
                    "dependencies": {
                        "lodash": {"version": "4.17.20"},
                        "express": {
                            "version": "4.17.1",
                            "dependencies": {"debug": {"version": "2.6.9"}},
                        },
                    },
                }
            )
        )
        found = {(p["name"], p["version"]) for p in cli.parse_package_lock(path)}
        assert found == {("lodash", "4.17.20"), ("express", "4.17.1"), ("debug", "2.6.9")}

    def test_package_lock_skips_symlinked_workspaces(self, tmp_path):
        path = tmp_path / "package-lock.json"
        path.write_text(
            json.dumps(
                {
                    "packages": {
                        "node_modules/real": {"version": "1.0.0"},
                        "node_modules/linked": {"link": True, "resolved": "packages/linked"},
                    }
                }
            )
        )
        found = {p["name"] for p in cli.parse_package_lock(path)}
        assert found == {"real"}

    def test_requirements_txt_pinned_only(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text(
            "# comment\n"
            "requests==2.31.0\n"
            "django>=4.0\n"          # a range has no single version to audit
            "flask==3.0.0  # inline\n"
            "urllib3[socks]==2.0.7\n"
            "-r other.txt\n"
            "\n"
        )
        found = {(p["name"], p["version"]) for p in cli.parse_requirements(path)}
        assert found == {
            ("requests", "2.31.0"),
            ("flask", "3.0.0"),
            ("urllib3", "2.0.7"),
        }

    def test_poetry_lock(self, tmp_path):
        path = tmp_path / "poetry.lock"
        path.write_text(
            '[[package]]\nname = "requests"\nversion = "2.31.0"\n\n'
            '[[package]]\nname = "urllib3"\nversion = "2.0.7"\n'
        )
        found = {(p["name"], p["version"]) for p in cli.parse_poetry_lock(path)}
        assert found == {("requests", "2.31.0"), ("urllib3", "2.0.7")}

    def test_pipfile_lock(self, tmp_path):
        path = tmp_path / "Pipfile.lock"
        path.write_text(
            json.dumps(
                {
                    "default": {"requests": {"version": "==2.31.0"}},
                    "develop": {"pytest": {"version": "==8.0.0"}},
                }
            )
        )
        found = {(p["name"], p["version"]) for p in cli.parse_pipfile_lock(path)}
        assert found == {("requests", "2.31.0"), ("pytest", "8.0.0")}

    def test_discover_finds_multiple_ecosystems(self, tmp_path):
        (tmp_path / "package-lock.json").write_text(
            json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.21"}}})
        )
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        found = cli.discover(tmp_path)
        ecosystems = {ecosystem for _path, ecosystem, _pkgs in found}
        assert ecosystems == {"npm", "pypi"}

    def test_malformed_lockfile_yields_nothing_rather_than_raising(self, tmp_path):
        path = tmp_path / "package-lock.json"
        path.write_text("{not json")
        assert cli.parse_package_lock(path) == []


class TestCliConfigHandling:
    def test_managed_block_is_replaced_not_duplicated(self, tmp_path):
        path = tmp_path / ".npmrc"
        path.write_text("existing=setting\n")

        cli._upsert_lines(path, ["registry=http://a"], "minireg")
        cli._upsert_lines(path, ["registry=http://b"], "minireg")

        text = path.read_text()
        assert text.count(">>> minireg >>>") == 1
        assert "registry=http://b" in text
        assert "registry=http://a" not in text
        # Anything the user already had must survive.
        assert "existing=setting" in text

    def test_env_overrides_the_config_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        cli.save_config({"registry": "http://from-file", "token": "file-token"})

        monkeypatch.setenv("MINIREG_TOKEN", "env-token")
        monkeypatch.setenv("MINIREG_URL", "http://from-env")
        config = cli.load_config()
        assert config["token"] == "env-token"
        assert config["registry"] == "http://from-env"

    def test_config_file_is_written_private(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        cli.save_config({"token": "secret"})
        mode = cli.config_path().stat().st_mode & 0o777
        assert mode == 0o600, f"config must not be world readable, got {oct(mode)}"


class TestRequestedScopes:
    """`minireg login --scopes` is advisory: it pre-selects on the approval
    screen, and the server still caps what can actually be granted."""

    async def test_requested_scopes_reach_the_approval_screen(self, client):
        start = (
            await client.post(
                "/api/cli/auth/start",
                json={"hostname": "laptop", "scopes": ["read", "publish"]},
            )
        ).json()
        await login_session(client)

        pending = await client.get(f"/api/cli/auth/pending/{start['user_code']}")
        assert pending.json()["requested_scopes"] == ["publish", "read"]

    async def test_defaults_to_read_when_unspecified(self, client):
        start = (await client.post("/api/cli/auth/start", json={})).json()
        await login_session(client)
        pending = await client.get(f"/api/cli/auth/pending/{start['user_code']}")
        assert pending.json()["requested_scopes"] == ["read"]

    async def test_unknown_scopes_are_discarded(self, client):
        start = (
            await client.post(
                "/api/cli/auth/start", json={"scopes": ["read", "root", "sudo"]}
            )
        ).json()
        await login_session(client)
        pending = await client.get(f"/api/cli/auth/pending/{start['user_code']}")
        assert pending.json()["requested_scopes"] == ["read"]

    async def test_requesting_more_does_not_grant_more(self, client):
        # A read-only user approving a request that asked for admin still gets
        # a read token: the request is advisory, the approver's authority is not.
        start = (
            await client.post(
                "/api/cli/auth/start", json={"scopes": ["read", "publish", "admin"]}
            )
        ).json()
        await login_session(client, "reader", "reader-password-1234")
        approved = await client.post(
            "/api/cli/auth/approve",
            json={"user_code": start["user_code"], "scopes": ["read", "publish", "admin"]},
        )
        assert approved.json()["scopes"] == ["read"]
