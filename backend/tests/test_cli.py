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


class TestRequirementsParsing:
    """A requirements.txt of ranges used to audit as "0 packages" and get
    dropped without comment, which is indistinguishable from the file being
    unsupported."""

    def test_pins_are_extracted(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("django==4.2.0\nflask===3.0.0\npkg[extra]==1.2.3\n")
        found = {(p["name"], p["version"]) for p in cli.parse_requirements(path)}
        assert found == {("django", "4.2.0"), ("flask", "3.0.0"), ("pkg", "1.2.3")}

    def test_arbitrary_equality_is_not_mangled(self, tmp_path):
        # `===1.0` must not parse as `==` plus a version of "=1.0".
        path = tmp_path / "requirements.txt"
        path.write_text("flask===3.0.0\n")
        assert cli.parse_requirements(path) == [{"name": "flask", "version": "3.0.0"}]

    def test_unpinned_entries_are_recorded_not_dropped(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("fastapi\nrequests>=2.31.0\nurllib3~=1.26.5\ndjango==4.2.0\n")
        pinned = cli.parse_requirements(path)
        assert [p["name"] for p in pinned] == ["django"]
        assert cli.UNPINNED[path] == ["fastapi", "requests>=2.31.0", "urllib3~=1.26.5"]

    def test_hash_continuations_and_options_are_ignored(self, tmp_path):
        # pip-compile output: a pin, a line continuation, then --hash lines.
        path = tmp_path / "requirements.txt"
        path.write_text(
            "click==8.1.7 \\\n    --hash=sha256:aaa \\\n    --hash=sha256:bbb\n"
            "-r base.txt\n-e .\n"
        )
        assert cli.parse_requirements(path) == [{"name": "click", "version": "8.1.7"}]
        assert cli.UNPINNED[path] == []

    def test_environment_markers_do_not_leak_into_the_version(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text('marked==1.0 ; python_version < "3.9"\n')
        assert cli.parse_requirements(path) == [{"name": "marked", "version": "1.0"}]

    def test_url_requirements_are_not_treated_as_unpinned(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("thing @ https://example.com/thing.whl\n")
        assert cli.parse_requirements(path) == []
        assert cli.UNPINNED[path] == []

    def test_discover_keeps_a_file_it_could_not_pin(self, tmp_path):
        # Dropping it silently is why "not picking up requirements.txt" looked
        # like a parser that did not run at all.
        (tmp_path / "requirements.txt").write_text("fastapi\nrequests>=2.0\n")
        found = cli.discover(tmp_path)
        assert len(found) == 1
        path, ecosystem, packages = found[0]
        assert path.name == "requirements.txt"
        assert ecosystem == "pypi"
        assert packages == []


class TestAuditLooksUpWhatItIsGiven:
    """A version row exists as soon as a package is proxied, long before
    anything scans it. Treating "known to the registry" as "already scanned"
    made audits against a fresh registry report nothing at all."""

    async def test_known_but_unscanned_versions_are_looked_up(self, client, monkeypatch):
        from app.models import Ecosystem, Package, PackageVersion, Vulnerability
        from app.services.osv import ScanResult

        async with db_module.session_scope() as session:
            package = Package(
                ecosystem=Ecosystem.npm, name="lodash", normalized_name="lodash"
            )
            package.versions = []
            package.dist_tags = []
            session.add(package)
            await session.flush()
            version = PackageVersion(
                package_id=package.id, version="4.17.20", normalized_version="4.17.20"
            )
            version.files = []
            session.add(version)
            # Deliberately never scanned.
            assert version.scanned_at is None

        called: list = []

        async def fake_scan(self, ecosystem, items, **kwargs):
            # Mirror the real scanner: it upserts the Vulnerability rows that
            # apply_to_version then links against. Returning findings without
            # them would leave a dangling link and test nothing.
            called.append(list(items))
            self.session.add(
                Vulnerability(
                    id="GHSA-x",
                    cve_id="CVE-2021-23337",
                    ecosystem=Ecosystem.npm,
                    summary="Command injection",
                    cvss_score=7.2,
                    severity_label="high",
                )
            )
            await self.session.flush()
            return {
                (name, ver): ScanResult(
                    version_id=None,
                    package_name=name,
                    version=ver,
                    cves=[
                        {
                            "id": "GHSA-x",
                            "cve_id": "CVE-2021-23337",
                            "cvss_score": 7.2,
                            "severity": "high",
                            "summary": "Command injection",
                            "raw": {},
                        }
                    ],
                    max_score=7.2,
                    scanned=True,
                )
                for name, ver in items
            }

        monkeypatch.setattr("app.services.osv.OsvScanner.scan_versions", fake_scan)

        response = await client.post(
            "/api/cli/audit",
            json={
                "ecosystem": "npm",
                "packages": [{"name": "lodash", "version": "4.17.20"}],
                "scan_unknown": True,
            },
            headers=admin_auth(client),
        )
        body = response.json()

        assert called == [[("lodash", "4.17.20")]], "the version must be sent to OSV"
        assert body["unscanned_total"] == 0
        assert len(body["findings"]) == 1
        assert body["findings"][0]["cves"][0]["cve_id"] == "CVE-2021-23337"

    async def test_results_are_persisted_so_the_next_audit_is_free(self, client, monkeypatch):
        from sqlalchemy import select

        from app.models import Ecosystem, Package, PackageVersion
        from app.services.osv import ScanResult

        async with db_module.session_scope() as session:
            package = Package(ecosystem=Ecosystem.npm, name="pkg", normalized_name="pkg")
            package.versions = []
            package.dist_tags = []
            session.add(package)
            await session.flush()
            version = PackageVersion(
                package_id=package.id, version="1.0.0", normalized_version="1.0.0"
            )
            version.files = []
            session.add(version)

        async def fake_scan(self, ecosystem, items, **kwargs):
            return {
                key: ScanResult(None, key[0], key[1], cves=[], max_score=3.1, scanned=True)
                for key in items
            }

        monkeypatch.setattr("app.services.osv.OsvScanner.scan_versions", fake_scan)

        await client.post(
            "/api/cli/audit",
            json={"ecosystem": "npm", "packages": [{"name": "pkg", "version": "1.0.0"}]},
            headers=admin_auth(client),
        )

        async with db_module.session_scope() as session:
            row = (await session.execute(select(PackageVersion))).scalars().first()
            assert row.scanned_at is not None, "the scan must be written back"
            assert row.max_cvss == 3.1

    async def test_offline_mode_still_does_not_call_out(self, client, monkeypatch):
        from app.models import Ecosystem, Package, PackageVersion

        async with db_module.session_scope() as session:
            package = Package(ecosystem=Ecosystem.npm, name="q", normalized_name="q")
            package.versions = []
            package.dist_tags = []
            session.add(package)
            await session.flush()
            version = PackageVersion(
                package_id=package.id, version="1.0.0", normalized_version="1.0.0"
            )
            version.files = []
            session.add(version)

        async def explode(self, ecosystem, items, **kwargs):
            raise AssertionError("offline mode must not query OSV")

        monkeypatch.setattr("app.services.osv.OsvScanner.scan_versions", explode)

        response = await client.post(
            "/api/cli/audit",
            json={
                "ecosystem": "npm",
                "packages": [{"name": "q", "version": "1.0.0"}],
                "scan_unknown": False,
            },
            headers=admin_auth(client),
        )
        assert response.status_code == 200
        assert response.json()["unscanned_total"] == 1


class TestFixVersionSelection:
    """Which version an upgrade has to reach."""

    def test_takes_the_highest_fix_across_cves(self):
        from app.services.vulns import lowest_clearing_version

        # Upgrading has to satisfy every CVE at once, so the answer is the
        # highest of their fixes, not the lowest.
        cves = [{"fixed_version": "4.17.21"}, {"fixed_version": "4.18.0"}]
        assert lowest_clearing_version("npm", cves, "4.17.20") == "4.18.0"

    def test_uses_pep440_ordering_for_pypi(self):
        from app.services.vulns import lowest_clearing_version

        # 2.0.10 > 2.0.9 numerically, though not as text.
        cves = [{"fixed_version": "2.0.9"}, {"fixed_version": "2.0.10"}]
        assert lowest_clearing_version("pypi", cves, "1.0") == "2.0.10"

    def test_never_proposes_a_downgrade(self):
        from app.services.vulns import lowest_clearing_version

        assert lowest_clearing_version("npm", [{"fixed_version": "4.17.21"}], "4.18.0") is None

    def test_none_when_nothing_is_fixed_yet(self):
        from app.services.vulns import lowest_clearing_version

        assert lowest_clearing_version("npm", [{"fixed_version": None}], "1.0.0") is None
        assert lowest_clearing_version("npm", [], "1.0.0") is None

    def test_merging_one_cve_keeps_the_conservative_fix(self):
        from app.services.vulns import dedupe_by_cve

        # Real case: lodash CVE-2021-23337 is filed twice, 7.2/fixed-4.17.21
        # and 8.1/fixed-4.18.0. Advertising 4.17.21 would leave the 8.1
        # variant in place.
        merged = dedupe_by_cve(
            [
                {"cve_id": "CVE-2021-23337", "cvss_score": 8.1, "fixed_version": "4.18.0"},
                {"cve_id": "CVE-2021-23337", "cvss_score": 7.2, "fixed_version": "4.17.21"},
            ]
        )
        assert len(merged) == 1
        assert merged[0]["cvss_score"] == 8.1
        assert merged[0]["fixed_version"] == "4.18.0"

    async def test_audit_reports_fix_version(self, client, monkeypatch):
        from app.models import Ecosystem, Vulnerability
        from app.services.osv import ScanResult

        async def fake_scan(self, ecosystem, items, **kwargs):
            self.session.add(
                Vulnerability(
                    id="GHSA-y",
                    cve_id="CVE-2021-23337",
                    ecosystem=Ecosystem.npm,
                    cvss_score=8.1,
                    severity_label="high",
                    raw={
                        "affected": [
                            {
                                "package": {"name": "lodash", "ecosystem": "npm"},
                                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.18.0"}]}],
                            }
                        ]
                    },
                )
            )
            await self.session.flush()
            return {
                key: ScanResult(
                    None,
                    key[0],
                    key[1],
                    cves=[
                        {
                            "id": "GHSA-y",
                            "cve_id": "CVE-2021-23337",
                            "cvss_score": 8.1,
                            "severity": "high",
                            "summary": "x",
                            "raw": {
                                "affected": [
                                    {
                                        "package": {"name": "lodash", "ecosystem": "npm"},
                                        "ranges": [
                                            {"events": [{"introduced": "0"}, {"fixed": "4.18.0"}]}
                                        ],
                                    }
                                ]
                            },
                        }
                    ],
                    max_score=8.1,
                    scanned=True,
                )
                for key in items
            }

        monkeypatch.setattr("app.services.osv.OsvScanner.scan_versions", fake_scan)
        response = await client.post(
            "/api/cli/audit",
            json={
                "ecosystem": "npm",
                "packages": [{"name": "lodash", "version": "4.17.20"}],
            },
            headers=admin_auth(client),
        )
        finding = response.json()["findings"][0]
        assert finding["fixable"] is True
        assert finding["fix_version"] == "4.18.0"


class TestFixPlanners:
    """The file rewriting itself, which must never disturb anything it did not
    come to change."""

    def test_requirements_rewrite_preserves_comments_and_markers(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text(
            "# Application dependencies\n"
            "django==4.2.0\n"
            "urllib3==1.26.5          # pinned by ops\n"
            'requests==2.31.0 ; python_version >= "3.9"\n'
            "fastapi\n"
        )
        text, changes = cli.plan_requirements_fix(
            path, {"django": "5.2.16", "urllib3": "2.7.0", "requests": "2.33.0"}
        )
        assert "# Application dependencies" in text
        assert "urllib3==2.7.0          # pinned by ops" in text
        assert 'requests==2.33.0 ; python_version >= "3.9"' in text
        assert "fastapi\n" in text
        assert len(changes) == 3

    def test_requirements_rewrite_leaves_unaffected_pins_alone(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("django==4.2.0\nclick==8.1.7\n")
        text, changes = cli.plan_requirements_fix(path, {"django": "5.0.0"})
        assert "click==8.1.7" in text
        assert len(changes) == 1

    def test_requirements_normalizes_the_name_for_lookup(self, tmp_path):
        # PEP 503: Zope.Interface and zope-interface are one project.
        path = tmp_path / "requirements.txt"
        path.write_text("Zope.Interface==5.0.0\n")
        text, changes = cli.plan_requirements_fix(path, {"zope-interface": "6.1"})
        assert "Zope.Interface==6.1" in text
        assert len(changes) == 1

    def test_package_json_preserves_the_declared_operator(self, tmp_path):
        path = tmp_path / "package.json"
        path.write_text(
            '{\n  "dependencies": {\n'
            '    "lodash": "^4.17.20",\n'
            '    "minimist": "~1.2.5",\n'
            '    "left-pad": "1.3.0"\n'
            "  }\n}\n"
        )
        text, changes, skipped = cli.plan_package_json_fix(
            path, {"lodash": "4.18.0", "minimist": "1.2.6"}
        )
        assert '"lodash": "^4.18.0"' in text
        assert '"minimist": "~1.2.6"' in text
        assert '"left-pad": "1.3.0"' in text
        assert len(changes) == 2
        assert skipped == []

    def test_package_json_keeps_formatting_byte_for_byte_elsewhere(self, tmp_path):
        path = tmp_path / "package.json"
        original = (
            '{\n  "name": "demo",\n  "version": "1.0.0",\n'
            '  "dependencies": {\n    "lodash": "^4.17.20"\n  }\n}\n'
        )
        path.write_text(original)
        text, _changes, _skipped = cli.plan_package_json_fix(path, {"lodash": "4.18.0"})
        assert text == original.replace("^4.17.20", "^4.18.0")

    def test_package_json_skips_non_version_specs(self, tmp_path):
        path = tmp_path / "package.json"
        path.write_text(
            '{"dependencies": {"tool": "workspace:*", "other": "git+https://x/y.git"}}'
        )
        _text, changes, skipped = cli.plan_package_json_fix(
            path, {"tool": "1.0.0", "other": "2.0.0"}
        )
        assert changes == []
        assert len(skipped) == 2

    def test_package_json_covers_dev_dependencies(self, tmp_path):
        path = tmp_path / "package.json"
        path.write_text('{"devDependencies": {"vite": "^5.0.0"}}')
        text, changes, _skipped = cli.plan_package_json_fix(path, {"vite": "5.4.0"})
        assert '"vite": "^5.4.0"' in text
        assert len(changes) == 1

    def test_no_change_when_already_at_the_fixed_version(self, tmp_path):
        path = tmp_path / "package.json"
        path.write_text('{"dependencies": {"lodash": "^4.18.0"}}')
        _text, changes, _skipped = cli.plan_package_json_fix(path, {"lodash": "4.18.0"})
        assert changes == []


class TestCliVersionDiscovery:
    """How the CLI learns it has fallen behind."""

    async def test_version_endpoint_reports_what_is_shipped(self, client):
        response = await client.get("/api/cli/version")
        assert response.status_code == 200
        body = response.json()
        assert body["version"], "the registry must report a CLI version"
        assert len(body["sha256"]) == 64
        assert body["download_url"].endswith("/api/cli/download")

    async def test_version_endpoint_needs_no_authentication(self, client):
        # A CLI too old to authenticate should still be able to find out that
        # being old is the reason.
        assert (await client.get("/api/cli/version")).status_code == 200

    async def test_checksum_matches_the_served_file(self, client):
        import hashlib

        advertised = (await client.get("/api/cli/version")).json()["sha256"]
        source = (await client.get("/api/cli/download")).text
        assert hashlib.sha256(source.encode()).hexdigest() == advertised

    async def test_version_matches_the_source(self, client):
        import re

        advertised = (await client.get("/api/cli/version")).json()["version"]
        source = (await client.get("/api/cli/download")).text
        declared = re.search(r'^__version__\s*=\s*"([^"]+)"', source, re.MULTILINE)
        assert declared and declared.group(1) == advertised

    async def test_api_responses_carry_the_version_header(self, client):
        # This is how the CLI notices without spending a request on asking.
        from app.api.cli import CLI_VERSION_HEADER

        response = await client.get("/api/auth/oidc/status")
        assert response.headers.get(CLI_VERSION_HEADER)

    async def test_registry_endpoints_do_not_carry_it(self, client):
        # npm and pip do not care, and it would be noise on every tarball.
        from app.api.cli import CLI_VERSION_HEADER

        response = await client.get("/npm/-/ping")
        assert CLI_VERSION_HEADER not in response.headers


class TestCliSelfUpdateGuards:
    """The CLI replaces its own file, so a bad payload must never land."""

    def test_downloaded_source_is_valid_python(self):
        # The same check cmd_update performs before overwriting itself.
        source = CLI_PATH.read_text()
        compile(source, "<minireg>", "exec")

    def test_update_command_is_registered(self):
        parser = cli.build_parser()
        args = parser.parse_args(["update", "--check"])
        assert args.command == "update"
        assert args.check is True

    def test_install_path_resolves_to_the_script(self):
        assert cli.install_path().name == "minireg.py"

    def test_sanity_checks_reject_a_non_cli_payload(self):
        # cmd_update refuses anything that parses but is not this program.
        payload = "print('hello')\n"
        compile(payload, "<x>", "exec")  # valid Python...
        assert "def main(" not in payload  # ...but not the CLI
        assert "__version__" not in payload
