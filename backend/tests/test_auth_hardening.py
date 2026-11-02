"""Credentials and sessions: what each one may do, and how it is revoked.

Each class names the hole it closes.
"""

from __future__ import annotations

import base64

from sqlalchemy import func, select

from app import db as db_module
from app.config import settings
from app.models import ApiToken, Package, User
from tests import test_integration as _integration
from tests.test_integration import auth, npm_publish_body

#: The integration suite's app + seeded users, reused as a fixture.
app_client = _integration.app_client

SAME_ORIGIN = {"sec-fetch-site": "same-origin"}


def password_basic(username="publisher", password="publisher-password-1"):
    raw = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"authorization": f"Basic {raw}"}


async def login(client, username="publisher", password="publisher-password-1"):
    resp = await client.post(
        "/api/auth/login", json={"username": username, "password": password}, headers=SAME_ORIGIN
    )
    assert resp.status_code == 200, resp.text
    return resp.cookies.get(settings.session_cookie)


async def user_row(username: str) -> User:
    async with db_module.session_scope() as session:
        return (await session.execute(select(User).where(User.username == username))).scalar_one()


async def count(model, *where) -> int:
    async with db_module.session_scope() as session:
        stmt = select(func.count()).select_from(model)
        if where:
            stmt = stmt.where(*where)
        return (await session.execute(stmt)).scalar_one()


# --------------------------------------------------------------------------- #
class TestPasswordBasicIsReadOnly:
    """An account password over HTTP Basic counted as a session: it could
    publish to npm and PyPI and mint itself an admin token, although the docs
    promise passwords are refused for publishing."""

    async def test_it_reads(self, app_client, monkeypatch):
        monkeypatch.setattr(settings, "allow_anonymous_read", False)
        me = await app_client.get("/api/auth/me", headers=password_basic())
        assert me.status_code == 200
        assert me.json()["auth_method"] == "basic_password"
        assert me.json()["scopes"] == ["read"]
        # A read-guarded registry route accepts it.
        assert (await app_client.get("/cargo/index/config.json")).status_code == 401
        resp = await app_client.get("/cargo/index/config.json", headers=password_basic())
        assert resp.status_code == 200

    async def test_it_cannot_publish_to_npm(self, app_client):
        resp = await app_client.put(
            "/npm/pw-published",
            json=npm_publish_body(name="pw-published"),
            headers=password_basic(),
        )
        assert resp.status_code == 403, resp.text
        assert "API token" in resp.text
        assert await count(Package, Package.name == "pw-published") == 0

    async def test_it_cannot_publish_to_pypi(self, app_client):
        data = {
            ":action": "file_upload",
            "protocol_version": "1",
            "name": "pw-wheel",
            "version": "1.0.0",
            "filetype": "bdist_wheel",
            "pyversion": "py3",
            "metadata_version": "2.1",
        }
        files = {"content": ("pw_wheel-1.0.0-py3-none-any.whl", b"wheel", "application/octet-stream")}
        resp = await app_client.post(
            "/pypi/legacy/", data=data, files=files, headers=password_basic()
        )
        assert resp.status_code == 403, resp.text
        assert await count(Package, Package.name == "pw-wheel") == 0

    async def test_it_cannot_mint_tokens(self, app_client):
        before = await count(ApiToken)
        resp = await app_client.post(
            "/api/auth/tokens",
            json={"name": "from-a-password", "scopes": ["admin"]},
            headers=password_basic("admin", "admin-password-1234"),
        )
        assert resp.status_code == 403, resp.text
        assert await count(ApiToken) == before

    async def test_it_cannot_administer(self, app_client):
        resp = await app_client.get(
            "/api/admin/users", headers=password_basic("admin", "admin-password-1234")
        )
        assert resp.status_code == 403
        assert "read-only" in resp.json()["detail"]
        # The same admin's token still can.
        assert (await app_client.get("/api/admin/users", headers=auth(app_client, "admin"))).status_code == 200

    async def test_tokens_and_sessions_still_publish(self, app_client):
        resp = await app_client.put(
            "/npm/token-published",
            json=npm_publish_body(name="token-published"),
            headers=auth(app_client),
        )
        assert resp.status_code in (200, 201), resp.text
