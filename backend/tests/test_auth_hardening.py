"""Credentials and sessions: what each one may do, and how it is revoked.

Each class names the hole it closes.
"""

from __future__ import annotations

import base64
import hashlib

import pytest
from sqlalchemy import func, select

from app import db as db_module
from app.config import settings
from app.core import cache, security
from app.models import ApiToken, AuditLog, AuthProvider, Package, User
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


@pytest.fixture
def login_throttle(monkeypatch):
    """Login limiting on, on the in-process fallback, in a frozen window.

    The clock is pinned a second into a window: the counters reset on every
    minute boundary, and a test that crossed one would see its count vanish.
    """
    import time

    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(settings, "rate_limit_login_per_minute", 3)
    start = (int(time.time()) // 60) * 60 + 1.0
    monkeypatch.setattr(cache.time, "time", lambda: start)

    async def no_cache():
        return None

    monkeypatch.setattr(cache, "ensure_redis", no_cache)
    cache._local_counters.clear()
    yield
    cache._local_counters.clear()


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


# --------------------------------------------------------------------------- #
class TestEveryLoginPaysForOneVerify:
    """An unknown (or, over Basic, a disabled) account skipped argon2 and
    answered in microseconds, while a real one took ~60 ms: a reliable
    oracle for which usernames exist."""

    @pytest.fixture
    def verifies(self, monkeypatch):
        real = security._hasher
        calls: list[str] = []

        class Counting:
            def __getattr__(self, name):
                return getattr(real, name)

            def verify(self, hashed, password):
                calls.append(hashed)
                return real.verify(hashed, password)

        monkeypatch.setattr(security, "_hasher", Counting())
        return calls

    async def _disable(self, username):
        async with db_module.session_scope() as session:
            user = (
                await session.execute(select(User).where(User.username == username))
            ).scalar_one()
            user.is_active = False

    async def test_login_endpoint(self, app_client, verifies):
        await self._disable("reader")
        for username in ("nobody-here", "publisher", "reader"):
            verifies.clear()
            resp = await app_client.post(
                "/api/auth/login", json={"username": username, "password": "wrong-password"}
            )
            assert resp.status_code == 401
            assert len(verifies) == 1, username

    async def test_basic_password(self, app_client, verifies):
        await self._disable("reader")
        for username in ("nobody-here", "publisher", "reader"):
            verifies.clear()
            resp = await app_client.get(
                "/api/auth/me", headers=password_basic(username, "wrong-password")
            )
            assert resp.status_code == 401
            assert len(verifies) == 1, username
        # A disabled account is refused even with its right password.
        verifies.clear()
        resp = await app_client.get(
            "/api/auth/me", headers=password_basic("reader", "reader-password-12345")
        )
        assert resp.status_code == 401
        assert len(verifies) == 1


# --------------------------------------------------------------------------- #
class TestLoginThrottleCountsOnlyFailures:
    """Every Basic-password request -- successes included -- was counted in
    the login buckets, so a client sending its password got 429 after ten
    requests a minute and locked its owner out of the web login too. And the
    per-account bucket was global: ten wrong guesses from anywhere locked the
    real user out of every client."""

    @pytest.fixture(autouse=True)
    def throttled(self, login_throttle):
        return login_throttle

    @staticmethod
    def frm(ip):
        return {"x-forwarded-for": ip}

    async def test_successes_are_not_counted(self, app_client):
        statuses = [
            (await app_client.get("/api/auth/me", headers=password_basic())).status_code
            for _ in range(10)
        ]
        assert statuses == [200] * 10
        await login(app_client)

    async def test_a_stranger_cannot_lock_the_owner_out(self, app_client):
        attacker = self.frm("203.0.113.66")
        for _ in range(3):
            resp = await app_client.post(
                "/api/auth/login",
                json={"username": "publisher", "password": "guess"},
                headers=attacker,
            )
            assert resp.status_code == 401
        # The attacker's address is throttled for this account...
        resp = await app_client.post(
            "/api/auth/login", json={"username": "publisher", "password": "guess"}, headers=attacker
        )
        assert resp.status_code == 429
        assert resp.headers.get("retry-after")
        # ...even with the right password, so guessing stays capped.
        resp = await app_client.get(
            "/api/auth/me", headers={**password_basic(), **attacker}
        )
        assert resp.status_code == 429
        # The owner, elsewhere, is not.
        owner = self.frm("198.51.100.7")
        resp = await app_client.get("/api/auth/me", headers={**password_basic(), **owner})
        assert resp.status_code == 200
        resp = await app_client.post(
            "/api/auth/login",
            json={"username": "publisher", "password": "publisher-password-1"},
            headers={**SAME_ORIGIN, **owner},
        )
        assert resp.status_code == 200

    async def test_one_address_cannot_spray_many_accounts(self, app_client):
        source = self.frm("203.0.113.67")
        codes = []
        for name in ("a1", "a2", "a3", "a4"):
            resp = await app_client.post(
                "/api/auth/login", json={"username": name, "password": "guess"}, headers=source
            )
            codes.append(resp.status_code)
        assert codes == [401, 401, 401, 429]

    async def test_a_distributed_guess_hits_the_account_ceiling(self, app_client):
        # 3/min per address, 30/min per account across all addresses.
        for n in range(30):
            resp = await app_client.get(
                "/api/auth/me",
                headers={**password_basic("publisher", "guess"), **self.frm(f"203.0.113.{n}")},
            )
            assert resp.status_code == 401, n
        resp = await app_client.get(
            "/api/auth/me", headers={**password_basic(), **self.frm("198.51.100.8")}
        )
        assert resp.status_code == 429


# --------------------------------------------------------------------------- #
class TestChangePasswordIsThrottled:
    """POST /api/auth/password checked the current password with no limit
    and no audit row, so a stolen session cookie was an unlimited, silent
    oracle for the account's password."""

    async def test_wrong_guesses_are_throttled_and_audited(self, app_client, login_throttle):
        await login(app_client)
        codes = []
        for n in range(4):
            resp = await app_client.post(
                "/api/auth/password",
                json={"current_password": f"guess-{n}", "new_password": "a-new-password-123"},
                headers=SAME_ORIGIN,
            )
            codes.append(resp.status_code)
        assert codes == [401, 401, 401, 429]
        async with db_module.session_scope() as session:
            rows = (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "auth.login.failed",
                        AuditLog.actor_username == "publisher",
                    )
                )
            ).scalars().all()
        assert len(rows) == 3
        assert all(r.detail["method"] == "password change" for r in rows)

    async def test_the_right_password_still_changes_it(self, app_client):
        await login(app_client)
        resp = await app_client.post(
            "/api/auth/password",
            json={"current_password": "publisher-password-1", "new_password": "a-new-password-123"},
            headers=SAME_ORIGIN,
        )
        assert resp.status_code == 200
        app_client.cookies.clear()
        await login(app_client, password="a-new-password-123")


# --------------------------------------------------------------------------- #
@pytest.fixture
def provider(monkeypatch):
    """An OIDC provider whose next ID token carries the claims in the dict."""
    from app.services import oidc

    monkeypatch.setattr(settings, "oidc_enabled", True)
    monkeypatch.setattr(settings, "oidc_issuer", "https://idp.example")
    monkeypatch.setattr(settings, "oidc_auto_create_users", True)
    monkeypatch.setattr(settings, "oidc_user_group", None)
    monkeypatch.setattr(settings, "oidc_admin_group", "minireg-admins")
    claims: dict = {"iss": "https://idp.example"}

    async def exchange(code, redirect_uri, verifier):
        return {"id_token": "x", "access_token": None}

    async def verify(token, nonce):
        return dict(claims)

    monkeypatch.setattr(oidc, "exchange_code", exchange)
    monkeypatch.setattr(oidc, "verify_id_token", verify)
    return claims


async def sso(client):
    """Run the OIDC callback as the browser that started the flow."""
    from app.api.auth import OIDC_BIND_COOKIE
    from app.core.security import create_state_token

    state = create_state_token(
        {"nonce": "n", "verifier": "v", "next": "/", "bind": hashlib.sha256(b"b").hexdigest()}
    )
    client.cookies.set(OIDC_BIND_COOKIE, "b")
    return await client.get("/api/auth/oidc/callback", params={"code": "c", "state": state})


class TestLinkedAccountsLoseTheirPassword:
    """Linking a local account to an OIDC subject kept its password, and
    neither the login form nor Basic looked at the provider: the password
    went on working after the IdP removed the person from the required group
    or disabled them, while both password-change paths refused to touch it."""

    async def test_linking_drops_the_password_and_its_sessions(self, app_client, provider):
        old_cookie = await login(app_client)
        app_client.cookies.clear()
        provider.update(
            {"sub": "pub-sub", "preferred_username": "pub", "email": "pub@test", "email_verified": True}
        )
        resp = await sso(app_client)
        assert resp.status_code == 302
        row = await user_row("publisher")
        assert row.provider == AuthProvider.oidc
        assert row.password_hash is None
        # The SSO cookie just issued works...
        assert (await app_client.get("/api/auth/me")).status_code == 200
        # ...a session opened with the password before the link does not.
        app_client.cookies.clear()
        app_client.cookies.set(settings.session_cookie, old_cookie)
        assert (await app_client.get("/api/auth/me")).status_code == 401
        app_client.cookies.clear()

        # The password no longer signs in, by form or by Basic.
        resp = await app_client.post(
            "/api/auth/login",
            json={"username": "publisher", "password": "publisher-password-1"},
            headers=SAME_ORIGIN,
        )
        assert resp.status_code == 401
        resp = await app_client.get("/api/auth/me", headers=password_basic())
        assert resp.status_code == 401
        # Its API tokens are untouched.
        assert (await app_client.get("/api/auth/me", headers=auth(app_client))).status_code == 200

    async def test_an_oidc_row_with_a_password_is_refused(self, app_client):
        """Defence in depth for rows the startup fix has not reached."""
        async with db_module.session_scope() as session:
            row = (
                await session.execute(select(User).where(User.username == "publisher"))
            ).scalar_one()
            row.provider = AuthProvider.oidc
        resp = await app_client.post(
            "/api/auth/login",
            json={"username": "publisher", "password": "publisher-password-1"},
            headers=SAME_ORIGIN,
        )
        assert resp.status_code == 401
        assert (await app_client.get("/api/auth/me", headers=password_basic())).status_code == 401

    async def test_startup_clears_already_linked_rows_once(self, app_client):
        async with db_module.session_scope() as session:
            row = (
                await session.execute(select(User).where(User.username == "publisher"))
            ).scalar_one()
            row.provider = AuthProvider.oidc
            row.oidc_subject = "linked-before-the-fix"
            version = row.session_version
        await db_module.create_schema()
        row = await user_row("publisher")
        assert row.password_hash is None
        assert row.session_version == version + 1
        # Idempotent: a second boot changes nothing.
        await db_module.create_schema()
        assert (await user_row("publisher")).session_version == version + 1
        # Local accounts keep their passwords.
        assert (await user_row("admin")).password_hash


class TestEmailVerifiedIsReadStrictly:
    """email_verified went through bool(), so the string "false" counted as
    verified and linked the attacker's subject onto the matching account."""

    @pytest.mark.parametrize(
        ("value", "verified"),
        [
            (True, True),
            ("true", True),
            ("TRUE", True),
            (False, False),
            ("false", False),
            ("False", False),
            ("0", False),
            ("no", False),
            (1, False),
            (None, False),
            ({}, False),
        ],
    )
    def test_claim_values(self, value, verified):
        from app.services.oidc import build_profile

        claims = {"sub": "s", "iss": "https://idp.example", "email": "x@test"}
        if value is not None:
            claims["email_verified"] = value
        assert build_profile(claims, {}).email_verified is verified

    async def test_string_false_does_not_link(self, app_client, provider):
        provider.update(
            {"sub": "evil", "preferred_username": "evil", "email": "admin@test", "email_verified": "false"}
        )
        assert (await sso(app_client)).status_code == 302
        admin = await user_row("admin")
        assert admin.oidc_subject is None
        assert admin.provider == AuthProvider.local
        # A separate account was made for the subject instead.
        assert (await user_row("evil")).oidc_subject == "evil"
