"""The web security layer: login throttling, CSRF, token management, OIDC
account creation, error detail, response headers and the trusted-proxy check.

Each class names the hole it closes.
"""

from __future__ import annotations

import hashlib
import logging

import pytest
from sqlalchemy import select

from app import db as db_module
from app.config import settings
from app.core import cache
from app.models import ApiToken, AuthProvider, User
from tests import test_integration as _integration
from tests.test_integration import auth

#: The integration suite's app + seeded users, reused as a fixture.
app_client = _integration.app_client

SAME_ORIGIN = {"sec-fetch-site": "same-origin"}


async def login(client, username="publisher", password="publisher-password-1"):
    resp = await client.post(
        "/api/auth/login", json={"username": username, "password": password}, headers=SAME_ORIGIN
    )
    assert resp.status_code == 200, resp.text
    return resp


# --------------------------------------------------------------------------- #
class TestLoginThrottleFailsClosed:
    """With the cache down, /api/auth/login used to let every guess through,
    while the Basic-auth path on the same buckets already fell back to an
    in-process counter."""

    async def test_login_is_throttled_without_the_cache(self, app_client, monkeypatch):
        monkeypatch.setattr(settings, "rate_limit_enabled", True)
        monkeypatch.setattr(settings, "rate_limit_login_per_minute", 2)

        async def no_cache():
            return None

        monkeypatch.setattr(cache, "ensure_redis", no_cache)
        cache._local_counters.clear()

        statuses = []
        for _ in range(4):
            resp = await app_client.post(
                "/api/auth/login", json={"username": "throttle-me", "password": "wrong"}
            )
            statuses.append(resp.status_code)
        assert statuses[:2] == [401, 401]
        assert statuses[2:] == [429, 429]
        assert resp.headers.get("retry-after")
        cache._local_counters.clear()


# --------------------------------------------------------------------------- #
class TestTokenManagementNeedsAPrimaryCredential:
    """A leaked read-only token could list its owner's other tokens and
    revoke them (knocking CI over), because list and revoke took any token."""

    async def _owner_tokens(self, username):
        async with db_module.session_scope() as session:
            user = (
                await session.execute(select(User).where(User.username == username))
            ).scalar_one()
            return (
                await session.execute(select(ApiToken).where(ApiToken.user_id == user.id))
            ).scalars().all()

    async def test_a_read_token_cannot_list_tokens(self, app_client):
        resp = await app_client.get("/api/auth/tokens", headers=auth(app_client, "reader"))
        assert resp.status_code == 403

    async def test_a_publish_token_cannot_revoke_a_sibling(self, app_client):
        # A second token for the publisher, which the first must not touch.
        await login(app_client)
        created = await app_client.post(
            "/api/auth/tokens", json={"name": "ci-2", "scopes": ["read"]}, headers=SAME_ORIGIN
        )
        assert created.status_code == 201
        sibling = created.json()["id"]
        app_client.cookies.clear()

        resp = await app_client.delete(
            f"/api/auth/tokens/{sibling}", headers=auth(app_client, "publisher")
        )
        assert resp.status_code == 403
        rows = {t.id: t for t in await self._owner_tokens("publisher")}
        assert rows[sibling].revoked is False

    async def test_a_session_and_an_admin_token_still_can(self, app_client):
        resp = await app_client.get("/api/auth/tokens", headers=auth(app_client, "admin"))
        assert resp.status_code == 200
        await login(app_client)
        listed = await app_client.get("/api/auth/tokens")
        assert listed.status_code == 200
        token_id = listed.json()["tokens"][0]["id"]
        resp = await app_client.delete(f"/api/auth/tokens/{token_id}", headers=SAME_ORIGIN)
        assert resp.status_code == 200


# --------------------------------------------------------------------------- #
class TestCsrf:
    """The session cookie was accepted on every method with no origin check;
    SameSite=Lax does nothing about a sibling app on the same parent domain."""

    @pytest.mark.parametrize(
        "headers",
        [
            {"sec-fetch-site": "cross-site"},
            {"sec-fetch-site": "same-site"},
            {"origin": "https://evil.example"},
            {"origin": "http://registry.test.evil.example"},
            {"origin": "null"},
            {"referer": "https://evil.example/page"},
            # The browser's own header wins over a matching Origin.
            {"sec-fetch-site": "same-site", "origin": "http://registry.test"},
        ],
    )
    async def test_cross_site_state_change_with_the_cookie_is_refused(self, app_client, headers):
        await login(app_client)
        resp = await app_client.post(
            "/api/auth/tokens", json={"name": "csrf", "scopes": ["read"]}, headers=headers
        )
        assert resp.status_code == 403
        assert "cross-site" in resp.json()["detail"]
        rows = (await app_client.get("/api/auth/tokens")).json()["tokens"]
        assert all(t["name"] != "csrf" for t in rows)

    @pytest.mark.parametrize(
        "headers",
        [
            {"sec-fetch-site": "same-origin"},
            {"sec-fetch-site": "none"},
            {"origin": "http://registry.test"},
            {"origin": "http://registry.test:80"},
            {"referer": "http://registry.test/account"},
            # What the Vue app sends: fetch() from the same origin.
            {"sec-fetch-site": "same-origin", "origin": "http://registry.test"},
            # Not a browser (no Origin on a POST); see is_cross_site.
            {},
        ],
    )
    async def test_same_origin_requests_work(self, app_client, headers):
        await login(app_client)
        resp = await app_client.post(
            "/api/auth/tokens", json={"name": "ok", "scopes": ["read"]}, headers=headers
        )
        assert resp.status_code == 201, resp.text

    async def test_reads_are_not_checked(self, app_client):
        await login(app_client)
        resp = await app_client.get("/api/auth/me", headers={"sec-fetch-site": "cross-site"})
        assert resp.status_code == 200

    async def test_tokens_are_unaffected(self, app_client):
        """npm, twine, docker and the CLI never carry the cookie; a token
        request from anywhere is fine."""
        resp = await app_client.post(
            "/api/auth/tokens",
            json={"name": "from-ci", "scopes": ["read"]},
            headers={**auth(app_client, "admin"), "sec-fetch-site": "cross-site"},
        )
        assert resp.status_code == 201

    async def test_logout_from_another_site_is_refused(self, app_client):
        await login(app_client)
        resp = await app_client.post("/api/auth/logout", headers={"origin": "https://evil.example"})
        assert resp.status_code == 403

    async def test_login_form_works(self, app_client):
        resp = await app_client.post(
            "/api/auth/login",
            json={"username": "publisher", "password": "publisher-password-1"},
            headers={"sec-fetch-site": "same-origin", "origin": "http://registry.test"},
        )
        assert resp.status_code == 200
        assert settings.session_cookie in resp.cookies


# --------------------------------------------------------------------------- #
class TestOidcCallback:
    """preferred_username is chosen by the user at most IdPs. A clash with an
    existing username was an IntegrityError -- a 500 -- and a failed exchange
    echoed the provider's response and token URL to the browser."""

    @pytest.fixture
    def provider(self, monkeypatch):
        from app.services import oidc

        monkeypatch.setattr(settings, "oidc_enabled", True)
        monkeypatch.setattr(settings, "oidc_issuer", "https://idp.example")
        monkeypatch.setattr(settings, "oidc_auto_create_users", True)
        monkeypatch.setattr(settings, "oidc_user_group", None)
        claims: dict = {}

        async def exchange(code, redirect_uri, verifier):
            if code == "bad":
                raise oidc.OidcError(
                    "token exchange returned HTTP 400: {secret provider body} -- "
                    "check https://idp.example/internal/token"
                )
            return {"id_token": "x", "access_token": None}

        async def verify(token, nonce):
            return dict(claims)

        monkeypatch.setattr(oidc, "exchange_code", exchange)
        monkeypatch.setattr(oidc, "verify_id_token", verify)
        return claims

    async def _callback(self, client, code="good"):
        from app.api.auth import OIDC_BIND_COOKIE
        from app.core.security import create_state_token

        state = create_state_token(
            {
                "nonce": "n",
                "verifier": "v",
                "next": "/",
                "bind": hashlib.sha256(b"binder").hexdigest(),
            }
        )
        client.cookies.set(OIDC_BIND_COOKIE, "binder")
        return await client.get(
            "/api/auth/oidc/callback", params={"code": code, "state": state}
        )

    async def test_username_collision_gets_a_suffix(self, app_client, provider):
        provider.update(
            {"sub": "subject-1", "iss": "https://idp.example", "preferred_username": "admin"}
        )
        resp = await self._callback(app_client)
        assert resp.status_code == 302, resp.text
        async with db_module.session_scope() as session:
            users = {
                u.username: u for u in (await session.execute(select(User))).scalars().all()
            }
        # The local admin is untouched, not linked by name.
        assert users["admin"].provider == AuthProvider.local
        assert users["admin"].oidc_subject is None
        assert users["admin-2"].oidc_subject == "subject-1"

        # A second subject claiming the same name gets the next suffix, and
        # the first subject keeps signing in to its own account.
        app_client.cookies.clear()
        provider.update({"sub": "subject-2"})
        assert (await self._callback(app_client)).status_code == 302
        app_client.cookies.clear()
        provider.update({"sub": "subject-1"})
        assert (await self._callback(app_client)).status_code == 302
        async with db_module.session_scope() as session:
            rows = (
                await session.execute(
                    select(User.username, User.oidc_subject).where(User.oidc_subject.isnot(None))
                )
            ).all()
        assert sorted(rows) == [("admin-2", "subject-1"), ("admin-3", "subject-2")]

    async def test_verified_email_still_links_a_local_account(self, app_client, provider):
        """Linking order is unchanged: subject, then a verified email."""
        provider.update(
            {
                "sub": "subject-9",
                "iss": "https://idp.example",
                "preferred_username": "someone-else",
                "email": "pub@test",
                "email_verified": True,
            }
        )
        assert (await self._callback(app_client)).status_code == 302
        async with db_module.session_scope() as session:
            linked = (
                await session.execute(select(User).where(User.oidc_subject == "subject-9"))
            ).scalar_one()
        assert linked.username == "publisher"

    async def test_failure_detail_stays_in_the_log(self, app_client, provider, caplog):
        with caplog.at_level(logging.WARNING):
            resp = await self._callback(app_client, code="bad")
        assert resp.status_code == 401
        body = resp.text
        assert "secret provider body" not in body
        assert "idp.example" not in body
        assert "secret provider body" in caplog.text


class TestShadowCheckDetail:
    async def test_resolver_error_is_not_shown_to_the_publisher(
        self, app_client, monkeypatch, caplog
    ):
        from app.services import ownership
        from tests.test_integration import npm_publish_body

        async def broken(*_a, **_k):
            raise ownership.ShadowCheckUnavailable(
                "gitlab-internal: https://10.1.2.3/api/v4 refused: secret-detail"
            )

        monkeypatch.setattr(ownership, "_resolves_upstream", broken)
        with caplog.at_level(logging.WARNING):
            resp = await app_client.put(
                "/npm/brand-new-name",
                json=npm_publish_body("brand-new-name"),
                headers=auth(app_client, "publisher"),
            )
        assert resp.status_code == 503
        assert "could not check" in resp.text
        assert "secret-detail" not in resp.text
        assert "10.1.2.3" not in resp.text
        # The operator still has it.
        assert "secret-detail" in caplog.text


# --------------------------------------------------------------------------- #
class TestResponseHeaders:
    async def test_api_responses_carry_the_basics(self, app_client):
        resp = await app_client.get("/api/auth/oidc/status")
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["referrer-policy"] == "same-origin"
        assert resp.headers["x-frame-options"] == "DENY"
        # JSON is not a document; it gets no CSP.
        assert "content-security-policy" not in resp.headers
        # PUBLIC_URL is http in the tests: no HSTS.
        assert "strict-transport-security" not in resp.headers

    async def _through_middleware(self, response, path="/"):
        from starlette.requests import Request

        from app.main import security_headers

        request = Request({"type": "http", "method": "GET", "path": path, "headers": []})

        async def call_next(_request):
            return response

        return await security_headers(request, call_next)

    async def test_html_gets_a_csp_the_app_satisfies(self):
        """The SPA (index.html) is the only HTML this app serves; the built
        static tree is absent in tests, so the middleware is driven directly."""
        from fastapi.responses import HTMLResponse

        from app.main import UI_CSP

        resp = await self._through_middleware(HTMLResponse("<!doctype html><title>x</title>"))
        csp = resp.headers["content-security-policy"]
        assert csp == UI_CSP
        directives = dict(d.split(" ", 1) for d in csp.split("; "))
        # The built index.html loads one module script and one stylesheet
        # from /assets; Vue writes inline style attributes; nothing evals.
        assert directives["script-src"] == "'self'"
        assert "'unsafe-inline'" not in directives["script-src"]
        assert "'unsafe-eval'" not in csp
        assert "'unsafe-inline'" in directives["style-src"]
        assert directives["frame-ancestors"] == "'none'"
        assert directives["connect-src"] == "'self'"

    async def test_registry_responses_get_no_csp(self):
        from fastapi.responses import Response

        resp = await self._through_middleware(
            Response(b"{}", media_type="application/vnd.oci.image.manifest.v1+json"), "/v2/x"
        )
        assert "content-security-policy" not in resp.headers
        assert resp.headers["x-content-type-options"] == "nosniff"

    async def test_hsts_only_for_https(self, monkeypatch):
        from fastapi.responses import HTMLResponse

        import app.main as main_mod

        assert main_mod.hsts_value("http://registry.test") is None
        assert main_mod.hsts_value("HTTPS://registry.example") == "max-age=31536000"
        monkeypatch.setattr(main_mod, "_HSTS", main_mod.hsts_value("https://registry.example"))
        resp = await self._through_middleware(HTMLResponse("x"))
        assert resp.headers["strict-transport-security"] == "max-age=31536000"


# --------------------------------------------------------------------------- #
class TestTrustedProxyWarning:
    """With the default TRUSTED_PROXY_IPS and BIND_ADDRESS=0.0.0.0, Docker's
    userland proxy relays every client from the bridge gateway, a trusted
    address -- so X-Forwarded-For becomes the client's to choose."""

    def test_gateway_is_read_from_the_routing_table(self, tmp_path):
        from app.core.deps import _default_gateway

        table = tmp_path / "route"
        table.write_text(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\n"
            "eth0\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\n"
        )
        assert _default_gateway(str(table)) == "172.18.0.1"
        assert _default_gateway(str(tmp_path / "missing")) is None

    def test_startup_notes_a_trusted_gateway_without_warning(self, monkeypatch, caplog):
        # The safe default layout trusts the gateway too, so this is INFO;
        # only the traffic-based check below may warn.
        from app.core import deps

        monkeypatch.setattr(deps, "_default_gateway", lambda: "172.18.0.1")
        with caplog.at_level(logging.INFO):
            assert deps.check_trusted_proxy_config() == "172.18.0.1"
        assert "BIND_ADDRESS" in caplog.text
        assert all(r.levelno < logging.WARNING for r in caplog.records)

    def test_startup_is_quiet_when_it_is_not(self, monkeypatch, caplog):
        from app.core import deps

        monkeypatch.setattr(deps, "_default_gateway", lambda: "203.0.113.1")
        with caplog.at_level(logging.WARNING):
            assert deps.check_trusted_proxy_config() is None
        assert caplog.text == ""

    def test_a_direct_client_through_the_relay_is_flagged_once(self, monkeypatch, caplog):
        from starlette.requests import Request

        from app.core import deps

        monkeypatch.setattr(deps, "_relay_state", {"gateway": "172.18.0.1"})

        def request(headers):
            return Request(
                {
                    "type": "http",
                    "method": "GET",
                    "path": "/",
                    "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
                    "client": ("172.18.0.1", 5000),
                }
            )

        with caplog.at_level(logging.WARNING):
            # A reverse proxy always adds the header: not a warning.
            assert deps.client_ip(request({"x-forwarded-for": "198.51.100.7"})) == "198.51.100.7"
            assert "X-Forwarded-For" not in caplog.text
            deps.client_ip(request({}))
            deps.client_ip(request({}))
        assert caplog.text.count("this container's gateway") == 1
