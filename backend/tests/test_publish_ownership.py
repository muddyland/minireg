"""Who may publish what, and what a version number promises.

These are the properties that separate a caching mirror from a malware
delivery service. Each test names the attack it forecloses.
"""

from __future__ import annotations

import base64

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import db as db_module
from app.core.security import generate_token, hash_password
from app.models import (
    ApiToken,
    Ecosystem,
    Package,
    RetiredVersion,
    User,
)
from app.services.policy import invalidate_policy_cache
from app.services.storage import BlobStore, set_store


def publish_body(name, version, tarball: bytes | None = None):
    tarball = tarball or f"tarball-for-{name}-{version}".encode()
    return {
        "name": name,
        "dist-tags": {"latest": version},
        "versions": {version: {"name": name, "version": version, "dist": {}}},
        "_attachments": {
            f"{name.split('/')[-1]}-{version}.tgz": {
                "content_type": "application/octet-stream",
                "data": base64.b64encode(tarball).decode(),
                "length": len(tarball),
            }
        },
    }


async def _make_user(username, *, is_admin=False, scopes=("read", "publish")):
    async with db_module.session_scope() as session:
        user = User(
            username=username,
            password_hash=hash_password("a-long-enough-password"),
            is_admin=is_admin,
            can_publish=True,
        )
        session.add(user)
        await session.flush()
        full, prefix, token_hash = generate_token()
        session.add(
            ApiToken(
                user_id=user.id,
                name=f"{username}-token",
                prefix=prefix,
                token_hash=token_hash,
                scopes=list(scopes),
            )
        )
        return full


@pytest_asyncio.fixture
async def env(tmp_path):
    from app.main import app

    db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'own.db'}")
    await db_module.create_schema()
    store = BlobStore(str(tmp_path / "storage"))
    store.ensure_dirs()
    set_store(store)
    await invalidate_policy_cache()

    alice = await _make_user("alice")
    bob = await _make_user("bob")
    admin = await _make_user("root", is_admin=True, scopes=("read", "publish", "admin"))

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://registry.test"
    ) as c:
        yield c, {"alice": alice, "bob": bob, "admin": admin}

    await db_module.dispose_engine()
    set_store(None)  # type: ignore[arg-type]


def as_user(client, token):
    client.headers.update({"authorization": f"Bearer {token}"})
    return client


class TestUpstreamShadowing:
    """The critical one: a publish must not be able to replace a public
    package for everyone using the mirror."""

    async def test_cannot_publish_over_a_cached_upstream_package(self, env):
        client, tokens = env
        # A package that arrived from an upstream, exactly as a proxied fetch
        # would leave it.
        async with db_module.session_scope() as session:
            session.add(
                Package(
                    ecosystem=Ecosystem.npm,
                    name="lodash",
                    normalized_name="lodash",
                    is_local=False,
                )
            )

        response = await as_user(client, tokens["alice"]).put(
            "/npm/lodash", json=publish_body("lodash", "4.17.99")
        )
        assert response.status_code == 403
        assert "upstream" in response.json()["error"].lower()

        # And the package must not have been flipped to local on the way out:
        # a local package is never refreshed from upstream again.
        async with db_module.session_scope() as session:
            row = (
                await session.execute(
                    db_module.select_package_stmt()
                    if hasattr(db_module, "select_package_stmt")
                    else __import__("sqlalchemy").select(Package)
                )
            ).scalars().first()
            assert row.is_local is False

    async def test_admin_is_not_a_way_around_it(self, env):
        client, tokens = env
        async with db_module.session_scope() as session:
            session.add(
                Package(
                    ecosystem=Ecosystem.npm,
                    name="lodash",
                    normalized_name="lodash",
                    is_local=False,
                )
            )
        response = await as_user(client, tokens["admin"]).put(
            "/npm/lodash", json=publish_body("lodash", "4.17.99")
        )
        # Shadowing is refused on its own terms; an admin who really wants it
        # reserves the namespace explicitly rather than punching through here.
        assert response.status_code == 403


class TestOwnership:
    async def test_first_publisher_owns_the_name(self, env):
        client, tokens = env
        assert (
            await as_user(client, tokens["alice"]).put(
                "/npm/internal-lib", json=publish_body("internal-lib", "1.0.0")
            )
        ).status_code in (200, 201)

        response = await as_user(client, tokens["bob"]).put(
            "/npm/internal-lib", json=publish_body("internal-lib", "1.1.0")
        )
        assert response.status_code == 403
        assert "owned by another user" in response.json()["error"]

    async def test_owner_can_publish_further_versions(self, env):
        client, tokens = env
        await as_user(client, tokens["alice"]).put(
            "/npm/internal-lib", json=publish_body("internal-lib", "1.0.0")
        )
        response = await as_user(client, tokens["alice"]).put(
            "/npm/internal-lib", json=publish_body("internal-lib", "1.1.0")
        )
        assert response.status_code in (200, 201)

    async def test_another_user_cannot_repoint_latest(self, env):
        client, tokens = env
        await as_user(client, tokens["alice"]).put(
            "/npm/internal-lib", json=publish_body("internal-lib", "1.0.0")
        )
        await as_user(client, tokens["alice"]).put(
            "/npm/internal-lib", json=publish_body("internal-lib", "2.0.0")
        )
        response = await as_user(client, tokens["bob"]).put(
            "/npm/-/package/internal-lib/dist-tags/latest", content='"1.0.0"'
        )
        assert response.status_code == 403

    async def test_another_user_cannot_unpublish(self, env):
        client, tokens = env
        await as_user(client, tokens["alice"]).put(
            "/npm/internal-lib", json=publish_body("internal-lib", "1.0.0")
        )
        response = await as_user(client, tokens["bob"]).delete(
            "/npm/internal-lib/-rev/1"
        )
        assert response.status_code == 403


class TestVersionsAreNotReusable:
    async def test_unpublished_version_cannot_be_republished(self, env):
        client, tokens = env
        alice = as_user(client, tokens["alice"])
        await alice.put("/npm/internal-lib", json=publish_body("internal-lib", "1.0.0"))
        await alice.put("/npm/internal-lib", json=publish_body("internal-lib", "1.1.0"))

        removed = await alice.delete("/npm/internal-lib/-/internal-lib-1.0.0.tgz/-rev/1")
        assert removed.status_code == 200

        async with db_module.session_scope() as session:
            import sqlalchemy

            tomb = (
                await session.execute(sqlalchemy.select(RetiredVersion))
            ).scalars().all()
            assert [t.version for t in tomb] == ["1.0.0"]

        # Same number, different bytes. This is the left-pad problem, and the
        # only thing that would have noticed before was a lockfile digest.
        again = await alice.put(
            "/npm/internal-lib",
            json=publish_body("internal-lib", "1.0.0", tarball=b"different-bytes"),
        )
        assert again.status_code == 409
        assert "withdrawn" in again.json()["error"]


class TestPublishIntegrity:
    async def test_integrity_is_recomputed_not_trusted(self, env):
        client, tokens = env
        body = publish_body("internal-lib", "1.0.0")
        body["versions"]["1.0.0"]["dist"] = {"integrity": "sha512-" + "A" * 86}
        response = await as_user(client, tokens["alice"]).put("/npm/internal-lib", json=body)
        assert response.status_code in (200, 201)

        document = (await client.get("/npm/internal-lib")).json()
        served = document["versions"]["1.0.0"]["dist"]["integrity"]
        # The client's claim is discarded: a wrong SRI string would make the
        # version permanently uninstallable with EINTEGRITY.
        assert served != "sha512-" + "A" * 86
        assert served.startswith("sha512-")

    async def test_dist_tag_naming_a_missing_version_is_dropped(self, env):
        client, tokens = env
        body = publish_body("internal-lib", "1.0.0")
        body["dist-tags"] = {"latest": "9.9.9"}
        response = await as_user(client, tokens["alice"]).put("/npm/internal-lib", json=body)
        assert response.status_code in (200, 201)

        tags = (await client.get("/npm/-/package/internal-lib/dist-tags")).json()
        assert tags["latest"] == "1.0.0"


class TestUploadLimits:
    async def test_oversized_body_is_refused_before_it_is_read(self, env):
        client, tokens = env
        from app.config import settings

        response = await as_user(client, tokens["alice"]).put(
            "/npm/internal-lib",
            content=b"{}",
            headers={"content-length": str(settings.max_publish_bytes + 1)},
        )
        assert response.status_code == 413


# Built from code points so the file itself stays ASCII: the whole point is
# that the two spellings are indistinguishable on screen.
_CYRILLIC_O = "\u043e"


@pytest.mark.parametrize(
    "name,ok",
    [
        ("@scope/lodash", True),
        (f"@scope/l{_CYRILLIC_O}dash", False),
        (f"l{_CYRILLIC_O}dash", False),
    ],
)
def test_lookalike_names_are_refused(name, ok):
    """A homoglyph name sits beside the real package in search results and in
    `npm view` output, and no reader can tell them apart."""
    from app.core.naming import is_valid_npm_name

    assert is_valid_npm_name(name)[0] is ok
