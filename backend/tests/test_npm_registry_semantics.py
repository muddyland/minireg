"""npm registry semantics the public registry has and a mirror must keep.

Each test drives the real routes the npm CLI talks to, with the request
shapes libnpmpublish and npm-registry-fetch actually send.

``TEST_DATABASE_URL`` runs the module against PostgreSQL (a fresh schema per
test), which is stricter than SQLite about OFFSET, types and constraints.
"""

from __future__ import annotations

import os

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import db as db_module
from app.services.policy import invalidate_policy_cache
from app.services.storage import BlobStore, set_store

from .test_publish_ownership import _make_user, as_user, publish_body


@pytest_asyncio.fixture
async def env(tmp_path):
    from app.main import app

    pg_url = os.environ.get("TEST_DATABASE_URL")
    if pg_url:
        db_module.init_engine(pg_url)
        from app.models import Base

        async with db_module.get_engine().begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    else:
        db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'npm.db'}")
    await db_module.create_schema()
    store = BlobStore(str(tmp_path / "storage"))
    store.ensure_dirs()
    set_store(store)
    await invalidate_policy_cache()

    tokens = {
        "alice": await _make_user("alice"),
        "bob": await _make_user("bob"),
        "admin": await _make_user("root", is_admin=True, scopes=("read", "publish", "admin")),
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://registry.test"
    ) as client:
        yield client, tokens

    await db_module.dispose_engine()
    set_store(None)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Search paging
# --------------------------------------------------------------------------- #
async def test_search_tolerates_junk_and_negative_paging(env):
    """``from=abc`` was a 500 and ``from=-5`` a negative OFFSET, which
    PostgreSQL rejects. npmjs reads junk as the default and clamps."""
    client, tokens = env
    as_user(client, tokens["alice"])
    assert (await client.put("/npm/findme", json=publish_body("findme", "1.0.0"))).status_code == 201

    for query in ("from=abc", "from=-5", "from=", "size=abc", "size=-3", "size=100000",
                  "from=99999999999999999999999"):
        response = await client.get(f"/npm/-/v1/search?text=findme&{query}")
        assert response.status_code == 200, (query, response.text)

    first = (await client.get("/npm/-/v1/search?text=findme&from=-5")).json()
    assert [o["package"]["name"] for o in first["objects"]] == ["findme"]
    assert (await client.get("/npm/-/v1/search?text=findme&from=1")).json()["objects"] == []


# --------------------------------------------------------------------------- #
# dist-tag names
# --------------------------------------------------------------------------- #
BAD_TAGS = ("v1.0.0", "1", "1.x", "^2", "x", "%20", "a%20b", "a%2Bb", "caf%C3%A9")


async def test_dist_tag_names_npm_cannot_install_are_refused(env):
    """``v1.0.0`` was accepted (only strict semver was refused), as were
    ``' '`` and ``'a b'``; npm reads a range before a tag, so none of these
    could ever be installed by name, and the blank ones break the URL."""
    client, tokens = env
    as_user(client, tokens["alice"])
    assert (await client.put("/npm/tagpkg", json=publish_body("tagpkg", "1.0.0"))).status_code == 201

    for tag in BAD_TAGS:
        response = await client.put(f"/npm/-/package/tagpkg/dist-tags/{tag}", content='"1.0.0"')
        assert response.status_code == 400, (tag, response.text)
    good = await client.put("/npm/-/package/tagpkg/dist-tags/next-1_rc.2", content='"1.0.0"')
    assert good.status_code == 200, good.text

    tags = (await client.get("/npm/-/package/tagpkg/dist-tags")).json()
    assert tags == {"latest": "1.0.0", "next-1_rc.2": "1.0.0"}


async def test_publish_document_dist_tags_follow_the_same_rules(env):
    client, tokens = env
    as_user(client, tokens["alice"])
    for tag in ("v1.0.0", " ", "", "a b", "~1"):
        body = publish_body("doctags", "1.0.0")
        body["dist-tags"] = {tag: "1.0.0"}
        response = await client.put("/npm/doctags", json=body)
        assert response.status_code == 400, (tag, response.text)
    # Nothing was created by the refused publishes.
    assert (await client.get("/npm/doctags")).status_code == 404


# --------------------------------------------------------------------------- #
# GET /{pkg}/{tag} agrees with the packument
# --------------------------------------------------------------------------- #
async def _block(pattern: str, version_spec: str) -> None:
    from app.models import Ecosystem, PackageRule, RuleAction

    async with db_module.session_scope() as session:
        session.add(
            PackageRule(
                ecosystem=Ecosystem.npm,
                pattern=pattern,
                action=RuleAction.block,
                version_spec=version_spec,
                reason=f"blocked {pattern}@{version_spec}",
            )
        )
    await invalidate_policy_cache()


async def test_version_route_resolves_latest_like_the_packument(env):
    """With `latest` blocked, the packument and the dist-tags endpoint point
    it at the newest surviving release, but GET /pkg/latest answered 403."""
    client, tokens = env
    as_user(client, tokens["alice"])
    for version in ("1.0.0", "2.0.0"):
        assert (await client.put("/npm/vdoc", json=publish_body("vdoc", version))).status_code == 201
    body = publish_body("vdoc", "3.0.0-rc.1")
    body["dist-tags"] = {"next": "3.0.0-rc.1"}
    assert (await client.put("/npm/vdoc", json=body)).status_code == 201
    await _block("vdoc", "2.0.0 || 3.0.0-rc.1")

    packument = (await client.get("/npm/vdoc")).json()
    assert packument["dist-tags"] == {"latest": "1.0.0"}
    assert (await client.get("/npm/-/package/vdoc/dist-tags")).json() == {"latest": "1.0.0"}

    latest = await client.get("/npm/vdoc/latest")
    assert latest.status_code == 200, latest.text
    assert latest.json()["version"] == "1.0.0"

    # A blocked version asked for by number, or a tag that only names a
    # blocked version, is still refused with the policy's reason.
    assert (await client.get("/npm/vdoc/2.0.0")).status_code == 403
    nxt = await client.get("/npm/vdoc/next")
    assert nxt.status_code == 403
    assert "blocked" in nxt.json()["error"]
    assert (await client.get("/npm/vdoc/nonesuch")).status_code == 404
