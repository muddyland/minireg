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
