"""The in-app documentation endpoint.

The docs ship inside the image so a registry with no route to the internet
still has them. The endpoint reads files off disk, so the interesting
questions are which files, and for whom.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import db as db_module
from app.api import help as help_api
from app.core.security import generate_token, hash_password
from app.models import ApiToken, User
from app.services.storage import BlobStore, set_store


@pytest_asyncio.fixture
async def client(tmp_path):
    from app.main import app

    db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'help.db'}")
    await db_module.create_schema()
    store = BlobStore(str(tmp_path / "storage"))
    store.ensure_dirs()
    set_store(store)

    async with db_module.session_scope() as session:
        user = User(
            username="reader",
            password_hash=hash_password("a-long-enough-password"),
            is_admin=False,
        )
        session.add(user)
        await session.flush()
        full, prefix, token_hash = generate_token()
        session.add(
            ApiToken(
                user_id=user.id, name="t", prefix=prefix, token_hash=token_hash, scopes=["read"]
            )
        )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://registry.test"
    ) as c:
        c.headers.update({"authorization": f"Bearer {full}"})
        yield c

    await db_module.dispose_engine()
    set_store(None)  # type: ignore[arg-type]


class TestIndex:
    async def test_lists_the_shipped_pages(self, client):
        body = (await client.get("/api/help/pages")).json()
        slugs = [p["slug"] for p in body["pages"]]
        assert "installation" in slugs
        assert "configuration" in slugs

    async def test_reading_order_is_not_alphabetical(self, client):
        """Someone opening the docs for the first time wants Installation, not
        the API reference."""
        slugs = [p["slug"] for p in (await client.get("/api/help/pages")).json()["pages"]]
        assert slugs[0] == "installation"
        assert slugs.index("installation") < slugs.index("api")

    async def test_every_page_has_a_title(self, client):
        for page in (await client.get("/api/help/pages")).json()["pages"]:
            assert page["title"] and page["title"] != page["slug"]

    async def test_every_page_has_a_summary(self, client):
        for page in (await client.get("/api/help/pages")).json()["pages"]:
            assert page["summary"], f"{page['slug']} has no summary"

    async def test_summaries_are_prose_not_code(self, client):
        """Several pages open with a command or an ASCII diagram; quoting that
        as the summary tells a reader nothing."""
        for page in (await client.get("/api/help/pages")).json()["pages"]:
            summary = page["summary"] or ""
            assert not summary.startswith(("$", "docker ", "curl ", "|", "#", "```"))

    async def test_summaries_are_plain_text(self, client):
        """They render as a label in a list, not as markdown, so leaving the
        source syntax in shows readers `**Client setup**` verbatim."""
        for page in (await client.get("/api/help/pages")).json()["pages"]:
            summary = page["summary"] or ""
            assert "**" not in summary
            assert "`" not in summary
            assert "](" not in summary


class TestPage:
    async def test_returns_the_markdown(self, client):
        body = (await client.get("/api/help/pages/installation")).json()
        assert body["slug"] == "installation"
        assert body["markdown"].lstrip().startswith("# Installation")

    async def test_unknown_page_is_404(self, client):
        assert (await client.get("/api/help/pages/nope")).status_code == 404

    @pytest.mark.parametrize(
        "slug",
        [
            "../../../etc/passwd",
            "..%2f..%2fetc%2fpasswd",
            "....//....//etc/passwd",
            "installation/../../../../etc/passwd",
            "/etc/passwd",
        ],
    )
    async def test_traversal_cannot_escape_the_docs_directory(self, client, slug):
        """The slug is matched against the on-disk listing rather than joined
        onto a path, so there is nothing to escape from.

        These requests do not even reach the endpoint: the path normalises to
        something outside `/api/help/pages/` and lands on the SPA catch-all,
        which answers `index.html`. Either way the property under test is that
        no file outside the docs directory is ever returned, so that is what
        is asserted rather than a particular status code.
        """
        response = await client.get(f"/api/help/pages/{slug}")
        assert "root:x:" not in response.text
        assert "markdown" not in response.text
        if response.status_code == 200:
            # Fell through to the single-page app, not to a file read.
            assert response.headers["content-type"].startswith("text/html")
            assert response.text.lstrip().startswith("<!doctype html>")

    async def test_a_file_outside_the_index_is_not_served(self, client, monkeypatch, tmp_path):
        """Even a real markdown file is refused unless the index found it."""
        secret = tmp_path / "secrets.md"
        secret.write_text("# Secrets\n\ntoken: hunter2\n")
        monkeypatch.setattr(help_api, "docs_dir", lambda: tmp_path)
        help_api._index.cache_clear()
        try:
            listed = [p["slug"] for p in (await client.get("/api/help/pages")).json()["pages"]]
            assert listed == ["secrets"]  # sanity: the stub directory is in use
            assert (await client.get("/api/help/pages/installation")).status_code == 404
        finally:
            help_api._index.cache_clear()


class TestAccess:
    async def test_anonymous_callers_are_refused(self, tmp_path):
        """Reads can be anonymous; the docs describe the deployment, and the
        `?` that reaches them is inside the authenticated UI."""
        from app.main import app

        db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'anon.db'}")
        await db_module.create_schema()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://registry.test"
        ) as c:
            assert (await c.get("/api/help/pages")).status_code == 401
            assert (await c.get("/api/help/pages/installation")).status_code == 401
        await db_module.dispose_engine()
