"""The live tail of package requests.

Served as server-sent events, tailing the table by primary key. The
interesting properties are that it does not hold a pooled connection open for
the life of the page, that it respects the same filters as the paged list,
and that it cannot be opened without limit.
"""

from __future__ import annotations

import asyncio
import inspect
import json

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import db as db_module
from app.api.admin import insights
from app.core.security import generate_token, hash_password
from app.models import ApiToken, DownloadLog, User
from app.services.storage import BlobStore, set_store


@pytest_asyncio.fixture
async def client(tmp_path):
    from app.main import app

    db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'stream.db'}")
    await db_module.create_schema()
    store = BlobStore(str(tmp_path / "storage"))
    store.ensure_dirs()
    set_store(store)

    async with db_module.session_scope() as session:
        user = User(
            username="root",
            password_hash=hash_password("a-long-enough-password"),
            is_admin=True,
        )
        session.add(user)
        await session.flush()
        full, prefix, token_hash = generate_token()
        session.add(
            ApiToken(
                user_id=user.id,
                name="t",
                prefix=prefix,
                token_hash=token_hash,
                scopes=["read", "admin"],
            )
        )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://registry.test"
    ) as c:
        c.headers.update({"authorization": f"Bearer {full}"})
        yield c

    await db_module.dispose_engine()
    set_store(None)  # type: ignore[arg-type]


async def record(**kwargs):
    """Write a request row the way the batching recorder eventually does."""
    defaults = {
        "ecosystem": "npm",
        "package_name": "left-pad",
        "version": None,
        "filename": None,
        "kind": "metadata",
        "username": None,
        "ip": "10.0.0.1",
        "user_agent": "curl/8",
        "bytes_sent": 0,
        "cache_hit": False,
        "status": 200,
        "duration_ms": None,
    }
    async with db_module.session_scope() as session:
        session.add(DownloadLog(**{**defaults, **kwargs}))


def parse_events(text: str) -> list[dict]:
    """Pull the payloads out of an SSE body."""
    rows: list[dict] = []
    for block in text.split("\n\n"):
        if "event: downloads" not in block:
            continue
        for line in block.splitlines():
            if line.startswith("data: "):
                rows.extend(json.loads(line[6:]))
    return rows


@pytest.fixture(autouse=True)
def brisk_stream(monkeypatch):
    """Shrink the tail's timers so tests run on their own clock.

    `STREAM_MAX_SECONDS` is the important one. An ASGI transport in-process
    never delivers `http.disconnect`, so `request.is_disconnected()` stays
    False and the only thing that ends the generator is its own age cap --
    which is exactly why that cap exists, and why reading to the end here is
    deterministic rather than a race.
    """
    monkeypatch.setattr(insights, "STREAM_POLL_SECONDS", 0.1)
    monkeypatch.setattr(insights, "STREAM_HEARTBEAT_SECONDS", 0.2)
    monkeypatch.setattr(insights, "STREAM_MAX_SECONDS", 1.2)


async def read_stream(client, url):
    """Open the tail and return everything it emitted before it aged out."""
    async with client.stream("GET", url) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        return "".join([chunk async for chunk in response.aiter_text()])


class TestTail:
    """Rows are seeded before the tail opens and read back with `since_id`.

    Writing *during* an open stream is what a browser sees, and it is
    verified against a running server; it cannot be tested through an
    in-process ASGI transport, which runs the endpoint to completion before
    handing back a body rather than interleaving with the writer.
    """

    async def test_emits_rows_after_the_cursor(self, client):
        await record(package_name="chalk")
        body = await read_stream(client, "/api/admin/downloads/stream?since_id=0")
        assert [r["package_name"] for r in parse_events(body)] == ["chalk"]

    async def test_does_not_replay_history_by_default(self, client):
        """The page already lists what came before; a fresh tail starts at
        now, or every reconnect would duplicate the table."""
        await record(package_name="ancient")
        body = await read_stream(client, "/api/admin/downloads/stream")
        assert parse_events(body) == []
        assert "tailing from #1" in body

    async def test_resuming_loses_nothing_recorded_during_the_gap(self, client):
        """What a client does after the tail ages out: it names the last row
        it saw, and gets everything since."""
        await record(package_name="seen")
        async with db_module.session_scope() as session:
            from sqlalchemy import func, select

            last_seen = (await session.execute(select(func.max(DownloadLog.id)))).scalar_one()
        await record(package_name="missed-1")
        await record(package_name="missed-2")

        body = await read_stream(
            client, f"/api/admin/downloads/stream?since_id={last_seen}"
        )
        assert [r["package_name"] for r in parse_events(body)] == ["missed-1", "missed-2"]

    async def test_filters_apply_to_the_stream(self, client):
        await record(ecosystem="npm", package_name="chalk")
        await record(ecosystem="pypi", package_name="requests")
        body = await read_stream(
            client, "/api/admin/downloads/stream?ecosystem=pypi&since_id=0"
        )
        assert [r["package_name"] for r in parse_events(body)] == ["requests"]

    async def test_carries_the_fields_the_table_shows(self, client):
        await record(
            package_name="left-pad",
            version="1.3.0",
            filename="left-pad-1.3.0.tgz",
            kind="file",
            bytes_sent=3619,
            cache_hit=True,
            duration_ms=58,
        )
        body = await read_stream(client, "/api/admin/downloads/stream?since_id=0")
        (row,) = parse_events(body)
        assert row["version"] == "1.3.0"
        assert row["bytes_sent"] == 3619
        assert row["cache_hit"] is True
        assert row["duration_ms"] == 58
        assert row["ts"]


class TestLimits:
    async def test_concurrent_tails_are_capped(self, client, monkeypatch):
        """Each tail wakes on a timer and takes a connection for a moment;
        an unbounded number would quietly eat the pool."""
        monkeypatch.setattr(insights, "MAX_DOWNLOAD_STREAMS", 2)

        opened: list = []

        async def hold():
            async with client.stream("GET", "/api/admin/downloads/stream") as r:
                opened.append(r.status_code)
                # Read to the end so the slot is released by the generator
                # rather than by a cancellation.
                async for _ in r.aiter_text():
                    pass

        tasks = [asyncio.create_task(hold()) for _ in range(2)]
        await asyncio.sleep(0.5)
        refused = await client.get("/api/admin/downloads/stream")
        assert refused.status_code == 429

        await asyncio.gather(*tasks)
        assert opened == [200, 200]

    async def test_a_finished_tail_frees_its_slot(self, client):
        assert insights._active_streams == 0
        await read_stream(client, "/api/admin/downloads/stream")
        assert insights._active_streams == 0

    async def test_a_tail_ages_out_and_says_so(self, client):
        """A page left open in a forgotten tab should not hold a slot for
        ever. The client reconnects on this event."""
        body = await read_stream(client, "/api/admin/downloads/stream")
        assert "event: expired" in body


class TestConnectionUse:
    def test_the_tail_does_not_hold_the_request_session(self):
        """A response that lives as long as the operator leaves the page open
        must not be holding one of the pool's connections while it does."""
        source = inspect.getsource(insights.stream_downloads)
        assert "session_scope()" in source, "the tail should open its own short sessions"
        assert "Depends(get_session)" not in source
