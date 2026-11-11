"""Daily download rollups and the dashboard figures read from them.

The figures must be the same whatever state the rollup is in -- never run,
part way through a backfill, or current -- because the dashboard reads closed
days from ``download_daily`` and the rest from the raw log.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest_asyncio
from sqlalchemy import func, select

from app import db as db_module
from app.models import DownloadDaily, DownloadLog
from app.services import rollup


@pytest_asyncio.fixture
async def db(tmp_path):
    pg_url = os.environ.get("DOCKER_TEST_DATABASE_URL")
    if pg_url:
        db_module.init_engine(pg_url)
        from app.models import Base

        async with db_module.get_engine().begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    else:
        db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'rollup.db'}")
    await db_module.create_schema()
    yield
    await db_module.dispose_engine()


NOW = datetime.now(UTC)


async def seed() -> None:
    """Five days of traffic: two packages, three users plus anonymous."""
    rows = []
    for days_ago in range(5):
        base = rollup.today() - timedelta(days=days_ago) + timedelta(hours=1)
        if days_ago == 0:
            base = min(base, NOW - timedelta(minutes=1))
        for i in range(10 + days_ago):
            rows.append(
                DownloadLog(
                    ts=base + timedelta(seconds=i),
                    ecosystem="npm" if i % 3 else "pypi",
                    package_name="lodash" if i % 2 else "requests",
                    kind="file" if i % 4 == 0 else "metadata",
                    user_id=(i % 3) or None,
                    bytes_sent=100 * i,
                    cache_hit=i % 5 != 0,
                )
            )
    async with db_module.session_scope() as session:
        session.add_all(rows)


async def figures(days: int = 7) -> tuple:
    async with db_module.session_scope() as session:
        totals = await rollup.totals(session, days)
        top = [
            tuple(r.values())
            for r in await rollup.top_packages(session, days, 10, ecosystem=None, kind=None)
        ]
        top_files = [
            tuple(r.values())
            for r in await rollup.top_packages(session, days, 10, ecosystem="npm", kind="file")
        ]
        timeline = sorted(
            (rollup.day_label(r.day), r.ecosystem, int(r.downloads), int(r.bytes))
            for r in await rollup.timeline(session, days)
        )
    return totals, sorted(top), sorted(top_files), timeline


async def test_figures_are_identical_before_during_and_after_the_rollup(db):
    await seed()
    before = await figures()
    assert before[0]["total"] == sum(10 + d for d in range(5))

    # Part way: only the oldest days rolled.
    async with db_module.session_scope() as session:
        for days_ago in (4, 3):
            await rollup.roll_day(session, rollup.today() - timedelta(days=days_ago))
        await rollup._set_watermark(session, rollup.today() - timedelta(days=3))
    assert await figures() == before

    async with db_module.session_scope() as session:
        result = await rollup.run_rollup(session, now=NOW + timedelta(hours=1))
    # Everything but today, which has not closed.
    assert result["days"] == 2
    assert await figures() == before

    async with db_module.session_scope() as session:
        rolled_days = (
            await session.execute(select(func.count(func.distinct(DownloadDaily.day))))
        ).scalar_one()
    assert rolled_days == 4


async def test_a_first_run_backfills_and_a_rerun_changes_nothing(db):
    await seed()
    before = await figures()
    async with db_module.session_scope() as session:
        first = await rollup.run_rollup(session)
    assert first["days"] == 4
    async with db_module.session_scope() as session:
        rows = (await session.execute(select(func.count(DownloadDaily.id)))).scalar_one()
        again = await rollup.run_rollup(session)
        rows_again = (await session.execute(select(func.count(DownloadDaily.id)))).scalar_one()
    assert again["days"] == 0
    assert rows == rows_again
    assert await figures() == before


async def test_rolling_a_day_twice_replaces_it(db):
    await seed()
    day = rollup.today() - timedelta(days=2)
    async with db_module.session_scope() as session:
        first = await rollup.roll_day(session, day)
        second = await rollup.roll_day(session, day)
        stored = (
            await session.execute(
                select(func.sum(DownloadDaily.downloads)).where(DownloadDaily.day == day)
            )
        ).scalar_one()
    assert first == second
    assert stored == 12


async def test_distinct_users_ignore_anonymous_requests(db):
    await seed()
    async with db_module.session_scope() as session:
        await rollup.run_rollup(session)
        top = await rollup.top_packages(session, 7, 10, ecosystem=None, kind=None)
    users = {(r["ecosystem"], r["name"]): r["distinct_users"] for r in top}
    # Users 1 and 2 only ever come from npm (i % 3 != 0); every pypi request
    # in the seed is anonymous, which must not count as a user.
    assert users[("npm", "lodash")] == 2
    assert users[("pypi", "lodash")] == 0


async def test_a_day_is_not_rolled_until_it_has_settled(db):
    await seed()
    just_after_midnight = rollup.today() + timedelta(minutes=5)
    async with db_module.session_scope() as session:
        await rollup.run_rollup(session, now=just_after_midnight)
        mark = await rollup.rolled_through(session)
    # Yesterday ended five minutes ago: still inside SETTLE, so not rolled.
    assert mark == rollup.today() - timedelta(days=2)


async def test_an_empty_log_sets_a_starting_point(db):
    async with db_module.session_scope() as session:
        result = await rollup.run_rollup(session)
        mark = await rollup.rolled_through(session)
    assert result == {"days": 0}
    assert mark == rollup.today() - timedelta(days=1)
