"""Daily download rollups, and the dashboard figures read from them.

``download_log`` holds one row per request. Aggregating it on every
dashboard load meant scanning millions of rows several times over; the
figures below read one row per (day, package, kind) for every closed
day, and the raw log only for today, which the ``ts`` index keeps small.

Rolling up is idempotent: a day's rows are replaced wholesale, and a
watermark (the last day rolled) is kept in the settings table so a restart
or a second replica picks up where the last pass stopped. Days roll up only
once they have been over for ``SETTLE`` -- the request recorder buffers
writes for a few seconds, and a day rolled before its last rows landed would
lose them.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import Integer, and_, case, delete, func, insert, literal, select, tuple_, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import DownloadDaily, DownloadDailyUser, DownloadLog, Setting

log = logging.getLogger(__name__)

WATERMARK_KEY = "download_rollup"
#: A day is rolled up this long after it ends.
SETTLE = timedelta(minutes=15)
#: Days rolled per housekeeping pass, so the first pass after an upgrade
#: (which backfills up to the log's whole retention) cannot run for an hour.
MAX_DAYS_PER_PASS = 400
TIME_BUDGET_SECONDS = 120.0


def day_start(when: datetime) -> datetime:
    when = when if when.tzinfo else when.replace(tzinfo=UTC)
    when = when.astimezone(UTC)
    return when.replace(hour=0, minute=0, second=0, microsecond=0)


def today() -> datetime:
    return day_start(datetime.now(UTC))


async def _watermark(session: AsyncSession) -> datetime | None:
    row = await session.get(Setting, WATERMARK_KEY)
    if row is None or not isinstance(row.value, dict) or not row.value.get("rolled_through"):
        return None
    return datetime.fromisoformat(row.value["rolled_through"])


async def _set_watermark(session: AsyncSession, day: datetime) -> None:
    row = await session.get(Setting, WATERMARK_KEY)
    value = {"rolled_through": day.isoformat()}
    if row is None:
        session.add(Setting(key=WATERMARK_KEY, value=value, updated_by="housekeeping"))
    else:
        row.value = value


async def rolled_through(session: AsyncSession) -> datetime | None:
    """The last day whose rollup is complete, or None before the first pass."""
    return await _watermark(session)


async def roll_day(session: AsyncSession, day: datetime) -> int:
    """(Re)build one day's rollup from the raw log. Returns the rows written."""
    start = day_start(day)
    end = start + timedelta(days=1)
    await session.execute(delete(DownloadDaily).where(DownloadDaily.day == start))
    await session.execute(delete(DownloadDailyUser).where(DownloadDailyUser.day == start))
    await session.execute(
        insert(DownloadDailyUser).from_select(
            ["day", "ecosystem", "package_name", "user_id"],
            select(
                literal(start, DownloadDailyUser.day.type).label("day"),
                DownloadLog.ecosystem,
                DownloadLog.package_name,
                DownloadLog.user_id,
            )
            .where(
                DownloadLog.ts >= start,
                DownloadLog.ts < end,
                DownloadLog.user_id.is_not(None),
            )
            .distinct()
        )
    )
    source = (
        select(
            literal(start, DownloadDaily.day.type).label("day"),
            DownloadLog.ecosystem,
            DownloadLog.package_name,
            DownloadLog.kind,
            func.count().label("downloads"),
            func.coalesce(func.sum(DownloadLog.bytes_sent), 0).label("bytes_sent"),
            func.sum(case((DownloadLog.cache_hit.is_(True), 1), else_=0)).label("cache_hits"),
        )
        .where(DownloadLog.ts >= start, DownloadLog.ts < end)
        .group_by(DownloadLog.ecosystem, DownloadLog.package_name, DownloadLog.kind)
    )
    result = await session.execute(
        insert(DownloadDaily).from_select(
            [
                "day",
                "ecosystem",
                "package_name",
                "kind",
                "downloads",
                "bytes_sent",
                "cache_hits",
            ],
            source,
        )
    )
    return result.rowcount or 0


async def run_rollup(session: AsyncSession, now: datetime | None = None) -> dict:
    """Roll up every closed, settled day after the watermark."""
    now = now or datetime.now(UTC)
    last_closed = day_start(now - SETTLE) - timedelta(days=1)
    mark = await _watermark(session)
    if mark is None:
        oldest = (await session.execute(select(func.min(DownloadLog.ts)))).scalar_one_or_none()
        if oldest is None:
            # Nothing logged yet: start from yesterday, so today rolls next.
            await _set_watermark(session, last_closed)
            await session.commit()
            return {"days": 0}
        start = day_start(oldest)
        retention = settings.download_log_retention_days
        if retention > 0:
            start = max(start, day_start(now) - timedelta(days=retention))
    else:
        start = mark + timedelta(days=1)

    days = 0
    rows = 0
    started = time.monotonic()
    day = start
    while day <= last_closed and days < MAX_DAYS_PER_PASS:
        rows += await roll_day(session, day)
        await _set_watermark(session, day)
        await session.commit()
        days += 1
        day += timedelta(days=1)
        if time.monotonic() - started > TIME_BUDGET_SECONDS:
            break
    return {"days": days, "rows": rows}


async def prune_rollups(session: AsyncSession) -> int:
    """Rollups are small, so they outlive the raw log: three times its
    retention, and at least two years."""
    retention = settings.download_log_retention_days
    if retention <= 0:
        return 0
    keep = max(retention * 3, 730)
    cutoff = today() - timedelta(days=keep)
    result = await session.execute(delete(DownloadDaily).where(DownloadDaily.day < cutoff))
    await session.execute(delete(DownloadDailyUser).where(DownloadDailyUser.day < cutoff))
    return result.rowcount or 0


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class Window:
    """The last ``days`` days including today, split at the rollup watermark.

    Days up to ``rolled_through`` come from ``download_daily``; everything
    after (today, and any day the rollup has not reached yet) comes from the
    raw log, so the figures are complete whatever state the rollup is in.
    """

    since: datetime
    raw_from: datetime

    @classmethod
    async def last(cls, session: AsyncSession, days: int) -> Window:
        since = today() - timedelta(days=days - 1)
        mark = await rolled_through(session)
        raw_from = since if mark is None else max(since, mark + timedelta(days=1))
        return cls(since=since, raw_from=raw_from)


def _union(window: Window, *, ecosystem: str | None = None, kind: str | None = None):
    """Rollup rows and raw rows in one shape: day, ecosystem, package_name,
    kind, downloads, bytes_sent, cache_hits."""
    from ..db import get_engine

    if get_engine().dialect.name == "postgresql":
        raw_day = func.date_trunc("day", DownloadLog.ts)
    else:
        raw_day = func.date(DownloadLog.ts)
    rolled_conditions = [DownloadDaily.day >= window.since, DownloadDaily.day < window.raw_from]
    raw_conditions = [DownloadLog.ts >= window.raw_from]
    if ecosystem is not None:
        rolled_conditions.append(DownloadDaily.ecosystem == ecosystem)
        raw_conditions.append(DownloadLog.ecosystem == ecosystem)
    if kind is not None:
        rolled_conditions.append(DownloadDaily.kind == kind)
        raw_conditions.append(DownloadLog.kind == kind)
    rolled = select(
        DownloadDaily.day.label("day"),
        DownloadDaily.ecosystem,
        DownloadDaily.package_name,
        DownloadDaily.kind,
        DownloadDaily.downloads,
        DownloadDaily.bytes_sent,
        DownloadDaily.cache_hits,
    ).where(and_(*rolled_conditions))
    raw = select(
        raw_day.label("day"),
        DownloadLog.ecosystem,
        DownloadLog.package_name,
        DownloadLog.kind,
        literal(1, Integer).label("downloads"),
        func.coalesce(DownloadLog.bytes_sent, 0).label("bytes_sent"),
        case((DownloadLog.cache_hit.is_(True), 1), else_=0).label("cache_hits"),
    ).where(and_(*raw_conditions))
    return union_all(rolled, raw).subquery("dl")


async def totals(session: AsyncSession, days: int) -> dict:
    window = await Window.last(session, days)
    u = _union(window)
    row = (
        await session.execute(
            select(
                func.coalesce(func.sum(u.c.downloads), 0),
                func.coalesce(func.sum(case((u.c.kind == "file", u.c.downloads), else_=0)), 0),
                func.coalesce(func.sum(u.c.bytes_sent), 0),
                func.coalesce(func.sum(u.c.cache_hits), 0),
            )
        )
    ).one()
    total, artifacts, bytes_sent, hits = (int(v or 0) for v in row)
    return {"total": total, "artifacts": artifacts, "bytes_served": bytes_sent, "cache_hits": hits}


async def top_packages(
    session: AsyncSession, days: int, limit: int, *, ecosystem: str | None, kind: str | None
) -> list[dict]:
    window = await Window.last(session, days)
    u = _union(window, ecosystem=ecosystem, kind=kind)
    downloads = func.sum(u.c.downloads).label("downloads")
    rows = (
        await session.execute(
            select(
                u.c.ecosystem,
                u.c.package_name,
                downloads,
                func.coalesce(func.sum(u.c.bytes_sent), 0).label("bytes"),
            )
            .group_by(u.c.ecosystem, u.c.package_name)
            .order_by(downloads.desc())
            .limit(limit)
        )
    ).all()
    if not rows:
        return []
    # Distinct users for just these packages: closed days from the per-day
    # user rollup through its (ecosystem, package_name, day) key, the rest
    # from the raw log. Unlike the counts, these cannot be summed per day.
    # The kind filter is not applied to closed days (the user rollup has no
    # kind); it only ever narrows a count the dashboard does not show split.
    wanted = [(r.ecosystem, r.package_name) for r in rows]
    raw_conditions = [
        DownloadLog.ts >= window.raw_from,
        DownloadLog.user_id.is_not(None),
        tuple_(DownloadLog.ecosystem, DownloadLog.package_name).in_(wanted),
    ]
    if kind is not None:
        raw_conditions.append(DownloadLog.kind == kind)
    pairs = union_all(
        select(
            DownloadDailyUser.ecosystem, DownloadDailyUser.package_name, DownloadDailyUser.user_id
        ).where(
            DownloadDailyUser.day >= window.since,
            DownloadDailyUser.day < window.raw_from,
            tuple_(DownloadDailyUser.ecosystem, DownloadDailyUser.package_name).in_(wanted),
        ),
        select(DownloadLog.ecosystem, DownloadLog.package_name, DownloadLog.user_id).where(
            and_(*raw_conditions)
        ),
    ).subquery("pairs")
    users = {
        (eco, name): count
        for eco, name, count in (
            await session.execute(
                select(
                    pairs.c.ecosystem,
                    pairs.c.package_name,
                    func.count(func.distinct(pairs.c.user_id)),
                ).group_by(pairs.c.ecosystem, pairs.c.package_name)
            )
        ).all()
    }
    return [
        {
            "ecosystem": r.ecosystem,
            "name": r.package_name,
            "downloads": int(r.downloads or 0),
            "bytes": int(r.bytes or 0),
            "distinct_users": users.get((r.ecosystem, r.package_name), 0),
        }
        for r in rows
    ]


def day_label(value) -> str:
    """``YYYY-MM-DD`` for a day bucket, whichever side of the union (and
    whichever database) produced it."""
    if isinstance(value, datetime):
        return value.date().isoformat()
    return str(value)[:10]


async def timeline(session: AsyncSession, days: int) -> list:
    window = await Window.last(session, days)
    u = _union(window)
    return list(
        (
            await session.execute(
                select(
                    u.c.day,
                    u.c.ecosystem,
                    func.sum(u.c.downloads).label("downloads"),
                    func.coalesce(func.sum(u.c.bytes_sent), 0).label("bytes"),
                )
                .group_by(u.c.day, u.c.ecosystem)
                .order_by(u.c.day)
            )
        ).all()
    )
