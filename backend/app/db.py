"""Async engine / session plumbing."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from .config import settings
from .models import Base

log = logging.getLogger(__name__)

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _engine_kwargs(url: str) -> dict:
    if url.startswith("sqlite"):
        # aiosqlite has no real pooling story; NullPool keeps tests deterministic.
        return {"poolclass": NullPool}
    return {
        "pool_size": settings.db_pool_size,
        "max_overflow": settings.db_max_overflow,
        "pool_pre_ping": True,
        "pool_recycle": 1800,
    }


def init_engine(url: str | None = None) -> AsyncEngine:
    global _engine, _sessionmaker
    target = url or settings.database_url
    _engine = create_async_engine(target, echo=settings.db_echo, future=True, **_engine_kwargs(target))
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)
    return _engine


def get_engine() -> AsyncEngine:
    if _engine is None:
        init_engine()
    assert _engine is not None
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    if _sessionmaker is None:
        init_engine()
    assert _sessionmaker is not None
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency."""
    async with get_sessionmaker()() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """For background tasks, which have no request scope."""
    async with get_sessionmaker()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# Columns added after the first release. There is no migration framework here,
# so new *additive* columns are applied at startup; anything destructive (a drop,
# a rename, a type change) would need a real migration and is deliberately not
# handled by this mechanism.
ADDITIVE_COLUMNS: list[tuple[str, str, str]] = [
    ("upstreams", "web_url_template", "VARCHAR(512)"),
]


async def create_schema() -> None:
    """Create tables, apply additive column migrations, and build the
    Postgres-only accelerators.

    Kept idempotent so container restarts are safe.
    """
    engine = get_engine()
    async with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            from sqlalchemy import text

            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
        await conn.run_sync(Base.metadata.create_all)

        if engine.dialect.name == "postgresql":
            from sqlalchemy import text

            for table, column, coltype in ADDITIVE_COLUMNS:
                await conn.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {coltype}")
                )

            # Trigram index powers substring package search without a full scan.
            for stmt in (
                "CREATE INDEX IF NOT EXISTS ix_package_name_trgm "
                "ON packages USING gin (normalized_name gin_trgm_ops)",
                "CREATE INDEX IF NOT EXISTS ix_package_desc_trgm "
                "ON packages USING gin (description gin_trgm_ops)",
                # BRIN is ~1000x smaller than btree for an append-only time column.
                "CREATE INDEX IF NOT EXISTS ix_download_log_ts_brin "
                "ON download_log USING brin (ts) WITH (pages_per_range = 32)",
                "CREATE INDEX IF NOT EXISTS ix_audit_log_ts_brin "
                "ON audit_log USING brin (ts) WITH (pages_per_range = 32)",
            ):
                try:
                    await conn.execute(text(stmt))
                except Exception as exc:  # pragma: no cover - index creation is best effort
                    log.warning("index creation skipped: %s", exc)


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
