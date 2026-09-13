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
        # Waiting forever for a connection turns a slow upstream into a total
        # outage: cached, purely local requests queue behind cold fetches that
        # are holding connections across the network. Fail fast instead.
        "pool_timeout": settings.db_pool_timeout_seconds,
        "connect_args": {
            "server_settings": {
                # A runaway query cannot pin a connection indefinitely, and an
                # abandoned transaction cannot hold row locks forever.
                "statement_timeout": str(int(settings.db_statement_timeout_seconds * 1000)),
                "idle_in_transaction_session_timeout": str(
                    int(settings.db_idle_transaction_timeout_seconds * 1000)
                ),
            }
        },
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
# Known limitation, stated plainly: this is not a migration framework. It
# handles additive columns and nothing else -- a drop, a rename, a type change
# or a backfill needs a real migration, applied by hand. If the schema starts
# needing those regularly, adopt alembic and baseline it against the current
# tables rather than extending this list.
ADDITIVE_COLUMNS: list[tuple[str, str, str]] = [
    ("upstreams", "web_url_template", "VARCHAR(512)"),
    ("device_authorizations", "requested_scopes", "JSONB"),
    ("package_versions", "has_fix", "BOOLEAN NOT NULL DEFAULT FALSE"),
    # INTEGER, not BIGINT: users.id is Integer, and a fresh database built by
    # create_all must end up with the same type as a migrated one.
    ("packages", "owner_user_id", "INTEGER"),
    ("upstreams", "name_patterns", "JSONB"),
    ("upstreams", "require_digest", "BOOLEAN NOT NULL DEFAULT TRUE"),
    ("users", "session_version", "INTEGER NOT NULL DEFAULT 0"),
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

            # Replicas all run this on boot. Concurrent CREATE ... IF NOT
            # EXISTS is not actually safe in Postgres -- two sessions can both
            # pass the existence check and one then fails on a duplicate --
            # so take a transaction-scoped advisory lock and let the others
            # wait. Released automatically when this transaction ends.
            await conn.execute(text("SELECT pg_advisory_xact_lock(4127905311)"))
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
                # Matches the index create_all builds from `index=True` on
                # Package.owner_user_id, so a migrated schema equals a fresh one.
                "CREATE INDEX IF NOT EXISTS ix_packages_owner_user_id "
                "ON packages (owner_user_id)",
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
                except Exception as exc:
                    # Loud, and named. A missing trigram index degrades search
                    # to a sequential scan over a table that can hold most of
                    # PyPI, and a warning nobody reads is how that goes
                    # unnoticed for months.
                    log.error(
                        "COULD NOT CREATE INDEX -- search and log pruning will be "
                        "slow until this is fixed. Statement: %s. Error: %s",
                        stmt.split(" ON ")[0],
                        exc,
                    )


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
