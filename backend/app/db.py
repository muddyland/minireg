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


# Known limitation, stated plainly: this is not a migration framework. It
# handles additive columns and the idempotent backfills in DATA_FIXES, and
# nothing else -- a drop, a rename or a type change needs a real migration,
# applied by hand. If the schema starts needing those regularly, adopt
# alembic and baseline it against the current tables rather than extending
# this list.
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
    ("api_tokens", "docker_repo_prefixes", "JSONB"),
    ("users", "publish_via_oidc_admin", "BOOLEAN NOT NULL DEFAULT FALSE"),
    ("package_versions", "has_advisories", "BOOLEAN NOT NULL DEFAULT FALSE"),
    ("package_versions", "is_malicious", "BOOLEAN NOT NULL DEFAULT FALSE"),
]

# Backfills for the columns above, run after them on every start. Each must be
# idempotent (it runs again on every boot) and portable SQL (SQLite runs it
# too). Keep the WHERE narrow so a re-run touches no rows.
DATA_FIXES: list[str] = [
    # An OIDC login used to link a local account by email but leave its
    # password in place, so the password kept working beside SSO -- past an
    # IdP group removal or a disabled IdP account. Linked accounts sign in
    # through the provider only; their old password and every session that
    # may have come from it go.
    "UPDATE users SET password_hash = NULL, session_version = session_version + 1 "
    "WHERE provider = 'oidc' AND password_hash IS NOT NULL",
    # has_advisories: a version scanned before the column existed has its
    # advisories in package_vulnerabilities. Only a 0.0 maximum consults the
    # flag, so this is what keeps "advisories that all score 0.0" from
    # reading as clean after the upgrade.
    "UPDATE package_versions SET has_advisories = TRUE "
    "WHERE has_advisories = FALSE "
    "AND id IN (SELECT version_id FROM package_vulnerabilities)",
    # is_malicious: versions linked to a malicious-package record. A record
    # filed under another id with only a MAL-* alias is caught by the
    # version's next rescan instead.
    "UPDATE package_versions SET is_malicious = TRUE "
    "WHERE is_malicious = FALSE AND id IN ("
    "SELECT pv.version_id FROM package_vulnerabilities pv "
    "JOIN vulnerabilities v ON v.id = pv.vulnerability_id "
    "WHERE v.id LIKE 'MAL-%' OR v.severity_type = 'MALICIOUS')",
]


async def create_schema() -> None:
    """Create tables, apply additive column migrations, and build the
    Postgres-only accelerators.

    Kept idempotent so container restarts are safe.
    """
    from sqlalchemy import text

    engine = get_engine()
    async with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            # Replicas all run this on boot. Concurrent CREATE ... IF NOT
            # EXISTS is not actually safe in Postgres -- two sessions can both
            # pass the existence check and one then fails on a duplicate --
            # so take a transaction-scoped advisory lock and let the others
            # wait. Released automatically when this transaction ends.
            await conn.execute(text("SELECT pg_advisory_xact_lock(4127905311)"))
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
        await conn.run_sync(Base.metadata.create_all)

        if engine.dialect.name == "postgresql":
            for table, column, coltype in ADDITIVE_COLUMNS:
                await conn.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {coltype}")
                )

        if engine.dialect.name == "postgresql":
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

        # Backfills run on every dialect: the SQL is portable, and a fresh
        # database (where create_all already made the columns) has nothing
        # for them to touch.
        from sqlalchemy import text

        for fix in DATA_FIXES:
            await conn.execute(text(fix))


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
