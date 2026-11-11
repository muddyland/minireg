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
# handles additive columns, the idempotent SQL backfills in DATA_FIXES and
# the small row repairs in DATA_REPAIRS, and nothing else -- a drop, a
# rename, a type change or a large backfill needs a real migration, applied
# by hand. If the schema starts needing those regularly, adopt alembic and
# baseline it against the current tables rather than extending this list.
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
    ("docker_repo_manifests", "push_block_reason", "TEXT"),
    ("upstreams", "is_public", "BOOLEAN"),
    ("packages", "first_published_at", "TIMESTAMP WITH TIME ZONE"),
]

# Backfills for the columns above, run after them on every start. Each must be
# idempotent (it runs again on every boot) and portable SQL (SQLite runs it
# too). Keep the WHERE narrow so a re-run touches no rows.
DATA_FIXES: list[str] = [
    # first_published_at: packages cached before the column existed get their
    # oldest upstream release, when every release has a date (an undated one
    # means the package predates dates, so it stays NULL: not new). The next
    # refresh from the upstream replaces this with npm's `time.created`.
    "UPDATE packages SET first_published_at = ("
    "SELECT MIN(v.published_at) FROM package_versions v "
    "WHERE v.package_id = packages.id AND v.is_local = FALSE) "
    "WHERE first_published_at IS NULL AND is_local = FALSE "
    "AND EXISTS (SELECT 1 FROM package_versions v "
    "WHERE v.package_id = packages.id AND v.is_local = FALSE) "
    "AND NOT EXISTS (SELECT 1 FROM package_versions v "
    "WHERE v.package_id = packages.id AND v.is_local = FALSE AND v.published_at IS NULL)",
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
    # The push verdict moved from the shared manifest row to the link of a
    # local repository (DockerRepoManifest.push_block_reason). Carry existing
    # verdicts over to the local repositories holding the digest -- never to
    # upstream ones, where the shared row's verdict refused pulls the push
    # rules have no say over -- then clear the old column so it cannot be
    # carried over again after a policy change cleared the new one.
    "UPDATE docker_repo_manifests SET push_block_reason = ("
    " SELECT m.policy_block_reason FROM docker_manifests m"
    " WHERE m.id = docker_repo_manifests.manifest_id)"
    " WHERE push_block_reason IS NULL"
    " AND manifest_id IN (SELECT id FROM docker_manifests WHERE policy_block_reason IS NOT NULL)"
    " AND repository_id IN (SELECT id FROM docker_repositories WHERE is_local = TRUE)",
    "UPDATE docker_manifests SET policy_block_reason = NULL WHERE policy_block_reason IS NOT NULL",
]


# --------------------------------------------------------------------------- #
# Data repairs
#
# Rows an older release wrote in a shape the code no longer produces. Each
# repair runs on every boot, on SQLite and PostgreSQL alike, so it must be
# idempotent (a no-op once applied), portable, and cheap when there is
# nothing left to do: select the few affected rows first, then fix them.
# --------------------------------------------------------------------------- #
async def _repair_npm_scoped_tarball_names(conn) -> None:
    """npm files stored under the publish attachment's key, scope included.

    libnpmpublish keys a scoped tarball ``@scope/pkg-1.0.0.tgz``, and the
    publish path used to store that key as the filename. The tarball URL
    rendered from it could never be fetched, so these versions were
    uninstallable. The canonical name (:func:`npm_tarball_filename`) is the
    part after the slash. A version that somehow already has a file by that
    name is left alone rather than tripping the unique constraint.
    """
    from sqlalchemy import text

    rows = (
        await conn.execute(
            text(
                "SELECT f.id, f.filename FROM package_files f "
                "JOIN package_versions v ON v.id = f.version_id "
                "JOIN packages p ON p.id = v.package_id "
                "WHERE p.ecosystem = 'npm' AND f.filename LIKE '%/%'"
            )
        )
    ).all()
    for file_id, filename in rows:
        canonical = filename.rsplit("/", 1)[-1]
        await conn.execute(
            text(
                "UPDATE package_files SET filename = :canonical WHERE id = :id "
                "AND NOT EXISTS (SELECT 1 FROM package_files other "
                "WHERE other.version_id = package_files.version_id "
                "AND other.filename = :canonical)"
            ),
            {"canonical": canonical, "id": file_id},
        )
        log.warning("repaired npm tarball filename %r -> %r", filename, canonical)


#: Settings row recording that the one-shot npm case repair has run.
NPM_CASE_REPAIR_MARKER = "repair:npm-case-sensitive-names"


async def _repair_npm_case_folded_keys(conn) -> None:
    """Re-key npm packages stored under a lowercased name; drop case-sibling rows.

    npm names used to be lowercased into ``normalized_name``. They are
    case-sensitive now (see ``normalize_npm_name``), so:

    1. A row whose display name has capitals (``JSONStream`` under the key
       ``jsonstream``) is re-keyed to the name it was stored with, which is
       the spelling its upstream document declared. Its cached copy keeps
       serving; validators and freshness are reset so the next request
       re-reads it from upstream, replacing a document that may have been
       written by the other spelling.
    2. While the key was shared, a refresh of one spelling merged its files
       and versions into the other's row (`Q` into `q`). A non-local file
       whose name differs from the row's canonical tarball name *only in
       case* came from the sibling, and goes; a version left with no file of
       its own goes too. The next refresh restores anything genuine.

    A row is not re-keyed when the target key is already taken. Runs once,
    recorded in the settings table, because step 2 scans every npm file.
    """
    from datetime import UTC, datetime

    from sqlalchemy import and_, delete, func, insert, or_, select, update

    from .core.naming import npm_tarball_filename
    from .models import (
        Blob,
        DistTag,
        Ecosystem,
        Package,
        PackageFile,
        PackageVersion,
        PackageVulnerability,
        Setting,
    )

    if (
        await conn.execute(select(Setting.key).where(Setting.key == NPM_CASE_REPAIR_MARKER))
    ).first() is not None:
        return

    packages = Package.__table__
    is_npm = packages.c.ecosystem == Ecosystem.npm
    rekeyed = 0
    for package_id, name, normalized in (
        await conn.execute(
            select(packages.c.id, packages.c.name, packages.c.normalized_name).where(
                is_npm, packages.c.name != packages.c.normalized_name
            )
        )
    ).all():
        target = name.strip()
        if target == normalized or target.lower() != normalized:
            continue
        taken = (
            await conn.execute(
                select(packages.c.id).where(is_npm, packages.c.normalized_name == target)
            )
        ).first()
        if taken is not None:
            log.warning("npm case repair: %r already exists; leaving %r", target, normalized)
            continue
        await conn.execute(
            update(packages)
            .where(packages.c.id == package_id)
            .values(normalized_name=target, cached_at=None, cached_etag=None)
        )
        rekeyed += 1

    files = PackageFile.__table__
    versions = PackageVersion.__table__
    candidates = (
        await conn.execute(
            select(packages.c.id, packages.c.name)
            .distinct()
            .select_from(
                packages.join(versions, versions.c.package_id == packages.c.id).join(
                    files, files.c.version_id == versions.c.id
                )
            )
            .where(
                is_npm,
                versions.c.is_local.is_(False),
                or_(
                    packages.c.name != func.lower(packages.c.name),
                    files.c.filename != func.lower(files.c.filename),
                ),
            )
        )
    ).all()
    purged_files = purged_versions = 0
    for package_id, name in candidates:
        rows = (
            await conn.execute(
                select(
                    versions.c.id,
                    versions.c.version,
                    files.c.id,
                    files.c.filename,
                    files.c.blob_sha256,
                )
                .select_from(versions.join(files, files.c.version_id == versions.c.id))
                .where(versions.c.package_id == package_id, versions.c.is_local.is_(False))
            )
        ).all()
        by_version: dict[int, tuple[str, list]] = {}
        for version_id, version, file_id, filename, sha in rows:
            by_version.setdefault(version_id, (version, []))[1].append((file_id, filename, sha))
        doomed_versions: list[tuple[int, str]] = []
        doomed_files: list[tuple[int, str | None]] = []
        for version_id, (version, version_files) in by_version.items():
            expected = npm_tarball_filename(name, version)
            foreign = [
                (file_id, sha)
                for file_id, filename, sha in version_files
                if filename != expected and filename.lower() == expected.lower()
            ]
            if not foreign:
                continue
            doomed_files.extend(foreign)
            if len(foreign) == len(version_files):
                doomed_versions.append((version_id, version))
        if not doomed_files:
            continue

        for file_id, sha in doomed_files:
            await conn.execute(delete(files).where(files.c.id == file_id))
            if sha:
                # The orphan sweep deletes the bytes once nothing points at them.
                await conn.execute(
                    update(Blob.__table__)
                    .where(Blob.__table__.c.sha256 == sha)
                    .values(refcount=Blob.__table__.c.refcount - 1)
                )
        version_ids = [version_id for version_id, _ in doomed_versions]
        if version_ids:
            vulns = PackageVulnerability.__table__
            await conn.execute(delete(vulns).where(vulns.c.version_id.in_(version_ids)))
            await conn.execute(delete(versions).where(versions.c.id.in_(version_ids)))
            tags = DistTag.__table__
            await conn.execute(
                delete(tags).where(
                    and_(
                        tags.c.package_id == package_id,
                        tags.c.version.in_([v for _, v in doomed_versions]),
                    )
                )
            )
            await conn.execute(
                update(packages)
                .where(
                    packages.c.id == package_id,
                    packages.c.latest_version.in_([v for _, v in doomed_versions]),
                )
                .values(latest_version=None)
            )
        await conn.execute(
            update(packages)
            .where(packages.c.id == package_id)
            .values(cached_at=None, cached_etag=None)
        )
        purged_files += len(doomed_files)
        purged_versions += len(doomed_versions)

    await conn.execute(
        insert(Setting.__table__).values(
            key=NPM_CASE_REPAIR_MARKER,
            value={
                "rekeyed": rekeyed,
                "purged_files": purged_files,
                "purged_versions": purged_versions,
                "at": datetime.now(UTC).isoformat(),
            },
        )
    )
    if rekeyed or purged_files:
        log.warning(
            "npm case repair: re-keyed %d package(s), removed %d file(s) and %d "
            "version(s) a differently-cased package had merged in",
            rekeyed,
            purged_files,
            purged_versions,
        )


DATA_REPAIRS = [
    _repair_npm_scoped_tarball_names,
    _repair_npm_case_folded_keys,
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

        # Inside the same transaction (and, on Postgres, the same advisory
        # lock), so replicas booting together do not repair the same rows.
        for repair in DATA_REPAIRS:
            await repair(conn)


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
