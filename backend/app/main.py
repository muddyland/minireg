"""Application entrypoint."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import secrets
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import defer

from .api import auth as auth_api
from .api import cargo as cargo_api
from .api import cli as cli_api
from .api import help as help_api
from .api import npm as npm_api
from .api import pypi as pypi_api
from .api import search as search_api
from .api.admin import router as admin_router
from .config import settings
from .core.cache import close_redis, init_redis
from .core.deps import Identity, require_admin, resolve_identity
from .core.security import hash_password
from .db import create_schema, dispose_engine, init_engine, session_scope
from .models import User
from .services.audit import get_recorder, prune_old_logs, record_audit
from .services.storage import get_store
from .upstreams.base import close_http_client

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("minireg")

STATIC_DIR = Path(__file__).resolve().parent / "static"


async def bootstrap_admin() -> None:
    """Create the first admin account if the instance has no users.

    The password comes from BOOTSTRAP_ADMIN_PASSWORD; if unset we generate one
    and print it once, because shipping a default password would be worse.
    """
    async with session_scope() as session:
        count = (await session.execute(select(func.count(User.id)))).scalar_one()
        if count:
            return

        password = settings.bootstrap_admin_password or secrets.token_urlsafe(18)
        user = User(
            username=settings.bootstrap_admin_username,
            email=settings.bootstrap_admin_email,
            password_hash=hash_password(password),
            is_admin=True,
            can_publish=True,
            is_active=True,
        )
        session.add(user)
        await session.flush()
        await record_audit(
            session,
            "admin.bootstrap",
            actor_type="system",
            actor_username="system",
            target_type="user",
            target_id=str(user.id),
            detail={"username": user.username},
        )

        if not settings.bootstrap_admin_password:
            # Not into the log. Docker's json-file driver keeps stdout for the
            # life of the container, so a password printed here is readable by
            # anyone with the docker socket or a log shipper, forever. A 0600
            # file next to the data can be read once and deleted.
            secret_path = Path(settings.storage_path).parent / "initial-admin-password"
            written = False
            try:
                fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as handle:
                    handle.write(f"{user.username}\n{password}\n")
                written = True
            except OSError as exc:
                log.error("could not write the initial admin password file: %s", exc)
            if written:
                log.warning(
                    "\n"
                    "=========================================================\n"
                    " Created the initial admin account '%s'.\n"
                    " The generated password was written to:\n"
                    "   %s\n"
                    " Read it, log in, change it, then delete that file.\n"
                    "=========================================================",
                    user.username,
                    secret_path,
                )
            else:
                log.warning(
                    "Created the initial admin account '%s' but could not store its "
                    "password. Set BOOTSTRAP_ADMIN_PASSWORD and restart, or reset it "
                    "from the database.",
                    user.username,
                )
        else:
            log.info("created initial admin account '%s'", user.username)


async def _prune_task() -> None:
    from sqlalchemy import update

    from .models import DeviceAuthorization
    from .services.artifacts import collect_orphan_blobs

    async with session_scope() as session:
        removed = await prune_old_logs(session)
        orphans = await collect_orphan_blobs(session)

        # A device authorization that was approved but never polled keeps the
        # token in plaintext until someone collects it. Expired rows never
        # will be, so the plaintext is cleared rather than left sitting in the
        # table. Reaping only happened on the next /auth/start before this.
        cleared = (
            await session.execute(
                update(DeviceAuthorization)
                .where(
                    DeviceAuthorization.expires_at < datetime.now(UTC),
                    DeviceAuthorization.token_plaintext.isnot(None),
                )
                .values(token_plaintext=None)
            )
        ).rowcount
        if removed or orphans or cleared:
            log.info(
                "housekeeping: pruned=%s orphan_blobs=%d expired_device_tokens=%s",
                removed,
                orphans,
                cleared,
            )
    get_store().cleanup_tmp()


async def _cve_refresh_task() -> None:
    """Re-scan the oldest versions until the backlog clears or time runs out.

    One batch per hour could not keep up: with a 77k backlog and a batch of
    200, a full pass took about sixteen days, so the six-hour refresh interval
    was fiction and a CVE published today reached an already-scanned version a
    fortnight later. This keeps taking batches within a wall-clock budget.

    Batches are also isolated. A batch that always fails -- one malformed
    version making OSV reject the whole query, say -- used to leave all 200
    rows with a null ``scanned_at``, so the same 200 were reselected every hour
    and nothing behind them was ever scanned. Here a failed batch is retried in
    halves, and a single poisonous row is skipped rather than blocking the
    queue.
    """
    from .models import Package, PackageVersion
    from .services.osv import OsvScanner

    if not settings.osv_enabled:
        return

    deadline = time.monotonic() + settings.osv_housekeeping_budget_seconds
    cutoff = datetime.now(UTC) - timedelta(seconds=settings.osv_refresh_interval_seconds)
    total = 0

    while time.monotonic() < deadline:
        async with session_scope() as session:
            # Select the two package columns the scan actually uses rather than
            # the Package entity. The entity drags cached_document -- the whole
            # upstream packument, 18MB for playwright and 37MB for vite -- once
            # per *row*, so a 200-row batch pulled and JSON-parsed multiple GB
            # and got the container OOM-killed. metadata_json is deferred for
            # the same reason; apply_to_version never reads it.
            rows = (
                await session.execute(
                    select(Package.ecosystem, Package.name, PackageVersion)
                    .join(PackageVersion, PackageVersion.package_id == Package.id)
                    .options(defer(PackageVersion.metadata_json))
                    .where(
                        (PackageVersion.scanned_at.is_(None))
                        | (PackageVersion.scanned_at < cutoff)
                    )
                    # Never-scanned first, then oldest. Within that, the
                    # versions people actually resolve to: a package's own
                    # `latest` and its most-downloaded releases earn their scan
                    # before some 0.0.1 nobody installs.
                    .order_by(
                        PackageVersion.scanned_at.asc().nullsfirst(),
                        PackageVersion.published_at.desc().nullslast(),
                    )
                    .limit(settings.osv_batch_size)
                )
            ).all()
            if not rows:
                break

            scanner = OsvScanner(session)
            grouped: dict = {}
            for eco, name, version in rows:
                grouped.setdefault(eco, []).append((name, version))
            for ecosystem, items in grouped.items():
                await _scan_group(scanner, ecosystem, items)
            total += len(rows)

        if len(rows) < settings.osv_batch_size:
            break

    if total:
        log.info("background CVE refresh scanned %d versions", total)


async def _scan_group(scanner, ecosystem, items: list) -> None:
    """Scan one ecosystem's slice, splitting on failure so one bad row cannot
    wedge the queue behind it."""
    try:
        results = await scanner.scan_versions(
            ecosystem, [(n, v.version) for n, v in items]
        )
    except Exception:
        if len(items) == 1:
            name, version = items[0]
            # Mark it examined so the queue moves on; the next refresh cycle
            # will try again rather than this one spinning on it forever.
            log.warning(
                "CVE scan permanently failing for %s@%s; skipping", name, version.version
            )
            version.scanned_at = datetime.now(UTC)
            return
        mid = len(items) // 2
        log.warning("CVE batch of %d failed; retrying in halves", len(items))
        await _scan_group(scanner, ecosystem, items[:mid])
        await _scan_group(scanner, ecosystem, items[mid:])
        return

    for name, version in items:
        result = results.get((name, version.version))
        if result is not None:
            await scanner.apply_to_version(version, result, name)


async def housekeeping_loop() -> None:
    """Retention pruning, orphan-blob GC, and background CVE refresh.

    Each task has its own error boundary. They used to share one, so a failure
    while pruning logs silently skipped the GC and the CVE refresh for the
    whole hour.

    A Redis lock keeps this to one runner: replicas all execute this loop, and
    without the lock they duplicate every OSV call and race each other's
    upserts.
    """
    from .core.cache import herd_guard

    # Stagger the first run so a restart storm does not converge on one moment.
    await asyncio.sleep(60)
    while True:
        try:
            async with herd_guard("housekeeping", ttl=3600, wait=False) as acquired:
                if acquired:
                    for name, task in (
                        ("prune", _prune_task),
                        ("cve-refresh", _cve_refresh_task),
                    ):
                        try:
                            await task()
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            log.exception("housekeeping task %s failed", name)
                else:
                    log.debug("housekeeping already running elsewhere; skipping")
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("housekeeping iteration failed")

        await asyncio.sleep(3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_engine()
    await create_schema()
    await init_redis()
    get_store().ensure_dirs()
    await bootstrap_admin()
    await get_recorder().start()

    task = asyncio.create_task(housekeeping_loop())
    log.info("%s ready at %s", settings.app_name, settings.public_url)
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await get_recorder().stop()
        await close_http_client()
        await close_redis()
        await dispose_engine()


app = FastAPI(
    title="minireg",
    description="Caching npm + PyPI + cargo registry with tiered upstreams, OIDC, and CVE policy",
    version="1.0.0",
    lifespan=lifespan,
    # The interactive docs enumerate every admin route and its schema. Useful
    # in development, free reconnaissance in production.
    docs_url="/api/docs" if settings.environment == "dev" else None,
    openapi_url="/api/openapi.json" if settings.environment == "dev" else None,
    redoc_url=None,
)

if settings.environment == "dev":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


#: Paths that accept a package upload. Everything else gets a much smaller
#: ceiling, because nothing else has a legitimate reason to be large.
_UPLOAD_METHODS = {"PUT", "POST"}
_SMALL_BODY_LIMIT = 2 * 1024 * 1024


#: Counters an operator can scrape. Deliberately tiny: the point is to make
#: the silent failure modes visible, not to reimplement Prometheus.
METRICS: dict[str, int] = defaultdict(int)


def bump(name: str, amount: int = 1) -> None:
    METRICS[name] += amount


@app.middleware("http")
async def access_log(request: Request, call_next):
    """One line per request, and a counter per outcome.

    Access logging was switched off at the uvicorn level and nothing replaced
    it, so the only lines in the log were outgoing httpx calls. A 502 from a
    failed artifact fetch, or a CVE scan that failed open, left no trace an
    operator could find.
    """
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        bump("requests.exception")
        log.exception(
            "%s %s failed after %.0fms",
            request.method,
            request.url.path,
            (time.perf_counter() - started) * 1000,
        )
        raise

    duration_ms = (time.perf_counter() - started) * 1000
    bump("requests.total")
    bump(f"requests.status.{response.status_code // 100}xx")

    if response.status_code >= 500:
        level = logging.ERROR
    elif response.status_code in (401, 403, 413, 429):
        level = logging.WARNING
    else:
        level = logging.DEBUG
    log.log(
        level,
        '%s %s %s %.0fms',
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    """Reject oversized bodies on Content-Length, before anything reads them.

    An npm publish arrives as one JSON document with the tarball base64'd
    inside it, so the handler holds the raw bytes, the parsed string and the
    decoded tarball at once -- roughly four times the artifact. The size check
    used to happen after all of that, against a 1 GiB ceiling, which made a
    single authenticated publisher able to push the container past its memory
    limit and take every in-flight download down with it.

    A chunked request has no Content-Length; those are bounded by the reverse
    proxy's own limit, which the shipped nginx config sets.
    """
    if request.method in _UPLOAD_METHODS:
        raw_length = request.headers.get("content-length")
        if raw_length and raw_length.isdigit():
            length = int(raw_length)
            path = request.url.path
            is_upload = path.startswith(("/npm/", "/pypi/"))
            limit = settings.max_publish_bytes if is_upload else _SMALL_BODY_LIMIT
            if length > limit:
                return JSONResponse(
                    {
                        "error": (
                            f"request body is {length} bytes, over the "
                            f"{limit} byte limit"
                        )
                    },
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                )
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)

    # Advertise the CLI version on API responses. The CLI compares it against
    # its own and nudges when it has fallen behind, which costs no extra
    # request -- it learns from traffic it was making anyway.
    if request.url.path.startswith("/api/"):
        from .api.cli import CLI_VERSION_HEADER, cli_version

        shipped = cli_version()
        if shipped:
            response.headers.setdefault(CLI_VERSION_HEADER, shipped)

    response.headers.setdefault("x-content-type-options", "nosniff")
    response.headers.setdefault("referrer-policy", "same-origin")
    # The registry endpoints are consumed by CLIs, not browsers, so a frame
    # policy only matters for the admin UI -- but it costs nothing here.
    response.headers.setdefault("x-frame-options", "DENY")
    return response


@app.get("/health", tags=["meta"])
async def health() -> JSONResponse:
    """Liveness, and the container healthcheck target.

    Deliberately touches the database. A constant 200 meant a process whose
    connection pool was wedged or whose disk was full stayed "healthy"
    forever, so `restart: unless-stopped` never restarted it. Kept cheap and
    short-timeout so a slow query cannot make the healthcheck itself the
    outage.
    """
    from sqlalchemy import text

    from .db import get_engine

    payload = {"status": "ok", "service": settings.app_name, "version": "1.0.0"}
    try:
        async with asyncio.timeout(2):
            async with get_engine().connect() as conn:
                await conn.execute(text("SELECT 1"))
    except Exception as exc:
        log.warning("health check failed: %s", exc)
        payload["status"] = "degraded"
        return JSONResponse(payload, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
    return JSONResponse(payload)


@app.get("/api/metrics", tags=["meta"])
async def metrics(identity=Depends(require_admin)) -> JSONResponse:
    """Counters for the things that otherwise fail quietly.

    Admin-only: the counts describe traffic and policy behaviour, which is not
    something to hand out anonymously.
    """
    from .core.cache import redis_client

    return JSONResponse(
        {
            "counters": dict(sorted(METRICS.items())),
            "cache_connected": redis_client() is not None,
        }
    )


@app.get("/api/health/detailed", tags=["meta"])
async def health_detailed(
    identity: Identity = Depends(resolve_identity),
) -> JSONResponse:
    """Component status.

    Error strings are only rendered for an admin: an asyncpg failure message
    names the host, port and database, and disk figures describe the
    deployment. Anonymous callers get booleans, which is all a monitor needs.
    """
    from .core.cache import redis_client
    from .db import get_engine

    detailed = bool(identity.user and identity.is_admin)

    def failure(exc: Exception) -> dict:
        return {"ok": False, **({"error": str(exc)} if detailed else {})}

    checks: dict[str, dict] = {}

    try:
        async with get_engine().connect() as conn:
            await conn.execute(select(1))
        checks["database"] = {"ok": True}
    except Exception as exc:
        log.error("health: database check failed: %s", exc)
        checks["database"] = failure(exc)

    client = redis_client()
    if client is None:
        checks["cache"] = {"ok": False, "detail": "not connected (running without cache)"}
    else:
        try:
            await client.ping()
            checks["cache"] = {"ok": True}
        except Exception as exc:
            checks["cache"] = failure(exc)
    # Compatibility: the key was called `redis` before the move to Valkey.
    checks["redis"] = checks["cache"]

    try:
        usage = await get_store().disk_usage()
        checks["storage"] = {"ok": True, **(usage if detailed else {})}
    except Exception as exc:
        log.error("health: storage check failed: %s", exc)
        checks["storage"] = failure(exc)

    # Redis being down degrades performance but not correctness.
    healthy = checks["database"]["ok"] and checks["storage"]["ok"]
    return JSONResponse(
        {"status": "ok" if healthy else "degraded", "checks": checks},
        status_code=status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE,
    )


# API routers first, then the registry mounts, then the SPA catch-all.
app.include_router(auth_api.router)
app.include_router(cli_api.router)
app.include_router(help_api.router)
app.include_router(search_api.router)
app.include_router(admin_router)
app.include_router(npm_api.router, prefix="/npm")
app.include_router(pypi_api.router, prefix="/pypi")
app.include_router(cargo_api.router, prefix="/cargo")


if STATIC_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

    @app.get("/{spa_path:path}", include_in_schema=False)
    async def serve_spa(spa_path: str) -> FileResponse:
        """Serve the built Vue app, falling back to index.html for client-side
        routes. API and registry paths are matched by the routers above, so
        anything reaching here is a UI route or a static file."""
        candidate = (STATIC_DIR / spa_path).resolve()
        if (
            spa_path
            and candidate.is_file()
            and candidate.is_relative_to(STATIC_DIR.resolve())
        ):
            return FileResponse(candidate)
        return FileResponse(STATIC_DIR / "index.html")
