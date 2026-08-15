"""Application entrypoint."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select

from .api import auth as auth_api
from .api import cli as cli_api
from .api import npm as npm_api
from .api import pypi as pypi_api
from .api import search as search_api
from .api.admin import router as admin_router
from .config import settings
from .core.cache import close_redis, init_redis
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
            log.warning(
                "\n"
                "=========================================================\n"
                " Created the initial admin account.\n"
                "   username: %s\n"
                "   password: %s\n"
                " This password is shown once. Change it after logging in.\n"
                "=========================================================",
                user.username,
                password,
            )
        else:
            log.info("created initial admin account '%s'", user.username)


async def housekeeping_loop() -> None:
    """Retention pruning, orphan-blob GC, and background CVE refresh."""
    from .models import Package, PackageVersion
    from .services.artifacts import collect_orphan_blobs
    from .services.osv import OsvScanner

    # Stagger the first run so a restart storm does not converge on one moment.
    await asyncio.sleep(60)
    while True:
        try:
            async with session_scope() as session:
                removed = await prune_old_logs(session)
                orphans = await collect_orphan_blobs(session)
                if removed or orphans:
                    log.info("housekeeping: pruned=%s orphan_blobs=%d", removed, orphans)
            get_store().cleanup_tmp()

            if settings.osv_enabled:
                cutoff = datetime.now(UTC) - timedelta(seconds=settings.osv_refresh_interval_seconds)
                async with session_scope() as session:
                    rows = (
                        await session.execute(
                            select(Package, PackageVersion)
                            .join(PackageVersion, PackageVersion.package_id == Package.id)
                            .where(
                                (PackageVersion.scanned_at.is_(None))
                                | (PackageVersion.scanned_at < cutoff)
                            )
                            .order_by(PackageVersion.scanned_at.asc().nullsfirst())
                            .limit(settings.osv_batch_size)
                        )
                    ).all()
                    if rows:
                        scanner = OsvScanner(session)
                        grouped: dict = {}
                        for package, version in rows:
                            grouped.setdefault(package.ecosystem, []).append((package, version))
                        for ecosystem, items in grouped.items():
                            results = await scanner.scan_versions(
                                ecosystem, [(p.name, v.version) for p, v in items]
                            )
                            for package, version in items:
                                result = results.get((package.name, version.version))
                                if result is not None:
                                    await scanner.apply_to_version(version, result, package.name)
                        log.info("background CVE refresh scanned %d versions", len(rows))
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
    description="Caching npm + PyPI registry with tiered upstreams, OIDC, and CVE policy",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
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
async def health() -> dict:
    return {"status": "ok", "service": settings.app_name, "version": "1.0.0"}


@app.get("/api/health/detailed", tags=["meta"])
async def health_detailed() -> JSONResponse:
    from .core.cache import redis_client
    from .db import get_engine

    checks: dict[str, dict] = {}

    try:
        async with get_engine().connect() as conn:
            await conn.execute(select(1))
        checks["database"] = {"ok": True}
    except Exception as exc:
        checks["database"] = {"ok": False, "error": str(exc)}

    client = redis_client()
    if client is None:
        checks["redis"] = {"ok": False, "error": "not connected (running without cache)"}
    else:
        try:
            await client.ping()
            checks["redis"] = {"ok": True}
        except Exception as exc:
            checks["redis"] = {"ok": False, "error": str(exc)}

    try:
        usage = await get_store().disk_usage()
        checks["storage"] = {"ok": True, **usage}
    except Exception as exc:
        checks["storage"] = {"ok": False, "error": str(exc)}

    # Redis being down degrades performance but not correctness.
    healthy = checks["database"]["ok"] and checks["storage"]["ok"]
    return JSONResponse(
        {"status": "ok" if healthy else "degraded", "checks": checks},
        status_code=status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE,
    )


# API routers first, then the registry mounts, then the SPA catch-all.
app.include_router(auth_api.router)
app.include_router(cli_api.router)
app.include_router(search_api.router)
app.include_router(admin_router)
app.include_router(npm_api.router, prefix="/npm")
app.include_router(pypi_api.router, prefix="/pypi")


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
