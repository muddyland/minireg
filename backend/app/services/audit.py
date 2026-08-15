"""Audit log and download telemetry.

Two very different write profiles:

* **Audit** entries are low-volume and must not be lost, so they are written
  synchronously in the caller's transaction.
* **Download** entries are extremely high-volume (every metadata hit from every
  CI job) and are worthless individually, so they go through an in-process
  queue drained by a background task in batches. A dropped download row under
  extreme load is preferable to adding a synchronous INSERT to every request.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import logging
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import AuditLog, DownloadLog

log = logging.getLogger(__name__)

# Audit action vocabulary, kept as constants so the admin UI can filter reliably.
LOGIN_SUCCESS = "auth.login.success"
LOGIN_FAILED = "auth.login.failed"
LOGIN_OIDC = "auth.login.oidc"
LOGOUT = "auth.logout"
TOKEN_CREATED = "auth.token.created"
TOKEN_REVOKED = "auth.token.revoked"
TOKEN_AUTH_FAILED = "auth.token.failed"

USER_CREATED = "admin.user.created"
USER_UPDATED = "admin.user.updated"
USER_DELETED = "admin.user.deleted"
UPSTREAM_CREATED = "admin.upstream.created"
UPSTREAM_UPDATED = "admin.upstream.updated"
UPSTREAM_DELETED = "admin.upstream.deleted"
RULE_CREATED = "admin.rule.created"
RULE_UPDATED = "admin.rule.updated"
RULE_DELETED = "admin.rule.deleted"
SETTING_UPDATED = "admin.setting.updated"
CACHE_PURGED = "admin.cache.purged"
PACKAGE_DELETED = "admin.package.deleted"
SCAN_TRIGGERED = "admin.scan.triggered"
VULN_SUPPRESSED = "admin.vuln.suppressed"

PACKAGE_PUBLISHED = "registry.publish"
PACKAGE_PUBLISH_DENIED = "registry.publish.denied"
PACKAGE_UNPUBLISHED = "registry.unpublish"
PACKAGE_BLOCKED = "registry.blocked"
DIST_TAG_UPDATED = "registry.disttag.updated"


def jsonable(value):
    """Coerce a detail payload into something the JSON/JSONB column accepts.

    Callers routinely pass ORM-shaped dicts containing datetimes and enums;
    an audit write must never fail because of a type the encoder dislikes.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [jsonable(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, enum.Enum):
        return value.value
    return str(value)


async def record_audit(
    session: AsyncSession,
    action: str,
    *,
    actor_user_id: int | None = None,
    actor_username: str | None = None,
    actor_type: str = "user",
    target_type: str | None = None,
    target_id: str | None = None,
    success: bool = True,
    ip: str | None = None,
    user_agent: str | None = None,
    detail: dict | None = None,
) -> None:
    session.add(
        AuditLog(
            action=action,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_type=actor_type,
            target_type=target_type,
            target_id=target_id,
            success=success,
            ip=ip,
            user_agent=(user_agent or "")[:512] or None,
            detail=jsonable(detail) or {},
        )
    )
    await session.flush()


# --------------------------------------------------------------------------- #
# Download telemetry
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class DownloadEvent:
    ecosystem: str
    package_name: str
    version: str | None = None
    filename: str | None = None
    kind: str = "file"
    user_id: int | None = None
    username: str | None = None
    token_id: int | None = None
    ip: str | None = None
    user_agent: str | None = None
    bytes_sent: int = 0
    cache_hit: bool = False
    upstream_id: int | None = None
    status: int = 200
    duration_ms: int | None = None


class DownloadRecorder:
    """Bounded queue + batching writer."""

    def __init__(self, maxsize: int = 20000, batch_size: int = 500, flush_interval: float = 2.0):
        self.queue: asyncio.Queue[DownloadEvent] = asyncio.Queue(maxsize=maxsize)
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._task: asyncio.Task | None = None
        self._stopping = False
        self.dropped = 0

    def record(self, event: DownloadEvent) -> None:
        """Non-blocking. Drops on overflow rather than back-pressuring a
        download."""
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1
            if self.dropped % 1000 == 1:
                log.warning("download log queue full, dropped %d events", self.dropped)

    async def start(self) -> None:
        if self._task is None:
            self._stopping = False
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stopping = True
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        await self._drain_once()

    async def _run(self) -> None:
        while not self._stopping:
            try:
                await asyncio.sleep(self.flush_interval)
                await self._drain_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("download log flush failed")

    async def _drain_once(self) -> None:
        batch: list[DownloadEvent] = []
        while len(batch) < self.batch_size:
            try:
                batch.append(self.queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        if not batch:
            return

        from ..db import session_scope

        rows = [asdict(event) for event in batch]
        try:
            async with session_scope() as session:
                await session.execute(insert(DownloadLog), rows)
        except Exception:  # noqa: BLE001
            log.exception("failed to persist %d download events", len(rows))


_recorder = DownloadRecorder()


def get_recorder() -> DownloadRecorder:
    return _recorder


def record_download(event: DownloadEvent) -> None:
    _recorder.record(event)


# --------------------------------------------------------------------------- #
# Retention
# --------------------------------------------------------------------------- #
async def prune_old_logs(session: AsyncSession) -> dict[str, int]:
    """Enforce retention windows. Called by the housekeeping task."""
    now = datetime.now(UTC)
    removed = {}
    if settings.download_log_retention_days > 0:
        cutoff = now - timedelta(days=settings.download_log_retention_days)
        result = await session.execute(delete(DownloadLog).where(DownloadLog.ts < cutoff))
        removed["download_log"] = result.rowcount or 0
    if settings.audit_log_retention_days > 0:
        cutoff = now - timedelta(days=settings.audit_log_retention_days)
        result = await session.execute(delete(AuditLog).where(AuditLog.ts < cutoff))
        removed["audit_log"] = result.rowcount or 0
    return removed
