"""Scan queue, result ingestion and the CISA KEV catalogue.

The scanner worker is a separate container holding Trivy, its database and
a scan-only token. It has no database access and no upstream credentials:
it asks this module for work over HTTP, pulls the image from our own /v2 by
digest, and posts back a Trivy JSON report and a CycloneDX SBOM.

Its output is treated as untrusted. The worker unpacks hostile layers by
design, so if one of them gets the better of Trivy, whatever it then sends
here must not get the better of the registry: the report is size-capped,
parsed against a narrow schema, every string is truncated, and nothing from
it is ever rendered as HTML.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import orjson
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..core.metrics import bump
from ..models import (
    DockerFinding,
    DockerManifest,
    DockerRepoManifest,
    DockerRepository,
    DockerScan,
    DockerScanJob,
    KevEntry,
)
from .policy import SEVERITIES, ImagePolicy, evaluate_rules, load_policy
from .store import get_oci_store

log = logging.getLogger(__name__)

#: Priorities. Lower runs first.
PRIORITY_PUSH = 10
PRIORITY_HOLD = 20
PRIORITY_PULL = 50
PRIORITY_MANUAL = 60
PRIORITY_WATCH = 80
PRIORITY_SCHEDULE = 100

LEASE = timedelta(minutes=2)
MAX_ATTEMPTS = 3
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_SBOM_BYTES = 64 * 1024 * 1024
MAX_FINDINGS = 25_000

_VULN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,63}$")


class ReportInvalid(Exception):
    pass


# --------------------------------------------------------------------------- #
# Queue
# --------------------------------------------------------------------------- #
async def enqueue(
    session: AsyncSession,
    manifest: DockerManifest,
    repository: str,
    *,
    reason: str,
    priority: int,
    mode: str | None = None,
) -> DockerScanJob | None:
    """Queue a scan unless one is already waiting or running for this digest.

    Returns the job (new or existing), or None if the manifest is not
    something Trivy can scan.
    """
    if manifest.kind != "image":
        return None
    existing = (
        await session.execute(
            select(DockerScanJob)
            .where(
                DockerScanJob.manifest_id == manifest.id,
                DockerScanJob.status.in_(("queued", "running")),
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        if priority < existing.priority and existing.status == "queued":
            existing.priority = priority
        return existing
    if mode is None:
        mode = "sbom" if manifest.sbom_digest and reason == "schedule" else "image"
    job = DockerScanJob(
        manifest_id=manifest.id,
        repository=repository[:512],
        mode=mode,
        reason=reason,
        priority=priority,
    )
    session.add(job)
    if manifest.scan_status in ("unscanned", "failed"):
        manifest.scan_status = "queued"
    await session.flush()
    bump("docker.scan.enqueued", reason=reason)
    return job


async def claim(session: AsyncSession, worker: str) -> DockerScanJob | None:
    """Take the next job. SKIP LOCKED lets any number of workers drain the
    queue without two of them taking the same job."""
    now = datetime.now(UTC)
    # Jobs whose worker stopped renewing the lease go back to the queue.
    await session.execute(
        update(DockerScanJob)
        .where(DockerScanJob.status == "running", DockerScanJob.lease_until < now)
        .values(status="queued", worker=None, lease_until=None)
    )
    stmt = (
        select(DockerScanJob)
        .where(DockerScanJob.status == "queued")
        .order_by(DockerScanJob.priority.asc(), DockerScanJob.id.asc())
        .limit(1)
    )
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        stmt = stmt.with_for_update(skip_locked=True)
    job = (await session.execute(stmt)).scalar_one_or_none()
    if job is None:
        return None
    job.status = "running"
    job.worker = worker[:128]
    job.attempts += 1
    job.started_at = now
    job.lease_until = now + LEASE
    manifest = await session.get(DockerManifest, job.manifest_id)
    if manifest is not None:
        manifest.scan_status = "scanning"
    await session.flush()
    return job


async def renew(session: AsyncSession, job: DockerScanJob) -> None:
    job.lease_until = datetime.now(UTC) + LEASE


async def fail(session: AsyncSession, job: DockerScanJob, error: str) -> None:
    job.error = (error or "unknown error")[:2000]
    manifest = await session.get(DockerManifest, job.manifest_id)
    if job.attempts >= MAX_ATTEMPTS:
        job.status = "failed"
        job.finished_at = datetime.now(UTC)
        if manifest is not None:
            manifest.scan_status = "failed"
        bump("docker.scan.failed")
    else:
        job.status = "queued"
        job.worker = None
        job.lease_until = None
        if manifest is not None and manifest.scan_status == "scanning":
            manifest.scan_status = "queued"
        bump("docker.scan.retried")


async def skip(session: AsyncSession, job: DockerScanJob, reason: str) -> None:
    """The job cannot be scanned by design (too big, not an image)."""
    job.status = "done"
    job.error = reason[:2000]
    job.finished_at = datetime.now(UTC)
    manifest = await session.get(DockerManifest, job.manifest_id)
    if manifest is not None:
        manifest.scan_status = "not_applicable"


# --------------------------------------------------------------------------- #
# Report parsing
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class ParsedFinding:
    vuln_id: str
    pkg_name: str
    pkg_type: str | None
    installed_version: str | None
    fixed_version: str | None
    severity: str
    cvss: float | None
    title: str | None
    url: str | None
    layer_digest: str | None


@dataclass(slots=True)
class ParsedReport:
    findings: list[ParsedFinding]
    os_family: str | None
    os_name: str | None
    trivy_version: str | None
    db_updated_at: datetime | None


def _s(value, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, (str, int, float)):
        return None
    text = str(value).replace("\x00", "")
    return text[:limit] if text else None


def _url(value) -> str | None:
    text = _s(value, 512)
    if text and text.startswith(("https://", "http://")):
        return text
    return None


def _cvss(v: Any) -> float | None:
    """Highest v3 (else v2) score across the sources Trivy reports."""
    if not isinstance(v, dict):
        return None
    best = None
    for source in v.values():
        if not isinstance(source, dict):
            continue
        for key in ("V40Score", "V3Score", "V2Score"):
            score = source.get(key)
            if isinstance(score, (int, float)) and 0 <= score <= 10:
                best = score if best is None else max(best, float(score))
                break
    return best


def parse_report(raw: bytes, policy: ImagePolicy) -> ParsedReport:
    if len(raw) > MAX_REPORT_BYTES:
        raise ReportInvalid(f"report exceeds {MAX_REPORT_BYTES} bytes")
    try:
        doc = orjson.loads(raw)
    except orjson.JSONDecodeError as exc:
        raise ReportInvalid("report is not JSON") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("Results", []), list):
        raise ReportInvalid("report is not a Trivy JSON report")
    meta = doc.get("Metadata") if isinstance(doc.get("Metadata"), dict) else {}
    os_info = meta.get("OS") if isinstance(meta.get("OS"), dict) else {}
    trivy = doc.get("Trivy") if isinstance(doc.get("Trivy"), dict) else {}
    db_updated = None
    vdb = trivy.get("VulnerabilityDB") if isinstance(trivy.get("VulnerabilityDB"), dict) else None
    if vdb and isinstance(vdb.get("UpdatedAt"), str):
        db_updated = _parse_time(vdb["UpdatedAt"])
    wanted = set(policy.severities or SEVERITIES)
    findings: list[ParsedFinding] = []
    seen: set[tuple[str, str, str | None]] = set()
    for result in doc.get("Results") or []:
        if not isinstance(result, dict):
            continue
        pkg_type = _s(result.get("Type"), 32)
        for v in result.get("Vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            vuln_id = _s(v.get("VulnerabilityID"), 64)
            if not vuln_id or not _VULN_ID.match(vuln_id):
                continue
            severity = (_s(v.get("Severity"), 10) or "UNKNOWN").upper()
            if severity not in SEVERITIES:
                severity = "UNKNOWN"
            if severity not in wanted:
                continue
            fixed = _s(v.get("FixedVersion"), 255)
            if policy.ignore_unfixed and not fixed:
                continue
            pkg = _s(v.get("PkgName"), 255) or "?"
            installed = _s(v.get("InstalledVersion"), 128)
            key = (vuln_id, pkg, installed)
            if key in seen:
                continue
            seen.add(key)
            layer = v.get("Layer") if isinstance(v.get("Layer"), dict) else {}
            layer_digest = _s(layer.get("Digest"), 80)
            if layer_digest and not re.match(r"^sha256:[a-f0-9]{64}$", layer_digest):
                layer_digest = None
            findings.append(
                ParsedFinding(
                    vuln_id=vuln_id,
                    pkg_name=pkg,
                    pkg_type=pkg_type,
                    installed_version=installed,
                    fixed_version=fixed,
                    severity=severity,
                    cvss=_cvss(v.get("CVSS")),
                    title=_s(v.get("Title"), 500),
                    url=_url(v.get("PrimaryURL")),
                    layer_digest=layer_digest,
                )
            )
            if len(findings) > MAX_FINDINGS:
                raise ReportInvalid(f"report lists more than {MAX_FINDINGS} findings")
    return ParsedReport(
        findings=findings,
        os_family=_s(os_info.get("Family"), 64),
        os_name=_s(os_info.get("Name"), 64),
        trivy_version=_s(trivy.get("Version"), 32),
        db_updated_at=db_updated,
    )


def _parse_time(value: str) -> datetime | None:
    try:
        text = value.replace("Z", "+00:00")
        # Trivy prints nanoseconds; fromisoformat takes at most microseconds.
        text = re.sub(r"(\.\d{6})\d+", r"\1", text)
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return None


def validate_sbom(raw: bytes) -> None:
    if len(raw) > MAX_SBOM_BYTES:
        raise ReportInvalid(f"SBOM exceeds {MAX_SBOM_BYTES} bytes")
    try:
        doc = orjson.loads(raw)
    except orjson.JSONDecodeError as exc:
        raise ReportInvalid("SBOM is not JSON") from exc
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise ReportInvalid("SBOM is not a CycloneDX document")


# --------------------------------------------------------------------------- #
# Ingestion
# --------------------------------------------------------------------------- #
async def ingest(
    session: AsyncSession,
    job: DockerScanJob,
    report_raw: bytes,
    sbom_raw: bytes | None,
    duration_ms: int | None = None,
) -> DockerScan:
    manifest = await session.get(DockerManifest, job.manifest_id)
    if manifest is None:
        raise ReportInvalid("the manifest this job was for no longer exists")
    policy = await load_policy(session)
    parsed = parse_report(report_raw, policy)
    if sbom_raw is not None:
        validate_sbom(sbom_raw)

    store = get_oci_store()
    report_digest = await store.put_bytes(report_raw)
    if sbom_raw is not None:
        new_sbom = await store.put_bytes(sbom_raw)
        if manifest.sbom_digest and manifest.sbom_digest != new_sbom:
            await _release_file(session, manifest.sbom_digest)
        manifest.sbom_digest = new_sbom

    kev = set(
        (
            await session.execute(
                select(KevEntry.cve_id).where(
                    KevEntry.cve_id.in_({f.vuln_id for f in parsed.findings if f.vuln_id.startswith("CVE-")})
                )
            )
        ).scalars().all()
    ) if parsed.findings else set()

    counts: dict[str, Any] = dict.fromkeys(SEVERITIES, 0)
    fixable_counts: dict[str, int] = dict.fromkeys(SEVERITIES, 0)
    max_cvss = None
    fixable = 0
    for f in parsed.findings:
        counts[f.severity] += 1
        if f.fixed_version:
            fixable += 1
            fixable_counts[f.severity] += 1
        if f.cvss is not None:
            max_cvss = f.cvss if max_cvss is None else max(max_cvss, f.cvss)

    scan = DockerScan(
        manifest_id=manifest.id,
        mode=job.mode,
        trivy_version=parsed.trivy_version,
        db_updated_at=parsed.db_updated_at,
        os_family=parsed.os_family,
        os_name=parsed.os_name,
        severity_counts={**counts, "fixable": fixable_counts},
        finding_count=len(parsed.findings),
        max_cvss=max_cvss,
        report_digest=report_digest,
        duration_ms=duration_ms,
    )
    session.add(scan)
    await session.flush()

    await session.execute(delete(DockerFinding).where(DockerFinding.manifest_id == manifest.id))
    if parsed.findings:
        await session.execute(
            DockerFinding.__table__.insert(),
            [
                {
                    "manifest_id": manifest.id,
                    "scan_id": scan.id,
                    "vuln_id": f.vuln_id,
                    "pkg_name": f.pkg_name,
                    "pkg_type": f.pkg_type,
                    "installed_version": f.installed_version,
                    "fixed_version": f.fixed_version,
                    "severity": f.severity,
                    "cvss": f.cvss,
                    "title": f.title,
                    "url": f.url,
                    "layer_digest": f.layer_digest,
                    "kev": f.vuln_id in kev,
                }
                for f in parsed.findings
            ],
        )

    manifest.scan_status = "scanned"
    manifest.scanned_at = datetime.now(UTC)
    manifest.latest_scan_id = scan.id
    manifest.severity_counts = {**counts, "fixable": fixable_counts}
    manifest.max_cvss = max_cvss
    manifest.fixable_count = fixable
    manifest.kev_count = sum(1 for f in parsed.findings if f.vuln_id in kev)

    job.status = "done"
    job.finished_at = datetime.now(UTC)
    job.error = None

    await _prune_reports(session, manifest.id, policy.keep_reports)
    await apply_push_policy(session, manifest, policy)
    bump("docker.scan.completed", mode=job.mode)
    return scan


async def apply_push_policy(
    session: AsyncSession, manifest: DockerManifest, policy: ImagePolicy | None = None
) -> None:
    """Hold an image pushed here to the push bar, once its scan is in.

    The verdict is written onto the manifest, so every later pull of that
    digest is refused with the reason, until an admin changes the policy (the
    verdict is re-evaluated on every policy save) or a fixed image is pushed.
    """
    if manifest.upstream_id is not None or manifest.kind != "image":
        return
    if manifest.scan_status != "scanned":
        return
    policy = policy or await load_policy(session)
    verdict = await evaluate_rules(session, manifest, policy, policy.push, label="push")
    manifest.policy_block_reason = None if verdict.allowed else verdict.reason
    if not verdict.allowed:
        bump("docker.push.policy_blocked")


async def reapply_push_policy(session: AsyncSession) -> int:
    policy = await load_policy(session)
    rows = (
        await session.execute(
            select(DockerManifest).where(
                DockerManifest.upstream_id.is_(None),
                DockerManifest.kind == "image",
                DockerManifest.scan_status == "scanned",
            )
        )
    ).scalars().all()
    for manifest in rows:
        await apply_push_policy(session, manifest, policy)
    return len(rows)


async def _prune_reports(session: AsyncSession, manifest_id: int, keep: int) -> None:
    scans = (
        await session.execute(
            select(DockerScan)
            .where(DockerScan.manifest_id == manifest_id)
            .order_by(DockerScan.id.desc())
        )
    ).scalars().all()
    for old in scans[keep:]:
        if old.report_digest:
            await _release_file(session, old.report_digest)
            old.report_digest = None


async def _release_file(session: AsyncSession, digest: str) -> None:
    """Delete a report/SBOM file unless another row still points at it."""
    still = (
        await session.execute(
            select(func.count()).select_from(DockerScan).where(DockerScan.report_digest == digest)
        )
    ).scalar_one()
    still += (
        await session.execute(
            select(func.count())
            .select_from(DockerManifest)
            .where(DockerManifest.sbom_digest == digest)
        )
    ).scalar_one()
    if still <= 1:
        get_oci_store().delete(digest)


# --------------------------------------------------------------------------- #
# Scheduling
# --------------------------------------------------------------------------- #
async def schedule_rescans(session: AsyncSession, limit: int = 500) -> int:
    """Queue SBOM rescans for digests whose last scan is older than
    ``rescan_hours``. An SBOM rescan never pulls the image: it re-matches the
    stored package list against the current vulnerability database."""
    policy = await load_policy(session)
    if not policy.scanning_enabled:
        return 0
    now = datetime.now(UTC)
    stale = now - timedelta(hours=policy.rescan_hours)
    recent = now - timedelta(days=policy.rescan_recent_days)
    rows = (
        await session.execute(
            select(DockerManifest, DockerRepository.name)
            .join(DockerRepoManifest, DockerRepoManifest.manifest_id == DockerManifest.id)
            .join(DockerRepository, DockerRepository.id == DockerRepoManifest.repository_id)
            .where(
                DockerManifest.kind == "image",
                DockerManifest.scan_status == "scanned",
                DockerManifest.scanned_at < stale,
                DockerManifest.last_accessed_at >= recent,
            )
            .order_by(DockerManifest.scanned_at.asc())
            .limit(limit)
        )
    ).all()
    queued = 0
    done: set[int] = set()
    for manifest, repo_name in rows:
        if manifest.id in done:
            continue
        done.add(manifest.id)
        mode = "sbom" if manifest.sbom_digest else "image"
        if await enqueue(
            session, manifest, repo_name, reason="schedule", priority=PRIORITY_SCHEDULE, mode=mode
        ):
            queued += 1
    return queued


async def queue_depth(session: AsyncSession) -> dict[str, int]:
    rows = (
        await session.execute(
            select(DockerScanJob.status, func.count()).group_by(DockerScanJob.status)
        )
    ).all()
    return dict(rows)


async def prune_jobs(session: AsyncSession, older_than_days: int = 14) -> int:
    cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
    result = await session.execute(
        delete(DockerScanJob).where(
            DockerScanJob.status.in_(("done", "failed")), DockerScanJob.finished_at < cutoff
        )
    )
    return result.rowcount or 0


# --------------------------------------------------------------------------- #
# CISA KEV
# --------------------------------------------------------------------------- #
async def refresh_kev(session: AsyncSession) -> int:
    """Load the KEV catalogue and re-flag findings."""
    from ..upstreams.base import get_http_client
    from ..upstreams.netguard import check_fetchable

    url = settings.kev_feed_url
    if not url:
        return 0
    host = url.split("/")[2] if "://" in url else ""
    check_fetchable(url, upstream_url=f"https://{host}")
    resp = await get_http_client().get(url, timeout=60)
    resp.raise_for_status()
    if len(resp.content) > 32 * 1024 * 1024:
        raise ReportInvalid("KEV feed is implausibly large")
    doc = resp.json()
    entries = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ReportInvalid("KEV feed has no vulnerabilities list")
    rows = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        cve = _s(e.get("cveID"), 32)
        if not cve or not cve.startswith("CVE-"):
            continue
        rows.append(
            {
                "cve_id": cve,
                "vendor": _s(e.get("vendorProject"), 255),
                "product": _s(e.get("product"), 255),
                "name": _s(e.get("vulnerabilityName"), 1000),
                "date_added": _s(e.get("dateAdded"), 16),
                "ransomware": str(e.get("knownRansomwareCampaignUse", "")).lower() == "known",
            }
        )
    if not rows:
        raise ReportInvalid("KEV feed parsed to nothing")
    await session.execute(delete(KevEntry))
    for start in range(0, len(rows), 500):
        await session.execute(KevEntry.__table__.insert(), rows[start : start + 500])
    await reflag_kev(session)
    bump("docker.kev.refreshed")
    log.info("KEV catalogue refreshed: %d entries", len(rows))
    return len(rows)


async def reflag_kev(session: AsyncSession) -> None:
    kev_ids = select(KevEntry.cve_id)
    await session.execute(
        update(DockerFinding).values(kev=DockerFinding.vuln_id.in_(kev_ids))
    )
    counts = (
        select(func.count())
        .select_from(DockerFinding)
        .where(DockerFinding.manifest_id == DockerManifest.id, DockerFinding.kev.is_(True))
        .scalar_subquery()
    )
    await session.execute(
        update(DockerManifest)
        .where(DockerManifest.scan_status == "scanned")
        .values(kev_count=counts)
    )
    await reapply_push_policy(session)
