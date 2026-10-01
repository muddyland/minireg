"""Image policy: what may be pulled, what a push must meet, how scans run.

Why not the package CVE threshold: Trivy's figures for ordinary base images
are measured in hundreds (``python:3.12-slim`` 165, ``postgres:16`` 335,
``node:22`` 4408). A "block CVSS >= 8" rule refuses essentially every image
on Docker Hub, so it gets switched off and protects nothing. The levers that
hold up are narrower:

* an explicit CVE **deny list**, always enforced;
* CISA's **Known Exploited Vulnerabilities** -- being exploited in the wild,
  not merely scored high;
* a per-repository **quarantine**;
* a **stricter bar for pushes than pulls**. Upstream base images will always
  carry CVEs, but images built here can be held to a standard before anyone
  runs them, which is where this fits into the delivery pipeline.

Severity thresholds remain available for both, off for pulls by default.
"""

from __future__ import annotations

import contextlib
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from sqlalchemy import and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.cache import cache_delete, cache_get_json, cache_set_json
from ..models import DockerFinding, DockerManifest, DockerManifestRef, DockerRepository, Setting

KEY_DOCKER_POLICY = "docker_policy"
_CACHE_KEY = "docker:policy"
SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def _rank(severity: str | None) -> int:
    try:
        return SEVERITIES.index((severity or "").upper())
    except ValueError:
        return 0


@dataclass(slots=True)
class GateRules:
    block_kev: bool = False
    #: Block when any finding at or above this severity remains, e.g.
    #: "CRITICAL". None disables the threshold.
    block_severity: str | None = None
    #: With a threshold set, count only findings that have a fixed version.
    #: A finding nobody can fix yet is not something a rebuild can clear.
    only_fixable: bool = True

    @classmethod
    def from_dict(cls, data: dict | None, **defaults) -> GateRules:
        base = cls(**defaults)
        if not isinstance(data, dict):
            return base
        sev = data.get("block_severity", base.block_severity)
        if sev is not None:
            sev = str(sev).upper()
            if sev not in SEVERITIES:
                sev = None
        return cls(
            block_kev=bool(data.get("block_kev", base.block_kev)),
            block_severity=sev,
            only_fixable=bool(data.get("only_fixable", base.only_fixable)),
        )


@dataclass(slots=True)
class ImagePolicy:
    scanning_enabled: bool = True
    #: Queue a scan the first time a digest is pulled.
    scan_on_pull: bool = True
    #: Hold a cold pull while the image is scanned, up to hold_seconds, but
    #: only for images no larger than hold_max_bytes: a 5 GB image cannot be
    #: scanned inside any client's timeout and holding it only ties up a
    #: connection. Off by default; background scanning is the default.
    hold_enabled: bool = False
    hold_seconds: float = 15.0
    hold_max_bytes: int = 200 * 1024 * 1024
    #: Never serve an image that has not been scanned: answer 503 with
    #: Retry-After and queue the scan. Docker retries a 503 a few times and
    #: then fails the pull, so this suits environments that prefer a failed
    #: deploy to an unexamined one.
    strict_mode: bool = False
    #: CVEs that block every image containing them, pulled or pushed.
    deny_cves: list[str] = field(default_factory=list)
    #: CVEs whose risk has been accepted: they never count towards a block.
    allow_cves: list[str] = field(default_factory=list)
    pull: GateRules = field(default_factory=GateRules)
    push: GateRules = field(
        default_factory=lambda: GateRules(block_kev=True, block_severity="CRITICAL", only_fixable=True)
    )
    #: Hold pulls of a pushed image until its scan finishes (they are local,
    #: so the scan takes seconds), then answer 503 if it still has not.
    push_require_scan: bool = True
    # -- scanner behaviour -------------------------------------------------- #
    rescan_hours: int = 24
    #: Rescan only digests pulled within this many days; older cache entries
    #: are not worth the worker's time.
    rescan_recent_days: int = 30
    scan_timeout_seconds: int = 900
    #: Images larger than this are recorded as not scanned rather than
    #: pulled into a worker.
    max_scan_bytes: int = 6 * 1024 * 1024 * 1024
    #: Platforms of a multi-platform image to scan. Empty = all.
    platforms: list[str] = field(default_factory=lambda: ["linux/amd64", "linux/arm64"])
    #: Severities recorded as findings.
    severities: list[str] = field(default_factory=lambda: list(SEVERITIES))
    ignore_unfixed: bool = False
    #: Kept reports per digest.
    keep_reports: int = 3
    # -- storage ------------------------------------------------------------ #
    storage_budget_bytes: int | None = None

    def scans_platform(self, platform: str | None) -> bool:
        """Is this platform on the scan list?

        A listed platform without a variant covers its variants: registries
        publish arm64 as ``linux/arm64/v8``, and an exact comparison against
        the default ``linux/arm64`` meant arm64 images were never scanned.
        """
        if not platform or not self.platforms:
            return True
        return any(platform == p or (p.count("/") == 1 and platform.startswith(p + "/")) for p in self.platforms)

    @classmethod
    def from_dict(cls, data: dict | None) -> ImagePolicy:
        p = cls()
        if not isinstance(data, dict):
            return p
        for name in (
            "scanning_enabled",
            "scan_on_pull",
            "hold_enabled",
            "strict_mode",
            "push_require_scan",
            "ignore_unfixed",
        ):
            if name in data:
                setattr(p, name, bool(data[name]))
        for name, lo, hi in (
            ("hold_seconds", 0.0, 120.0),
            ("hold_max_bytes", 0, 1 << 40),
            ("rescan_hours", 1, 24 * 90),
            ("rescan_recent_days", 1, 3650),
            ("scan_timeout_seconds", 30, 7200),
            ("max_scan_bytes", 0, 1 << 44),
            ("keep_reports", 1, 50),
        ):
            if name in data and data[name] is not None:
                try:
                    value = type(getattr(p, name))(data[name])
                except (TypeError, ValueError):
                    continue
                setattr(p, name, min(max(value, lo), hi))
        if data.get("storage_budget_bytes") is not None:
            with contextlib.suppress(TypeError, ValueError):
                p.storage_budget_bytes = max(0, int(data["storage_budget_bytes"]))
        p.deny_cves = _cve_list(data.get("deny_cves"))
        p.allow_cves = _cve_list(data.get("allow_cves"))
        if isinstance(data.get("platforms"), list):
            p.platforms = [str(x)[:64] for x in data["platforms"] if x][:32]
        if isinstance(data.get("severities"), list):
            p.severities = [s for s in (str(x).upper() for x in data["severities"]) if s in SEVERITIES]
        p.pull = GateRules.from_dict(data.get("pull"))
        p.push = GateRules.from_dict(
            data.get("push"), block_kev=True, block_severity="CRITICAL", only_fixable=True
        )
        return p

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def budget(self) -> int:
        from ..config import settings

        if self.storage_budget_bytes is not None:
            return self.storage_budget_bytes
        return settings.docker_storage_budget_bytes


def _cve_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    out = []
    for item in value:
        s = str(item).strip().upper()
        if s and len(s) <= 64:
            out.append(s)
    return sorted(set(out))[:5000]


_local: tuple[float, ImagePolicy] | None = None


async def load_policy(session: AsyncSession) -> ImagePolicy:
    """Read the policy. Cached briefly in-process and in Redis."""
    global _local
    if _local and _local[0] > time.monotonic():
        return _local[1]
    cached = await cache_get_json(_CACHE_KEY)
    if cached is None:
        row = await session.get(Setting, KEY_DOCKER_POLICY)
        cached = {"v": row.value if row else None}
        await cache_set_json(_CACHE_KEY, cached, 60)
    policy = ImagePolicy.from_dict(cached.get("v"))
    _local = (time.monotonic() + 5, policy)
    return policy


async def invalidate_policy() -> None:
    global _local
    _local = None
    await cache_delete(_CACHE_KEY)


# --------------------------------------------------------------------------- #
# Verdicts
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class ImageVerdict:
    allowed: bool
    reason: str | None = None
    #: DENIED (policy) or UNAVAILABLE (not scanned yet, try again)
    code: str = "DENIED"
    retry_after: int | None = None
    source: str | None = None


ALLOW = ImageVerdict(True)


async def gate_counts(
    session: AsyncSession, manifest: DockerManifest, policy: ImagePolicy
) -> dict[str, Any]:
    """Findings that count against the gates, after the accepted-risk list."""
    conds = [DockerFinding.manifest_id == manifest.id]
    if policy.allow_cves:
        conds.append(DockerFinding.vuln_id.notin_(policy.allow_cves))
    # One labelled expression, grouped by label. Repeating the expression in
    # GROUP BY works on SQLite but not on PostgreSQL, which sees two
    # differently-bound parameters ('' twice) and refuses the query.
    fixable = case(
        (and_(DockerFinding.fixed_version.isnot(None), DockerFinding.fixed_version != ""), True),
        else_=False,
    ).label("fixable")
    rows = (
        await session.execute(
            select(DockerFinding.severity, fixable, DockerFinding.kev, func.count())
            .where(and_(*conds))
            .group_by(DockerFinding.severity, fixable, DockerFinding.kev)
        )
    ).all()
    counts: dict[str, Any] = {"kev": 0, "by_severity": {}, "fixable_by_severity": {}}
    for severity, fixable, kev, n in rows:
        sev = (severity or "UNKNOWN").upper()
        counts["by_severity"][sev] = counts["by_severity"].get(sev, 0) + n
        if fixable:
            counts["fixable_by_severity"][sev] = counts["fixable_by_severity"].get(sev, 0) + n
        if kev:
            counts["kev"] += n
    return counts


async def denied_cves_present(
    session: AsyncSession, manifest: DockerManifest, policy: ImagePolicy
) -> list[str]:
    if not policy.deny_cves:
        return []
    rows = (
        await session.execute(
            select(DockerFinding.vuln_id)
            .where(
                DockerFinding.manifest_id == manifest.id,
                DockerFinding.vuln_id.in_(policy.deny_cves),
            )
            .distinct()
            .limit(5)
        )
    ).scalars().all()
    return list(rows)


def _threshold_hits(rules: GateRules, counts: dict) -> int:
    if not rules.block_severity:
        return 0
    floor = _rank(rules.block_severity)
    table = counts["fixable_by_severity"] if rules.only_fixable else counts["by_severity"]
    return sum(n for sev, n in table.items() if _rank(sev) >= floor)


async def evaluate_rules(
    session: AsyncSession,
    manifest: DockerManifest,
    policy: ImagePolicy,
    rules: GateRules,
    *,
    label: str,
) -> ImageVerdict:
    """Deny list, KEV and severity threshold against a scanned manifest."""
    denied = await denied_cves_present(session, manifest, policy)
    if denied:
        return ImageVerdict(
            False,
            f"image contains {', '.join(denied)}, which the image policy denies",
            source="deny_list",
        )
    if not (rules.block_kev or rules.block_severity):
        return ALLOW
    counts = await gate_counts(session, manifest, policy)
    if rules.block_kev and counts["kev"]:
        return ImageVerdict(
            False,
            f"{label} policy: image contains {counts['kev']} known-exploited "
            "vulnerabilities (CISA KEV)",
            source="kev",
        )
    hits = _threshold_hits(rules, counts)
    if hits:
        qualifier = "fixable " if rules.only_fixable else ""
        return ImageVerdict(
            False,
            f"{label} policy: image has {hits} {qualifier}findings at "
            f"{rules.block_severity} or above",
            source="severity",
        )
    return ALLOW


async def _evaluate_index(
    session: AsyncSession,
    repo: DockerRepository,
    index: DockerManifest,
    policy: ImagePolicy,
) -> ImageVerdict:
    """An index takes the verdict of its worst platform image.

    Judging only the child left a hole: Docker resolves a tag through the
    index, and a client that already holds the child manifest (the machine
    that built it, any node that pulled it before the block) never asks for
    the child again, so the block was never seen. Refusing the index makes a
    block apply to everyone who resolves the tag.

    Only a firm DENIED propagates. "Not scanned yet" does not: the child
    request answers that itself, and one slow platform should not hold up
    the others.
    """
    child_digests = (
        await session.execute(
            select(DockerManifestRef.digest).where(
                DockerManifestRef.manifest_id == index.id, DockerManifestRef.ref_type == "manifest"
            )
        )
    ).scalars().all()
    if not child_digests:
        return ALLOW
    children = (
        await session.execute(
            select(DockerManifest).where(
                DockerManifest.digest.in_(child_digests), DockerManifest.kind == "image"
            )
        )
    ).scalars().all()
    for child in children:
        if child.policy_block_reason:
            verdict = ImageVerdict(False, child.policy_block_reason, source="push_policy")
        elif child.scan_status == "scanned":
            verdict = await evaluate_rules(session, child, policy, policy.pull, label="pull")
        else:
            continue
        if not verdict.allowed and verdict.code == "DENIED":
            where = child.platform or child.digest[:19]
            return ImageVerdict(False, f"{where}: {verdict.reason}", source=verdict.source)
    return ALLOW


async def evaluate_pull(
    session: AsyncSession,
    repo: DockerRepository,
    manifest: DockerManifest,
    policy: ImagePolicy,
) -> ImageVerdict:
    """May this manifest be served from this repository right now?"""
    if repo.quarantined:
        return ImageVerdict(
            False,
            f"repository {repo.name} is quarantined"
            + (f": {repo.quarantine_reason}" if repo.quarantine_reason else ""),
            source="quarantine",
        )
    if manifest.policy_block_reason:
        return ImageVerdict(False, manifest.policy_block_reason, source="push_policy")
    if manifest.kind == "index":
        return await _evaluate_index(session, repo, manifest, policy)
    if manifest.kind != "image":
        return ALLOW
    if manifest.scan_status == "scanned":
        return await evaluate_rules(session, manifest, policy, policy.pull, label="pull")
    if not policy.scanning_enabled:
        return ALLOW
    local = manifest.upstream_id is None
    pending = manifest.scan_status in ("unscanned", "queued", "scanning")
    if pending and (policy.strict_mode or (local and policy.push_require_scan)):
        return ImageVerdict(
            False,
            "image has not been scanned yet; a scan is queued, retry shortly",
            code="UNAVAILABLE",
            retry_after=15,
            source="unscanned",
        )
    return ALLOW
