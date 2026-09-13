"""OSV.dev vulnerability scanning, restricted to CVEs.

Policy decisions baked in here:

* **CVE only.** OSV aggregates GHSA, PYSEC, GO, MAL and more. We keep a record
  only when it carries a ``CVE-*`` alias, and we key our reporting on that CVE.
* **Scores.** OSV entries carry zero or more ``severity`` items. v3.x is
  computed exactly and is preferred; v4 is approximated (see ``_cvss4_base``)
  and only used when no v3 vector is published; v2 is the last resort.
* **Inline scanning** happens on first sight of a version, under a strict
  timeout, so a slow OSV never becomes a slow ``npm install``. On timeout we
  fail open by default (configurable) and queue a background scan.

OSV ecosystem identifiers: ``npm``, ``PyPI`` and ``crates.io`` (note the
capitalisation -- OSV rejects a query whose ecosystem name is not exact).
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from ..config import settings
from ..models import Ecosystem, Package, PackageVersion, PackageVulnerability, Vulnerability
from ..upstreams.base import get_http_client

log = logging.getLogger(__name__)


def _bump(counter: str) -> None:
    """Record a fail-open. Imported lazily to avoid a cycle with main."""
    try:
        from ..main import bump

        bump(counter)
    except Exception:  # pragma: no cover - metrics must never break a scan
        pass

OSV_ECOSYSTEM = {
    Ecosystem.npm: "npm",
    Ecosystem.pypi: "PyPI",
    Ecosystem.cargo: "crates.io",
}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
# OpenSSF malicious-package advisories. These are the records that say "this
# release is malware", and they are precisely what a registry billed as
# supply-chain defence exists to stop.
MAL_RE = re.compile(r"^MAL-\d{4}-\d+$", re.IGNORECASE)
# Malware has no CVSS vector to compute, and "we do not know how bad it is"
# is the wrong reading of a confirmed backdoor. Score it at the top of the
# scale so any sane block range catches it.
MALICIOUS_SCORE = 10.0

# CVSS v3/v4 qualitative rating scale (FIRST.org).
SEVERITY_BANDS = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "none"),
)

# v3 is preferred over v4: our v4 score is an approximation (see _cvss4_base)
# while v3 is computed exactly, so when a record publishes both we use the one
# we can stand behind.
_SEVERITY_PREFERENCE = {"CVSS_V3": 3, "CVSS_V4": 2, "CVSS_V2": 1}

# A v4 vector that declares any impact never scores below this, so an
# approximation error cannot present a real vulnerability as harmless.
LOW_FLOOR = 2.0


def severity_label(score: float | None) -> str | None:
    if score is None:
        return None
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "none"


def is_malicious(record: dict) -> bool:
    """Whether an OSV record is a malicious-package (MAL-*) advisory."""
    ident = record.get("id") or ""
    if MAL_RE.match(ident):
        return True
    return any(
        isinstance(alias, str) and MAL_RE.match(alias)
        for alias in record.get("aliases") or []
    )


def extract_cve(record: dict) -> str | None:
    """The CVE id for an OSV record, from ``id`` or ``aliases``."""
    ident = record.get("id") or ""
    if CVE_RE.match(ident):
        return ident.upper()
    for alias in record.get("aliases") or []:
        if isinstance(alias, str) and CVE_RE.match(alias):
            return alias.upper()
    return None


def parse_cvss_vector(vector: str) -> float | None:
    """Read the base score out of a CVSS vector string.

    OSV publishes vectors, not scores, so we compute. ``cvss`` is not a
    dependency we want, so this implements the v3.x/v4.0 base equations
    directly for the metrics that determine the base score.
    """
    if not vector:
        return None
    vector = vector.strip()
    if vector.startswith("CVSS:3"):
        return _cvss3_base(vector)
    if vector.startswith("CVSS:4"):
        return _cvss4_base(vector)
    if vector.startswith("AV:"):  # bare v2 vector
        return _cvss2_base(vector)
    return None


def _vector_parts(vector: str) -> dict[str, str]:
    parts = {}
    for chunk in vector.split("/"):
        if ":" in chunk:
            key, _, value = chunk.partition(":")
            parts[key.strip()] = value.strip()
    return parts


def _round_up(value: float) -> float:
    """CVSS 3.1 Appendix A roundup, done in integer space to dodge float error."""
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (int(integer / 10000) + 1) / 10.0


def _cvss3_base(vector: str) -> float | None:
    p = _vector_parts(vector)
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[p["AV"]]
        ac = {"L": 0.77, "H": 0.44}[p["AC"]]
        ui = {"N": 0.85, "R": 0.62}[p["UI"]]
        scope_changed = p["S"] == "C"
        pr_map = (
            {"N": 0.85, "L": 0.68, "H": 0.50} if scope_changed else {"N": 0.85, "L": 0.62, "H": 0.27}
        )
        pr = pr_map[p["PR"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        conf, integ, avail = cia[p["C"]], cia[p["I"]], cia[p["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    # Kept as a branch rather than a ternary: these are the two impact
    # sub-formulas from the CVSS 3.1 specification, and side by side they can
    # be checked against it line for line.
    if scope_changed:  # noqa: SIM108
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = min((impact + exploitability) * (1.08 if scope_changed else 1.0), 10.0)
    return _round_up(raw)


def _cvss4_base(vector: str) -> float | None:
    """Approximate a CVSS v4.0 base score.

    v4 scores via a 270-entry macrovector lookup table that cannot be
    faithfully reproduced from the equations, so this is explicitly an
    approximation and :func:`best_severity` always prefers a v3 vector when the
    same record publishes one.

    Two things it must get right, because getting them wrong understates risk:

    * v4 splits impact into the *vulnerable* system (VC/VI/VA) and the
      *subsequent* system (SC/SI/SA). A vector like
      ``VC:N/VI:N/VA:N/SC:L/SI:L/SA:L`` -- no impact on the component itself,
      real impact downstream -- is a genuine vulnerability, and reading only
      VC/VI/VA scores it a flat zero.
    * Attack Requirements (AT) is new in v4 and lowers exploitability.

    A vector that declares any impact at all never scores below LOW_FLOOR, so
    an approximation error can never present a real vulnerability as harmless.
    """
    p = _vector_parts(vector)
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[p["AV"]]
        ac = {"L": 0.77, "H": 0.44}[p["AC"]]
        at = {"N": 1.0, "P": 0.7}[p.get("AT", "N")]
        ui = {"N": 0.85, "P": 0.68, "A": 0.62}[p.get("UI", "N")]
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}[p.get("PR", "N")]

        vulnerable = {"H": 0.56, "L": 0.22, "N": 0.0}
        # Downstream impact is real but weighs less than impact on the
        # component itself.
        subsequent = {"H": 0.30, "L": 0.12, "N": 0.0}

        conf = vulnerable[p.get("VC", p.get("C", "N"))]
        integ = vulnerable[p.get("VI", p.get("I", "N"))]
        avail = vulnerable[p.get("VA", p.get("A", "N"))]
        sub_conf = subsequent[p.get("SC", "N")]
        sub_integ = subsequent[p.get("SI", "N")]
        sub_avail = subsequent[p.get("SA", "N")]
    except KeyError:
        return None

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    sss = 1 - ((1 - sub_conf) * (1 - sub_integ) * (1 - sub_avail))
    combined = min(1.0, iss + (sss * (1.0 - iss)))

    impact = 6.42 * combined
    exploitability = 8.22 * av * ac * at * pr * ui

    if combined <= 0:
        # Every impact metric is None: genuinely no impact, score zero.
        return 0.0

    score = _round_up(min(impact + exploitability, 10.0))
    return max(score, LOW_FLOOR)


def _cvss2_base(vector: str) -> float | None:
    p = _vector_parts(vector)
    try:
        av = {"L": 0.395, "A": 0.646, "N": 1.0}[p["AV"]]
        ac = {"H": 0.35, "M": 0.61, "L": 0.71}[p["AC"]]
        au = {"M": 0.45, "S": 0.56, "N": 0.704}[p["Au"]]
        cia = {"N": 0.0, "P": 0.275, "C": 0.660}
        conf, integ, avail = cia[p["C"]], cia[p["I"]], cia[p["A"]]
    except KeyError:
        return None
    impact = 10.41 * (1 - (1 - conf) * (1 - integ) * (1 - avail))
    exploitability = 20 * av * ac * au
    f_impact = 0.0 if impact == 0 else 1.176
    return round(((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact, 1)


def best_severity(record: dict) -> tuple[float | None, str | None, str | None]:
    """Return ``(score, type, vector)`` for the highest-confidence severity."""
    candidates: list[tuple[int, float, str, str]] = []
    for entry in record.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        stype = (entry.get("type") or "").upper()
        raw = entry.get("score") or ""
        score = parse_cvss_vector(raw)
        if score is None:
            # Some sources publish a bare numeric score.
            try:
                score = float(raw)
            except (TypeError, ValueError):
                continue
        candidates.append((_SEVERITY_PREFERENCE.get(stype, 0), score, stype, raw))

    # Also look in database_specific, where GHSA-derived records often hide it.
    if not candidates:
        db_specific = record.get("database_specific") or {}
        raw = db_specific.get("cvss") or {}
        if isinstance(raw, dict) and raw.get("vectorString"):
            score = parse_cvss_vector(raw["vectorString"])
            if score is not None:
                candidates.append((2, score, "CVSS_V3", raw["vectorString"]))

    # Last resort: the qualitative label. GHSA records essentially always carry
    # one even when they publish no vector, and treating those as "unscored"
    # made a `block >= 7.0` rule quietly ignore every GHSA-only advisory. The
    # band floor is deliberately conservative -- it is the lowest score that
    # still earns the label, so we never inflate a severity.
    if not candidates:
        label = ((record.get("database_specific") or {}).get("severity") or "")
        floor = _SEVERITY_LABEL_FLOOR.get(str(label).strip().upper())
        if floor is not None:
            return floor, "LABEL", str(label).strip().upper()

    if not candidates:
        return None, None, None
    # Prefer the newest CVSS version; break ties on the higher score.
    candidates.sort(key=lambda c: (c[0], c[1]), reverse=True)
    _, score, stype, vector = candidates[0]
    return score, stype or None, vector or None


# Floor of each qualitative band, used only when a record publishes a label
# but no CVSS vector.
_SEVERITY_LABEL_FLOOR = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MODERATE": 4.0,
    "MEDIUM": 4.0,
    "LOW": 0.1,
}


def _parse_dt(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


# A GIT range's `fixed` event names a commit SHA. That is not installable from
# a registry, and reporting it as the fixed version -- which happened whenever
# OSV listed the git range first -- masked the real ECOSYSTEM fix and made the
# finding look unfixable. Any other range type (including a record that omits
# the field) is treated as naming a release.
_UNINSTALLABLE_RANGE_TYPES = {"GIT"}


def fixed_version_for(record: dict, package_name: str, ecosystem: str) -> str | None:
    """First installable ``fixed`` bound OSV lists for this package, if any."""
    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("name", "").lower() != package_name.lower():
            continue
        for rng in affected.get("ranges") or []:
            if (rng.get("type") or "").upper() in _UNINSTALLABLE_RANGE_TYPES:
                continue
            for event in rng.get("events") or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


@dataclass(slots=True)
class ScanResult:
    version_id: int | None
    package_name: str
    version: str
    cves: list[dict] = field(default_factory=list)
    max_score: float | None = None
    has_fix: bool = False
    scanned: bool = True

    @property
    def severity(self) -> str | None:
        return severity_label(self.max_score)


class OsvScanner:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # -- OSV calls ---------------------------------------------------------- #
    async def _query_batch(self, queries: list[dict], timeout: float | None = None) -> list[dict]:
        """POST /v1/querybatch. Returns one result list per query, in order.

        querybatch returns *abbreviated* records (id + modified only), so any
        hit has to be re-fetched via /v1/vulns/{id} for the full detail.
        """
        if not queries:
            return []
        client = get_http_client()
        try:
            resp = await client.post(
                f"{settings.osv_api_url}/v1/querybatch",
                json={"queries": queries},
                timeout=timeout or settings.osv_timeout_seconds,
            )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise TimeoutError(f"OSV querybatch failed: {exc}") from exc
        if resp.status_code != 200:
            raise RuntimeError(f"OSV querybatch HTTP {resp.status_code}")
        return (resp.json() or {}).get("results") or []

    async def _fetch_vuln(self, osv_id: str, timeout: float | None = None) -> dict | None:
        client = get_http_client()
        try:
            resp = await client.get(
                f"{settings.osv_api_url}/v1/vulns/{osv_id}",
                timeout=timeout or settings.osv_timeout_seconds,
            )
        except (httpx.TimeoutException, httpx.TransportError):
            return None
        if resp.status_code != 200:
            return None
        return resp.json()

    # -- scanning ----------------------------------------------------------- #
    async def scan_versions(
        self,
        ecosystem: Ecosystem,
        items: list[tuple[str, str]],
        *,
        timeout: float | None = None,
    ) -> dict[tuple[str, str], ScanResult]:
        """Scan ``[(package_name, version), ...]`` and return results keyed by
        the same tuple. Records are persisted as a side effect."""
        if not settings.osv_enabled or not items:
            return {
                key: ScanResult(None, key[0], key[1], scanned=False) for key in items
            }

        osv_eco = OSV_ECOSYSTEM[ecosystem]
        results: dict[tuple[str, str], ScanResult] = {}
        chunk = settings.osv_batch_size

        for start in range(0, len(items), chunk):
            batch = items[start : start + chunk]
            queries = [
                {"package": {"name": name, "ecosystem": osv_eco}, "version": version}
                for name, version in batch
            ]
            try:
                raw_results = await self._query_batch(queries, timeout=timeout)
            except (TimeoutError, RuntimeError) as exc:
                _bump("cve.batch.failed")
                log.warning("OSV batch failed: %s", exc)
                for name, version in batch:
                    results[(name, version)] = ScanResult(None, name, version, scanned=False)
                continue

            # querybatch answers one result per query, in order. If it does
            # not, we cannot tell which answer belongs to which package, and
            # padding the gap with "no vulnerabilities" would stamp the whole
            # batch as scanned and clean -- which is what a degraded OSV, a
            # proxy error page with a JSON body, or a WAF used to produce.
            if len(raw_results) != len(batch):
                log.warning(
                    "OSV batch returned %d results for %d queries; treating as unscanned",
                    len(raw_results),
                    len(batch),
                )
                for name, version in batch:
                    results[(name, version)] = ScanResult(None, name, version, scanned=False)
                continue

            # Collect every distinct OSV id in this batch, then hydrate once.
            needed: set[str] = set()
            per_item_ids: list[list[str]] = []
            for entry in raw_results:
                ids = [v["id"] for v in (entry.get("vulns") or []) if v.get("id")]
                per_item_ids.append(ids)
                needed.update(ids)

            hydrated = await self._hydrate(needed, ecosystem, timeout=timeout)

            for (name, version), ids in zip(batch, per_item_ids, strict=True):
                cves = []
                max_score = None
                has_fix = False
                for osv_id in ids:
                    record = hydrated.get(osv_id)
                    if record is None:
                        continue  # filtered out, or hydration failed
                    # The fix bound is package-specific, so it can only be
                    # resolved here where the package name is known -- not in
                    # _hydrate, which serves a whole batch of packages at once.
                    if record.get("raw"):
                        record = {
                            **record,
                            "fixed_version": fixed_version_for(
                                record["raw"], name, ecosystem.value
                            ),
                        }
                    cves.append(record)
                    score = record.get("cvss_score")
                    if score is not None and (max_score is None or score > max_score):
                        max_score = score
                    if record.get("fixed_version"):
                        has_fix = True
                if not cves:
                    # Scanned, nothing found. Recorded as a real zero rather
                    # than None so the policy engine can tell "clean" from
                    # "we do not know" -- see CvePolicy.blocks.
                    max_score = 0.0
                results[(name, version)] = ScanResult(
                    version_id=None,
                    package_name=name,
                    version=version,
                    cves=cves,
                    max_score=max_score,
                    has_fix=has_fix,
                    scanned=True,
                )
        return results

    async def _hydrate(
        self, osv_ids: set[str], ecosystem: Ecosystem, *, timeout: float | None = None
    ) -> dict[str, dict]:
        """Fetch full records, keeping only CVEs, and upsert them."""
        if not osv_ids:
            return {}

        # Records we already have and that are fresh enough are not re-fetched.
        known = (
            await self.session.execute(
                select(Vulnerability).where(Vulnerability.id.in_(list(osv_ids)))
            )
        ).scalars().all()
        cached = {
            v.id: {
                "id": v.id,
                "cve_id": v.cve_id,
                "cvss_score": v.cvss_score,
                "severity": v.severity_label,
                "summary": v.summary,
                "fixed_version": None,
                # The full record has to come along: apply_to_version reads the
                # affected ranges out of it to work out which release fixed the
                # issue. Omitting it here meant every CVE we had already seen
                # reported "no fix available", regardless of the truth.
                "raw": v.raw,
            }
            for v in known
        }
        missing = osv_ids - set(cached)
        if not missing:
            return cached

        # Bounded fan-out. A batch covering a heavily-advised package can name
        # hundreds of distinct ids, and firing them all at once is what earns
        # the 429 that then fails the whole batch.
        sem = asyncio.Semaphore(settings.osv_hydrate_concurrency)

        async def _fetch(osv_id: str):
            async with sem:
                return await self._fetch_vuln(osv_id, timeout=timeout)

        # Sorted, so every process that touches an overlapping set of
        # advisories takes their row locks in the same order.
        #
        # `missing` is a set, so iteration order varied per process. Two
        # concurrent scans -- the hourly refresh and an admin pressing "Scan
        # new versions", which now overlap far more often since the refresh
        # drains for minutes rather than doing one batch -- would upsert the
        # same ids in opposite orders and deadlock in Postgres. Consistent
        # ordering is the standard fix, and costs nothing.
        ordered = sorted(missing)
        fetched = await asyncio.gather(
            *(_fetch(i) for i in ordered), return_exceptions=True
        )
        for record in fetched:
            if not isinstance(record, dict):
                continue
            cve_id = extract_cve(record)
            malicious = is_malicious(record)
            # OSV_CVE_ONLY drops advisory noise that carries no CVE, but a
            # malicious-package record is never noise: npm and PyPI malware
            # almost never gets a CVE assigned, so honouring the flag here
            # meant the registry scanned malware and recorded it as clean.
            if settings.osv_cve_only and not cve_id and not malicious:
                continue
            osv_id = record.get("id")
            if not osv_id:
                continue
            score, stype, vector = best_severity(record)
            if malicious and score is None:
                score, stype, vector = MALICIOUS_SCORE, "MALICIOUS", None
            row = {
                "id": osv_id,
                "cve_id": cve_id or osv_id,
                "ecosystem": ecosystem,
                "summary": record.get("summary"),
                "details": (record.get("details") or "")[:20000] or None,
                "severity_type": stype,
                "cvss_vector": vector,
                "cvss_score": score,
                "severity_label": severity_label(score),
                "aliases": record.get("aliases") or [],
                "references": record.get("references") or [],
                "published": _parse_dt(record.get("published")),
                "modified": _parse_dt(record.get("modified")),
                "withdrawn": _parse_dt(record.get("withdrawn")),
                "raw": record,
                "fetched_at": datetime.now(UTC),
            }
            await self._upsert_vulnerability(row)
            cached[osv_id] = {
                "id": osv_id,
                "cve_id": cve_id or osv_id,
                "cvss_score": score,
                "severity": severity_label(score),
                "summary": record.get("summary"),
                "fixed_version": None,
                "raw": record,
            }
        return cached

    async def _upsert_vulnerability(self, row: dict) -> None:
        from ..db import get_engine

        if get_engine().dialect.name == "postgresql":
            stmt = pg_insert(Vulnerability).values(**row)
            stmt = stmt.on_conflict_do_update(
                index_elements=[Vulnerability.id],
                set_={
                    k: stmt.excluded[k]
                    for k in row
                    if k not in ("id",)
                },
            )
            await self.session.execute(stmt)
        else:
            existing = await self.session.get(Vulnerability, row["id"])
            if existing is None:
                self.session.add(Vulnerability(**row))
            else:
                for key, value in row.items():
                    setattr(existing, key, value)

    async def rescore_stored(self) -> dict[str, int]:
        """Recompute severities from the OSV records we already hold.

        The full record is kept in ``raw``, so a change to the scoring code -- a
        corrected CVSS equation, a new vector version -- can be applied to
        history without re-fetching anything. Without this, a scoring fix would
        only ever reach newly discovered vulnerabilities while every existing
        row stayed quietly wrong.
        """
        rows = (
            await self.session.execute(
                select(Vulnerability).where(Vulnerability.raw.isnot(None))
            )
        ).scalars().all()

        changed = 0
        for vuln in rows:
            if not isinstance(vuln.raw, dict) or not vuln.raw:
                continue
            score, stype, vector = best_severity(vuln.raw)
            if score != vuln.cvss_score or stype != vuln.severity_type:
                vuln.cvss_score = score
                vuln.severity_type = stype
                vuln.cvss_vector = vector
                vuln.severity_label = severity_label(score)
                changed += 1
        await self.session.flush()

        # Version-level max_cvss is denormalized from these rows, so it has to
        # be recomputed too or the policy engine keeps enforcing old numbers.
        pairs = (
            await self.session.execute(
                select(PackageVulnerability.version_id, Vulnerability.cvss_score).join(
                    Vulnerability, Vulnerability.id == PackageVulnerability.vulnerability_id
                )
            )
        ).all()
        worst: dict[int, float | None] = {}
        for version_id, score in pairs:
            current = worst.get(version_id)
            if score is not None and (current is None or score > current):
                worst[version_id] = score
            worst.setdefault(version_id, None)

        versions_updated = 0
        for version_id, score in worst.items():
            version_row = await self.session.get(
                PackageVersion, version_id, options=[defer(PackageVersion.metadata_json)]
            )
            if version_row is not None and version_row.max_cvss != score:
                version_row.max_cvss = score
                versions_updated += 1
        await self.session.flush()

        # Fixed versions are derived from the same stored records, and were
        # historically left NULL whenever the CVE was already cached. Recompute
        # them here so a rescore repairs that too.
        by_id = {v.id: v for v in rows}
        links = (await self.session.execute(select(PackageVulnerability))).scalars().all()
        packages = {
            p.id: p
            for p in (
                await self.session.execute(
                    # cached_document is the whole upstream packument. A
                    # rescore touches every package that has a CVE, so
                    # selecting the entity here is the OOM the project already
                    # had once, triggered from an admin button.
                    select(Package).options(defer(Package.cached_document)).where(
                        Package.id.in_(
                            select(PackageVersion.package_id).where(
                                PackageVersion.id.in_([link.version_id for link in links] or [0])
                            )
                        )
                    )
                )
            ).scalars().all()
        }
        versions = {
            v.id: v
            for v in (
                await self.session.execute(
                    select(PackageVersion)
                    .options(defer(PackageVersion.metadata_json))
                    .where(
                        PackageVersion.id.in_([link.version_id for link in links] or [0])
                    )
                )
            ).scalars().all()
        }

        fixes_updated = 0
        for link in links:
            vuln = by_id.get(link.vulnerability_id)
            version_row = versions.get(link.version_id)
            if vuln is None or version_row is None or not isinstance(vuln.raw, dict):
                continue
            package = packages.get(version_row.package_id)
            if package is None:
                continue
            fixed = fixed_version_for(vuln.raw, package.name, package.ecosystem.value)
            if fixed != link.fixed_version:
                link.fixed_version = fixed
                fixes_updated += 1
        await self.session.flush()

        return {
            "vulnerabilities_examined": len(rows),
            "vulnerabilities_rescored": changed,
            "versions_updated": versions_updated,
            "fixed_versions_updated": fixes_updated,
        }

    # -- persistence -------------------------------------------------------- #
    async def apply_to_version(
        self, version_row: PackageVersion, result: ScanResult, package_name: str
    ) -> bool:
        """Persist scan output onto a stored version and its CVE links.

        Returns whether the stored verdict changed, so a caller that holds the
        package identity can drop the rendered documents that have the old
        verdict baked into them.
        """
        if not result.scanned:
            return False

        changed = (
            version_row.max_cvss != result.max_score
            or version_row.scanned_at is None
            or version_row.has_fix != result.has_fix
        )
        version_row.max_cvss = result.max_score
        version_row.has_fix = result.has_fix
        version_row.scanned_at = datetime.now(UTC)

        existing_links = {
            link.vulnerability_id: link
            for link in (
                await self.session.execute(
                    select(PackageVulnerability).where(
                        PackageVulnerability.version_id == version_row.id
                    )
                )
            ).scalars().all()
        }
        seen: set[str] = set()
        for record in result.cves:
            osv_id = record["id"]
            seen.add(osv_id)
            # scan_versions already resolved this against the package name.
            fixed = record.get("fixed_version")
            if fixed is None and record.get("raw"):
                fixed = fixed_version_for(record["raw"], package_name, "")
            if osv_id in existing_links:
                existing_links[osv_id].fixed_version = fixed
                continue
            self.session.add(
                PackageVulnerability(
                    version_id=version_row.id,
                    vulnerability_id=osv_id,
                    fixed_version=fixed,
                )
            )
        # Links for CVEs that no longer apply (record withdrawn, range revised).
        for osv_id, link in existing_links.items():
            if osv_id not in seen:
                await self.session.delete(link)
                changed = True
        return changed

    async def scan_and_apply(
        self, ecosystem: Ecosystem, version_row: PackageVersion, package_name: str, *, timeout=None
    ) -> ScanResult:
        results = await self.scan_versions(
            ecosystem, [(package_name, version_row.version)], timeout=timeout
        )
        result = results.get(
            (package_name, version_row.version),
            ScanResult(None, package_name, version_row.version, scanned=False),
        )
        if await self.apply_to_version(version_row, result, package_name):
            from ..core.naming import normalize_name_for
            from .packages import invalidate_package_cache

            await invalidate_package_cache(
                ecosystem.value, normalize_name_for(ecosystem.value, package_name)
            )
        return result


async def inline_scan(
    session: AsyncSession, ecosystem: Ecosystem, package_name: str, version: str
) -> ScanResult:
    """Best-effort scan on the request path.

    Bounded by ``OSV_INLINE_TIMEOUT_SECONDS``. On timeout the result is marked
    unscanned, which the policy engine interprets according to
    ``block_unscored``.
    """
    if not settings.osv_enabled or not settings.osv_inline_scan:
        return ScanResult(None, package_name, version, scanned=False)
    scanner = OsvScanner(session)
    try:
        results = await asyncio.wait_for(
            scanner.scan_versions(ecosystem, [(package_name, version)]),
            timeout=settings.osv_inline_timeout_seconds,
        )
    except (TimeoutError, asyncio.CancelledError):
        # A fail-open. With block_unscored off (the default) the version is
        # about to be served unscanned, which is exactly the state an operator
        # needs to be able to see.
        _bump("cve.scan.timeout")
        log.warning(
            "inline OSV scan timed out for %s@%s; serving it unscanned",
            package_name,
            version,
        )
        return ScanResult(None, package_name, version, scanned=False)
    except Exception as exc:
        log.warning("inline OSV scan failed for %s@%s: %s", package_name, version, exc)
        return ScanResult(None, package_name, version, scanned=False)
    return results.get(
        (package_name, version), ScanResult(None, package_name, version, scanned=False)
    )
