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

OSV ecosystem identifiers: ``npm`` and ``PyPI`` (note the capitalisation).
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

from ..config import settings
from ..models import Ecosystem, PackageVersion, PackageVulnerability, Vulnerability
from ..upstreams.base import get_http_client

log = logging.getLogger(__name__)

OSV_ECOSYSTEM = {Ecosystem.npm: "npm", Ecosystem.pypi: "PyPI"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

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
    integer = int(round(value * 100000))
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
    if scope_changed:
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

    if not candidates:
        return None, None, None
    # Prefer the newest CVSS version; break ties on the higher score.
    candidates.sort(key=lambda c: (c[0], c[1]), reverse=True)
    _, score, stype, vector = candidates[0]
    return score, stype or None, vector or None


def _parse_dt(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def fixed_version_for(record: dict, package_name: str, ecosystem: str) -> str | None:
    """First ``fixed`` bound OSV lists for this package, if any."""
    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("name", "").lower() != package_name.lower():
            continue
        for rng in affected.get("ranges") or []:
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
                log.warning("OSV batch failed: %s", exc)
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
            while len(per_item_ids) < len(batch):
                per_item_ids.append([])

            hydrated = await self._hydrate(needed, ecosystem, timeout=timeout)

            for (name, version), ids in zip(batch, per_item_ids, strict=False):
                cves = []
                max_score = None
                has_fix = False
                for osv_id in ids:
                    record = hydrated.get(osv_id)
                    if record is None:
                        continue  # not a CVE, or hydration failed
                    cves.append(record)
                    score = record.get("cvss_score")
                    if score is not None and (max_score is None or score > max_score):
                        max_score = score
                    if record.get("fixed_version"):
                        has_fix = True
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
            }
            for v in known
        }
        missing = osv_ids - set(cached)
        if not missing:
            return cached

        fetched = await asyncio.gather(
            *(self._fetch_vuln(i, timeout=timeout) for i in missing), return_exceptions=True
        )
        for record in fetched:
            if not isinstance(record, dict):
                continue
            cve_id = extract_cve(record)
            if settings.osv_cve_only and not cve_id:
                # Not a CVE: by policy we ignore GHSA-only / MAL-only records.
                continue
            osv_id = record.get("id")
            if not osv_id:
                continue
            score, stype, vector = best_severity(record)
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
            version_row = await self.session.get(PackageVersion, version_id)
            if version_row is not None and version_row.max_cvss != score:
                version_row.max_cvss = score
                versions_updated += 1
        await self.session.flush()

        return {
            "vulnerabilities_examined": len(rows),
            "vulnerabilities_rescored": changed,
            "versions_updated": versions_updated,
        }

    # -- persistence -------------------------------------------------------- #
    async def apply_to_version(
        self, version_row: PackageVersion, result: ScanResult, package_name: str
    ) -> None:
        """Persist scan output onto a stored version and its CVE links."""
        if not result.scanned:
            return

        version_row.max_cvss = result.max_score
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
            fixed = None
            if record.get("raw"):
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
        await self.apply_to_version(version_row, result, package_name)
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
        log.info("inline OSV scan timed out for %s@%s", package_name, version)
        return ScanResult(None, package_name, version, scanned=False)
    except Exception as exc:  # noqa: BLE001
        log.warning("inline OSV scan failed for %s@%s: %s", package_name, version, exc)
        return ScanResult(None, package_name, version, scanned=False)
    return results.get(
        (package_name, version), ScanResult(None, package_name, version, scanned=False)
    )
