"""Shared CVE presentation helpers."""

from __future__ import annotations

from ..core.semver import SemVer


def dedupe_by_cve(entries: list[dict]) -> list[dict]:
    """Collapse OSV records that describe the same CVE.

    OSV routinely carries several records for one CVE -- a GHSA and a PYSEC
    entry, say -- and listing both makes an audit look twice as bad as it is.
    We keep the highest score (worst case wins) but the *lowest* fixed version,
    because that is the smallest upgrade that resolves it.
    """
    def fix_key(value: str | None):
        if not value:
            return None
        parsed = SemVer.parse(value)
        return parsed._key() if parsed else (0, 0, 0, (0, (value,)))

    merged: dict[str, dict] = {}
    for entry in entries:
        key = entry.get("cve_id") or entry.get("osv_id") or ""
        current = merged.get(key)
        if current is None:
            merged[key] = dict(entry)
            continue

        if (entry.get("cvss_score") or 0) > (current.get("cvss_score") or 0):
            # Keep the worse score, and the description that goes with it.
            fixed = current.get("fixed_version")
            current.update(entry)
            current["fixed_version"] = fixed or entry.get("fixed_version")

        candidate = entry.get("fixed_version")
        existing = current.get("fixed_version")
        if candidate and (
            not existing or (fix_key(candidate) or ()) < (fix_key(existing) or ())
        ):
            current["fixed_version"] = candidate

        # A CVE is only suppressed if every record for it is.
        current["suppressed"] = bool(current.get("suppressed")) and bool(entry.get("suppressed"))

    return sorted(merged.values(), key=lambda e: e.get("cvss_score") or 0, reverse=True)
