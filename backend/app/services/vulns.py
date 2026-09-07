"""Shared CVE presentation helpers."""

from __future__ import annotations

from ..core.semver import SemVer


def dedupe_by_cve(entries: list[dict]) -> list[dict]:
    """Collapse OSV records that describe the same CVE.

    OSV routinely carries several records for one CVE -- a GHSA and a PYSEC
    entry, say -- and listing both makes an audit look twice as bad as it is.

    The highest score wins, and so does the **highest** fixed version. Those
    records can disagree about which release actually fixed the issue: lodash
    CVE-2021-23337 is filed once as 7.2/fixed-in-4.17.21 and again as
    8.1/fixed-in-4.18.0. Taking the lowest would advertise 4.17.21 as
    sufficient and leave the 8.1 variant in place, so the conservative bound is
    the correct one for a tool people upgrade against.
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
            # Keep the worse score and the description that goes with it. The
            # fixed version is reconciled separately below, so it must not be
            # clobbered by whichever record happened to have the higher score.
            fixed = current.get("fixed_version")
            current.update(entry)
            current["fixed_version"] = fixed or entry.get("fixed_version")

        candidate = entry.get("fixed_version")
        existing = current.get("fixed_version")
        if candidate and (
            not existing or (fix_key(candidate) or ()) > (fix_key(existing) or ())
        ):
            current["fixed_version"] = candidate

        # A CVE is only suppressed if every record for it is.
        current["suppressed"] = bool(current.get("suppressed")) and bool(entry.get("suppressed"))

    return sorted(merged.values(), key=lambda e: e.get("cvss_score") or 0, reverse=True)


def lowest_clearing_version(
    ecosystem: str, cves: list[dict], current_version: str | None = None
) -> str | None:
    """The lowest version that resolves every CVE with a known fix.

    Each CVE reports the release that fixed *it*; upgrading has to satisfy all
    of them at once, so the answer is the highest of those fixes, not the
    lowest. Returns None when no CVE names a fix -- there is nothing to
    upgrade to -- or when the current version already clears them all.
    """
    fixes = [c["fixed_version"] for c in cves if c.get("fixed_version")]
    if not fixes:
        return None

    # Order by the ecosystem's own precedence rules. Reaching for PEP 440 as
    # the default would be wrong for cargo: it is semver, and a prerelease like
    # `1.0.0-beta.1` does not parse as PEP 440 at all, so it would sort into
    # the unparseable bucket and could be handed back as the recommended fix.
    from ..core.naming import sort_versions_for

    ordered = sort_versions_for(ecosystem, list({*fixes}))
    if not ordered:
        return None
    target = ordered[-1]

    # Never propose a downgrade or a no-op.
    if current_version:
        ranked = sort_versions_for(ecosystem, [current_version, target])
        if ranked and ranked[-1] == current_version:
            return None
    return target
