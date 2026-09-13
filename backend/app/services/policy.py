"""Allow/block rules and CVE-score policy.

Evaluation order (deliberate, and the block list is *always* enforced):

1. Explicit block rules. If any matches, deny. Nothing overrides this --
   not an allow rule, not allowlist mode, not an admin's CVE suppression.
2. Allowlist mode (optional). When enabled, a package must match an allow rule
   to pass. This is the "default deny" posture.
3. CVE policy. A version whose highest CVSS score falls inside the configured
   block range is denied.

Rules are cached in Redis and in-process because they are consulted on every
single request; the cache is invalidated whenever a rule is written.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import asdict, dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.cache import cache_delete_prefix, cache_get_json, cache_set_json
from ..core.naming import _PEP503_RE
from ..core.semver import is_valid_range, satisfies
from ..models import Ecosystem, PackageRule, RuleAction, Setting

log = logging.getLogger(__name__)

RULES_CACHE_KEY = "policy:rules"
SETTINGS_CACHE_KEY = "policy:settings"
CACHE_TTL = 60

# Setting keys
KEY_ALLOWLIST_MODE = "allowlist_mode"
KEY_CVE_POLICY = "cve_policy"


@dataclass(slots=True)
class Verdict:
    allowed: bool
    reason: str | None = None
    rule_id: int | None = None
    # "block_rule" | "allowlist" | "cve" | None
    source: str | None = None

    @property
    def blocked(self) -> bool:
        return not self.allowed


ALLOWED = Verdict(allowed=True)


@dataclass(slots=True)
class CvePolicy:
    """Block when ``min_score <= max_cvss <= max_score``.

    Defaults to disabled. ``block_unscored`` covers the fail-closed posture for
    a package we could not scan in time.
    """

    enabled: bool = False
    min_score: float = 7.0
    max_score: float = 10.0
    block_unscored: bool = False
    # Deny only when the CVE has a fix available upstream, if set.
    require_fix_available: bool = False

    def blocks(self, score: float | None, *, scanned: bool = True) -> bool:
        """Whether this policy denies a version with ``score``.

        Three states, and conflating any two of them breaks the policy:

        * ``scanned=False`` -- OSV never answered for this version. Unknown
          risk, so ``block_unscored`` decides.
        * ``score is None`` with ``scanned=True`` -- OSV answered and the
          version *has* advisories, but none carried a usable severity. Also
          unknown risk, so ``block_unscored`` decides here too.
        * ``score == 0.0`` -- scanned, no advisories at all. Clean, and never
          blocked. This is the case an earlier version got wrong: clean
          versions were stored as ``None`` and so were indistinguishable from
          unscanned, which made ``block_unscored`` deny every package in the
          registry and left fail-closed mode unusable.
        """
        if not self.enabled:
            return False
        if not scanned or score is None:
            return self.block_unscored
        return self.min_score <= score <= self.max_score

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "min_score": self.min_score,
            "max_score": self.max_score,
            "block_unscored": self.block_unscored,
            "require_fix_available": self.require_fix_available,
        }

    @classmethod
    def from_dict(cls, data: dict | None) -> CvePolicy:
        if not data:
            return cls()
        return cls(
            enabled=bool(data.get("enabled", False)),
            min_score=float(data.get("min_score", 7.0)),
            max_score=float(data.get("max_score", 10.0)),
            block_unscored=bool(data.get("block_unscored", False)),
            require_fix_available=bool(data.get("require_fix_available", False)),
        )


@dataclass(slots=True)
class RuleSnapshot:
    ecosystem: str | None
    pattern: str
    action: str
    version_spec: str | None
    reason: str | None
    id: int


def _normalize_pattern(pattern: str, ecosystem: str) -> str:
    """Normalize a rule pattern the same way the package name it is matched
    against was normalized.

    Package names are stored per-ecosystem canonical form, but rule patterns
    are stored exactly as the admin typed them. Without this, a PyPI rule
    written ``typing_extensions`` (the importable spelling, and the one people
    reach for) never matched the stored ``typing-extensions`` and silently
    blocked nothing.

    Only PyPI folds separators -- PEP 503 collapses runs of ``-_.`` to a single
    ``-``. npm and cargo names are lowercased but keep ``-`` and ``_`` distinct,
    so folding them here would make one rule match two different crates.
    Glob metacharacters survive all of these unchanged.
    """
    base = pattern.strip().lower()
    if ecosystem == "pypi":
        return _PEP503_RE.sub("-", base)
    return base


def _matches_name(pattern: str, normalized_name: str, ecosystem: str) -> bool:
    """Glob match against the *normalized* name.

    ``fnmatchcase`` is used because both sides are already lowercased by
    :func:`_normalize_pattern`; ``fnmatch`` would additionally apply os.path
    rules on some platforms, which we do not want.
    """
    return fnmatch.fnmatchcase(normalized_name, _normalize_pattern(pattern, ecosystem))


def _matches_version(spec: str | None, ecosystem: str, version: str | None) -> bool:
    """Whether a rule's optional version constraint covers ``version``.

    A rule with no spec covers every version. A spec with no version to test
    against does not match (the rule is version-scoped, we are asking about the
    package as a whole).

    npm and cargo specs are full node-semver ranges -- ``^1.2.3``,
    ``<4.17.21``, ``>=3.0.0 <3.0.2``, ``1.x || 2.x``. Both ecosystems are
    semver 2.0.0 so one engine serves both; they differ only in that a bare
    ``1.2.3`` is an exact pin to npm and a caret range to cargo, and a *rule*
    is read here with npm's meaning -- the stricter of the two, which is the
    safe direction for something that decides what to block. PyPI specs are
    PEP 440 specifier sets. Either way, a spec that does not parse falls back
    to a glob so a rule written before this understood ranges keeps working.

    Prereleases are matched *inclusively* on both sides. This deliberately
    departs from npm's install-time default, where ``>=1.0.0 <2.0.0`` skips
    ``1.5.0-beta``: a block list that silently let a prerelease of a blocked
    version through would be a hole, so blocking errs toward blocking.
    """
    if not spec:
        return True
    if version is None:
        return False
    spec = spec.strip()
    if spec in ("*", "x", "X"):
        return True

    if ecosystem == "pypi":
        try:
            from packaging.specifiers import SpecifierSet
            from packaging.version import Version

            return Version(version) in SpecifierSet(spec, prereleases=True)
        except Exception:
            return fnmatch.fnmatchcase(version, spec)

    if is_valid_range(spec):
        return satisfies(version, spec, include_prerelease=True)

    # Not a parseable range: treat it as a glob, which is what pre-range rules
    # relied on and what a pattern like `*-nightly*` still needs.
    return version == spec or fnmatch.fnmatchcase(version, spec)


class PolicyEngine:
    """Rule and CVE evaluation.

    One instance is created per request and may be asked about thousands of
    versions (a packument render evaluates every version it is about to
    serve). Rules and settings are therefore memoised on the instance: without
    it, each ``evaluate`` cost three Redis round trips, so rendering a package
    with 5,600 versions meant ~17,000 sequential lookups -- and three
    *Postgres* queries apiece whenever the cache was down.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self._rules: list[RuleSnapshot] | None = None
        self._settings: dict[str, object] = {}

    # -- loading ------------------------------------------------------------ #
    async def _load_rules(self) -> list[RuleSnapshot]:
        if self._rules is not None:
            return self._rules
        cached = await cache_get_json(RULES_CACHE_KEY)
        if cached is not None:
            self._rules = [RuleSnapshot(**r) for r in cached]
            return self._rules

        rows = (
            await self.session.execute(
                select(PackageRule).where(PackageRule.enabled.is_(True))
            )
        ).scalars().all()
        snapshots = [
            RuleSnapshot(
                id=r.id,
                ecosystem=r.ecosystem.value if r.ecosystem else None,
                pattern=r.pattern,
                action=r.action.value,
                version_spec=r.version_spec,
                reason=r.reason,
            )
            for r in rows
        ]
        await cache_set_json(RULES_CACHE_KEY, [asdict(s) for s in snapshots], CACHE_TTL)
        self._rules = snapshots
        return snapshots

    async def get_setting(self, key: str, default=None):
        if key in self._settings:
            return self._settings[key]
        cached = await cache_get_json(f"{SETTINGS_CACHE_KEY}:{key}")
        if cached is not None:
            value = cached.get("v", default)
            self._settings[key] = value
            return value
        row = await self.session.get(Setting, key)
        value = row.value if row else default
        await cache_set_json(f"{SETTINGS_CACHE_KEY}:{key}", {"v": value}, CACHE_TTL)
        self._settings[key] = value
        return value

    async def get_cve_policy(self) -> CvePolicy:
        return CvePolicy.from_dict(await self.get_setting(KEY_CVE_POLICY, None))

    async def allowlist_mode(self) -> bool:
        value = await self.get_setting(KEY_ALLOWLIST_MODE, {"enabled": False})
        if isinstance(value, dict):
            return bool(value.get("enabled", False))
        return bool(value)

    # -- evaluation --------------------------------------------------------- #
    async def evaluate(
        self,
        ecosystem: Ecosystem | str,
        normalized_name: str,
        version: str | None = None,
        *,
        max_cvss: float | None = None,
        has_fix: bool = False,
        scanned: bool = True,
        _name_level: bool = False,
    ) -> Verdict:
        eco = ecosystem.value if isinstance(ecosystem, Ecosystem) else str(ecosystem)
        name = normalized_name.lower()
        rules = await self._load_rules()

        applicable = [r for r in rules if r.ecosystem in (None, eco)]

        # 1. Block rules are absolute.
        for rule in applicable:
            if rule.action != RuleAction.block.value:
                continue
            if not _matches_name(rule.pattern, name, eco):
                continue
            if not _matches_version(rule.version_spec, eco, version):
                continue
            return Verdict(
                allowed=False,
                reason=rule.reason or f"blocked by rule '{rule.pattern}'",
                rule_id=rule.id,
                source="block_rule",
            )

        # 2. Allowlist mode.
        if await self.allowlist_mode():
            for rule in applicable:
                if rule.action != RuleAction.allow.value:
                    continue
                if not _matches_name(rule.pattern, name, eco):
                    continue
                # At name level a version-scoped allow rule still allows the
                # *package* -- we are deciding whether to serve the index at
                # all, and which versions survive is settled per version
                # further down. Requiring a version match here meant an
                # allowlist of `lodash >=4.17.21` refused the packument
                # outright, so no version of lodash could be installed.
                if _name_level or _matches_version(rule.version_spec, eco, version):
                    break
            else:
                return Verdict(
                    allowed=False,
                    reason="allowlist mode is enabled and this package is not on the allowlist",
                    source="allowlist",
                )

        # 3. CVE score policy.
        policy = await self.get_cve_policy()
        if version is not None and policy.blocks(max_cvss, scanned=scanned):
            if not scanned:
                return Verdict(
                    allowed=False,
                    reason=(
                        "package has not been scanned for CVEs and unscanned "
                        "packages are blocked"
                    ),
                    source="cve",
                )
            if max_cvss is None:
                return Verdict(
                    allowed=False,
                    reason=(
                        "package has advisories with no published severity and "
                        "unscored packages are blocked"
                    ),
                    source="cve",
                )
            # `require_fix_available` narrows a *score* block to what an
            # operator can actually act on. It deliberately does not suppress
            # the unscanned/unscored blocks above: those are not about a
            # specific advisory, so "is there a fix" has no answer.
            if policy.require_fix_available and not has_fix:
                return ALLOWED
            return Verdict(
                allowed=False,
                reason=(
                    f"blocked by CVE policy: highest CVSS {max_cvss:.1f} falls within "
                    f"the blocked range {policy.min_score:.1f}-{policy.max_score:.1f}"
                ),
                source="cve",
            )

        return ALLOWED

    async def is_name_blocked(self, ecosystem: Ecosystem | str, normalized_name: str) -> Verdict:
        """Package-level check with no version context, used before we have
        resolved anything upstream."""
        return await self.evaluate(ecosystem, normalized_name, version=None, _name_level=True)


async def invalidate_policy_cache() -> None:
    """Drop every cache a policy change can invalidate.

    The rendered packument / simple-index documents have policy baked into them
    -- blocked versions are filtered out before caching -- so dropping only the
    rule and setting caches would leave a stale document serving a
    just-blocked version for up to META_CACHE_TTL. Policy edits are rare and
    re-rendering only costs a local database read, so we clear them all.
    """
    await cache_delete_prefix(RULES_CACHE_KEY)
    await cache_delete_prefix(SETTINGS_CACHE_KEY)
    await cache_delete_prefix("pkg:")
    await cache_delete_prefix("search:")
