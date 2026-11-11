"""Allow/block rules and CVE-score policy.

Evaluation order (deliberate, and the block list is *always* enforced):

1. Explicit block rules. If any matches, deny. Nothing overrides this --
   not an allow rule, not allowlist mode, not an admin's CVE suppression.
2. Allowlist mode (optional). When enabled, a package must match an allow rule
   to pass. This is the "default deny" posture.
3. Malware. A version a malicious-package (``MAL-*``) advisory names is denied.
   This is its own switch, on by default, and does not depend on the CVE policy.
4. CVE policy. A version whose highest CVSS score falls inside the configured
   block range is denied.
5. New packages. Every version of a package that first appeared on a public
   registry less than ``min_days`` ago is refused, unless an ``exempt`` rule
   covers it: that is what a typosquatted or AI-hallucinated name looks like.
6. Release age. A version a public upstream published less than
   ``min_days`` ago is held back, unless an ``exempt`` rule covers it or it is
   the fix for a CVE an older version of the package has.

Rules are cached in Redis and in-process because they are consulted on every
single request; the cache is invalidated whenever a rule is written.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.cache import cache_delete_prefix, cache_get_json, cache_set_json
from ..core.naming import _PEP503_RE
from ..core.semver import is_valid_range, satisfies
from ..models import (
    Ecosystem,
    Package,
    PackageRule,
    PackageVersion,
    PackageVulnerability,
    RuleAction,
    Setting,
    Upstream,
    upstream_is_public,
)

log = logging.getLogger(__name__)

RULES_CACHE_KEY = "policy:rules"
SETTINGS_CACHE_KEY = "policy:settings"
CACHE_TTL = 60

# Setting keys
KEY_ALLOWLIST_MODE = "allowlist_mode"
KEY_CVE_POLICY = "cve_policy"
KEY_RELEASE_AGE = "release_age"
KEY_NEW_PACKAGES = "new_packages"


@dataclass(slots=True)
class Verdict:
    allowed: bool
    reason: str | None = None
    rule_id: int | None = None
    # "block_rule" | "allowlist" | "malware" | "cve" | "new_package" | "release_age" | None
    source: str | None = None

    @property
    def blocked(self) -> bool:
        return not self.allowed


ALLOWED = Verdict(allowed=True)


@dataclass(slots=True)
class CvePolicy:
    """Block when ``min_score <= max_cvss <= max_score``.

    Enabled by default, blocking high and critical (7.0-10.0): minireg is
    meant to protect people who never open the policy page, so a fresh install
    has to refuse known-dangerous releases on its own. ``block_unscored``
    covers the fail-closed posture for a package we could not scan in time.

    ``block_malware`` refuses versions a malicious-package advisory names. It
    is independent of ``enabled``: turning the score range off is a choice
    about vulnerable code, and must not quietly start serving malware too.
    """

    enabled: bool = True
    min_score: float = 7.0
    max_score: float = 10.0
    block_unscored: bool = False
    # Deny only when the CVE has a fix available upstream, if set.
    require_fix_available: bool = False
    block_malware: bool = True

    def blocks(
        self,
        score: float | None,
        *,
        scanned: bool = True,
        has_advisories: bool | None = None,
    ) -> bool:
        """Whether this policy denies a version with ``score``.

        Three states, and conflating any two of them breaks the policy:

        * ``scanned=False`` -- OSV never answered for this version. Unknown
          risk, so ``block_unscored`` decides.
        * ``score is None`` with ``scanned=True`` -- OSV answered and the
          version *has* advisories, but none carried a usable severity. Also
          unknown risk, so ``block_unscored`` decides here too.
        * no advisories at all (stored as ``score == 0.0``) -- clean, and
          never blocked, whatever the range. An earlier version stored clean
          versions as ``None``, which made ``block_unscored`` deny every
          package in the registry; a later one stored them as 0.0 and so a
          range starting at 0 ("anything with a CVE") denied every package
          instead.

        ``has_advisories`` tells a clean version from one whose advisories
        all score 0.0, which a range starting at 0 does block. It is only
        consulted for 0.0: any other score already means advisories exist.
        Callers without it read 0.0 as clean.
        """
        if not self.enabled:
            return False
        if not scanned or score is None:
            return self.block_unscored
        if score == 0.0 and not has_advisories:
            return False
        return self.min_score <= score <= self.max_score

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "min_score": self.min_score,
            "max_score": self.max_score,
            "block_unscored": self.block_unscored,
            "require_fix_available": self.require_fix_available,
            "block_malware": self.block_malware,
        }

    @classmethod
    def from_dict(cls, data: dict | None) -> CvePolicy:
        if not data:
            return cls()
        return cls(
            enabled=bool(data.get("enabled", True)),
            min_score=float(data.get("min_score", 7.0)),
            max_score=float(data.get("max_score", 10.0)),
            block_unscored=bool(data.get("block_unscored", False)),
            require_fix_available=bool(data.get("require_fix_available", False)),
            # Saved before the switch existed: malware blocking was tied to
            # `enabled` then, and is on for everyone now.
            block_malware=bool(data.get("block_malware", True)),
        )


@dataclass(slots=True)
class ReleaseAgePolicy:
    """Hold back releases a public upstream published less than ``min_days`` ago.

    Most malicious releases on npm, PyPI and crates.io -- a hijacked
    maintainer account, a self-spreading worm, a dependency-confusion upload
    -- are found and pulled within hours to a few days. A registry that waits
    that long before serving a release keeps its users out of that window,
    which matters most for the people minireg is for: nobody in a home lab or
    a classroom is watching advisories in real time, and an AI agent will
    install whatever was published a minute ago. On by default.

    ``exempt_security_fixes`` lets a release through early when it is the
    fixed version an advisory names for an older version of the same package,
    so the hold never keeps a vulnerable version in place.
    """

    enabled: bool = True
    min_days: int = 3
    exempt_security_fixes: bool = True

    def held_until(self, published_at: datetime | None, now: datetime | None = None):
        """When a release published at ``published_at`` stops being held, or
        None when it is not held (old enough, policy off, or unknown age)."""
        if not self.enabled or published_at is None or self.min_days <= 0:
            return None
        if published_at.tzinfo is None:
            published_at = published_at.replace(tzinfo=UTC)
        until = published_at + timedelta(days=self.min_days)
        return until if (now or datetime.now(UTC)) < until else None

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "min_days": self.min_days,
            "exempt_security_fixes": self.exempt_security_fixes,
        }

    @classmethod
    def from_dict(cls, data: dict | None) -> ReleaseAgePolicy:
        if not data:
            return cls()
        return cls(
            enabled=bool(data.get("enabled", True)),
            min_days=int(data.get("min_days", 3)),
            exempt_security_fixes=bool(data.get("exempt_security_fixes", True)),
        )


@dataclass(slots=True)
class NewPackagePolicy:
    """Refuse packages that first appeared on a public registry recently.

    Attackers register the names people mistype (typosquatting) and the
    names AI assistants invent when they hallucinate a dependency
    ("slopsquatting"), then wait for someone to install them. Such a name is
    almost always days or weeks old, while the packages people actually mean
    to use have usually existed for months or years. On by default, 30 days.
    """

    enabled: bool = True
    min_days: int = 30

    def new_until(self, first_published: datetime | None, now: datetime | None = None):
        """When a package first published at ``first_published`` stops being
        new, or None when it is not new (or its age is unknown)."""
        if not self.enabled or first_published is None or self.min_days <= 0:
            return None
        if first_published.tzinfo is None:
            first_published = first_published.replace(tzinfo=UTC)
        until = first_published + timedelta(days=self.min_days)
        return until if (now or datetime.now(UTC)) < until else None

    def to_dict(self) -> dict:
        return {"enabled": self.enabled, "min_days": self.min_days}

    @classmethod
    def from_dict(cls, data: dict | None) -> NewPackagePolicy:
        if not data:
            return cls()
        return cls(
            enabled=bool(data.get("enabled", True)),
            min_days=int(data.get("min_days", 30)),
        )


def version_facts(row) -> dict:
    """The keyword arguments :meth:`PolicyEngine.evaluate` needs for a
    stored version: a PackageVersion, or a column row carrying the same names.

    Every caller holding a version row goes through this, so a new input to
    the policy reaches every path at once. Attributes are read directly, not
    with defaults: a column query that forgot one fails loudly in tests
    instead of silently skipping a check.
    """
    return {
        "max_cvss": row.max_cvss,
        "has_fix": bool(row.has_fix),
        "scanned": row.scanned_at is not None,
        "has_advisories": row.has_advisories,
        "malicious": bool(row.is_malicious),
        "published_at": row.published_at,
        "upstream_id": row.upstream_id,
        "is_local": bool(row.is_local),
    }


#: The PackageVersion columns :func:`version_facts` reads, for column queries.
VERSION_FACT_COLUMNS = (
    PackageVersion.max_cvss,
    PackageVersion.has_fix,
    PackageVersion.scanned_at,
    PackageVersion.has_advisories,
    PackageVersion.is_malicious,
    PackageVersion.published_at,
    PackageVersion.upstream_id,
    PackageVersion.is_local,
)


def _same_version(ecosystem: str, a: str, b: str) -> bool:
    if ecosystem == "pypi":
        try:
            from packaging.version import Version

            return Version(a) == Version(b)
        except Exception:
            return a.strip().lower() == b.strip().lower()
    return a.strip().lstrip("v=") == b.strip().lstrip("v=")


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
        self._public_upstreams: dict[int, bool] | None = None
        self._security_fixes: dict[tuple[str, str], list[str]] = {}
        self._first_published: dict[tuple[str, str], datetime | None] = {}

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

    async def get_release_age_policy(self) -> ReleaseAgePolicy:
        return ReleaseAgePolicy.from_dict(await self.get_setting(KEY_RELEASE_AGE, None))

    async def get_new_package_policy(self) -> NewPackagePolicy:
        return NewPackagePolicy.from_dict(await self.get_setting(KEY_NEW_PACKAGES, None))

    async def _package_first_published(self, eco: str, name: str) -> datetime | None:
        key = (eco, name)
        if key not in self._first_published:
            self._first_published[key] = (
                await self.session.execute(
                    select(Package.first_published_at).where(
                        Package.ecosystem == eco,
                        Package.normalized_name == name,
                        Package.is_local.is_(False),
                    )
                )
            ).scalar_one_or_none()
        return self._first_published[key]

    async def _upstream_public(self, upstream_id: int | None) -> bool:
        """Whether releases from this upstream are held. A version whose
        upstream is unknown (deleted, or never recorded) counts as public:
        that is the safe direction."""
        if upstream_id is None:
            return True
        if self._public_upstreams is None:
            rows = (await self.session.execute(select(Upstream))).scalars().all()
            self._public_upstreams = {u.id: upstream_is_public(u) for u in rows}
        return self._public_upstreams.get(upstream_id, True)

    async def _is_security_fix(self, eco: str, name: str, version: str) -> bool:
        """Whether ``version`` is the fixed version an advisory names for
        another version of this package. Loaded once per package, and only
        for a version that is actually being held."""
        key = (eco, name)
        if key not in self._security_fixes:
            rows = (
                await self.session.execute(
                    select(PackageVulnerability.fixed_version)
                    .join(PackageVersion, PackageVersion.id == PackageVulnerability.version_id)
                    .join(Package, Package.id == PackageVersion.package_id)
                    .where(
                        Package.ecosystem == eco,
                        Package.normalized_name == name,
                        PackageVulnerability.fixed_version.is_not(None),
                        PackageVulnerability.suppressed.is_(False),
                    )
                    .distinct()
                )
            ).scalars().all()
            self._security_fixes[key] = [r for r in rows if r]
        return any(_same_version(eco, version, fixed) for fixed in self._security_fixes[key])

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
        has_advisories: bool | None = None,
        malicious: bool = False,
        published_at: datetime | None = None,
        upstream_id: int | None = None,
        is_local: bool = False,
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

        # 3. Malware.
        policy = await self.get_cve_policy()
        if version is not None and policy.block_malware and malicious:
            # A malicious-package advisory says the release *is* malware.
            # There is no fixed version of a backdoor -- OSV records have no
            # `fixed` event -- so require_fix_available let every one of them
            # through, and a score range is the wrong question to ask. It used
            # to apply only while the CVE score policy was on, so an install
            # that had never enabled it served known malware.
            return Verdict(
                allowed=False,
                reason="blocked as malware: an OSV malicious-package advisory "
                "names this version as malicious",
                source="malware",
            )

        # 4. CVE score policy.
        if version is not None and policy.blocks(
            max_cvss, scanned=scanned, has_advisories=has_advisories
        ):
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

        # 5. New packages. Only what someone else published, like the hold.
        if version is not None and not is_local:
            guard = await self.get_new_package_policy()
            if guard.enabled:
                first = await self._package_first_published(eco, name)
                until = guard.new_until(first)
                if (
                    until is not None
                    and await self._upstream_public(upstream_id)
                    and not self._exempted(applicable, name, eco, version)
                ):
                    return Verdict(
                        allowed=False,
                        reason=(
                            f"blocked as a new package: {normalized_name} first appeared on "
                            f"its registry on {first:%Y-%m-%d} UTC, and this registry only "
                            f"serves packages that are at least {guard.min_days} days old, "
                            f"from {until:%Y-%m-%d} UTC. A name that new is how typosquatted "
                            "and AI-hallucinated packages are published: check this is the "
                            "package you meant. If it is, ask an admin to exempt it"
                        ),
                        source="new_package",
                    )

        # 6. Release age. Only what someone else published: a version
        # published to this registry is the operator's own.
        if version is not None and not is_local and published_at is not None:
            hold = await self.get_release_age_policy()
            until = hold.held_until(published_at)
            if (
                until is not None
                and await self._upstream_public(upstream_id)
                and not self._exempted(applicable, name, eco, version)
                and not (
                    hold.exempt_security_fixes
                    and await self._is_security_fix(eco, name, version)
                )
            ):
                published = published_at if published_at.tzinfo else published_at.replace(tzinfo=UTC)
                return Verdict(
                    allowed=False,
                    reason=(
                        f"held back: {version} was published "
                        f"{published:%Y-%m-%d %H:%M} UTC, and this registry serves new "
                        f"releases {hold.min_days} days after publication, from "
                        f"{until:%Y-%m-%d %H:%M} UTC. Use an earlier version, or ask "
                        "an admin to exempt this package"
                    ),
                    source="release_age",
                )

        return ALLOWED

    @staticmethod
    def _exempted(rules: list[RuleSnapshot], name: str, eco: str, version: str | None) -> bool:
        """Whether an ``exempt`` rule covers this package version.

        Exempt rules only skip the new-package guard and the hold on new
        releases. They never override a block rule, malware or the CVE
        policy, which run first.
        """
        for rule in rules:
            if rule.action != RuleAction.exempt.value:
                continue
            if _matches_name(rule.pattern, name, eco) and _matches_version(
                rule.version_spec, eco, version
            ):
                return True
        return False

    async def evaluate_version(
        self, ecosystem: Ecosystem | str, normalized_name: str, row
    ) -> Verdict:
        """:meth:`evaluate` for a stored version row (see :func:`version_facts`)."""
        return await self.evaluate(ecosystem, normalized_name, row.version, **version_facts(row))

    async def all_blocked_reason(
        self, ecosystem: Ecosystem | str, normalized_name: str, rows, fallback: str
    ) -> str:
        """Why a package whose every version is blocked cannot be installed.

        The reason of its newest version, which is the one a client asking
        for the package would have got: "all versions are blocked by policy"
        tells a person, or an AI agent, nothing they can act on, where "this
        package is two days old" or "held until Friday" does.
        """
        rows = list(rows)
        if not rows:
            return fallback
        epoch = datetime.min.replace(tzinfo=UTC)

        def when(row):
            stamp = row.published_at
            if stamp is None:
                return epoch
            return stamp if stamp.tzinfo else stamp.replace(tzinfo=UTC)

        verdict = await self.evaluate_version(ecosystem, normalized_name, max(rows, key=when))
        return verdict.reason or fallback

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
