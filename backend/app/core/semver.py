"""node-semver compatible version and range handling.

npm version ranges are their own grammar -- ``^1.2.3``, ``~1.2``, ``1.2.x``,
``1.2.3 - 2.3.4``, ``>=1.2 <2.0.0 || 3.x`` -- and a glob match gets them wrong
in both directions. This module implements the grammar as specified by
node-semver so that a block rule means exactly what an npm user expects it to.

Reference: https://github.com/npm/node-semver#ranges

The two subtle parts, both reproduced faithfully:

* **Desugared upper bounds carry ``-0``.** ``^1.2.3`` becomes
  ``>=1.2.3 <2.0.0-0``, not ``<2.0.0``. Without the ``-0`` a prerelease of the
  next major (``2.0.0-alpha``) would sort below ``2.0.0`` and slip through.

* **Prereleases need an opt-in.** By default a version carrying a prerelease
  tag satisfies a comparator set only when some comparator in that set names
  the same ``major.minor.patch`` *and* carries a prerelease of its own. So
  ``^1.2.3`` does not match ``1.2.4-alpha`` even though the arithmetic allows
  it, but ``^1.2.3-alpha`` does match ``1.2.3-beta``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Union

# --------------------------------------------------------------------------- #
# Grammar fragments
# --------------------------------------------------------------------------- #
_NUM = r"0|[1-9]\d*"
_NON_NUM = r"\d*[a-zA-Z-][0-9a-zA-Z-]*"
_PRE_IDENT = rf"(?:{_NUM}|{_NON_NUM})"
_PRERELEASE = rf"(?:-({_PRE_IDENT}(?:\.{_PRE_IDENT})*))"
_BUILD = r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))"

FULL_VERSION_RE = re.compile(
    rf"^[v=\s]*({_NUM})\.({_NUM})\.({_NUM}){_PRERELEASE}?{_BUILD}?\s*$"
)

# A "partial" version, where any component may be x/X/* or simply absent.
_XID = rf"{_NUM}|x|X|\*"
_XRANGE_PLAIN = (
    rf"[v=\s]*({_XID})"
    rf"(?:\.({_XID})"
    rf"(?:\.({_XID})"
    rf"{_PRERELEASE}?{_BUILD}?"
    rf")?)?"
)

TILDE_RE = re.compile(rf"^\s*~>?{_XRANGE_PLAIN}\s*$")
CARET_RE = re.compile(rf"^\s*\^{_XRANGE_PLAIN}\s*$")
XRANGE_RE = re.compile(rf"^\s*([<>]?=?)\s*{_XRANGE_PLAIN}\s*$")
HYPHEN_RE = re.compile(rf"^\s*({_XRANGE_PLAIN})\s+-\s+({_XRANGE_PLAIN})\s*$")
COMPARATOR_RE = re.compile(
    rf"^\s*([<>]?=?)\s*[v=\s]*({_NUM})\.({_NUM})\.({_NUM}){_PRERELEASE}?{_BUILD}?\s*$"
)

# Collapses "  >=  1.2.3" into ">=1.2.3" so tokens split cleanly on whitespace.
_OPERATOR_SPACE_RE = re.compile(r"([<>]?=|[<>]|~>?|\^)\s+")


def _is_x(value: str | None) -> bool:
    return value is None or value == "" or value.lower() == "x" or value == "*"


# --------------------------------------------------------------------------- #
# Version
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str | int, ...] = ()
    build: str | None = None

    @staticmethod
    def parse(value: str) -> "SemVer | None":
        if not isinstance(value, str):
            return None
        match = FULL_VERSION_RE.match(value.strip())
        if match is None:
            return None
        major, minor, patch, pre, build = match.groups()
        return SemVer(
            major=int(major),
            minor=int(minor),
            patch=int(patch),
            prerelease=_split_prerelease(pre),
            build=build,
        )

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)

    @property
    def tuple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            base += "-" + ".".join(str(p) for p in self.prerelease)
        if self.build:
            base += f"+{self.build}"
        return base

    # Build metadata is explicitly excluded from precedence (semver 2.0.0 §10).
    def _key(self) -> tuple:
        return (self.major, self.minor, self.patch, _prerelease_key(self.prerelease))

    def __lt__(self, other: "SemVer") -> bool:
        return self._key() < other._key()

    def __le__(self, other: "SemVer") -> bool:
        return self._key() <= other._key()

    def __gt__(self, other: "SemVer") -> bool:
        return self._key() > other._key()

    def __ge__(self, other: "SemVer") -> bool:
        return self._key() >= other._key()

    def equivalent(self, other: "SemVer") -> bool:
        """Precedence equality, ignoring build metadata."""
        return self._key() == other._key()


def _split_prerelease(raw: str | None) -> tuple[str | int, ...]:
    if not raw:
        return ()
    return tuple(int(part) if part.isdigit() else part for part in raw.split("."))


def _prerelease_key(prerelease: tuple[str | int, ...]) -> tuple:
    """Sort key for the prerelease field.

    A version with no prerelease outranks every prerelease of the same
    major.minor.patch, so the absent case sorts highest. Within a prerelease,
    numeric identifiers rank below alphanumeric ones, numerics compare
    numerically, and a longer identifier list wins ties (semver 2.0.0 §11.4).
    """
    if not prerelease:
        return (1,)
    parts = []
    for item in prerelease:
        if isinstance(item, int):
            parts.append((0, item, ""))
        else:
            parts.append((1, 0, item))
    return (0, tuple(parts))


def compare(a: str, b: str) -> int:
    """-1, 0, or 1. Unparseable versions sort below every valid one."""
    left, right = SemVer.parse(a), SemVer.parse(b)
    if left is None and right is None:
        return (a > b) - (a < b)
    if left is None:
        return -1
    if right is None:
        return 1
    return (left._key() > right._key()) - (left._key() < right._key())


# --------------------------------------------------------------------------- #
# Comparators
# --------------------------------------------------------------------------- #
class _Any:
    """The comparator produced by ``*`` -- matches every version."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<ANY>"


ANY = _Any()


@dataclass(frozen=True, slots=True)
class Comparator:
    operator: str  # '' | '=' | '<' | '<=' | '>' | '>='
    semver: Union[SemVer, _Any]

    def test(self, version: SemVer) -> bool:
        if isinstance(self.semver, _Any):
            return True
        operator = self.operator or "="
        if operator == "=":
            return version.equivalent(self.semver)
        if operator == ">":
            return version > self.semver
        if operator == ">=":
            return version >= self.semver
        if operator == "<":
            return version < self.semver
        if operator == "<=":
            return version <= self.semver
        return False

    def __str__(self) -> str:
        return "*" if isinstance(self.semver, _Any) else f"{self.operator}{self.semver}"


class ComparatorSet:
    """A whitespace-joined group of comparators, ANDed together."""

    __slots__ = ("comparators",)

    def __init__(self, comparators: list[Comparator]):
        self.comparators = comparators

    def test(self, version: SemVer, include_prerelease: bool = False) -> bool:
        for comparator in self.comparators:
            if not comparator.test(version):
                return False

        if version.is_prerelease and not include_prerelease:
            # The prerelease opt-in rule: a prerelease only qualifies when some
            # comparator explicitly names the same major.minor.patch with a
            # prerelease of its own. Otherwise `^1.2.3` would quietly accept
            # `1.2.4-alpha`, which is not what a user asking for `^1.2.3` means.
            for comparator in self.comparators:
                if isinstance(comparator.semver, _Any):
                    continue
                bound = comparator.semver
                if bound.is_prerelease and bound.tuple == version.tuple:
                    return True
            return False
        return True

    def __str__(self) -> str:
        return " ".join(str(c) for c in self.comparators) or "*"


class Range:
    """A full range: comparator sets ORed together with ``||``."""

    __slots__ = ("raw", "sets", "include_prerelease")

    def __init__(self, raw: str, sets: list[ComparatorSet], include_prerelease: bool = False):
        self.raw = raw
        self.sets = sets
        self.include_prerelease = include_prerelease

    def test(self, version: SemVer | str) -> bool:
        parsed = SemVer.parse(version) if isinstance(version, str) else version
        if parsed is None:
            return False
        return any(s.test(parsed, self.include_prerelease) for s in self.sets)

    def __str__(self) -> str:
        return " || ".join(str(s) for s in self.sets)


class InvalidRange(ValueError):
    """The string is not a parseable npm version range."""


# --------------------------------------------------------------------------- #
# Range parsing
# --------------------------------------------------------------------------- #
def _desugar_hyphen(match: re.Match, include_prerelease: bool) -> str:
    """``1.2.3 - 2.3.4`` -> ``>=1.2.3 <=2.3.4``, honouring partial bounds."""
    groups = match.groups()
    # 0 = whole left partial, 1..5 = its parts; 6 = whole right, 7..11 its parts.
    from_raw, f_major, f_minor, f_patch, f_pre, _f_build = groups[0:6]
    to_raw, t_major, t_minor, t_patch, t_pre, _t_build = groups[6:12]
    lower_pre = "-0" if include_prerelease else ""

    if _is_x(f_major):
        lower = ""
    elif _is_x(f_minor):
        lower = f">={f_major}.0.0{lower_pre}"
    elif _is_x(f_patch):
        lower = f">={f_major}.{f_minor}.0{lower_pre}"
    else:
        lower = f">={from_raw.strip()}"

    if _is_x(t_major):
        upper = ""
    elif _is_x(t_minor):
        # An open minor means "anything below the next major".
        upper = f"<{int(t_major) + 1}.0.0-0"
    elif _is_x(t_patch):
        upper = f"<{t_major}.{int(t_minor) + 1}.0-0"
    elif t_pre:
        upper = f"<={t_major}.{t_minor}.{t_patch}-{t_pre}"
    else:
        upper = f"<={to_raw.strip()}"

    return f"{lower} {upper}".strip()


def _desugar_tilde(match: re.Match, include_prerelease: bool) -> str:
    """``~1.2.3`` allows patch churn; ``~1.2`` and ``~1`` widen accordingly."""
    major, minor, patch, pre, _build = match.groups()
    lower_pre = "-0" if include_prerelease else ""

    if _is_x(major):
        return "*"
    if _is_x(minor):
        return f">={major}.0.0{lower_pre} <{int(major) + 1}.0.0-0"
    if _is_x(patch):
        return f">={major}.{minor}.0{lower_pre} <{major}.{int(minor) + 1}.0-0"
    if pre:
        return f">={major}.{minor}.{patch}-{pre} <{major}.{int(minor) + 1}.0-0"
    return f">={major}.{minor}.{patch}{lower_pre} <{major}.{int(minor) + 1}.0-0"


def _desugar_caret(match: re.Match, include_prerelease: bool) -> str:
    """``^`` allows changes that keep the left-most non-zero component."""
    major, minor, patch, pre, _build = match.groups()
    lower_pre = "-0" if include_prerelease else ""

    if _is_x(major):
        return "*"
    if _is_x(minor):
        return f">={major}.0.0{lower_pre} <{int(major) + 1}.0.0-0"
    if _is_x(patch):
        if major == "0":
            return f">={major}.{minor}.0{lower_pre} <{major}.{int(minor) + 1}.0-0"
        return f">={major}.{minor}.0{lower_pre} <{int(major) + 1}.0.0-0"

    # 0.0.x, 0.y.z and x.y.z each pin a different component.
    if pre:
        lower = f">={major}.{minor}.{patch}-{pre}"
    else:
        lower = f">={major}.{minor}.{patch}{lower_pre if major == '0' else ''}"

    if major == "0":
        if minor == "0":
            return f"{lower} <{major}.{minor}.{int(patch) + 1}-0"
        return f"{lower} <{major}.{int(minor) + 1}.0-0"
    return f"{lower} <{int(major) + 1}.0.0-0"


def _desugar_xrange(match: re.Match, include_prerelease: bool) -> str:
    """``1.2.x``, ``1.x``, ``*``, and operator forms like ``>=1.2.x``."""
    operator, major, minor, patch, _pre, _build = match.groups()
    x_major = _is_x(major)
    x_minor = x_major or _is_x(minor)
    x_patch = x_minor or _is_x(patch)
    any_x = x_patch
    lower_pre = "-0" if include_prerelease else ""

    if operator == "=" and any_x:
        operator = ""

    if x_major:
        if operator in (">", "<"):
            # ">x" and "<x" can never be satisfied.
            return "<0.0.0-0"
        return "*"

    if operator and any_x:
        minor_value = 0 if x_minor else int(minor)
        major_value = int(major)
        patch_value = 0

        if operator == ">":
            operator = ">="
            if x_minor:
                major_value += 1
                minor_value = 0
            else:
                minor_value += 1
        elif operator == "<=":
            operator = "<"
            if x_minor:
                major_value += 1
            else:
                minor_value += 1

        suffix = "-0" if operator == "<" else ""
        return f"{operator}{major_value}.{minor_value}.{patch_value}{suffix}"

    if x_minor:
        return f">={major}.0.0{lower_pre} <{int(major) + 1}.0.0-0"
    if x_patch:
        return f">={major}.{minor}.0{lower_pre} <{major}.{int(minor) + 1}.0-0"

    # Fully specified: hand back unchanged for comparator parsing.
    return match.group(0).strip()


def _parse_comparator(token: str) -> Comparator:
    token = token.strip()
    if token in ("", "*", "x", "X"):
        return Comparator("", ANY)

    match = COMPARATOR_RE.match(token)
    if match is None:
        raise InvalidRange(f"invalid comparator: {token!r}")

    operator, major, minor, patch, pre, build = match.groups()
    return Comparator(
        operator=operator or "",
        semver=SemVer(
            major=int(major),
            minor=int(minor),
            patch=int(patch),
            prerelease=_split_prerelease(pre),
            build=build,
        ),
    )


def _parse_comparator_set(raw: str, include_prerelease: bool) -> ComparatorSet:
    raw = raw.strip()
    if raw == "":
        return ComparatorSet([Comparator("", ANY)])

    hyphen = HYPHEN_RE.match(raw)
    if hyphen is not None:
        raw = _desugar_hyphen(hyphen, include_prerelease)

    # Normalize "  >=  1.2.3" so whitespace becomes a reliable token separator.
    raw = _OPERATOR_SPACE_RE.sub(r"\1", raw.strip())
    if raw == "":
        return ComparatorSet([Comparator("", ANY)])

    comparators: list[Comparator] = []
    for token in raw.split():
        expanded = token
        for pattern, desugar in (
            (TILDE_RE, _desugar_tilde),
            (CARET_RE, _desugar_caret),
            (XRANGE_RE, _desugar_xrange),
        ):
            match = pattern.match(expanded)
            if match is not None:
                expanded = desugar(match, include_prerelease)
                break

        for part in expanded.split():
            comparators.append(_parse_comparator(part))

    if not comparators:
        comparators.append(Comparator("", ANY))
    return ComparatorSet(comparators)


@lru_cache(maxsize=2048)
def parse_range(range_str: str, include_prerelease: bool = False) -> Range:
    """Parse an npm range. Raises :class:`InvalidRange` on bad input.

    Cached because block rules are evaluated on every single request and a
    range string is a tiny, stable key.
    """
    if range_str is None:
        raise InvalidRange("range is None")
    raw = str(range_str).strip()

    sets = [
        _parse_comparator_set(part, include_prerelease)
        for part in re.split(r"\s*\|\|\s*", raw)
    ]
    return Range(raw, sets, include_prerelease)


def is_valid_range(range_str: str) -> bool:
    try:
        parse_range(range_str)
    except InvalidRange:
        return False
    return True


def satisfies(version: str, range_str: str, include_prerelease: bool = False) -> bool:
    """Whether ``version`` falls inside ``range_str``.

    Returns False rather than raising when either side is unparseable, so a
    malformed rule can never take a request down.
    """
    parsed = SemVer.parse(version)
    if parsed is None:
        return False
    try:
        return parse_range(range_str, include_prerelease).test(parsed)
    except InvalidRange:
        return False


def max_satisfying(versions: list[str], range_str: str, include_prerelease: bool = False):
    """Highest version in ``versions`` satisfying the range, or None."""
    try:
        parsed_range = parse_range(range_str, include_prerelease)
    except InvalidRange:
        return None

    best = None
    best_parsed = None
    for candidate in versions:
        parsed = SemVer.parse(candidate)
        if parsed is None or not parsed_range.test(parsed):
            continue
        if best_parsed is None or parsed > best_parsed:
            best, best_parsed = candidate, parsed
    return best
