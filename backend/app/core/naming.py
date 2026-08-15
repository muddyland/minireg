"""Name and version normalization for both ecosystems.

This module is the single source of truth for how a client-supplied name maps
onto a storage key. Getting it wrong means cache misses at best and cache
poisoning at worst, so every rule here traces to a spec:

* PEP 503  -- PyPI project name normalization
* PEP 440  -- PyPI version normalization
* PEP 427 / PyPA binary distribution format -- wheel filename grammar
* npm ``validate-npm-package-name`` -- npm name rules

npm *version* semantics (precedence and ranges) live in
:mod:`app.core.semver`; this module re-exports the ordering helpers so callers
have one import for naming concerns.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from packaging.utils import (
    InvalidWheelFilename,
    canonicalize_name,
    canonicalize_version,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

from .semver import SemVer, _prerelease_key

# --------------------------------------------------------------------------- #
# PyPI
# --------------------------------------------------------------------------- #
_PEP503_RE = re.compile(r"[-_.]+")
# PEP 508 name grammar.
_PEP508_NAME_RE = re.compile(r"^([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])$")


def normalize_pypi_name(name: str) -> str:
    """PEP 503: lowercase, runs of ``-_.`` collapse to a single ``-``."""
    return _PEP503_RE.sub("-", name).lower()


def is_valid_pypi_name(name: str) -> bool:
    return bool(name) and len(name) <= 214 and bool(_PEP508_NAME_RE.match(name))


def normalize_pypi_version(version: str) -> str:
    """PEP 440 canonical form; falls back to the raw string for non-conforming
    versions so a legacy upstream file never becomes unreachable."""
    try:
        return str(Version(version))
    except InvalidVersion:
        try:
            return canonicalize_version(version)
        except Exception:
            return version.strip()


def parse_pypi_version(version: str) -> Version | None:
    try:
        return Version(version)
    except InvalidVersion:
        return None


def sort_pypi_versions(versions: list[str]) -> list[str]:
    """Ascending PEP 440 order; unparseable versions sort first, lexically."""

    def key(v: str):
        parsed = parse_pypi_version(v)
        return (1, parsed) if parsed is not None else (0, v)

    parseable = [v for v in versions if parse_pypi_version(v) is not None]
    other = sorted(v for v in versions if parse_pypi_version(v) is None)
    parseable.sort(key=lambda v: Version(v))
    return other + parseable


def parse_dist_filename(filename: str) -> tuple[str, str, str] | None:
    """Return ``(project_name, version, packagetype)`` for a distribution file.

    ``packagetype`` uses PyPI's vocabulary: ``bdist_wheel`` or ``sdist``.
    Returns None when the filename does not parse.
    """
    if filename.endswith(".whl"):
        try:
            name, version, _build, _tags = parse_wheel_filename(filename)
            return str(name), str(version), "bdist_wheel"
        except (InvalidWheelFilename, InvalidVersion):
            return None
    for suffix in (".tar.gz", ".zip", ".tar.bz2", ".tgz"):
        if filename.endswith(suffix):
            try:
                name, version = parse_sdist_filename(filename)
                return str(name), str(version), "sdist"
            except Exception:
                # packaging only accepts .tar.gz/.zip; hand-parse the rest.
                stem = filename[: -len(suffix)]
                if "-" not in stem:
                    return None
                name, _, version = stem.rpartition("-")
                if not name:
                    return None
                return name, version, "sdist"
    if filename.endswith(".egg"):
        stem = filename[: -len(".egg")]
        parts = stem.split("-")
        if len(parts) >= 2:
            return parts[0], parts[1], "bdist_egg"
    return None


def pypi_canonical_name(name: str) -> str:
    """``packaging``'s canonicalize_name, which implements PEP 503 verbatim."""
    return canonicalize_name(name)


# --------------------------------------------------------------------------- #
# npm
# --------------------------------------------------------------------------- #
_NPM_SCOPED_RE = re.compile(r"^@([^/]+)/([^/]+)$")
# Characters npm rejects outright in a name segment.
_NPM_ILLEGAL_RE = re.compile(r'[~\'!()*\s"]')
_NPM_BLACKLIST = {"node_modules", "favicon.ico"}


def normalize_npm_name(name: str) -> str:
    """npm names are case-insensitive for lookup but preserved for display.

    New names may not contain uppercase at all; legacy ones may, so lookup is
    lowercased while the published spelling is kept on the package row.
    """
    return name.strip().lower()


def is_valid_npm_name(name: str) -> tuple[bool, str | None]:
    """Mirrors ``validate-npm-package-name`` for *new* packages."""
    if not name or not name.strip():
        return False, "name cannot be empty"
    if len(name) > 214:
        return False, "name can no longer contain more than 214 characters"
    if name.lower() in _NPM_BLACKLIST:
        return False, "name is blacklisted"
    if name.startswith(".") or name.startswith("_"):
        return False, "name cannot start with a period or an underscore"
    if name != name.lower():
        return False, "name can no longer contain capital letters"
    if _NPM_ILLEGAL_RE.search(name):
        return False, "name can only contain URL-friendly characters"

    scoped = _NPM_SCOPED_RE.match(name)
    if scoped:
        scope, pkg = scoped.groups()
        for part in (scope, pkg):
            if not part or part.startswith(".") or part.startswith("_"):
                return False, "name cannot start with a period or an underscore"
            if _NPM_ILLEGAL_RE.search(part):
                return False, "name can only contain URL-friendly characters"
        return True, None

    if name.startswith("@") or "/" in name:
        return False, "name can only contain URL-friendly characters"
    if quote(name, safe="") != name:
        return False, "name can only contain URL-friendly characters"
    return True, None


def npm_name_to_path(name: str) -> str:
    """``@scope/pkg`` -> ``@scope%2fpkg`` for use in a single path segment."""
    return name.replace("/", "%2f")


def npm_path_to_name(path: str) -> str:
    """Reverse of :func:`npm_name_to_path`; accepts both encodings."""
    return path.replace("%2F", "/").replace("%2f", "/")


def npm_scope(name: str) -> str | None:
    m = _NPM_SCOPED_RE.match(name)
    return m.group(1) if m else None


def npm_tarball_filename(name: str, version: str) -> str:
    """npm's own convention: the scope is stripped from the tarball name."""
    base = name.split("/")[-1] if name.startswith("@") else name
    return f"{base}-{version}.tgz"


# Strict semver 2.0.0, anchored and with no tolerance for a leading `v` or `=`.
_STRICT_SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)


def is_valid_semver(version: str) -> bool:
    """Strict semver 2.0.0. Note this rejects the leading ``v`` that
    :func:`app.core.semver.SemVer.parse` tolerates, because a *published*
    version must be canonical even though a *range* may be written loosely."""
    return bool(_STRICT_SEMVER_RE.match(version))


def semver_key(version: str) -> tuple:
    """Sort key implementing semver 2.0.0 precedence.

    Delegates to the range engine's parser so ordering and range matching can
    never disagree about what a version means. Unparseable versions sort below
    every valid one, ordered lexically among themselves.
    """
    parsed = SemVer.parse(version)
    if parsed is None:
        return (0, (0, 0, 0), (1,), version)
    return (1, parsed.tuple, _prerelease_key(parsed.prerelease), "")


def sort_semver(versions: list[str]) -> list[str]:
    return sorted(versions, key=semver_key)


def max_semver(versions: list[str]) -> str | None:
    """Highest stable version; falls back to the highest prerelease when every
    version is a prerelease. This is how npm picks ``latest`` on publish."""
    if not versions:
        return None
    stable = [v for v in versions if is_valid_semver(v) and "-" not in v.split("+")[0]]
    pool = stable or versions
    return sorted(pool, key=semver_key)[-1]


def normalize_version_for(ecosystem: str, version: str) -> str:
    if ecosystem == "pypi":
        return normalize_pypi_version(version)
    return version.strip().lstrip("=v") if version.startswith(("=", "v")) else version.strip()


def normalize_name_for(ecosystem: str, name: str) -> str:
    return normalize_pypi_name(name) if ecosystem == "pypi" else normalize_npm_name(name)


def sort_versions_for(ecosystem: str, versions: list[str], reverse: bool = False) -> list[str]:
    """Order version strings by the ecosystem's own precedence rules.

    Sorting these lexically is wrong in a way that looks almost right: "4.9.0"
    sorts above "4.18.1" because "9" > "1" as text, so a package's newest
    release ends up buried in the middle of the list.
    """
    ordered = sort_semver(versions) if ecosystem == "npm" else sort_pypi_versions(versions)
    return list(reversed(ordered)) if reverse else ordered


def order_version_rows(ecosystem: str, rows: list, reverse: bool = False) -> list:
    """Same, for ORM rows carrying a ``version`` attribute."""
    position = {
        version: index
        for index, version in enumerate(
            sort_versions_for(ecosystem, [r.version for r in rows], reverse=reverse)
        )
    }
    return sorted(rows, key=lambda r: position.get(r.version, 0))
