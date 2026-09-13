"""Name and version normalization for both ecosystems.

This module is the single source of truth for how a client-supplied name maps
onto a storage key. Getting it wrong means cache misses at best and cache
poisoning at worst, so every rule here traces to a spec:

* PEP 503  -- PyPI project name normalization
* PEP 440  -- PyPI version normalization
* PEP 427 / PyPA binary distribution format -- wheel filename grammar
* npm ``validate-npm-package-name`` -- npm name rules
* RFC 2789 / the cargo book -- crates.io sparse-index path layout

Cargo versions are plain semver 2.0.0, so the npm ordering helpers below apply
to them unchanged; only the *range* dialect differs (a bare ``1.2.3`` means
``^1.2.3`` to cargo and an exact pin to npm), and ranges are the policy
engine's concern rather than this module's.

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
                # `packaging` only accepts .tar.gz/.zip, so this branch exists
                # for .tar.bz2 and .tgz -- but the version still has to be a
                # real one. Without the check, `foo-latest.tar.gz` uploaded
                # cleanly and then sorted ahead of every real release.
                try:
                    Version(version)
                except InvalidVersion:
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
            # The same URL-safety check unscoped names get. Skipping it here
            # let a scoped name through with Cyrillic look-alike letters,
            # which sit beside the real package in search and in `npm view`
            # output and are indistinguishable to a reader.
            if quote(part, safe="") != part:
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


# --------------------------------------------------------------------------- #
# cargo / crates.io
# --------------------------------------------------------------------------- #
# crates.io accepts ASCII alphanumerics plus `-` and `_`, and requires the
# first character to be a letter. 64 characters is the published maximum.
_CARGO_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")


def normalize_cargo_name(name: str) -> str:
    """Lowercase, which is the form the sparse index paths are built from.

    Note this is deliberately *not* the rule crates.io uses to decide whether
    two names collide -- there, ``-`` and ``_`` are also folded together, so
    ``foo-bar`` and ``foo_bar`` cannot both be registered. Folding them here
    too would be wrong for a mirror: the index is keyed on the name as spelled,
    so ``foo_bar`` must resolve to ``foo_bar`` and not to whichever of the pair
    we happened to cache first.
    """
    return name.strip().lower()


def is_valid_cargo_name(name: str) -> bool:
    return bool(_CARGO_NAME_RE.match(name.strip()))


def cargo_index_prefix(name: str) -> str:
    """The directory prefix a crate's index file lives under.

    The registry index shards names so no single directory holds the whole of
    crates.io. The layout is fixed by the cargo book and clients compute it
    themselves, so it has to match exactly:

        1 char    ``1/{name}``
        2 chars   ``2/{name}``
        3 chars   ``3/{first}/{name}``
        4+        ``{name[0:2]}/{name[2:4]}/{name}``

    Everything is lowercased.
    """
    lowered = normalize_cargo_name(name)
    length = len(lowered)
    if length == 0:
        raise ValueError("crate name cannot be empty")
    if length == 1:
        return "1"
    if length == 2:
        return "2"
    if length == 3:
        return f"3/{lowered[0]}"
    return f"{lowered[:2]}/{lowered[2:4]}"


def cargo_index_path(name: str) -> str:
    """``serde`` -> ``se/rd/serde``. The path clients request from the index."""
    return f"{cargo_index_prefix(name)}/{normalize_cargo_name(name)}"


def cargo_crate_filename(name: str, version: str) -> str:
    """cargo's own convention for a downloaded artifact.

    There is deliberately no inverse of this, unlike
    :func:`parse_dist_filename` for PyPI. The Simple API is file-oriented, so
    a wheel's version has to be recovered from its filename; the sparse index
    is version-oriented and states the version outright. Recovering it from
    the filename would also be ambiguous -- both crate names and semver
    prereleases contain ``-``, so ``serde-1.0.0-beta.1`` has no unique split.
    """
    return f"{name}-{version}.crate"


def normalize_version_for(ecosystem: str, version: str) -> str:
    if ecosystem == "pypi":
        return normalize_pypi_version(version)
    return version.strip().lstrip("=v") if version.startswith(("=", "v")) else version.strip()


def normalize_name_for(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        return normalize_pypi_name(name)
    if ecosystem == "cargo":
        return normalize_cargo_name(name)
    return normalize_npm_name(name)


def sort_versions_for(ecosystem: str, versions: list[str], reverse: bool = False) -> list[str]:
    """Order version strings by the ecosystem's own precedence rules.

    Sorting these lexically is wrong in a way that looks almost right: "4.9.0"
    sorts above "4.18.1" because "9" > "1" as text, so a package's newest
    release ends up buried in the middle of the list.
    """
    # cargo is semver 2.0.0, the same precedence rules the npm engine
    # implements, so pypi is the exception here rather than npm being the rule.
    ordered = sort_pypi_versions(versions) if ecosystem == "pypi" else sort_semver(versions)
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
