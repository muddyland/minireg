"""Sparse registry index rendering.

The index format is deliberately minimal: one JSON object per line, one line
per published version, ordered oldest to newest. Cargo reads every line, so the
document is append-only in spirit and we re-serve the upstream's own object
rather than rebuilding one.

That matters more here than it does for npm or PyPI. An index line carries the
crate's full dependency and feature graph, and cargo resolves against it
*before* downloading anything -- a field we drop or reshape does not degrade
metadata, it changes which versions the resolver picks. So the stored entry is
passed through whole and only the fields we are authoritative for (``yanked``,
and ``cksum``/``name``/``vers`` when the upstream omitted them) are touched.
"""

from __future__ import annotations

from typing import Any

import orjson

from ..config import settings
from ..core.naming import normalize_cargo_name, order_version_rows
from ..models import Package, PackageVersion

#: Cargo reads the index as newline-delimited JSON. It is not JSON overall, so
#: this content type is what crates.io itself serves.
INDEX_CONTENT_TYPE = "text/plain; charset=utf-8"
CRATE_CONTENT_TYPE = "application/x-tar"


# --------------------------------------------------------------------------- #
# URLs
# --------------------------------------------------------------------------- #
def index_url(name: str) -> str:
    from ..core.naming import cargo_index_path

    return f"{settings.cargo_base}/index/{cargo_index_path(name)}"


def download_url(name: str, version: str) -> str:
    return (
        f"{settings.cargo_base}/api/v1/crates/"
        f"{normalize_cargo_name(name)}/{version}/download"
    )


def render_config_json() -> dict[str, Any]:
    """The index root document.

    ``dl`` deliberately carries no substitution markers, so cargo appends
    ``/{crate}/{version}/download`` itself -- the same shape crates.io uses,
    which keeps our download route identical to the one clients already expect.

    ``api`` is omitted on purpose. It is what enables ``cargo publish``,
    ``cargo yank``, ``cargo search`` and ``cargo login`` against a registry, and
    this mirror implements none of them. Advertising it would turn a clear
    "registry does not support API commands" into a 404 from somewhere deeper.
    """
    return {"dl": f"{settings.cargo_base}/api/v1/crates"}


# --------------------------------------------------------------------------- #
# Index lines
# --------------------------------------------------------------------------- #
def _crate_file(version_row: PackageVersion):
    """The single ``.crate`` artifact for a version, if we know of one."""
    return version_row.files[0] if version_row.files else None


def render_index_entry(
    package: Package, version_row: PackageVersion, *, blocked: bool = False
) -> dict[str, Any]:
    """One index line as a dict.

    ``blocked`` marks a version the CVE policy denies. It is rendered as
    ``yanked``, which is the only "do not select this" signal the index format
    has; the download route refuses it outright, so this is the advisory half
    of the block rather than the enforcement. Expressing it in the protocol's
    own vocabulary gets cargo to say something intelligible about it instead of
    failing at download time with a bare 403.
    """
    stored = version_row.metadata_json
    entry: dict[str, Any] = dict(stored) if isinstance(stored, dict) else {}

    entry["name"] = entry.get("name") or package.name
    entry["vers"] = version_row.version

    file_row = _crate_file(version_row)
    if file_row is not None and file_row.sha256:
        entry["cksum"] = file_row.sha256
    entry.setdefault("cksum", "")

    # Cargo requires both keys to be present, and treats a missing `deps` as a
    # parse error rather than as "no dependencies".
    entry.setdefault("deps", [])
    entry.setdefault("features", {})

    entry["yanked"] = bool(version_row.yanked) or blocked
    return entry


def render_index(package: Package, *, blocked_versions: set[str] | None = None) -> str:
    """The full index file for one crate.

    Ordered oldest-first by semver precedence. Cargo does not require an order,
    but crates.io publishes in publication order and tooling that diffs index
    files is much easier to read when ours is stable rather than
    database-order.
    """
    blocked = blocked_versions or set()
    lines = [
        orjson.dumps(
            render_index_entry(package, version_row, blocked=version_row.version in blocked)
        ).decode()
        for version_row in order_version_rows("cargo", list(package.versions))
    ]
    # A trailing newline keeps the file line-oriented for anything that reads
    # it with a plain line iterator.
    return "\n".join(lines) + ("\n" if lines else "")
