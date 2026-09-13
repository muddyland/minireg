"""CLI support: device-authorization login, project audit, and distribution.

The login flow follows RFC 8628 (OAuth device authorization) in shape, which
means the CLI never sees a password and never needs a browser callback port:

    CLI                       registry                     browser
     |-- POST /auth/start ------->|
     |<-- user_code + verify_url -|
     |   (prints the code)        |
     |                            |<--- person opens verify_url, approves ---|
     |-- POST /auth/poll -------->|
     |<-- api token --------------|   (returned exactly once)

Approval happens under the person's existing web session, so OIDC/Authentik
logins work with no extra plumbing.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from ..config import settings
from ..core.cache import rate_limit
from ..core.deps import Identity, client_ip, require_primary_credential, require_user
from ..core.naming import normalize_name_for
from ..core.security import generate_token
from ..db import get_session
from ..models import (
    ApiToken,
    DeviceAuthorization,
    Ecosystem,
    Package,
    PackageVersion,
    PackageVulnerability,
    Vulnerability,
)
from ..services import audit
from ..services.osv import OsvScanner, fixed_version_for
from ..services.policy import PolicyEngine
from ..services.vulns import dedupe_by_cve, lowest_clearing_version

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/cli", tags=["cli"])

# Short enough to read aloud, long enough that guessing it inside the TTL is
# hopeless: 8 chars from a 31-symbol alphabet is ~8.5e11 combinations, and the
# approve endpoint is rate limited on top.
USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I/O/0/1
USER_CODE_LEN = 8
DEVICE_CODE_TTL = timedelta(minutes=10)
POLL_INTERVAL_SECONDS = 3

# Cap on how many versions one audit will look up, so a monorepo lockfile
# cannot turn into a multi-thousand-request storm against OSV.
MAX_ON_DEMAND_SCAN = 500

def _find_cli_source() -> Path | None:
    """Locate the bundled CLI.

    The repo nests the app under ``backend/`` while the image drops that level,
    so the relative depth differs between development and production. Rather
    than hard-code either, walk up and take the first ``cli/minireg.py``.
    """
    override = os.environ.get("MINIREG_CLI_PATH")
    if override:
        candidate = Path(override)
        return candidate if candidate.is_file() else None

    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "cli" / "minireg.py"
        if candidate.is_file():
            return candidate
    return None


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _make_user_code() -> str:
    raw = "".join(secrets.choice(USER_CODE_ALPHABET) for _ in range(USER_CODE_LEN))
    return f"{raw[:4]}-{raw[4:]}"


def _normalize_user_code(value: str) -> str:
    cleaned = "".join(c for c in (value or "").upper() if c in USER_CODE_ALPHABET)
    if len(cleaned) != USER_CODE_LEN:
        return ""
    return f"{cleaned[:4]}-{cleaned[4:]}"


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


# --------------------------------------------------------------------------- #
# Device authorization
# --------------------------------------------------------------------------- #
class DeviceStartRequest(BaseModel):
    hostname: str | None = Field(default=None, max_length=255)
    platform: str | None = Field(default=None, max_length=255)
    #: Scopes the CLI would like. Advisory only -- the approval screen shows
    #: them pre-selected and the person decides what is actually granted.
    scopes: list[str] = Field(default_factory=lambda: ["read"])


@router.post("/auth/start", status_code=status.HTTP_201_CREATED)
async def device_start(
    payload: DeviceStartRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    ip = client_ip(request)
    allowed, _ = await rate_limit(f"cli:start:{ip}", 20, fail_closed=True)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="too many login attempts"
        )

    # Opportunistically reap expired rows; this table is tiny and short-lived.
    await session.execute(
        delete(DeviceAuthorization).where(DeviceAuthorization.expires_at < datetime.now(UTC))
    )

    device_code = secrets.token_urlsafe(32)
    for _ in range(5):
        user_code = _make_user_code()
        existing = (
            await session.execute(
                select(DeviceAuthorization.id).where(DeviceAuthorization.user_code == user_code)
            )
        ).scalar_one_or_none()
        if existing is None:
            break
    else:  # pragma: no cover - astronomically unlikely
        raise HTTPException(status_code=500, detail="could not allocate a user code")

    record = DeviceAuthorization(
        device_code_hash=_hash(device_code),
        user_code=user_code,
        expires_at=datetime.now(UTC) + DEVICE_CODE_TTL,
        client_hostname=(payload.hostname or "")[:255] or None,
        client_platform=(payload.platform or "")[:255] or None,
        client_ip=ip,
        requested_scopes=sorted(
            {s for s in payload.scopes if s in ("read", "publish", "admin")} or {"read"}
        ),
    )
    session.add(record)
    await session.commit()

    return {
        "device_code": device_code,
        "user_code": user_code,
        # No `verification_url_complete`. RFC 8628 section 5.4 warns that a
        # pre-filled approval page is a phishing primitive: the target clicks
        # a link, sees a code they never typed next to machine details the
        # *initiator* supplied, and approves a token into someone else's
        # terminal. Making them type the code is the whole check.
        "verification_url": f"{settings.public_url}/cli-login",
        "expires_in": int(DEVICE_CODE_TTL.total_seconds()),
        "interval": POLL_INTERVAL_SECONDS,
    }


class DevicePollRequest(BaseModel):
    device_code: str


@router.post("/auth/poll")
async def device_poll(
    payload: DevicePollRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    allowed, _ = await rate_limit(f"cli:poll:{client_ip(request)}", 300)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="slow down"
        )

    record = (
        await session.execute(
            select(DeviceAuthorization).where(
                DeviceAuthorization.device_code_hash == _hash(payload.device_code)
            )
        )
    ).scalar_one_or_none()

    if record is None:
        # Same answer for unknown and expired, so polling cannot enumerate codes.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expired_token")
    if _aware(record.expires_at) < datetime.now(UTC):
        await session.delete(record)
        await session.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expired_token")
    if record.denied:
        await session.delete(record)
        await session.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="access_denied")
    if record.approved_at is None:
        return {"status": "authorization_pending", "interval": POLL_INTERVAL_SECONDS}

    token = record.token_plaintext
    if token is None:
        # Already collected. A token is handed over exactly once.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expired_token")

    user = None
    if record.approved_user_id:
        from ..models import User

        user = await session.get(User, record.approved_user_id)

    # Burn the plaintext immediately; from here only the hash remains.
    record.token_plaintext = None
    record.collected_at = datetime.now(UTC)
    await session.commit()

    return {
        "status": "complete",
        "token": token,
        "username": user.username if user else None,
        "registry": settings.public_url,
    }


@router.get("/auth/pending/{user_code}")
async def device_pending(
    user_code: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_user),
) -> dict:
    """What the browser shows on the approval screen."""
    allowed, _ = await rate_limit(f"cli:lookup:{client_ip(request)}", 30, fail_closed=True)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="slow down")

    normalized = _normalize_user_code(user_code)
    if not normalized:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown code")

    record = (
        await session.execute(
            select(DeviceAuthorization).where(DeviceAuthorization.user_code == normalized)
        )
    ).scalar_one_or_none()
    if record is None or _aware(record.expires_at) < datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="that code has expired or does not exist"
        )

    return {
        "user_code": record.user_code,
        "hostname": record.client_hostname,
        "platform": record.client_platform,
        "ip": record.client_ip,
        "requested_scopes": record.requested_scopes or ["read"],
        "requested_at": record.created_at,
        "expires_at": record.expires_at,
        "already_approved": record.approved_at is not None,
    }


class DeviceApproveRequest(BaseModel):
    user_code: str
    approve: bool = True
    #: Scopes to grant the CLI. Never more than the person already has.
    scopes: list[str] = Field(default_factory=lambda: ["read"])


@router.post("/auth/approve")
async def device_approve(
    payload: DeviceApproveRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_primary_credential),
) -> dict:
    allowed, _ = await rate_limit(
        f"cli:approve:{client_ip(request)}", 30, fail_closed=True
    )
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="slow down")

    normalized = _normalize_user_code(payload.user_code)
    if not normalized:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown code")

    record = (
        await session.execute(
            select(DeviceAuthorization).where(DeviceAuthorization.user_code == normalized)
        )
    ).scalar_one_or_none()
    if record is None or _aware(record.expires_at) < datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="that code has expired or does not exist"
        )
    if record.approved_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="that code was already approved"
        )

    user = identity.user
    assert user is not None

    if not payload.approve:
        record.denied = True
        await audit.record_audit(
            session,
            "auth.cli.denied",
            actor_user_id=user.id,
            actor_username=user.username,
            ip=client_ip(request),
            detail={"hostname": record.client_hostname, "user_code": record.user_code},
        )
        await session.commit()
        return {"ok": True, "approved": False}

    # A CLI token can never exceed the authority of the person approving it,
    # nor the authority of the credential they are approving with -- otherwise
    # a leaked read-only token could approve itself an admin CLI token.
    granted = {s for s in payload.scopes if s in ("read", "publish", "admin")} or {"read"}
    if "admin" in granted and not user.is_admin:
        granted.discard("admin")
    if "publish" in granted and not (user.can_publish or user.is_admin):
        granted.discard("publish")
    if identity.token is not None:
        granted &= set(identity.token.scopes or [])
    granted = granted or {"read"}

    full_token, prefix, token_hash = generate_token()
    api_token = ApiToken(
        user_id=user.id,
        name=f"cli@{record.client_hostname or 'unknown'}",
        prefix=prefix,
        token_hash=token_hash,
        scopes=sorted(granted),
        # CLI tokens land on developer laptops and had no expiry at all. A
        # default lifetime bounds the damage from one that walks; `minireg
        # login` re-runs in seconds.
        expires_at=(
            datetime.now(UTC) + timedelta(days=settings.cli_token_ttl_days)
            if settings.cli_token_ttl_days
            else None
        ),
    )
    session.add(api_token)
    await session.flush()

    record.approved_user_id = user.id
    record.approved_at = datetime.now(UTC)
    record.token_id = api_token.id
    record.token_plaintext = full_token

    await audit.record_audit(
        session,
        "auth.cli.approved",
        actor_user_id=user.id,
        actor_username=user.username,
        target_type="token",
        target_id=str(api_token.id),
        ip=client_ip(request),
        detail={
            "hostname": record.client_hostname,
            "platform": record.client_platform,
            "cli_ip": record.client_ip,
            "scopes": sorted(granted),
        },
    )
    await session.commit()
    return {"ok": True, "approved": True, "scopes": sorted(granted)}


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
class AuditItem(BaseModel):
    name: str
    version: str


class AuditRequest(BaseModel):
    ecosystem: Ecosystem
    packages: list[AuditItem] = Field(default_factory=list, max_length=4000)
    #: Look up anything we lack CVE data for. Off makes the call instant but
    #: blind to anything not already scanned.
    scan_unknown: bool = True
    #: Re-query OSV even for versions already scanned. Slower; use when you
    #: need today's advisories rather than the registry's last refresh.
    refresh: bool = False


@router.post("/audit")
async def audit_packages(
    payload: AuditRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_user),
) -> dict:
    """Report known CVEs, and this registry's policy verdict, for a dependency set."""
    if not payload.packages:
        return {"ecosystem": payload.ecosystem.value, "findings": [], "checked": 0, "unscanned": []}

    allowed, _ = await rate_limit(f"cli:audit:u{identity.user_id}", 60)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="slow down")

    ecosystem = payload.ecosystem
    wanted = {
        (normalize_name_for(ecosystem.value, item.name), item.version): item
        for item in payload.packages
    }

    # Filter on the requested versions as well as the requested names. Without
    # the version predicate an audit that mentions `playwright` pulled all 5,600
    # of its stored version rows; with the Package entity attached that meant
    # 5,600 copies of a 17MB packument. Both are fixed here: narrow rows, and
    # only the columns this handler reads.
    rows = (
        await session.execute(
            select(Package.name, Package.normalized_name, PackageVersion)
            .join(PackageVersion, PackageVersion.package_id == Package.id)
            .options(defer(PackageVersion.metadata_json))
            .where(
                Package.ecosystem == ecosystem,
                Package.normalized_name.in_({key[0] for key in wanted}),
                PackageVersion.version.in_({key[1] for key in wanted}),
            )
        )
    ).all()

    known: dict[tuple[str, str], tuple[str, PackageVersion]] = {}
    for name, normalized, version in rows:
        known[(normalized, version.version)] = (name, version)

    # Look up anything we do not already hold CVE data for -- which is *not* the
    # same as "anything the registry has never seen". Proxying a package creates
    # its version rows long before anything scans them, so treating "known" as
    # "scanned" silently reported freshly mirrored packages as clean. That made
    # an audit against a new registry return nothing at all.
    scanner = OsvScanner(session)
    to_scan: list[tuple[str, str]] = []
    for key, item in wanted.items():
        entry = known.get(key)
        needs_lookup = (
            entry is None or entry[1].scanned_at is None or payload.refresh
        )
        if needs_lookup:
            to_scan.append((item.name, item.version))

    scanned_now: dict[tuple[str, str], object] = {}
    if to_scan and payload.scan_unknown:
        try:
            scanned_now = await scanner.scan_versions(ecosystem, to_scan[:MAX_ON_DEMAND_SCAN])
        except Exception:
            log.warning("on-demand audit scan failed", exc_info=True)
        else:
            # Persist against the rows we do have, so the next audit is a
            # database read rather than another round trip to OSV.
            persisted = False
            for key, entry in known.items():
                item = wanted.get(key)
                if item is None:
                    continue
                result = scanned_now.get((item.name, item.version))
                if result is not None and getattr(result, "scanned", False):
                    await scanner.apply_to_version(entry[1], result, entry[0])
                    persisted = True
            if persisted:
                await session.commit()

    version_ids = [v.id for _name, v in known.values()]
    cve_rows = []
    if version_ids:
        cve_rows = (
            await session.execute(
                select(PackageVulnerability.version_id, Vulnerability, PackageVulnerability)
                .join(Vulnerability, Vulnerability.id == PackageVulnerability.vulnerability_id)
                .where(PackageVulnerability.version_id.in_(version_ids))
            )
        ).all()

    by_version: dict[int, list] = {}
    for version_id, vuln, link in cve_rows:
        by_version.setdefault(version_id, []).append(
            {
                "cve_id": vuln.cve_id,
                "osv_id": vuln.id,
                "cvss_score": vuln.cvss_score,
                "severity": vuln.severity_label,
                "summary": vuln.summary,
                "fixed_version": link.fixed_version,
                "suppressed": link.suppressed,
                "url": f"https://osv.dev/vulnerability/{vuln.id}",
            }
        )
    by_version = {
        version_id: dedupe_by_cve(entries) for version_id, entries in by_version.items()
    }

    policy = PolicyEngine(session)
    findings = []
    unscanned: list[dict] = []

    for (normalized, version), item in wanted.items():
        entry = known.get((normalized, version))
        cves: list = []
        max_cvss = None
        has_fix = False
        scanned = False

        if entry is not None:
            _name, version_row = entry
            cves = by_version.get(version_row.id, [])
            max_cvss = version_row.max_cvss
            has_fix = version_row.has_fix
            scanned = version_row.scanned_at is not None
        else:
            result = scanned_now.get((item.name, item.version))
            if result is not None and getattr(result, "scanned", False):
                scanned = True
                max_cvss = result.max_score
                has_fix = result.has_fix
                cves = dedupe_by_cve(
                    [
                        {
                            "cve_id": c.get("cve_id"),
                            "osv_id": c.get("id"),
                            "cvss_score": c.get("cvss_score"),
                            "severity": c.get("severity"),
                            "summary": c.get("summary"),
                            # "fixed in X" is the most actionable part of a
                            # finding, so dig it out of the raw OSV record
                            # rather than reporting None.
                            "fixed_version": fixed_version_for(
                                c.get("raw") or {}, item.name, ecosystem.value
                            ),
                            "suppressed": False,
                            "url": f"https://osv.dev/vulnerability/{c.get('id')}",
                        }
                        for c in result.cves
                    ]
                )

        if not scanned:
            unscanned.append({"name": item.name, "version": item.version})

        verdict = await policy.evaluate(
            ecosystem,
            normalized,
            version,
            max_cvss=max_cvss,
            has_fix=has_fix,
            scanned=scanned,
        )

        if cves or verdict.blocked:
            ordered_cves = sorted(cves, key=lambda c: c.get("cvss_score") or 0, reverse=True)
            fix_version = lowest_clearing_version(ecosystem.value, ordered_cves, item.version)
            findings.append(
                {
                    "name": item.name,
                    "version": item.version,
                    "max_cvss": max_cvss,
                    "cves": ordered_cves,
                    "blocked": verdict.blocked,
                    "block_reason": verdict.reason,
                    "known_to_registry": entry is not None,
                    # The lowest release that clears every CVE with a known
                    # fix, or None when nothing upstream fixes them yet.
                    "fix_version": fix_version,
                    "fixable": fix_version is not None,
                }
            )

    findings.sort(key=lambda f: (f["max_cvss"] or 0, f["blocked"]), reverse=True)
    return {
        "ecosystem": ecosystem.value,
        "checked": len(wanted),
        "findings": findings,
        "unscanned": unscanned[:50],
        "unscanned_total": len(unscanned),
    }


# --------------------------------------------------------------------------- #
# Distribution
# --------------------------------------------------------------------------- #
#: Response header carrying the CLI version the registry ships. Every API
#: response includes it, so the CLI learns it has fallen behind without ever
#: making a request purely to ask.
CLI_VERSION_HEADER = "x-minireg-cli-version"

_VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.MULTILINE)


@lru_cache(maxsize=1)
def cli_version() -> str | None:
    """Version declared by the bundled CLI. Cached: the file cannot change
    without a restart, and this is read on every API response."""
    path = _find_cli_source()
    if path is None:
        return None
    match = _VERSION_RE.search(path.read_text(encoding="utf-8"))
    return match.group(1) if match else None


def _cli_source() -> str:
    path = _find_cli_source()
    if path is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="the CLI is not bundled with this deployment",
        )
    return path.read_text(encoding="utf-8")


@router.get("/version")
async def cli_version_info() -> dict:
    """What the registry ships, so the CLI can tell whether it is current.

    Unauthenticated on purpose: a CLI that cannot log in should still be able to
    discover that it is the reason why.
    """
    source = _cli_source()
    return {
        "version": cli_version(),
        "sha256": hashlib.sha256(source.encode()).hexdigest(),
        "size": len(source.encode()),
        "download_url": f"{settings.public_url}/api/cli/download",
    }


@router.get("/download", include_in_schema=False)
async def download_cli() -> Response:
    """The CLI itself: one stdlib-only Python file, no install step required."""
    source = _cli_source()
    return Response(
        content=source,
        media_type="text/x-python",
        headers={
            "content-disposition": 'attachment; filename="minireg"',
            "cache-control": "no-cache",
        },
    )


@router.get("/install.sh", include_in_schema=False)
async def install_script() -> PlainTextResponse:
    """Installer, with this registry's URL already baked in."""
    base = settings.public_url
    # PUBLIC_URL is operator-controlled, but it lands inside a shell string
    # that every user pipes into sh, so a stray quote or $(...) would ship a
    # broken -- or worse -- installer to all of them.
    if any(ch in base for ch in '"\'`$\\ \n\r'):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="PUBLIC_URL contains characters that cannot be safely embedded "
            "in the installer script; fix the deployment configuration",
        )
    script = f"""#!/bin/sh
# minireg CLI installer
#
#   curl -fsSL {base}/api/cli/install.sh | sh
#
# Installs a single stdlib-only Python script. Override the location with
# MINIREG_BIN_DIR=/somewhere/bin.
set -eu

REGISTRY="{base}"
BIN_DIR="${{MINIREG_BIN_DIR:-$HOME/.local/bin}}"
TARGET="$BIN_DIR/minireg"

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required but was not found on PATH" >&2
  exit 1
fi

mkdir -p "$BIN_DIR"

fetch() {{
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    echo "error: neither curl nor wget is available" >&2
    exit 1
  fi
}}

fetch "$REGISTRY/api/cli/download" "$TARGET.tmp"

# Verify the download against the checksum the registry publishes separately.
# This is integrity, not authenticity -- both come from the same origin, so
# TLS is still what establishes trust in that origin -- but it does catch a
# truncated or corrupted transfer before it replaces a working CLI.
EXPECTED=$(fetch "$REGISTRY/api/cli/version" /dev/stdout \
  | sed -n 's/.*"sha256"[[:space:]]*:[[:space:]]*"\\([0-9a-f]*\\)".*/\\1/p')
if [ -n "$EXPECTED" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "$TARGET.tmp" | cut -d' ' -f1)
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "$TARGET.tmp" | cut -d' ' -f1)
  else
    ACTUAL=""
  fi
  if [ -n "$ACTUAL" ] && [ "$ACTUAL" != "$EXPECTED" ]; then
    rm -f "$TARGET.tmp"
    echo "error: checksum mismatch downloading the minireg CLI" >&2
    echo "  expected $EXPECTED" >&2
    echo "  got      $ACTUAL" >&2
    exit 1
  fi
fi

chmod 0755 "$TARGET.tmp"
mv "$TARGET.tmp" "$TARGET"

# Pre-seed the registry URL so `minireg login` needs no arguments.
CONFIG_DIR="${{XDG_CONFIG_HOME:-$HOME/.config}}/minireg"
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/config.json" ]; then
  printf '{{"registry": "%s"}}\\n' "$REGISTRY" > "$CONFIG_DIR/config.json"
  chmod 0600 "$CONFIG_DIR/config.json"
fi

echo "Installed minireg to $TARGET"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "note: $BIN_DIR is not on your PATH -- add it to use 'minireg' directly" ;;
esac
echo
echo "Next:  minireg login"
"""
    return PlainTextResponse(script, media_type="text/x-shellscript")
