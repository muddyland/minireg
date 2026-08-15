"""Admin: users, upstreams, rules, and runtime settings."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.deps import Identity, client_ip, require_admin
from ...core.security import encrypt_credential, hash_password
from ...core.semver import is_valid_range, parse_range
from ...db import get_session
from ...models import (
    ApiToken,
    AuthProvider,
    Ecosystem,
    PackageRule,
    RuleAction,
    Setting,
    Upstream,
    UpstreamKind,
    User,
)
from ...services import audit
from ...services.policy import (
    KEY_ALLOWLIST_MODE,
    KEY_CVE_POLICY,
    CvePolicy,
    PolicyEngine,
    invalidate_policy_cache,
)
from ...services.resolver import build_provider

log = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(require_admin)])


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #
class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=150)
    email: str | None = None
    full_name: str | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)
    is_admin: bool = False
    can_publish: bool = False
    is_active: bool = True


class UserUpdate(BaseModel):
    email: str | None = None
    full_name: str | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)
    is_admin: bool | None = None
    can_publish: bool | None = None
    is_active: bool | None = None


def user_payload(user: User, token_count: int = 0) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "is_admin": user.is_admin,
        "can_publish": user.can_publish,
        "is_active": user.is_active,
        "provider": user.provider.value,
        "created_at": user.created_at,
        "last_login_at": user.last_login_at,
        "token_count": token_count,
    }


@router.get("/users")
async def list_users(session: AsyncSession = Depends(get_session)) -> dict:
    users = (await session.execute(select(User).order_by(User.username))).scalars().all()
    counts = dict(
        (
            await session.execute(
                select(ApiToken.user_id, func.count(ApiToken.id))
                .where(ApiToken.revoked.is_(False))
                .group_by(ApiToken.user_id)
            )
        ).all()
    )
    return {"users": [user_payload(u, counts.get(u.id, 0)) for u in users]}


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password) if payload.password else None,
        is_admin=payload.is_admin,
        can_publish=payload.can_publish or payload.is_admin,
        is_active=payload.is_active,
        provider=AuthProvider.local,
    )
    session.add(user)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="username already exists"
        ) from exc

    await audit.record_audit(
        session,
        audit.USER_CREATED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="user",
        target_id=str(user.id),
        ip=client_ip(request),
        detail={"username": user.username, "is_admin": user.is_admin},
    )
    await session.commit()
    return user_payload(user)


@router.patch("/users/{user_id}")
async def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")

    # Guard against an admin locking everyone out of the instance.
    if user.id == identity.user_id and payload.is_admin is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="you cannot revoke your own admin rights"
        )
    if payload.is_active is False and user.id == identity.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="you cannot disable your own account"
        )

    changes: dict[str, Any] = {}
    for field in ("email", "full_name", "is_admin", "can_publish", "is_active"):
        value = getattr(payload, field)
        if value is not None and getattr(user, field) != value:
            changes[field] = value
            setattr(user, field, value)
    if payload.password:
        if user.provider == AuthProvider.oidc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="password is managed by the identity provider",
            )
        user.password_hash = hash_password(payload.password)
        changes["password"] = "changed"

    if user.is_admin:
        user.can_publish = True

    if await _would_orphan_admins(session):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="at least one active admin must remain",
        )

    await audit.record_audit(
        session,
        audit.USER_UPDATED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="user",
        target_id=str(user.id),
        ip=client_ip(request),
        detail={"username": user.username, "changes": changes},
    )
    await session.commit()
    return user_payload(user)


async def _would_orphan_admins(session: AsyncSession) -> bool:
    """True when the pending change would leave no active admin."""
    remaining = (
        await session.execute(
            select(func.count(User.id)).where(User.is_admin.is_(True), User.is_active.is_(True))
        )
    ).scalar_one()
    return remaining == 0


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
    if user.id == identity.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="you cannot delete your own account"
        )

    username = user.username
    await session.delete(user)
    await session.flush()
    if await _would_orphan_admins(session):
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="at least one active admin must remain"
        )

    await audit.record_audit(
        session,
        audit.USER_DELETED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="user",
        target_id=str(user_id),
        ip=client_ip(request),
        detail={"username": username},
    )
    await session.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Upstreams
# --------------------------------------------------------------------------- #
class UpstreamCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    ecosystem: Ecosystem
    kind: UpstreamKind
    url: str
    tier: int = Field(default=1, ge=1, le=100)
    priority: int = Field(default=100, ge=0, le=10000)
    enabled: bool = True
    auth_type: str = "none"
    credential: str | None = None
    auth_header_name: str | None = None
    timeout_seconds: float = Field(default=20.0, gt=0, le=300)
    verify_ssl: bool = True
    cache_artifacts: bool = True
    gitlab_project_id: str | None = None
    gitlab_group_id: str | None = None
    allow_publish: bool = False
    index_packages: bool = False
    web_url_template: str | None = None


class UpstreamUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    tier: int | None = Field(default=None, ge=1, le=100)
    priority: int | None = Field(default=None, ge=0, le=10000)
    enabled: bool | None = None
    auth_type: str | None = None
    credential: str | None = None
    auth_header_name: str | None = None
    timeout_seconds: float | None = Field(default=None, gt=0, le=300)
    verify_ssl: bool | None = None
    cache_artifacts: bool | None = None
    gitlab_project_id: str | None = None
    gitlab_group_id: str | None = None
    allow_publish: bool | None = None
    index_packages: bool | None = None
    web_url_template: str | None = None


def upstream_payload(upstream: Upstream) -> dict:
    return {
        "id": upstream.id,
        "name": upstream.name,
        "ecosystem": upstream.ecosystem.value,
        "kind": upstream.kind.value,
        "url": upstream.url,
        "tier": upstream.tier,
        "priority": upstream.priority,
        "enabled": upstream.enabled,
        "auth_type": upstream.auth_type,
        # Never return the credential itself; only whether one is set.
        "has_credential": bool(upstream.credential_enc),
        "auth_header_name": upstream.auth_header_name,
        "timeout_seconds": upstream.timeout_seconds,
        "verify_ssl": upstream.verify_ssl,
        "cache_artifacts": upstream.cache_artifacts,
        "gitlab_project_id": upstream.gitlab_project_id,
        "gitlab_group_id": upstream.gitlab_group_id,
        "allow_publish": upstream.allow_publish,
        "index_packages": upstream.index_packages,
        "web_url_template": upstream.web_url_template,
        "healthy": upstream.healthy,
        "last_error": upstream.last_error,
        "last_check_at": upstream.last_check_at,
        "last_indexed_at": upstream.last_indexed_at,
        "consecutive_failures": upstream.consecutive_failures,
        "created_at": upstream.created_at,
    }


def _validate_kind(ecosystem: Ecosystem, kind: UpstreamKind) -> None:
    npm_kinds = {UpstreamKind.npm, UpstreamKind.gitlab_npm}
    pypi_kinds = {UpstreamKind.pypi, UpstreamKind.gitlab_pypi}
    valid = npm_kinds if ecosystem == Ecosystem.npm else pypi_kinds
    if kind not in valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"kind '{kind.value}' is not valid for ecosystem '{ecosystem.value}'",
        )


@router.get("/upstreams")
async def list_upstreams(session: AsyncSession = Depends(get_session)) -> dict:
    rows = (
        await session.execute(
            select(Upstream).order_by(Upstream.ecosystem, Upstream.tier, Upstream.priority)
        )
    ).scalars().all()
    return {"upstreams": [upstream_payload(u) for u in rows]}


@router.post("/upstreams", status_code=status.HTTP_201_CREATED)
async def create_upstream(
    payload: UpstreamCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    _validate_kind(payload.ecosystem, payload.kind)
    data = payload.model_dump(exclude={"credential"})
    upstream = Upstream(**data, credential_enc=encrypt_credential(payload.credential))
    session.add(upstream)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="an upstream with that name already exists"
        ) from exc

    await audit.record_audit(
        session,
        audit.UPSTREAM_CREATED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="upstream",
        target_id=str(upstream.id),
        ip=client_ip(request),
        detail={
            "name": upstream.name,
            "ecosystem": upstream.ecosystem.value,
            "kind": upstream.kind.value,
            "url": upstream.url,
            "tier": upstream.tier,
        },
    )
    await session.commit()
    return upstream_payload(upstream)


@router.patch("/upstreams/{upstream_id}")
async def update_upstream(
    upstream_id: int,
    payload: UpstreamUpdate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    upstream = await session.get(Upstream, upstream_id)
    if upstream is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="upstream not found")

    changes: dict[str, Any] = {}
    for field, value in payload.model_dump(exclude_unset=True, exclude={"credential"}).items():
        if value is not None and getattr(upstream, field) != value:
            changes[field] = value
            setattr(upstream, field, value)

    if payload.credential is not None:
        # An empty string clears the stored credential.
        upstream.credential_enc = encrypt_credential(payload.credential) if payload.credential else None
        changes["credential"] = "set" if payload.credential else "cleared"

    # Any config change deserves a fresh health verdict.
    upstream.healthy = True
    upstream.consecutive_failures = 0
    upstream.last_error = None

    await audit.record_audit(
        session,
        audit.UPSTREAM_UPDATED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="upstream",
        target_id=str(upstream_id),
        ip=client_ip(request),
        detail={"name": upstream.name, "changes": changes},
    )
    await session.commit()
    return upstream_payload(upstream)


@router.delete("/upstreams/{upstream_id}")
async def delete_upstream(
    upstream_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    upstream = await session.get(Upstream, upstream_id)
    if upstream is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="upstream not found")
    name = upstream.name
    await session.delete(upstream)

    await audit.record_audit(
        session,
        audit.UPSTREAM_DELETED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="upstream",
        target_id=str(upstream_id),
        ip=client_ip(request),
        detail={"name": name},
    )
    await session.commit()
    return {"ok": True}


@router.post("/upstreams/{upstream_id}/test")
async def test_upstream(
    upstream_id: int, session: AsyncSession = Depends(get_session)
) -> dict:
    upstream = await session.get(Upstream, upstream_id)
    if upstream is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="upstream not found")

    provider = build_provider(upstream)
    healthy, error = await provider.health_check()
    upstream.healthy = healthy
    upstream.last_error = error
    upstream.last_check_at = datetime.now(UTC)
    if healthy:
        upstream.consecutive_failures = 0
    await session.commit()
    return {"healthy": healthy, "error": error}


@router.post("/upstreams/{upstream_id}/index")
async def index_upstream(
    upstream_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    """Pull an upstream's package list into the local search index.

    Only names are imported; full metadata is fetched lazily on first request.
    """
    upstream = await session.get(Upstream, upstream_id)
    if upstream is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="upstream not found")

    provider = build_provider(upstream)
    if not provider.supports_indexing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"upstream kind '{upstream.kind.value}' cannot enumerate packages",
        )

    from ...core.naming import normalize_name_for
    from ...models import Package

    try:
        names = await provider.list_packages()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=f"indexing failed: {exc}"
        ) from exc

    existing = set(
        (
            await session.execute(
                select(Package.normalized_name).where(Package.ecosystem == upstream.ecosystem)
            )
        ).scalars().all()
    )

    added = 0
    for name in names:
        normalized = normalize_name_for(upstream.ecosystem.value, name)
        if normalized in existing:
            continue
        session.add(
            Package(
                ecosystem=upstream.ecosystem,
                name=name,
                normalized_name=normalized,
                origin_upstream_id=upstream.id,
            )
        )
        existing.add(normalized)
        added += 1

    upstream.last_indexed_at = datetime.now(UTC)
    await audit.record_audit(
        session,
        "admin.upstream.indexed",
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="upstream",
        target_id=str(upstream_id),
        ip=client_ip(request),
        detail={"name": upstream.name, "discovered": len(names), "added": added},
    )
    await session.commit()
    return {"discovered": len(names), "added": added}


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
class RuleCreate(BaseModel):
    ecosystem: Ecosystem | None = None
    pattern: str = Field(min_length=1, max_length=512)
    action: RuleAction
    version_spec: str | None = None
    reason: str | None = None
    enabled: bool = True


class RuleUpdate(BaseModel):
    pattern: str | None = None
    action: RuleAction | None = None
    version_spec: str | None = None
    reason: str | None = None
    enabled: bool | None = None


def _validate_version_spec(ecosystem: Ecosystem | None, spec: str | None) -> str | None:
    """Reject a version spec that will not do what the admin thinks.

    A malformed spec would otherwise fall back to glob matching and quietly
    match nothing, leaving the admin believing a package is blocked when it is
    not. Returns a normalized description of what the spec expands to, for the
    API response.
    """
    if not spec or not spec.strip():
        return None
    spec = spec.strip()

    # An ecosystem-agnostic rule has to satisfy both grammars.
    check_npm = ecosystem in (None, Ecosystem.npm)
    check_pypi = ecosystem in (None, Ecosystem.pypi)

    if check_npm and not is_valid_range(spec):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"'{spec}' is not a valid npm version range. Examples: "
                "'1.2.3', '<4.17.21', '^1.2.3', '>=3.0.0 <3.0.2', '1.x || 2.x'."
            ),
        )

    if check_pypi:
        from packaging.specifiers import InvalidSpecifier, SpecifierSet

        try:
            SpecifierSet(spec)
        except InvalidSpecifier as exc:
            if ecosystem == Ecosystem.pypi:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"'{spec}' is not a valid PEP 440 specifier. Examples: "
                        "'==1.2.3', '<2.0', '>=1.0,<2.0', '~=1.4.2'."
                    ),
                ) from exc
            # Ecosystem-agnostic rule: npm already accepted it, so allow it
            # through and let PyPI evaluation fall back to a glob.

    if check_npm and is_valid_range(spec):
        return str(parse_range(spec))
    return spec


def rule_payload(rule: PackageRule) -> dict:
    return {
        "id": rule.id,
        "ecosystem": rule.ecosystem.value if rule.ecosystem else None,
        "pattern": rule.pattern,
        "action": rule.action.value,
        "version_spec": rule.version_spec,
        # What the range actually expands to, so an admin can confirm that
        # `^1.2.3` means what they think before it starts failing installs.
        "version_spec_expanded": _expand_spec(rule.ecosystem, rule.version_spec),
        "reason": rule.reason,
        "enabled": rule.enabled,
        "created_by": rule.created_by,
        "created_at": rule.created_at,
    }


def _expand_spec(ecosystem: Ecosystem | None, spec: str | None) -> str | None:
    if not spec or ecosystem == Ecosystem.pypi:
        return None
    try:
        return str(parse_range(spec)) if is_valid_range(spec) else None
    except Exception:
        return None


@router.get("/rules")
async def list_rules(session: AsyncSession = Depends(get_session)) -> dict:
    rows = (
        await session.execute(select(PackageRule).order_by(PackageRule.action, PackageRule.pattern))
    ).scalars().all()
    return {"rules": [rule_payload(r) for r in rows]}


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def create_rule(
    payload: RuleCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    _validate_version_spec(payload.ecosystem, payload.version_spec)
    rule = PackageRule(**payload.model_dump(), created_by=identity.username)
    session.add(rule)
    await session.flush()

    await audit.record_audit(
        session,
        audit.RULE_CREATED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="rule",
        target_id=str(rule.id),
        ip=client_ip(request),
        detail=rule_payload(rule),
    )
    await session.commit()
    await invalidate_policy_cache()
    return rule_payload(rule)


@router.patch("/rules/{rule_id}")
async def update_rule(
    rule_id: int,
    payload: RuleUpdate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    rule = await session.get(PackageRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="rule not found")

    fields = payload.model_dump(exclude_unset=True)
    if "version_spec" in fields:
        _validate_version_spec(rule.ecosystem, fields["version_spec"])

    changes = {}
    for field, value in payload.model_dump(exclude_unset=True).items():
        if value is not None and getattr(rule, field) != value:
            changes[field] = value.value if hasattr(value, "value") else value
            setattr(rule, field, value)

    await audit.record_audit(
        session,
        audit.RULE_UPDATED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="rule",
        target_id=str(rule_id),
        ip=client_ip(request),
        detail={"pattern": rule.pattern, "changes": changes},
    )
    await session.commit()
    await invalidate_policy_cache()
    return rule_payload(rule)


@router.delete("/rules/{rule_id}")
async def delete_rule(
    rule_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    rule = await session.get(PackageRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="rule not found")
    snapshot = rule_payload(rule)
    await session.delete(rule)

    await audit.record_audit(
        session,
        audit.RULE_DELETED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="rule",
        target_id=str(rule_id),
        ip=client_ip(request),
        detail=snapshot,
    )
    await session.commit()
    await invalidate_policy_cache()
    return {"ok": True}


class SpecPreviewRequest(BaseModel):
    ecosystem: Ecosystem | None = None
    version_spec: str
    probe_version: str | None = None


@router.post("/rules/preview-spec")
async def preview_version_spec(payload: SpecPreviewRequest) -> dict:
    """Explain what a version range means, without saving anything.

    The UI calls this rather than reimplementing semver in JavaScript: a
    preview computed by a second implementation could disagree with the engine
    that actually enforces the rule, which is worse than no preview at all.
    """
    spec = (payload.version_spec or "").strip()
    if not spec:
        return {"valid": True, "expanded": None, "matches": None}

    ecosystem = payload.ecosystem or Ecosystem.npm

    if ecosystem == Ecosystem.pypi:
        from packaging.specifiers import InvalidSpecifier, SpecifierSet

        try:
            expanded = str(SpecifierSet(spec))
        except InvalidSpecifier as exc:
            return {"valid": False, "error": f"not a valid PEP 440 specifier: {exc}"}
    else:
        if not is_valid_range(spec):
            return {
                "valid": False,
                "error": (
                    "not a valid npm version range — try '<4.17.21', '^1.2.3', "
                    "'>=3.0.0 <3.0.2', or '1.x || 2.x'"
                ),
            }
        expanded = str(parse_range(spec))

    matches = None
    if payload.probe_version:
        from ...services.policy import _matches_version

        matches = _matches_version(spec, ecosystem.value, payload.probe_version.strip())

    return {"valid": True, "expanded": expanded, "matches": matches}


@router.post("/rules/test")
async def test_rule(
    ecosystem: Ecosystem,
    name: str,
    version: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Dry-run the policy engine against a name so admins can confirm a rule
    does what they intended before it bites a CI job."""
    from ...core.naming import normalize_name_for

    verdict = await PolicyEngine(session).evaluate(
        ecosystem, normalize_name_for(ecosystem.value, name), version
    )
    return {
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "source": verdict.source,
        "rule_id": verdict.rule_id,
    }


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #
class CvePolicyUpdate(BaseModel):
    enabled: bool = False
    min_score: float = Field(default=7.0, ge=0.0, le=10.0)
    max_score: float = Field(default=10.0, ge=0.0, le=10.0)
    block_unscored: bool = False
    require_fix_available: bool = False


class AllowlistModeUpdate(BaseModel):
    enabled: bool


async def _write_setting(
    session: AsyncSession, key: str, value: dict, identity: Identity
) -> None:
    row = await session.get(Setting, key)
    if row is None:
        session.add(Setting(key=key, value=value, updated_by=identity.username))
    else:
        row.value = value
        row.updated_by = identity.username


@router.get("/settings")
async def get_settings_(session: AsyncSession = Depends(get_session)) -> dict:
    engine = PolicyEngine(session)
    return {
        "cve_policy": (await engine.get_cve_policy()).to_dict(),
        "allowlist_mode": await engine.allowlist_mode(),
    }


@router.put("/settings/cve-policy")
async def update_cve_policy(
    payload: CvePolicyUpdate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    if payload.min_score > payload.max_score:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="min_score must be less than or equal to max_score",
        )
    policy = CvePolicy(**payload.model_dump())
    await _write_setting(session, KEY_CVE_POLICY, policy.to_dict(), identity)

    await audit.record_audit(
        session,
        audit.SETTING_UPDATED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="setting",
        target_id=KEY_CVE_POLICY,
        ip=client_ip(request),
        detail=policy.to_dict(),
    )
    await session.commit()
    await invalidate_policy_cache()
    return policy.to_dict()


@router.put("/settings/allowlist-mode")
async def update_allowlist_mode(
    payload: AllowlistModeUpdate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_admin),
) -> dict:
    await _write_setting(session, KEY_ALLOWLIST_MODE, {"enabled": payload.enabled}, identity)
    await audit.record_audit(
        session,
        audit.SETTING_UPDATED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="setting",
        target_id=KEY_ALLOWLIST_MODE,
        ip=client_ip(request),
        detail={"enabled": payload.enabled},
    )
    await session.commit()
    await invalidate_policy_cache()
    return {"enabled": payload.enabled}
