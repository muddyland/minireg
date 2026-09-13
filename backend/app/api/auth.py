"""Authentication endpoints for the web UI and API-token management."""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..core.cache import rate_limit
from ..core.deps import Identity, client_ip, require_primary_credential, require_user, resolve_identity
from ..core.security import (
    create_session_token,
    create_state_token,
    decode_state_token,
    generate_token,
    hash_password,
    needs_rehash,
    verify_password,
)
from ..db import get_session
from ..models import ApiToken, AuthProvider, User
from ..services import audit, oidc

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])

VALID_SCOPES = {"read", "publish", "admin"}


def _safe_next(target: str | None) -> str:
    """Only ever redirect to a path on this site.

    ``//evil.example`` starts with "/" but is a protocol-relative URL, so a
    plain ``startswith("/")`` check sent the user to another origin holding a
    freshly minted session cookie -- an ideal setup for a fake "session
    expired" prompt. Backslashes are folded to slashes by some browsers, so
    they are rejected too.
    """
    if not target or not target.startswith("/"):
        return "/"
    if target.startswith("//") or "\\" in target:
        return "/"
    return target


class LoginRequest(BaseModel):
    # Bounded so a long username cannot overflow the audit row's column (which
    # turned a failed login into a 500 and lost the audit record), and a
    # multi-megabyte password cannot buy an argon2 verify over the whole thing.
    username: str = Field(min_length=1, max_length=150)
    password: str = Field(min_length=1, max_length=1024)


class TokenCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    scopes: list[str] = Field(default_factory=lambda: ["read"])
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=256)


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        settings.session_cookie,
        token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        samesite="lax",
        secure=settings.public_url.startswith("https://"),
        path="/",
    )


def _user_payload(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "is_admin": user.is_admin,
        "can_publish": user.can_publish,
        "provider": user.provider.value,
        "last_login_at": user.last_login_at,
    }


# --------------------------------------------------------------------------- #
# Local login
# --------------------------------------------------------------------------- #
@router.post("/login")
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
) -> dict:
    ip = client_ip(request)
    # Throttle by IP *and* username so neither a single source nor a single
    # account can be brute-forced.
    for key in (f"login:ip:{ip}", f"login:user:{payload.username}"):
        allowed, _ = await rate_limit(key, settings.rate_limit_login_per_minute)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="too many login attempts; try again shortly",
            )

    user = (
        await session.execute(select(User).where(User.username == payload.username))
    ).scalar_one_or_none()

    if user is None or not verify_password(payload.password, user.password_hash):
        await audit.record_audit(
            session,
            audit.LOGIN_FAILED,
            actor_username=payload.username,
            actor_type="anonymous",
            success=False,
            ip=ip,
            user_agent=request.headers.get("user-agent"),
            detail={"reason": "invalid credentials"},
        )
        await session.commit()
        # Same message either way: do not leak which usernames exist.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid username or password"
        )

    if not user.is_active:
        await audit.record_audit(
            session,
            audit.LOGIN_FAILED,
            actor_user_id=user.id,
            actor_username=user.username,
            success=False,
            ip=ip,
            detail={"reason": "account disabled"},
        )
        await session.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="account is disabled")

    if needs_rehash(user.password_hash or ""):
        user.password_hash = hash_password(payload.password)

    user.last_login_at = datetime.now(UTC)
    await audit.record_audit(
        session,
        audit.LOGIN_SUCCESS,
        actor_user_id=user.id,
        actor_username=user.username,
        ip=ip,
        user_agent=request.headers.get("user-agent"),
        detail={"method": "password"},
    )
    await session.commit()

    _set_session_cookie(response, create_session_token(user.id, user.username, user.is_admin))
    return {"user": _user_payload(user)}


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(resolve_identity),
) -> dict:
    if identity.is_authenticated:
        await audit.record_audit(
            session,
            audit.LOGOUT,
            actor_user_id=identity.user_id,
            actor_username=identity.username,
            ip=client_ip(request),
        )
        await session.commit()
    response.delete_cookie(settings.session_cookie, path="/")
    return {"ok": True}


@router.get("/me")
async def me(identity: Identity = Depends(require_user)) -> dict:
    assert identity.user is not None
    return {
        "user": _user_payload(identity.user),
        "auth_method": identity.method,
        "scopes": (identity.token.scopes if identity.token else ["read", "publish", "admin"]),
    }


@router.post("/password")
async def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_primary_credential),
) -> dict:
    user = identity.user
    assert user is not None
    if user.provider == AuthProvider.oidc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="password is managed by the identity provider",
        )
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="current password is incorrect"
        )

    user.password_hash = hash_password(payload.new_password)
    await audit.record_audit(
        session,
        "auth.password.changed",
        actor_user_id=user.id,
        actor_username=user.username,
        ip=client_ip(request),
    )
    await session.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- #
# API tokens
# --------------------------------------------------------------------------- #
@router.get("/tokens")
async def list_tokens(
    session: AsyncSession = Depends(get_session), identity: Identity = Depends(require_user)
) -> dict:
    rows = (
        await session.execute(
            select(ApiToken)
            .where(ApiToken.user_id == identity.user_id)
            .order_by(ApiToken.created_at.desc())
        )
    ).scalars().all()
    return {
        "tokens": [
            {
                "id": t.id,
                "name": t.name,
                "prefix": t.prefix,
                "scopes": t.scopes,
                "created_at": t.created_at,
                "expires_at": t.expires_at,
                "last_used_at": t.last_used_at,
                "revoked": t.revoked,
            }
            for t in rows
        ]
    }


@router.post("/tokens", status_code=status.HTTP_201_CREATED)
async def create_token(
    payload: TokenCreateRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_primary_credential),
) -> dict:
    user = identity.user
    assert user is not None

    requested = set(payload.scopes) or {"read"}
    if not requested <= VALID_SCOPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid scopes: {sorted(requested - VALID_SCOPES)}",
        )
    # A token can never exceed its owner's authority.
    if "admin" in requested and not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="only admins can mint admin tokens"
        )
    if "publish" in requested and not (user.can_publish or user.is_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="this account is not permitted to publish",
        )

    full_token, prefix, token_hash = generate_token()
    expires_at = (
        datetime.now(UTC) + timedelta(days=payload.expires_in_days)
        if payload.expires_in_days
        else None
    )
    row = ApiToken(
        user_id=user.id,
        name=payload.name,
        prefix=prefix,
        token_hash=token_hash,
        scopes=sorted(requested),
        expires_at=expires_at,
    )
    session.add(row)
    await session.flush()

    await audit.record_audit(
        session,
        audit.TOKEN_CREATED,
        actor_user_id=user.id,
        actor_username=user.username,
        target_type="token",
        target_id=str(row.id),
        ip=client_ip(request),
        detail={"name": payload.name, "scopes": sorted(requested)},
    )
    await session.commit()

    return {
        "id": row.id,
        "name": row.name,
        "scopes": row.scopes,
        "expires_at": row.expires_at,
        # Shown exactly once; only the hash is stored.
        "token": full_token,
    }


@router.delete("/tokens/{token_id}")
async def revoke_token(
    token_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    identity: Identity = Depends(require_user),
) -> dict:
    row = await session.get(ApiToken, token_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="token not found")
    # Revoking someone else's token is an admin action, so it needs the admin
    # scope and not merely an admin owner -- otherwise an admin's publish-only
    # CI token could revoke anyone's credentials.
    others = row.user_id != identity.user_id
    if others and not (identity.is_admin and identity.has_scope("admin")):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="not your token")

    row.revoked = True
    await audit.record_audit(
        session,
        audit.TOKEN_REVOKED,
        actor_user_id=identity.user_id,
        actor_username=identity.username,
        target_type="token",
        target_id=str(token_id),
        ip=client_ip(request),
        detail={"name": row.name, "owner_id": row.user_id},
    )
    await session.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- #
# OIDC
# --------------------------------------------------------------------------- #
@router.get("/oidc/status")
async def oidc_status() -> dict:
    return {
        "enabled": settings.oidc_enabled,
        "issuer": settings.oidc_issuer if settings.oidc_enabled else None,
        "login_url": "/api/auth/oidc/login" if settings.oidc_enabled else None,
    }


def _redirect_uri() -> str:
    return f"{settings.public_url}/api/auth/oidc/callback"


@router.get("/oidc/login")
async def oidc_login(next: str = "/") -> RedirectResponse:
    if not settings.oidc_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OIDC is not enabled")

    verifier, challenge = oidc.make_pkce()
    nonce = secrets.token_urlsafe(24)
    # All login state travels in the signed `state` parameter.
    state = create_state_token(
        {"nonce": nonce, "verifier": verifier, "next": _safe_next(next)}
    )
    try:
        url = await oidc.build_authorization_url(_redirect_uri(), state, nonce, challenge)
    except oidc.OidcError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    return RedirectResponse(url, status_code=status.HTTP_302_FOUND)


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    session: AsyncSession = Depends(get_session),
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> Response:
    ip = client_ip(request)

    if error:
        await audit.record_audit(
            session,
            audit.LOGIN_FAILED,
            actor_type="anonymous",
            success=False,
            ip=ip,
            detail={"method": "oidc", "error": error, "description": error_description},
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"identity provider returned an error: {error}",
        )

    if not code or not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="missing code or state"
        )

    state_payload = decode_state_token(state)
    if state_payload is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid or expired login state"
        )

    try:
        tokens = await oidc.exchange_code(code, _redirect_uri(), state_payload["verifier"])
        claims = await oidc.verify_id_token(tokens["id_token"], state_payload["nonce"])
        userinfo = (
            await oidc.fetch_userinfo(tokens["access_token"]) if tokens.get("access_token") else {}
        )
        profile = oidc.build_profile(claims, userinfo)
    except oidc.OidcError as exc:
        await audit.record_audit(
            session,
            audit.LOGIN_FAILED,
            actor_type="anonymous",
            success=False,
            ip=ip,
            detail={"method": "oidc", "error": str(exc)},
        )
        await session.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    if not profile.is_permitted():
        await audit.record_audit(
            session,
            audit.LOGIN_FAILED,
            actor_username=profile.username,
            actor_type="anonymous",
            success=False,
            ip=ip,
            detail={
                "method": "oidc",
                "reason": f"not a member of '{settings.oidc_user_group}'",
                "groups": profile.groups,
            },
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="your account is not permitted to access this registry",
        )

    user = (
        await session.execute(
            select(User).where(
                User.oidc_issuer == profile.issuer, User.oidc_subject == profile.subject
            )
        )
    ).scalar_one_or_none()

    if user is None and profile.email and profile.email_verified:
        # Link an existing local account with the same email on first OIDC
        # login -- but only an email the provider says it verified, and only
        # onto an account that is still local.
        #
        # Without those two conditions this was an account takeover: at an IdP
        # where users can set their own email, claiming `admin@localhost` (the
        # shipped bootstrap address) bound the existing admin row to the
        # attacker's subject, flipped it to OIDC so its password could no
        # longer be changed, and then rewrote its admin flag from the
        # attacker's group membership.
        candidates = (
            await session.execute(
                select(User).where(
                    func.lower(User.email) == profile.email.lower(),
                    User.provider == AuthProvider.local,
                )
            )
        ).scalars().all()
        # An ambiguous match is not a match. Email is not unique in this
        # schema, and picking one arbitrarily is how you link the wrong person.
        if len(candidates) == 1:
            user = candidates[0]
            user.oidc_issuer = profile.issuer
            user.oidc_subject = profile.subject
            user.provider = AuthProvider.oidc
            log.info("linked local account '%s' to OIDC subject", user.username)

    created = False
    if user is None:
        if not settings.oidc_auto_create_users:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="no local account exists and automatic creation is disabled",
            )
        user = User(
            username=profile.username,
            email=profile.email,
            full_name=profile.full_name,
            provider=AuthProvider.oidc,
            oidc_issuer=profile.issuer,
            oidc_subject=profile.subject,
            is_active=True,
        )
        session.add(user)
        created = True

    # Group membership is authoritative on every login, so revoking a group in
    # Authentik takes effect immediately here.
    user.is_admin = profile.is_admin
    if profile.is_admin:
        user.can_publish = True
    user.email = profile.email or user.email
    user.full_name = profile.full_name or user.full_name
    user.last_login_at = datetime.now(UTC)
    await session.flush()

    await audit.record_audit(
        session,
        audit.LOGIN_OIDC,
        actor_user_id=user.id,
        actor_username=user.username,
        ip=ip,
        user_agent=request.headers.get("user-agent"),
        detail={
            "issuer": profile.issuer,
            "subject": profile.subject,
            "groups": profile.groups,
            "is_admin": user.is_admin,
            "account_created": created,
        },
    )
    await session.commit()

    destination = _safe_next(state_payload.get("next"))
    response = RedirectResponse(destination, status_code=status.HTTP_302_FOUND)
    _set_session_cookie(response, create_session_token(user.id, user.username, user.is_admin))
    return response
