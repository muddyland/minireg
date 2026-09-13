"""FastAPI dependencies: identity resolution, RBAC, rate limiting.

Client credential shapes we must accept, because the tooling is not negotiable:

* npm  -> ``Authorization: Bearer <token>``
* pip  -> ``Authorization: Basic base64("__token__:<token>")`` (PyPI convention)
         and ``Basic base64("<user>:<token>")``
* twine -> same as pip
* UI   -> session JWT in an HttpOnly cookie
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..core.cache import rate_limit, rate_limit_retry_after
from ..core.security import (
    decode_session_token,
    extract_bearer,
    parse_basic_auth,
    split_token,
    verify_token_secret,
)
from ..db import get_session
from ..models import ApiToken, User

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Identity:
    """Who is making this request."""

    user: User | None = None
    token: ApiToken | None = None
    method: str = "anonymous"  # session|token|basic|anonymous

    @property
    def is_authenticated(self) -> bool:
        return self.user is not None

    @property
    def is_admin(self) -> bool:
        return bool(self.user and self.user.is_admin)

    @property
    def user_id(self) -> int | None:
        return self.user.id if self.user else None

    @property
    def username(self) -> str | None:
        return self.user.username if self.user else None

    @property
    def token_id(self) -> int | None:
        return self.token.id if self.token else None

    def has_scope(self, scope: str) -> bool:
        """Session logins carry full user authority; tokens are scope-limited."""
        if self.user is None:
            return False
        if self.token is None:
            return True
        return self.token_has_scope(scope)

    def token_has_scope(self, scope: str) -> bool:
        """Scope check that never falls back to full authority.

        Unlike :meth:`has_scope` this answers False for a session, so callers
        that specifically care about *token* authority cannot be fooled by an
        identity that simply has no token attached.
        """
        if self.token is None:
            return False
        scopes = self.token.scopes or []
        return scope in scopes or "admin" in scopes

    @property
    def can_publish(self) -> bool:
        if self.user is None or not self.user.is_active:
            return False
        if not (self.user.can_publish or self.user.is_admin):
            return False
        return self.has_scope("publish")


def client_ip(request: Request) -> str | None:
    """The caller's address, counting back from the right of X-Forwarded-For.

    The left-most entry is whatever the *client* sent. Reading it meant anyone
    could pick their own rate-limit bucket, their own audit-log address, and
    the "From IP" shown on a CLI approval screen, just by adding a header --
    an nginx that appends with ``$proxy_add_x_forwarded_for`` (the common
    copy-paste) preserves it verbatim.

    Each proxy appends the peer it saw, so with ``TRUSTED_PROXY_HOPS`` proxies
    in front, the last entry that no untrusted party could have written is the
    Nth from the right. With the default single proxy that is the last entry.
    """
    hops = max(1, settings.trusted_proxy_hops)
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            index = max(0, len(parts) - hops)
            return parts[index][:64]
    real = request.headers.get("x-real-ip")
    if real:
        return real.strip()[:64]
    return request.client.host if request.client else None


async def _token_identity(session: AsyncSession, presented: str) -> Identity | None:
    parts = split_token(presented)
    if parts is None:
        return None
    prefix, secret = parts

    token = (
        await session.execute(select(ApiToken).where(ApiToken.prefix == prefix))
    ).scalar_one_or_none()
    if token is None or token.revoked:
        return None
    if not verify_token_secret(secret, token.token_hash):
        return None
    if token.expires_at is not None:
        expires = token.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if expires < datetime.now(UTC):
            return None

    user = await session.get(User, token.user_id)
    if user is None or not user.is_active:
        return None

    # last_used_at is advisory; a stale value is not worth a write on every
    # request, so only bump it once a minute.
    now = datetime.now(UTC)
    last = token.last_used_at
    if last is not None and last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    if last is None or (now - last).total_seconds() > 60:
        token.last_used_at = now

    return Identity(user=user, token=token, method="token")


async def _basic_password_identity(
    session: AsyncSession, request: Request, username: str, password: str
) -> Identity:
    """Username/password over HTTP Basic.

    This runs on *every* route, not just the login endpoint, so it needs the
    login endpoint's protections: without them it was an unthrottled,
    unlogged password oracle that also cost a full argon2 verify per guess.

    The resulting identity is marked ``basic_password`` and carries no token,
    which :meth:`Identity.has_scope` treats as full user authority. That is
    correct for a password -- it is the user's primary credential -- but it is
    also why the guessing has to be as expensive here as it is at /auth/login.
    """
    from ..core.cache import rate_limit
    from ..core.security import verify_password
    from ..services.audit import LOGIN_FAILED, record_audit

    ip = client_ip(request) or "unknown"
    for key, limit in (
        (f"login:ip:{ip}", settings.rate_limit_login_per_minute),
        (f"login:user:{username[:150]}", settings.rate_limit_login_per_minute),
    ):
        allowed, _ = await rate_limit(key, limit, fail_closed=True)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="too many login attempts",
                headers={"Retry-After": str(rate_limit_retry_after())},
            )

    user = (
        await session.execute(select(User).where(User.username == username))
    ).scalar_one_or_none()
    if user and user.is_active and verify_password(password, user.password_hash):
        return Identity(user=user, method="basic_password")

    with contextlib.suppress(Exception):
        await record_audit(
            session,
            LOGIN_FAILED,
            actor_username=username[:150],
            success=False,
            ip=ip,
            detail={"method": "basic"},
        )
    return Identity()


async def resolve_identity(
    request: Request, session: AsyncSession = Depends(get_session)
) -> Identity:
    """Never raises. Routes decide what to do with an anonymous identity.

    An ``Authorization`` header is authoritative: if one is present but does not
    authenticate, we return anonymous rather than falling back to a session
    cookie. Otherwise a revoked token would keep appearing to work for any
    caller that happened to also carry a browser session.
    """
    auth_header = request.headers.get("authorization")

    if auth_header:
        bearer = extract_bearer(auth_header)
        if bearer:
            identity = await _token_identity(session, bearer)
            return identity or Identity()

        if auth_header.lower().startswith("basic "):
            credentials = parse_basic_auth(auth_header)
            if credentials is None:
                return Identity()
            username, password = credentials
            # PyPI convention: username "__token__" means the password is a token.
            identity = await _token_identity(session, password)
            if identity:
                return Identity(user=identity.user, token=identity.token, method="basic")
            # Plain username/password Basic, for clients that cannot send Bearer.
            if username not in ("__token__", "token"):
                return await _basic_password_identity(session, request, username, password)
            return Identity()

        # An Authorization scheme we do not implement.
        return Identity()

    cookie = request.cookies.get(settings.session_cookie)
    if cookie:
        payload = decode_session_token(cookie)
        if payload:
            user = await session.get(User, int(payload["sub"]))
            # The version in the cookie must still match the user row: a
            # password change or a sign-out-everywhere bumps it, which is what
            # makes a stateless session revocable.
            if user and user.is_active and payload.get("sv", 0) == user.session_version:
                return Identity(user=user, method="session")

    return Identity()


# --------------------------------------------------------------------------- #
# Guards
# --------------------------------------------------------------------------- #
async def require_user(identity: Identity = Depends(resolve_identity)) -> Identity:
    if not identity.is_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return identity


async def require_admin(identity: Identity = Depends(resolve_identity)) -> Identity:
    if not identity.is_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not identity.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin privileges required")
    if not identity.has_scope("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="token lacks the 'admin' scope"
        )
    return identity


async def require_primary_credential(
    identity: Identity = Depends(resolve_identity),
) -> Identity:
    """A logged-in session, or an admin-scoped token.

    Guards the routes that hand out or revoke authority. Everything else takes
    the *user's* rights as the ceiling, which is right for a browser session
    but wrong for a token: a leaked read-only CI token could POST /auth/tokens
    asking for ``admin`` and be handed one, because the check only ever looked
    at whether the *owner* was an admin. Scoping a token is only meaningful if
    the token cannot widen itself.
    """
    if identity.user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if identity.token is not None and not identity.token_has_scope("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "this action needs a browser session or an admin-scoped token; "
                "a token cannot grant scopes it does not hold"
            ),
        )
    return identity


async def require_publish(identity: Identity = Depends(resolve_identity)) -> Identity:
    """Publishing always requires a real credential -- never anonymous."""
    if not identity.is_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="an API token is required to publish",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not identity.can_publish:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="this account or token is not permitted to publish",
        )
    return identity


async def require_read(identity: Identity = Depends(resolve_identity)) -> Identity:
    """Read guard for the registry endpoints.

    Honours ALLOW_ANONYMOUS_READ, which most mirrors want on.
    """
    if settings.allow_anonymous_read:
        return identity
    if not identity.is_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not identity.has_scope("read"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="token lacks 'read' scope")
    return identity


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #
async def enforce_rate_limit(
    request: Request, identity: Identity, *, bucket: str = "read", limit: int | None = None
) -> None:
    if not settings.rate_limit_enabled:
        return
    if identity.is_authenticated:
        key = f"{bucket}:u{identity.user_id}"
        ceiling = limit or settings.rate_limit_authenticated_per_minute
    else:
        key = f"{bucket}:ip{client_ip(request) or 'unknown'}"
        ceiling = limit or settings.rate_limit_anonymous_per_minute

    allowed, remaining = await rate_limit(key, ceiling)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="rate limit exceeded",
            headers={
                "Retry-After": str(rate_limit_retry_after()),
                "X-RateLimit-Limit": str(ceiling),
                "X-RateLimit-Remaining": str(remaining),
            },
        )


async def rate_limited_read(
    request: Request, identity: Identity = Depends(require_read)
) -> Identity:
    await enforce_rate_limit(request, identity, bucket="read")
    return identity


async def rate_limited_publish(
    request: Request, identity: Identity = Depends(require_publish)
) -> Identity:
    await enforce_rate_limit(
        request, identity, bucket="publish", limit=settings.rate_limit_publish_per_minute
    )
    return identity
