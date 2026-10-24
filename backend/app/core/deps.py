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
import ipaddress
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache

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
    peer = request.client.host if request.client else None

    # Forwarding headers are only meaningful from a proxy we put there. From
    # anyone else they are just a field the caller filled in, so a direct
    # connection to the port could otherwise choose its own rate-limit bucket
    # and its own audit-log address.
    if not _is_trusted_proxy(peer):
        return peer[:64] if peer else None

    hops = max(1, settings.trusted_proxy_hops)
    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded and not request.headers.get("x-real-ip"):
        _warn_if_relayed_direct(peer)
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            index = max(0, len(parts) - hops)
            return parts[index][:64]
    real = request.headers.get("x-real-ip")
    if real:
        return real.strip()[:64]
    return peer[:64] if peer else None


def _default_gateway(route_table: str = "/proc/net/route") -> str | None:
    """The IPv4 default gateway, read from the kernel's routing table.

    In a container on a Docker bridge this is the bridge's address on the
    host -- the address Docker's userland proxy connects from when it relays
    a published port.
    """
    import socket
    import struct

    try:
        with open(route_table) as fh:
            lines = fh.read().splitlines()[1:]
    except OSError:
        return None
    for line in lines:
        fields = line.split()
        if len(fields) < 3 or fields[1] != "00000000":
            continue
        try:
            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
        except (ValueError, struct.error, OSError):
            return None
    return None


#: (gateway, already warned). Computed on first use.
_relay_state: dict[str, object] = {}


def check_trusted_proxy_config() -> str | None:
    """Startup check: does TRUSTED_PROXY_IPS trust our own gateway?

    Returns the gateway address when it does (after logging a warning), so
    the operator is told once per start that the setting is only safe while
    the published port is not reachable by clients directly. See
    :func:`_warn_if_relayed_direct` for the stronger, traffic-based signal.
    """
    gateway = _default_gateway()
    _relay_state["gateway"] = gateway
    if not gateway or not _is_trusted_proxy(gateway):
        return None
    log.warning(
        "TRUSTED_PROXY_IPS trusts %s, this container's gateway. Docker's port "
        "relay connects from that address, so X-Forwarded-For is believed from "
        "anything that reaches the published port. That is safe only while the "
        "port is bound to loopback (BIND_ADDRESS=127.0.0.1) or reachable solely "
        "by your reverse proxy; with BIND_ADDRESS=0.0.0.0 and no proxy, set "
        "TRUSTED_PROXY_IPS= (empty).",
        gateway,
    )
    return gateway


def _warn_if_relayed_direct(peer: str | None) -> None:
    """Warn, once, when a direct client reaches us through a trusted relay.

    The default TRUSTED_PROXY_IPS trusts the private ranges because the
    shipped layout has a proxy on the host reach the container over the
    Docker bridge. But Docker's userland proxy relays *every* connection to
    a published port from the bridge gateway, so with BIND_ADDRESS=0.0.0.0
    (or an LXC/rootless setup that relays everything) any client on the
    network arrives from that trusted address and may write its own
    X-Forwarded-For -- choosing its rate-limit bucket and audit address.

    That cannot be told apart at startup from the safe layout, where the
    host's proxy connects to 127.0.0.1 and is relayed from the same gateway.
    What does tell them apart is traffic: a reverse proxy always adds a
    forwarding header, a client connecting directly does not. So the first
    request from the gateway without one is logged as a warning. In-network
    callers (the scanner, the healthcheck) connect from their own addresses,
    not the gateway, and do not trigger it.
    """
    if not peer or _relay_state.get("warned"):
        return
    if "gateway" not in _relay_state:
        _relay_state["gateway"] = _default_gateway()
    gateway = _relay_state["gateway"]
    if not gateway or peer != gateway or not _is_trusted_proxy(peer):
        return
    _relay_state["warned"] = True
    log.warning(
        "A request arrived from %s, this container's gateway, with no "
        "X-Forwarded-For. That is a client reaching the published port directly "
        "through Docker's port relay, and TRUSTED_PROXY_IPS (%s) trusts that "
        "address -- so any such client can set X-Forwarded-For and choose the "
        "address used for rate limits and the audit log. Bind the port to "
        "loopback (BIND_ADDRESS=127.0.0.1) behind a reverse proxy, or narrow "
        "TRUSTED_PROXY_IPS to the proxy's own address (empty when nothing is "
        "in front).",
        peer,
        settings.trusted_proxy_ips,
    )


@lru_cache(maxsize=4096)
def _is_trusted_proxy(peer: str | None) -> bool:
    if not peer:
        return False
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(address in network for network in settings.trusted_proxy_networks)


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
    """Routes decide what to do with an anonymous identity.

    Raises only for a valid session cookie on a cross-site state-changing
    request (403, see :func:`is_cross_site`); a bad credential is anonymous.

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
                # The cookie is the one credential a browser attaches on its
                # own, so it is the only one a cross-site request can ride.
                reject_cross_site(request)
                return Identity(user=user, method="session")

    return Identity()


#: Methods that change state. A cookie-authenticated one must come from our
#: own pages.
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
#: Origins besides PUBLIC_URL's that may drive the session in development
#: (the Vite dev server, mirroring the CORS setup in main.py).
_DEV_ORIGINS = frozenset({"http://localhost:5173"})


def _origin_of(url: str) -> str | None:
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if scheme not in ("http", "https") or not host:
        return None
    default = 443 if scheme == "https" else 80
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}" + (f":{port}" if port and port != default else "")


def _trusted_origin(origin: str | None) -> bool:
    if not origin:
        return False
    if origin == _origin_of(settings.public_url):
        return True
    return settings.environment == "dev" and origin in _DEV_ORIGINS


def is_cross_site(request: Request) -> bool:
    """Whether a state-changing request did *not* come from our own pages.

    ``Sec-Fetch-Site`` is set by the browser and cannot be forged by page
    script; every current browser sends it. ``same-origin`` is our SPA,
    ``none`` is the user acting directly (typing a URL, a bookmark). Anything
    else -- including ``same-site``, which covers every other app on a shared
    parent domain that ``SameSite=Lax`` does nothing about -- is refused.

    Without that header (an older browser), ``Origin`` and then ``Referer``
    must name PUBLIC_URL's origin; ``Origin: null`` (sandboxed frames,
    privacy-sensitive redirects) counts as no match.

    A request carrying none of the three is let through. The Fetch standard
    has browsers attach ``Origin`` to every request whose method is not GET
    or HEAD, so such a request did not come from a browser -- and forging a
    request needs the victim's browser to send it. Scripts and test clients
    that hold a session cookie keep working.
    """
    if request.method.upper() not in _UNSAFE_METHODS:
        return False
    site = request.headers.get("sec-fetch-site")
    if site is not None:
        return site.strip().lower() not in ("same-origin", "none")
    origin = request.headers.get("origin")
    if origin is not None and origin.strip().lower() != "null":
        return not _trusted_origin(_origin_of(origin))
    referer = request.headers.get("referer")
    if referer:
        return not _trusted_origin(_origin_of(referer))
    # Origin: null with no Referer to vouch for it is a browser hiding where
    # the request came from; refuse. No Origin at all is not a browser.
    return origin is not None


def reject_cross_site(request: Request) -> None:
    """Refuse a cookie-authenticated unsafe request from another site."""
    if is_cross_site(request):
        log.warning(
            "refused cross-site %s %s (Sec-Fetch-Site=%r, Origin=%r)",
            request.method,
            request.url.path,
            request.headers.get("sec-fetch-site"),
            request.headers.get("origin"),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cross-site request refused; use this site's own pages or an API token",
        )


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
