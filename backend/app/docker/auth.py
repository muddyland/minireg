"""Who is calling /v2, and what they may do.

Docker clients learn how to authenticate from the ``/v2/`` ping: a 200
there means "no auth, ever", and a later push then fails with "no basic
auth credentials". So ``/v2/`` always answers 401 with a bearer challenge
pointing at ``/v2/token``, exactly as Docker Hub does, and anonymous pulls
work by fetching an anonymous pull-only token from that realm.

The token endpoint takes HTTP Basic with any username and an ``mrg_`` API
token as the password. Passwords are refused: an OIDC user has none, a
password in ``~/.docker/config.json`` is a primary credential sitting in a
file, and a token can be scoped and revoked.

Issued tokens are short-lived HS256 JWTs naming the API token they were
minted from, so revoking the API token cuts off every registry token
derived from it on the next request rather than at expiry.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

import jwt
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..core.deps import Identity, _token_identity
from ..core.security import extract_bearer, parse_basic_auth
from ..models import ApiToken, User
from .errors import RegistryError

log = logging.getLogger(__name__)

SERVICE = "minireg"
_ALG = "HS256"

#: Token scope that lets an API token push images. Deliberately separate from
#: "publish": a docker login token ends up base64'd in ~/.docker/config.json
#: on every CI runner, and a leak there should not publish npm packages.
PUSH_SCOPE = "docker:push"
#: Scope held only by the scanner worker's token: pull any image, including
#: quarantined and policy-blocked ones, and report scan results.
SCANNER_SCOPE = "scanner"


def _key() -> bytes:
    # Derived, so a registry token can never be replayed as a session cookie
    # (which is signed with the raw secret key).
    return hmac.new(settings.secret_key.encode(), b"minireg-registry-token", hashlib.sha256).digest()


@dataclass(slots=True)
class RegistryIdentity:
    user: User | None = None
    token: ApiToken | None = None
    #: repository name -> granted actions, from a bearer JWT. None means the
    #: caller authenticated directly (Basic / raw mrg_ bearer) and actions
    #: are decided per request.
    access: dict[str, set[str]] | None = None
    anonymous: bool = True
    scanner: bool = False
    method: str = "anonymous"
    extras: dict = field(default_factory=dict)

    @property
    def username(self) -> str | None:
        return self.user.username if self.user else None

    @property
    def user_id(self) -> int | None:
        return self.user.id if self.user else None

    @property
    def token_id(self) -> int | None:
        return self.token.id if self.token else None

    def as_identity(self) -> Identity:
        return Identity(user=self.user, token=self.token, method=self.method)


def challenge_header(request: Request, scope: str | None = None) -> dict[str, str]:
    realm = f"{_public_base(request)}/v2/token"
    value = f'Bearer realm="{realm}",service="{SERVICE}"'
    if scope:
        value += f',scope="{scope}"'
    return {"WWW-Authenticate": value}


def _public_base(request: Request) -> str:
    """The origin the client used, when it is one we answer to.

    The token realm must be on the host the client is talking to -- a client
    on the mirror hostname would otherwise be sent to PUBLIC_URL for a token
    it then presents to the mirror. Only the configured hosts are honoured;
    anything else falls back to PUBLIC_URL so a forged Host header cannot
    point the realm somewhere else.
    """
    from urllib.parse import urlsplit

    public = urlsplit(settings.public_url)
    host = (request.headers.get("host") or "").lower()
    allowed = {(public.netloc or "").lower()}
    if settings.docker_mirror_hostname:
        allowed.add(settings.docker_mirror_hostname.lower())
    if host in allowed:
        return f"{public.scheme}://{host}"
    if settings.docker_internal_url:
        internal = urlsplit(settings.docker_internal_url)
        if host and host == (internal.netloc or "").lower():
            # Its own scheme: the internal origin is usually plain HTTP
            # behind a public HTTPS one.
            return f"{internal.scheme}://{internal.netloc}"
    return settings.public_url


def unauthorized(request: Request, message: str = "authentication required", scope: str | None = None):
    return RegistryError("UNAUTHORIZED", message, headers=challenge_header(request, scope))


# --------------------------------------------------------------------------- #
# Token endpoint
# --------------------------------------------------------------------------- #
def parse_scopes(values: list[str]) -> list[tuple[str, str, set[str]]]:
    """``repository:foo/bar:pull,push`` -> [("repository", "foo/bar", {...})]."""
    out = []
    for value in values:
        for item in value.split(" "):
            if not item:
                continue
            kind, _, rest = item.partition(":")
            name, _, actions = rest.rpartition(":")
            if kind not in ("repository", "registry") or not name:
                continue
            out.append((kind, name, {a for a in actions.split(",") if a}))
    return out


async def authenticate_basic(
    session: AsyncSession, request: Request, *, secret: str | None = None
) -> RegistryIdentity | None:
    """Resolve credentials sent to the token endpoint (or directly).

    ``secret`` is a credential taken from somewhere other than the
    Authorization header -- the password field of an OAuth2 form post, which
    is how ``docker login`` sends it. It is passed in rather than written
    back into the request headers: Starlette caches ``request.headers`` the
    first time anything reads them (form parsing reads Content-Type), so a
    rewritten header is silently never seen and the login comes out
    anonymous.

    Returns None for no credentials, raises for bad ones.
    """
    header = request.headers.get("authorization")
    if not header and not secret:
        return None
    presented: str | None = None
    if secret:
        presented = secret
    elif header.lower().startswith("basic "):
        creds = parse_basic_auth(header)
        if creds is None:
            raise unauthorized(request, "malformed Basic credentials")
        presented = creds[1]
    else:
        presented = extract_bearer(header)
    if not presented:
        raise unauthorized(request, "unsupported authorization scheme")
    identity = await _token_identity(session, presented)
    if identity is None:
        from ..core.deps import client_ip
        from ..services.audit import TOKEN_AUTH_FAILED, record_audit

        try:
            await record_audit(
                session,
                TOKEN_AUTH_FAILED,
                actor_type="anonymous",
                success=False,
                ip=client_ip(request),
                detail={"path": "/v2", "hint": "registry login"},
            )
            await session.commit()
        except Exception:  # an audit write must not turn a 401 into a 500
            await session.rollback()
        raise unauthorized(
            request,
            "invalid credentials. Log in with an API token as the password; "
            "account passwords are not accepted by the container registry",
        )
    scopes = set(identity.token.scopes or []) if identity.token else set()
    return RegistryIdentity(
        user=identity.user,
        token=identity.token,
        anonymous=False,
        scanner=SCANNER_SCOPE in scopes,
        method="token",
    )


def can_read(ident: RegistryIdentity) -> bool:
    if ident.scanner:
        return True
    if ident.anonymous:
        return settings.allow_anonymous_read
    scopes = set(ident.token.scopes or []) if ident.token else set()
    return bool(scopes & {"read", "admin", PUSH_SCOPE, "publish"})


def push_problem(ident: RegistryIdentity, name: str) -> str | None:
    """Why this identity may not push to ``name`` (None if it may).

    Ownership is checked separately, against the database, when the push
    arrives: this only covers what the credential itself allows.
    """
    local = settings.docker_local_namespace
    if not name.startswith(f"{local}/"):
        return (
            f"images can only be pushed under '{local}/'. Pushing to Docker Hub or an "
            "upstream's path is not allowed."
        )
    if ident.anonymous or ident.user is None:
        return "pushing requires a login"
    if not (ident.user.can_publish or ident.user.is_admin):
        return "this account is not permitted to push"
    scopes = set(ident.token.scopes or []) if ident.token else set()
    if PUSH_SCOPE not in scopes and "admin" not in scopes:
        return f"this token lacks the '{PUSH_SCOPE}' scope"
    prefixes = (ident.token.docker_repo_prefixes or []) if ident.token else []
    if prefixes and not any(name.startswith(p) for p in prefixes):
        return "this token may only push to " + ", ".join(prefixes)
    return None


def issue_token(ident: RegistryIdentity, access: list[dict]) -> tuple[str, int]:
    now = int(time.time())
    ttl = settings.docker_token_ttl_seconds
    claims = {
        "iss": SERVICE,
        "aud": SERVICE,
        "iat": now,
        "nbf": now - 5,
        "exp": now + ttl,
        "sub": str(ident.user_id) if ident.user_id else "",
        "tid": ident.token_id,
        "access": access,
    }
    return jwt.encode(claims, _key(), algorithm=_ALG), ttl


async def resolve_registry_identity(session: AsyncSession, request: Request) -> RegistryIdentity:
    """Identity for a /v2 request other than the token endpoint."""
    header = request.headers.get("authorization")
    if not header:
        return RegistryIdentity()
    bearer = extract_bearer(header)
    if bearer and bearer.count(".") == 2:
        try:
            claims = jwt.decode(bearer, _key(), algorithms=[_ALG], audience=SERVICE, issuer=SERVICE)
        except jwt.PyJWTError as exc:
            raise unauthorized(request, "registry token is invalid or expired") from exc
        access: dict[str, set[str]] = {}
        for entry in claims.get("access") or []:
            if isinstance(entry, dict) and entry.get("type") == "repository":
                access.setdefault(str(entry.get("name")), set()).update(entry.get("actions") or [])
        tid = claims.get("tid")
        if not tid:
            return RegistryIdentity(access=access, method="anonymous-token")
        token = await session.get(ApiToken, int(tid))
        if token is None or token.revoked or (
            token.expires_at is not None
            and _aware(token.expires_at) < datetime.now(UTC)
        ):
            raise unauthorized(request, "the API token behind this login was revoked or expired")
        user = await session.get(User, token.user_id)
        if user is None or not user.is_active:
            raise unauthorized(request, "account disabled")
        scopes = set(token.scopes or [])
        return RegistryIdentity(
            user=user,
            token=token,
            access=access,
            anonymous=False,
            scanner=SCANNER_SCOPE in scopes,
            method="token",
        )
    # Basic, or a raw mrg_ token as a bearer (crane --token, scripts).
    ident = await authenticate_basic(session, request)
    return ident or RegistryIdentity()


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)
