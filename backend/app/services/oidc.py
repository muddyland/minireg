"""OIDC authentication, targeted at Authentik.

Flow: authorization code + PKCE. No server-side login state is kept -- the
``state`` parameter is itself a short-lived signed JWT carrying the nonce, the
PKCE verifier, and the post-login redirect, so any replica can finish a login
another replica started.

Authentik specifics:

* the issuer is per-application, e.g.
  ``https://authentik.example.com/application/o/minireg/``
* group membership arrives in the ``groups`` claim, but only when the
  provider's scope mapping includes it; we also read the userinfo endpoint as a
  fallback because Authentik omits groups from the ID token in some configs.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import jwt
from jwt import PyJWKClient

from ..config import settings
from ..upstreams.base import get_http_client

log = logging.getLogger(__name__)

_discovery_cache: dict[str, tuple[float, dict]] = {}
_jwk_clients: dict[str, PyJWKClient] = {}
DISCOVERY_TTL = 3600


class OidcError(Exception):
    pass


@dataclass(slots=True)
class OidcProfile:
    subject: str
    issuer: str
    username: str
    email: str | None = None
    email_verified: bool = False
    full_name: str | None = None
    groups: list[str] = field(default_factory=list)
    raw_claims: dict[str, Any] = field(default_factory=dict)

    @property
    def is_admin(self) -> bool:
        return settings.oidc_admin_group in self.groups

    def is_permitted(self) -> bool:
        """When OIDC_USER_GROUP is set, membership is required to log in."""
        if not settings.oidc_user_group:
            return True
        return settings.oidc_user_group in self.groups or self.is_admin


#: Signature algorithms accepted on an id_token. Asymmetric only.
_ID_TOKEN_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"]


def discovery_url() -> str:
    issuer = (settings.oidc_issuer or "").rstrip("/")
    if not issuer:
        raise OidcError("OIDC_ISSUER is not configured")
    return f"{issuer}/.well-known/openid-configuration"


async def get_discovery() -> dict:
    url = discovery_url()
    cached = _discovery_cache.get(url)
    now = time.time()
    if cached and now - cached[0] < DISCOVERY_TTL:
        return cached[1]

    client = get_http_client()
    try:
        response = await client.get(url, timeout=10.0)
    except Exception as exc:
        raise OidcError(f"could not reach the OIDC discovery endpoint: {exc}") from exc
    if response.status_code != 200:
        raise OidcError(f"OIDC discovery returned HTTP {response.status_code}")

    document = response.json()
    for required in ("authorization_endpoint", "token_endpoint", "issuer"):
        if required not in document:
            raise OidcError(f"OIDC discovery document is missing '{required}'")
    # The issuer we validate id_tokens against has to be the one the operator
    # configured, not one the discovery document nominates for itself.
    configured = (settings.oidc_issuer or "").rstrip("/")
    advertised = str(document["issuer"]).rstrip("/")
    if configured and advertised != configured:
        raise OidcError(
            f"OIDC discovery issuer '{advertised}' does not match the configured "
            f"issuer '{configured}'"
        )
    _discovery_cache[url] = (now, document)
    return document


def _jwk_client(jwks_uri: str) -> PyJWKClient:
    client = _jwk_clients.get(jwks_uri)
    if client is None:
        client = PyJWKClient(jwks_uri, cache_keys=True, lifespan=3600)
        _jwk_clients[jwks_uri] = client
    return client


def make_pkce() -> tuple[str, str]:
    """Return ``(verifier, challenge)`` for PKCE S256."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode().rstrip("=")
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


async def build_authorization_url(redirect_uri: str, state: str, nonce: str, challenge: str) -> str:
    from urllib.parse import urlencode

    discovery = await get_discovery()
    params = {
        "response_type": "code",
        "client_id": settings.oidc_client_id or "",
        "redirect_uri": redirect_uri,
        "scope": settings.oidc_scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"{discovery['authorization_endpoint']}?{urlencode(params)}"


async def exchange_code(code: str, redirect_uri: str, verifier: str) -> dict:
    discovery = await get_discovery()
    client = get_http_client()
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": settings.oidc_client_id or "",
        "code_verifier": verifier,
    }
    if settings.oidc_client_secret:
        data["client_secret"] = settings.oidc_client_secret

    try:
        response = await client.post(discovery["token_endpoint"], data=data, timeout=15.0)
    except Exception as exc:
        raise OidcError(f"token exchange failed: {exc}") from exc

    if response.status_code != 200:
        raise OidcError(f"token exchange returned HTTP {response.status_code}: {response.text[:300]}")
    payload = response.json()
    if "id_token" not in payload:
        raise OidcError("token response contained no id_token")
    return payload


async def verify_id_token(id_token: str, nonce: str) -> dict:
    """Validate signature, issuer, audience, expiry, and nonce."""
    discovery = await get_discovery()
    jwks_uri = discovery.get("jwks_uri")
    if not jwks_uri:
        raise OidcError("discovery document has no jwks_uri")

    try:
        signing_key = _jwk_client(jwks_uri).get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            # An explicit asymmetric allowlist. Taking this from discovery
            # means a tampered discovery document chooses the algorithm, and
            # only PyJWT's key-type guard then stands between that and HMAC
            # key confusion against the public JWKS key.
            algorithms=_ID_TOKEN_ALGORITHMS,
            audience=settings.oidc_client_id,
            issuer=discovery["issuer"],
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise OidcError(f"id_token validation failed: {exc}") from exc

    # The nonce binds this token to the authorization request we started.
    if claims.get("nonce") != nonce:
        raise OidcError("id_token nonce mismatch")
    return claims


async def fetch_userinfo(access_token: str) -> dict:
    """Authentik omits `groups` from the ID token unless explicitly mapped, so
    userinfo is consulted as a fallback."""
    try:
        discovery = await get_discovery()
        endpoint = discovery.get("userinfo_endpoint")
        if not endpoint:
            return {}
        response = await get_http_client().get(
            endpoint, headers={"authorization": f"Bearer {access_token}"}, timeout=10.0
        )
        if response.status_code != 200:
            return {}
        return response.json()
    except Exception:
        return {}


def _extract_groups(claims: dict) -> list[str]:
    raw = claims.get(settings.oidc_groups_claim)
    if raw is None:
        return []
    if isinstance(raw, str):
        return [g.strip() for g in raw.split(",") if g.strip()]
    if isinstance(raw, list):
        out = []
        for item in raw:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict) and item.get("name"):
                # Authentik can serialize groups as objects.
                out.append(item["name"])
        return out
    return []


def build_profile(claims: dict, userinfo: dict | None = None) -> OidcProfile:
    merged = {**(userinfo or {}), **claims}
    # Groups may live in either document; union them.
    groups = sorted(set(_extract_groups(claims)) | set(_extract_groups(userinfo or {})))

    subject = merged.get("sub")
    if not subject:
        raise OidcError("id_token has no subject claim")

    username = (
        merged.get(settings.oidc_username_claim)
        or merged.get("preferred_username")
        or merged.get("nickname")
        or merged.get("email")
        or subject
    )

    return OidcProfile(
        subject=str(subject),
        issuer=str(merged.get("iss") or settings.oidc_issuer or ""),
        username=str(username),
        email=merged.get("email"),
        # Only a provider-asserted verified email may be used to link an
        # existing local account; see the callback in api/auth.py.
        email_verified=bool(merged.get("email_verified")),
        full_name=merged.get("name") or merged.get("given_name"),
        groups=groups,
        raw_claims=merged,
    )
