"""OIDC authentication against any compliant provider.

Flow: authorization code + PKCE. No server-side login state is kept -- the
``state`` parameter is itself a short-lived signed JWT carrying the nonce, the
PKCE verifier, and the post-login redirect, so any replica can finish a login
another replica started.

Nothing here is written for one IdP. Everything past the issuer and the client
credentials -- endpoints, signing keys, and how the client authenticates at the
token endpoint -- comes out of the discovery document. Tested with Kanidm and
Authentik.

Where providers differ, and what this module does about it:

* **The issuer's shape.** Per-application at both, but spelled differently:
  ``https://idm.example.com/oauth2/openid/minireg`` at Kanidm,
  ``https://authentik.example.com/application/o/minireg/`` (trailing slash) at
  Authentik. Trailing slashes are stripped before comparison.
* **Group membership** arrives in the ``groups`` claim, but only when the
  provider is configured to send it -- Kanidm needs the ``groups`` scope,
  Authentik needs a scope mapping. Userinfo is read as a fallback because
  Authentik omits groups from the ID token in some configs.
* **Group names.** Kanidm names groups by SPN
  (``minireg-admins@idm.example.com``) and sends their UUIDs alongside; see
  ``group_matches``.
* **Client authentication** at the token endpoint. Basic unless the provider
  says otherwise; see ``token_auth_method``.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
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


def group_matches(configured: str | None, groups: list[str]) -> bool:
    """Whether `configured` names one of the groups the provider sent.

    Kanidm identifies groups by SPN ("minireg-admins@idm.example.com") and
    sends their UUIDs alongside, so a plain `in` test against a bare name
    matches nothing -- and nothing is logged, because as far as the code is
    concerned the user simply is not a member. The symptom is an admin who
    signs in with no admin rights, or, with OIDC_USER_GROUP set, everyone
    locked out while the group name on screen looks correct.

    A bare configured name therefore also matches an SPN's local part. A
    configured SPN is compared whole, so "ops@a.example.com" never matches
    "ops@b.example.com". Every comparison is exact: no substring, no case
    folding, nothing that widens who gets in or who becomes an admin.
    """
    wanted = (configured or "").strip()
    if not wanted:
        return False
    bare = "@" not in wanted
    for group in groups:
        if group == wanted:
            return True
        if bare and group.split("@", 1)[0] == wanted:
            return True
    return False


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
        return group_matches(settings.oidc_admin_group, self.groups)

    def is_permitted(self) -> bool:
        """When OIDC_USER_GROUP is set, membership is required to log in."""
        if not settings.oidc_user_group:
            return True
        return group_matches(settings.oidc_user_group, self.groups) or self.is_admin


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


def token_auth_method(discovery: dict) -> str:
    """How to present the client secret at the token endpoint.

    Read from the discovery document rather than assumed. Basic is the OIDC
    Core default when a provider advertises nothing, and it is the only method
    Kanidm accepts; Authentik takes either. Only a provider that advertises
    post WITHOUT basic gets the secret in the body.

    This matters more than it looks: a body-posted secret comes back from
    Kanidm as a 401, which reads exactly like a wrong secret, so the natural
    response is to rotate one that was always correct.
    """
    advertised = discovery.get("token_endpoint_auth_methods_supported")
    if not isinstance(advertised, list) or not advertised:
        return "client_secret_basic"
    if "client_secret_basic" not in advertised and "client_secret_post" in advertised:
        return "client_secret_post"
    return "client_secret_basic"


async def exchange_code(code: str, redirect_uri: str, verifier: str) -> dict:
    discovery = await get_discovery()
    client = get_http_client()
    client_id = settings.oidc_client_id or ""
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    }
    headers: dict[str, str] = {}
    method = token_auth_method(discovery)
    if settings.oidc_client_secret and method == "client_secret_basic":
        pair = f"{client_id}:{settings.oidc_client_secret}".encode()
        headers["authorization"] = f"Basic {base64.b64encode(pair).decode()}"
    else:
        # A public client has no secret to present; it still identifies itself.
        data["client_id"] = client_id
        if settings.oidc_client_secret:
            data["client_secret"] = settings.oidc_client_secret

    try:
        response = await client.post(
            discovery["token_endpoint"], data=data, headers=headers, timeout=15.0
        )
    except Exception as exc:
        raise OidcError(f"token exchange failed: {exc}") from exc

    if response.status_code in (400, 401):
        # The provider will not say which it was, and the difference decides
        # where to look, so name both.
        raise OidcError(
            f"token exchange returned HTTP {response.status_code}: "
            f"{response.text[:300]} -- check the client secret, and that this "
            f"client may authenticate with {method} at "
            f"{discovery['token_endpoint']}"
        )
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
        # Split rather than take whole: a substring test would make an
        # admin group of "admins" match a group called "not-admins".
        return [g for g in re.split(r"[,\s]+", raw) if g]
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
