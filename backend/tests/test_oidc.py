"""OIDC: the parts that break when the identity provider changes.

Everything asserted here fails QUIETLY when it is wrong, which is why it is
worth pinning:

- **Group names.** Kanidm sends SPNs; a plain `in` test against a bare name
  matches nothing, and nothing is logged, because as far as the code is
  concerned the user simply is not a member. The symptom is an admin who signs
  in with no admin rights -- or, with OIDC_USER_GROUP set, everyone locked out
  while the group name on screen looks correct.
- **Client authentication.** The secret in the form body rather than a Basic
  header comes back from Kanidm as a 401 that reads exactly like a wrong
  secret, so the natural response is to rotate one that was always right.
- **PKCE and the nonce** are already sent and already checked; they are here so
  a refactor cannot quietly drop them.
"""

import base64
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx

from app.config import settings
from app.services import oidc

ISSUER = "https://idm.example.com/oauth2/openid/minireg"
TOKEN_ENDPOINT = "https://idm.example.com/oauth2/token"
DISCOVERY = {
    "issuer": ISSUER,
    "authorization_endpoint": "https://idm.example.com/ui/oauth2",
    "token_endpoint": TOKEN_ENDPOINT,
    "jwks_uri": f"{ISSUER}/public_key.jwk",
    "userinfo_endpoint": "https://idm.example.com/oauth2/openid/minireg/userinfo",
}


@pytest.fixture
def configured(monkeypatch):
    """OIDC set up as an operator would, with discovery already cached.

    Seeding the cache keeps these tests off the network without having to mock
    discovery in each one; `discovery` overrides it where the document matters.
    """
    monkeypatch.setattr(settings, "oidc_enabled", True)
    monkeypatch.setattr(settings, "oidc_issuer", ISSUER)
    monkeypatch.setattr(settings, "oidc_client_id", "minireg")
    monkeypatch.setattr(settings, "oidc_client_secret", "s3cret")
    monkeypatch.setattr(settings, "oidc_admin_group", "minireg-admins")
    monkeypatch.setattr(settings, "oidc_user_group", None)
    monkeypatch.setattr(settings, "oidc_groups_claim", "groups")
    monkeypatch.setattr(settings, "oidc_scopes", "openid profile email groups")
    monkeypatch.setattr(oidc, "_discovery_cache", {})
    return monkeypatch


@pytest.fixture
def discovery(configured):
    """Install a discovery document, defaulting to the Kanidm-shaped one."""

    def _install(**overrides):
        import time

        document = {**DISCOVERY, **overrides}
        oidc._discovery_cache[oidc.discovery_url()] = (time.time(), document)
        return document

    _install()
    return _install


# --------------------------------------------------------------------------- #
# Group names
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "configured_name,groups,expected",
    [
        # A bare name against a bare claim, and against Kanidm's SPNs (which
        # arrive beside the group UUIDs).
        ("minireg-admins", ["minireg-admins"], True),
        ("minireg-admins", ["minireg-admins@idm.example.com", "e3a1-uuid"], True),
        # A configured SPN is matched whole: same name, other realm is not it.
        ("minireg-admins@idm.example.com", ["minireg-admins@idm.example.com"], True),
        ("minireg-admins@idm.example.com", ["minireg-admins@evil.example.com"], False),
        ("minireg-admins@idm.example.com", ["minireg-admins"], False),
        # Blank or absent means nobody, whatever the provider sends.
        ("", ["minireg-admins"], False),
        (None, ["minireg-admins"], False),
        ("minireg-admins", [], False),
    ],
)
def test_group_matches(configured_name, groups, expected):
    assert oidc.group_matches(configured_name, groups) is expected


@pytest.mark.parametrize(
    "groups",
    [
        ["not-minireg-admins"],
        ["minireg-admins-readonly"],
        ["minireg-admins-x@idm.example.com"],
    ],
)
def test_group_matching_is_never_a_substring(groups):
    """'minireg-admins' must not match 'not-minireg-admins'."""
    assert oidc.group_matches("minireg-admins", groups) is False


def test_admin_from_an_spn_group(configured):
    profile = oidc.build_profile(
        {"sub": "u1", "preferred_username": "alice",
         "groups": ["minireg-admins@idm.example.com", "8f2c-uuid"]}
    )
    assert profile.is_admin is True


def test_user_group_gate_accepts_an_spn(configured):
    configured.setattr(settings, "oidc_user_group", "minireg-users")
    profile = oidc.build_profile(
        {"sub": "u1", "groups": ["minireg-users@idm.example.com"]}
    )
    assert profile.is_permitted() is True
    assert profile.is_admin is False


def test_user_group_gate_still_refuses_a_non_member(configured):
    configured.setattr(settings, "oidc_user_group", "minireg-users")
    profile = oidc.build_profile({"sub": "u1", "groups": ["somebody-else"]})
    assert profile.is_permitted() is False


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, []),
        ([], []),
        (["a", "b"], ["a", "b"]),
        # A delimited string is split, not taken whole.
        ("a,b", ["a", "b"]),
        ("a b", ["a", "b"]),
        ("a, b", ["a", "b"]),
        # Some providers serialize groups as objects.
        ([{"name": "a"}, "b"], ["a", "b"]),
        ([7, None], []),
        (42, []),
    ],
)
def test_groups_claim_normalisation(configured, raw, expected):
    assert oidc._extract_groups({"groups": raw}) == expected


def test_groups_are_unioned_across_id_token_and_userinfo(configured):
    """Authentik puts them in one document or the other depending on config."""
    profile = oidc.build_profile(
        {"sub": "u1", "groups": ["from-id-token"]},
        {"groups": ["from-userinfo"]},
    )
    assert profile.groups == ["from-id-token", "from-userinfo"]


# --------------------------------------------------------------------------- #
# Client authentication at the token endpoint
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "advertised,expected",
    [
        # Nothing advertised: Basic is the OIDC Core default.
        (None, "client_secret_basic"),
        ([], "client_secret_basic"),
        (["client_secret_basic"], "client_secret_basic"),
        (["client_secret_basic", "client_secret_post"], "client_secret_basic"),
        # Only a provider offering post and not basic gets post.
        (["client_secret_post"], "client_secret_post"),
        (["client_secret_post", "private_key_jwt"], "client_secret_post"),
    ],
)
def test_token_auth_method_follows_discovery(advertised, expected):
    document = dict(DISCOVERY)
    if advertised is not None:
        document["token_endpoint_auth_methods_supported"] = advertised
    assert oidc.token_auth_method(document) == expected


@respx.mock
async def test_secret_is_sent_as_basic_not_in_the_body(discovery):
    """Kanidm's token endpoint accepts only Basic; the body gets a 401."""
    route = respx.post(TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(200, json={"id_token": "x", "access_token": "y"})
    )
    await oidc.exchange_code("the-code", "https://registry.test/cb", "verifier")

    request = route.calls.last.request
    expected = base64.b64encode(b"minireg:s3cret").decode()
    assert request.headers["authorization"] == f"Basic {expected}"

    body = parse_qs(request.content.decode())
    # The secret must not ALSO travel in the body: a provider reading both
    # would be authenticated twice, once by a method it may not accept.
    assert "client_secret" not in body
    assert "client_id" not in body
    assert body["code"] == ["the-code"]
    assert body["code_verifier"] == ["verifier"]


@respx.mock
async def test_secret_goes_in_the_body_when_that_is_all_the_provider_takes(discovery):
    discovery(token_endpoint_auth_methods_supported=["client_secret_post"])
    route = respx.post(TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(200, json={"id_token": "x"})
    )
    await oidc.exchange_code("the-code", "https://registry.test/cb", "verifier")

    request = route.calls.last.request
    assert "authorization" not in request.headers
    body = parse_qs(request.content.decode())
    assert body["client_secret"] == ["s3cret"]
    assert body["client_id"] == ["minireg"]


@respx.mock
async def test_a_public_client_still_identifies_itself(discovery, configured):
    """No secret to present, so the client_id goes in the body regardless."""
    configured.setattr(settings, "oidc_client_secret", None)
    route = respx.post(TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(200, json={"id_token": "x"})
    )
    await oidc.exchange_code("the-code", "https://registry.test/cb", "verifier")

    request = route.calls.last.request
    assert "authorization" not in request.headers
    assert parse_qs(request.content.decode())["client_id"] == ["minireg"]


@respx.mock
async def test_a_rejected_exchange_names_the_method_it_used(discovery):
    """So a 401 can be read rather than answered by rotating the secret."""
    respx.post(TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(401, json={"error": "invalid_client"})
    )
    with pytest.raises(oidc.OidcError) as exc:
        await oidc.exchange_code("the-code", "https://registry.test/cb", "verifier")
    message = str(exc.value)
    assert "client_secret_basic" in message
    assert TOKEN_ENDPOINT in message
    assert "client secret" in message


# --------------------------------------------------------------------------- #
# The authorization request
# --------------------------------------------------------------------------- #
async def test_authorization_url_carries_pkce_and_the_configured_scopes(discovery):
    """Kanidm refuses the request without a challenge, and sends no groups
    claim unless the scope asked for one."""
    verifier, challenge = oidc.make_pkce()
    url = await oidc.build_authorization_url(
        "https://registry.test/cb", "the-state", "the-nonce", challenge
    )
    query = parse_qs(urlsplit(url).query)
    assert query["code_challenge"] == [challenge]
    assert query["code_challenge_method"] == ["S256"]
    assert query["scope"] == ["openid profile email groups"]
    assert query["nonce"] == ["the-nonce"]
    assert query["state"] == ["the-state"]
    assert verifier != challenge


def test_the_default_scopes_ask_for_groups():
    """Without it Kanidm sends no groups claim, and OIDC_ADMIN_GROUP is dead."""
    assert "groups" in type(settings)().oidc_scopes.split()
