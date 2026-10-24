"""Package-upstream metadata fetches: redirects, credentials and DNS pinning.

`request()` -- every packument, simple page and index file -- followed
redirects inside httpx with no check at all, so an upstream could 302 to the
cloud metadata service and have the body cached and served back. It also
replayed GitLab's PRIVATE-TOKEN across origins.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from app.config import settings
from app.core.security import encrypt_credential
from app.upstreams import base, netguard
from app.upstreams.base import UpstreamError, render_url_template
from app.upstreams.netguard import BlockedUrl, PinnedBackend, check_fetchable, is_public_address
from app.upstreams.npm_provider import NpmProvider
from tests.test_upstreams import PACKUMENT, make_upstream

REG = "https://registry.example.com"


@pytest.fixture
def private_blocked(monkeypatch):
    """Production defaults: private addresses refused. Names resolve to a
    public documentation address unless a test says otherwise."""
    monkeypatch.setattr(settings, "upstream_allow_private_addresses", False)
    answers: dict[str, list[str]] = {}

    async def resolve(host, port):
        return answers.get(host, ["93.184.215.14"])

    monkeypatch.setattr(netguard, "resolve_host", resolve)
    return answers


class TestRedirectsAreGuarded:
    @respx.mock
    async def test_redirect_to_metadata_service_is_refused(self, private_blocked):
        metadata = respx.get("https://169.254.169.254/latest/meta-data/").mock(
            return_value=httpx.Response(200, json={"secret": "iam"})
        )
        respx.get(f"{REG}/lodash").mock(
            return_value=httpx.Response(
                302, headers={"location": "https://169.254.169.254/latest/meta-data/"}
            )
        )
        with pytest.raises(UpstreamError):
            await NpmProvider(make_upstream()).fetch_package("lodash")
        assert not metadata.called

    @respx.mock
    async def test_redirect_to_a_name_that_rebinds_private_is_refused(
        self, private_blocked, monkeypatch
    ):
        monkeypatch.setattr(settings, "upstream_artifact_hosts", "evil.example.net")
        private_blocked["evil.example.net"] = ["10.0.0.5"]
        target = respx.get("https://evil.example.net/x").mock(return_value=httpx.Response(200))
        respx.get(f"{REG}/lodash").mock(
            return_value=httpx.Response(302, headers={"location": "https://evil.example.net/x"})
        )
        with pytest.raises(UpstreamError):
            await NpmProvider(make_upstream()).fetch_package("lodash")
        assert not target.called

    @respx.mock
    async def test_redirect_to_an_unlisted_host_is_refused(self):
        target = respx.get("https://elsewhere.example/x").mock(return_value=httpx.Response(200))
        respx.get(f"{REG}/lodash").mock(
            return_value=httpx.Response(302, headers={"location": "https://elsewhere.example/x"})
        )
        with pytest.raises(UpstreamError, match="not an allowed"):
            await NpmProvider(make_upstream()).fetch_package("lodash")
        assert not target.called

    @respx.mock
    async def test_a_same_host_redirect_is_followed(self, private_blocked):
        respx.get(f"{REG}/Lodash").mock(
            return_value=httpx.Response(301, headers={"location": "/lodash"})
        )
        respx.get(f"{REG}/lodash").mock(return_value=httpx.Response(200, json=PACKUMENT))
        package = await NpmProvider(make_upstream()).fetch_package("Lodash")
        assert package.name == "lodash"

    @respx.mock
    async def test_the_configured_host_on_a_private_address_is_refused_by_default(
        self, private_blocked
    ):
        """Unchanged rule, now applied to metadata too: an internal upstream
        needs UPSTREAM_ALLOW_PRIVATE_ADDRESSES, as artifacts always did."""
        private_blocked["registry.example.com"] = ["192.168.1.20"]
        route = respx.get(f"{REG}/lodash").mock(return_value=httpx.Response(200, json=PACKUMENT))
        with pytest.raises(UpstreamError, match="private"):
            await NpmProvider(make_upstream()).fetch_package("lodash")
        assert not route.called

    @respx.mock
    async def test_internal_upstream_works_when_allowed(self, monkeypatch):
        monkeypatch.setattr(settings, "upstream_allow_private_addresses", True)
        respx.get("https://gitlab.internal.test/lodash").mock(
            return_value=httpx.Response(200, json=PACKUMENT)
        )
        package = await NpmProvider(
            make_upstream(url="https://gitlab.internal.test")
        ).fetch_package("lodash")
        assert package.name == "lodash"


class TestCredentialsStayHome:
    @respx.mock
    async def test_private_token_is_not_replayed_cross_origin(self, private_blocked, monkeypatch):
        monkeypatch.setattr(settings, "upstream_artifact_hosts", "cdn.example.com")
        seen = {}

        def origin(request):
            seen["origin"] = request.headers.get("private-token")
            return httpx.Response(302, headers={"location": "https://cdn.example.com/lodash"})

        def cdn(request):
            seen["cdn"] = request.headers.get("private-token")
            return httpx.Response(200, json=PACKUMENT)

        respx.get(f"{REG}/lodash").mock(side_effect=origin)
        respx.get("https://cdn.example.com/lodash").mock(side_effect=cdn)
        upstream = make_upstream(
            auth_type="token_header",
            auth_header_name="PRIVATE-TOKEN",
            credential_enc=encrypt_credential("glpat-secret"),
        )
        await NpmProvider(upstream).fetch_package("lodash")
        assert seen == {"origin": "glpat-secret", "cdn": None}

    @respx.mock
    async def test_publish_is_not_redirected(self, private_blocked):
        respx.put(f"{REG}/x").mock(
            return_value=httpx.Response(307, headers={"location": f"{REG}/elsewhere"})
        )
        other = respx.put(f"{REG}/elsewhere").mock(return_value=httpx.Response(201))
        resp = await NpmProvider(make_upstream()).request("PUT", f"{REG}/x", json={}, retries=0)
        assert resp.status_code == 307
        assert not other.called


class TestStreamGuardsTheFirstHop:
    @respx.mock
    async def test_artifact_url_on_a_private_address_is_refused(self, private_blocked):
        private_blocked["registry.example.com"] = ["127.0.0.1"]
        route = respx.get(f"{REG}/x.tgz").mock(return_value=httpx.Response(200))
        with pytest.raises(BlockedUrl):
            await NpmProvider(make_upstream()).stream(f"{REG}/x.tgz")
        assert not route.called


class TestPinning:
    class Inner:
        def __init__(self):
            self.calls = []

        async def connect_tcp(self, host, port, **kw):
            self.calls.append(host)
            return "stream"

    async def test_guard_pins_and_the_backend_connects_only_there(self, private_blocked):
        backend = PinnedBackend()
        backend._inner = inner = self.Inner()
        await netguard.guard_url(f"{REG}/x", upstream_url=REG, backend=backend)
        # A rebinding resolver now answers differently: irrelevant, nothing
        # is resolved at connect time.
        private_blocked["registry.example.com"] = ["10.0.0.5"]
        assert await backend.connect_tcp("registry.example.com", 443) == "stream"
        assert inner.calls == ["93.184.215.14"]

    async def test_unpinned_hosts_are_refused_unless_private_is_allowed(self, monkeypatch):
        backend = base._upstream_backend
        saved = dict(backend.pins)
        backend.pins.clear()
        inner, backend._inner = backend._inner, self.Inner()
        try:
            monkeypatch.setattr(settings, "upstream_allow_private_addresses", False)
            with pytest.raises(httpx.ConnectError):
                await backend.connect_tcp("never-checked.example", 443)
            monkeypatch.setattr(settings, "upstream_allow_private_addresses", True)
            assert await backend.connect_tcp("never-checked.example", 443) == "stream"
        finally:
            backend._inner = inner
            backend.pins.update(saved)

    def test_provider_client_is_the_pinned_one(self):
        provider = NpmProvider(make_upstream())
        assert provider.client is base.get_upstream_client(True)
        assert provider.client.follow_redirects is False


class TestOneDefinitionOfPrivate:
    @pytest.mark.parametrize(
        "address",
        ["100.64.0.1", "100.127.255.254", "10.0.0.1", "169.254.169.254", "::ffff:100.64.0.1", "::1"],
    )
    def test_refused_everywhere(self, address):
        from app.docker import upstream as docker_upstream

        assert not is_public_address(address)
        assert not docker_upstream._is_public(address)

    def test_cgnat_artifact_url_is_refused(self, monkeypatch):
        monkeypatch.setattr(settings, "upstream_allow_private_addresses", False)
        monkeypatch.setattr(settings, "upstream_artifact_hosts", "100.64.1.2")
        with pytest.raises(BlockedUrl, match="private"):
            check_fetchable("https://100.64.1.2/x.tgz", upstream_url=REG)

    def test_docker_and_packages_share_the_backend_class(self):
        from app.docker import upstream as docker_upstream

        assert isinstance(docker_upstream._backend, PinnedBackend)
        assert isinstance(base._upstream_backend, PinnedBackend)


class TestWebUrlTemplate:
    def test_documented_placeholders(self):
        values = {"name": "Foo_Bar", "normalized_name": "foo-bar"}
        assert (
            render_url_template("https://x/{name}/{normalized_name}/{{literal}}", values)
            == "https://x/Foo_Bar/foo-bar/{literal}"
        )

    @pytest.mark.parametrize(
        "template",
        [
            "https://x/{name.__class__}",
            "https://x/{name.__init__.__globals__}",
            "https://x/{name[0]}",
            "https://x/{0}",
            "https://x/{unknown}",
            "https://x/{name!r}",
            "https://x/{",
        ],
    )
    def test_anything_else_is_invalid(self, template):
        assert render_url_template(template, {"name": "a", "normalized_name": "a"}) is None

    def test_provider_uses_it(self):
        upstream = make_upstream(web_url_template="https://x/{name.__class__.__name__}")
        assert NpmProvider(upstream).package_web_url("lodash") is None
        upstream = make_upstream(web_url_template="https://x/p/{name}")
        assert NpmProvider(upstream).package_web_url("lodash") == "https://x/p/lodash"
