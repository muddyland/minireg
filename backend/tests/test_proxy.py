"""End-to-end proxy behaviour against mocked upstreams.

Covers the path a real `npm install` / `pip install` takes when the package is
not held locally: resolve upstream -> persist -> render -> fetch artifact ->
cache -> serve. This is the path that unit tests of pure functions and
locally-published integration tests both miss.
"""

import hashlib

import httpx
import pytest_asyncio
import respx
from httpx import ASGITransport, AsyncClient

from app import db as db_module
from app.models import Ecosystem, PackageRule, RuleAction, Upstream, UpstreamKind
from app.services.policy import invalidate_policy_cache
from app.services.storage import BlobStore, set_store

TARBALL = b"pretend-this-is-a-gzipped-npm-tarball" * 10
TARBALL_SHA1 = hashlib.sha1(TARBALL).hexdigest()

WHEEL = b"pretend-this-is-a-python-wheel" * 10
WHEEL_SHA256 = hashlib.sha256(WHEEL).hexdigest()

UPSTREAM_PACKUMENT = {
    "_id": "leftpad",
    "name": "leftpad",
    "description": "Pads on the left.",
    "dist-tags": {"latest": "1.1.0"},
    "time": {"1.0.0": "2020-01-01T00:00:00.000Z", "1.1.0": "2021-01-01T00:00:00.000Z"},
    "versions": {
        "1.0.0": {
            "name": "leftpad",
            "version": "1.0.0",
            "description": "Pads on the left.",
            "main": "index.js",
            "dependencies": {},
            "dist": {
                "shasum": "0" * 40,
                "tarball": "https://upstream.test/leftpad/-/leftpad-1.0.0.tgz",
            },
        },
        "1.1.0": {
            "name": "leftpad",
            "version": "1.1.0",
            "description": "Pads on the left.",
            "main": "index.js",
            "scripts": {"test": "mocha"},
            "dependencies": {"ms": "^2.0.0"},
            "dist": {
                "shasum": TARBALL_SHA1,
                "tarball": "https://upstream.test/leftpad/-/leftpad-1.1.0.tgz",
            },
        },
    },
}

UPSTREAM_PYPI = {
    "meta": {"api-version": "1.1"},
    "name": "widget",
    "versions": ["2.0.0"],
    "files": [
        {
            "filename": "widget-2.0.0-py3-none-any.whl",
            "url": "https://files.upstream.test/widget-2.0.0-py3-none-any.whl",
            "hashes": {"sha256": WHEEL_SHA256},
            "size": len(WHEEL),
            "requires-python": ">=3.9",
            "upload-time": "2024-01-15T10:00:00Z",
        }
    ],
}


@pytest_asyncio.fixture
async def proxy_client(tmp_path):
    from app.main import app

    db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'proxy.db'}")
    await db_module.create_schema()

    store = BlobStore(str(tmp_path / "storage"))
    store.ensure_dirs()
    set_store(store)

    async with db_module.session_scope() as session:
        session.add(
            Upstream(
                name="mock-npm",
                ecosystem=Ecosystem.npm,
                kind=UpstreamKind.npm,
                url="https://upstream.test",
                tier=1,
                enabled=True,
            )
        )
        session.add(
            Upstream(
                name="mock-pypi",
                ecosystem=Ecosystem.pypi,
                kind=UpstreamKind.pypi,
                url="https://pypi.upstream.test/simple",
                tier=1,
                enabled=True,
            )
        )
    await invalidate_policy_cache()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://registry.test"
    ) as client:
        yield client

    await db_module.dispose_engine()
    set_store(None)  # type: ignore[arg-type]


def mock_npm_upstream():
    respx.get("https://upstream.test/leftpad").mock(
        return_value=httpx.Response(200, json=UPSTREAM_PACKUMENT)
    )
    return respx.get("https://upstream.test/leftpad/-/leftpad-1.1.0.tgz").mock(
        return_value=httpx.Response(200, content=TARBALL)
    )


def mock_pypi_upstream():
    respx.get("https://pypi.upstream.test/simple/widget/").mock(
        return_value=httpx.Response(
            200,
            json=UPSTREAM_PYPI,
            headers={"content-type": "application/vnd.pypi.simple.v1+json"},
        )
    )
    return respx.get("https://files.upstream.test/widget-2.0.0-py3-none-any.whl").mock(
        return_value=httpx.Response(200, content=WHEEL)
    )


class TestNpmProxy:
    @respx.mock
    async def test_packument_is_proxied_and_rewritten(self, proxy_client):
        mock_npm_upstream()
        response = await proxy_client.get("/npm/leftpad")
        assert response.status_code == 200

        doc = response.json()
        assert doc["name"] == "leftpad"
        assert sorted(doc["versions"]) == ["1.0.0", "1.1.0"]
        assert doc["dist-tags"]["latest"] == "1.1.0"
        # Every tarball URL must point back at us, never at the upstream.
        for version in doc["versions"].values():
            assert version["dist"]["tarball"].startswith("http://registry.test/npm/")
            assert "upstream.test" not in version["dist"]["tarball"]

    @respx.mock
    async def test_upstream_metadata_survives_the_round_trip(self, proxy_client):
        mock_npm_upstream()
        doc = (await proxy_client.get("/npm/leftpad")).json()
        version = doc["versions"]["1.1.0"]
        assert version["dependencies"] == {"ms": "^2.0.0"}
        assert version["scripts"] == {"test": "mocha"}
        assert version["dist"]["shasum"] == TARBALL_SHA1
        assert doc["time"]["1.1.0"].startswith("2021-01-01T")

    @respx.mock
    async def test_abbreviated_form_from_upstream(self, proxy_client):
        mock_npm_upstream()
        response = await proxy_client.get(
            "/npm/leftpad", headers={"accept": "application/vnd.npm.install-v1+json"}
        )
        doc = response.json()
        assert set(doc) == {"name", "modified", "dist-tags", "versions"}
        assert "scripts" not in doc["versions"]["1.1.0"]

    @respx.mock
    async def test_tarball_is_fetched_cached_and_served(self, proxy_client):
        tarball_route = mock_npm_upstream()

        first = await proxy_client.get("/npm/leftpad/-/leftpad-1.1.0.tgz")
        assert first.status_code == 200
        assert first.content == TARBALL
        assert tarball_route.call_count == 1

        second = await proxy_client.get("/npm/leftpad/-/leftpad-1.1.0.tgz")
        assert second.status_code == 200
        assert second.content == TARBALL
        # The artifact is immutable, so the second request must be served from
        # local storage without touching the upstream again.
        assert tarball_route.call_count == 1

    @respx.mock
    async def test_digest_mismatch_is_rejected(self, proxy_client):
        respx.get("https://upstream.test/leftpad").mock(
            return_value=httpx.Response(200, json=UPSTREAM_PACKUMENT)
        )
        # Upstream serves bytes that do not match the advertised shasum.
        respx.get("https://upstream.test/leftpad/-/leftpad-1.1.0.tgz").mock(
            return_value=httpx.Response(200, content=b"corrupted-or-tampered-content")
        )
        response = await proxy_client.get("/npm/leftpad/-/leftpad-1.1.0.tgz")
        assert response.status_code == 502
        assert "integrity" in response.json()["error"]

    @respx.mock
    async def test_unknown_package_is_404(self, proxy_client):
        respx.get("https://upstream.test/ghost").mock(return_value=httpx.Response(404))
        assert (await proxy_client.get("/npm/ghost")).status_code == 404

    @respx.mock
    async def test_blocked_package_is_never_fetched(self, proxy_client):
        route = respx.get("https://upstream.test/leftpad").mock(
            return_value=httpx.Response(200, json=UPSTREAM_PACKUMENT)
        )
        async with db_module.session_scope() as session:
            session.add(
                PackageRule(pattern="leftpad", action=RuleAction.block, reason="not allowed")
            )
        await invalidate_policy_cache()

        response = await proxy_client.get("/npm/leftpad")
        assert response.status_code == 403
        # The block must short-circuit before any upstream traffic.
        assert route.call_count == 0

    @respx.mock
    async def test_version_document_from_upstream(self, proxy_client):
        mock_npm_upstream()
        response = await proxy_client.get("/npm/leftpad/1.0.0")
        assert response.status_code == 200
        assert response.json()["version"] == "1.0.0"

    @respx.mock
    async def test_dist_tags_from_upstream(self, proxy_client):
        mock_npm_upstream()
        response = await proxy_client.get("/npm/-/package/leftpad/dist-tags")
        assert response.status_code == 200
        assert response.json()["latest"] == "1.1.0"


class TestPypiProxy:
    @respx.mock
    async def test_simple_json_is_proxied_and_rewritten(self, proxy_client):
        mock_pypi_upstream()
        response = await proxy_client.get(
            "/pypi/simple/widget/", headers={"accept": "application/vnd.pypi.simple.v1+json"}
        )
        assert response.status_code == 200

        doc = response.json()
        assert doc["name"] == "widget"
        assert doc["versions"] == ["2.0.0"]
        entry = doc["files"][0]
        assert entry["url"].startswith("http://registry.test/pypi/files/")
        assert entry["hashes"]["sha256"] == WHEEL_SHA256
        assert entry["size"] == len(WHEEL)
        assert entry["requires-python"] == ">=3.9"

    @respx.mock
    async def test_simple_html_is_proxied(self, proxy_client):
        mock_pypi_upstream()
        response = await proxy_client.get("/pypi/simple/widget/")
        assert response.status_code == 200
        assert f"#sha256={WHEEL_SHA256}" in response.text
        assert 'data-requires-python="&gt;=3.9"' in response.text
        assert "widget-2.0.0-py3-none-any.whl" in response.text

    @respx.mock
    async def test_wheel_is_fetched_cached_and_served(self, proxy_client):
        wheel_route = mock_pypi_upstream()

        first = await proxy_client.get("/pypi/files/widget/widget-2.0.0-py3-none-any.whl")
        assert first.status_code == 200
        assert first.content == WHEEL
        assert wheel_route.call_count == 1

        second = await proxy_client.get("/pypi/files/widget/widget-2.0.0-py3-none-any.whl")
        assert second.content == WHEEL
        assert wheel_route.call_count == 1

    @respx.mock
    async def test_sha256_mismatch_is_rejected(self, proxy_client):
        respx.get("https://pypi.upstream.test/simple/widget/").mock(
            return_value=httpx.Response(
                200,
                json=UPSTREAM_PYPI,
                headers={"content-type": "application/vnd.pypi.simple.v1+json"},
            )
        )
        respx.get("https://files.upstream.test/widget-2.0.0-py3-none-any.whl").mock(
            return_value=httpx.Response(200, content=b"tampered")
        )
        response = await proxy_client.get("/pypi/files/widget/widget-2.0.0-py3-none-any.whl")
        assert response.status_code == 502

    @respx.mock
    async def test_normalized_name_lookup(self, proxy_client):
        mock_pypi_upstream()
        # A non-normalized request redirects to the PEP 503 form.
        response = await proxy_client.get("/pypi/simple/Widget/", follow_redirects=False)
        assert response.status_code == 301
        assert response.headers["location"].endswith("/pypi/simple/widget/")


class TestTieredFallback:
    @respx.mock
    async def test_tier_two_is_used_when_tier_one_404s(self, proxy_client):
        async with db_module.session_scope() as session:
            session.add(
                Upstream(
                    name="fallback-npm",
                    ecosystem=Ecosystem.npm,
                    kind=UpstreamKind.npm,
                    url="https://fallback.test",
                    tier=2,
                    enabled=True,
                )
            )

        respx.get("https://upstream.test/leftpad").mock(return_value=httpx.Response(404))
        fallback = respx.get("https://fallback.test/leftpad").mock(
            return_value=httpx.Response(200, json=UPSTREAM_PACKUMENT)
        )

        response = await proxy_client.get("/npm/leftpad")
        assert response.status_code == 200
        assert fallback.call_count == 1

    @respx.mock
    async def test_tier_two_is_used_when_tier_one_errors(self, proxy_client):
        async with db_module.session_scope() as session:
            session.add(
                Upstream(
                    name="fallback-npm",
                    ecosystem=Ecosystem.npm,
                    kind=UpstreamKind.npm,
                    url="https://fallback.test",
                    tier=2,
                    enabled=True,
                )
            )

        respx.get("https://upstream.test/leftpad").mock(return_value=httpx.Response(503))
        respx.get("https://fallback.test/leftpad").mock(
            return_value=httpx.Response(200, json=UPSTREAM_PACKUMENT)
        )

        response = await proxy_client.get("/npm/leftpad")
        assert response.status_code == 200
        assert response.json()["name"] == "leftpad"

    @respx.mock
    async def test_all_tiers_failing_is_404(self, proxy_client):
        respx.get("https://upstream.test/nothing").mock(return_value=httpx.Response(404))
        assert (await proxy_client.get("/npm/nothing")).status_code == 404
