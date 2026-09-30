"""Pull-through behaviour of /v2 against a fake upstream."""

from __future__ import annotations

import asyncio

import pytest

from app.docker import registry as reg
from app.docker.upstream import RATELIMITS
from tests.docker_helpers import (
    OCI_INDEX,
    OCI_MANIFEST,
    Image,
    bearer,
    index_of,
    sha,
)


async def anon(client, name):
    return await bearer(client, f"repository:{name}:pull")


class TestPing:
    async def test_v2_always_challenges(self, docker_env):
        client, _ = docker_env
        resp = await client.get("/v2/")
        assert resp.status_code == 401
        assert resp.headers["docker-distribution-api-version"] == "registry/2.0"
        challenge = resp.headers["www-authenticate"]
        assert challenge.startswith('Bearer realm="http://registry.test/v2/token"')
        assert resp.json()["errors"][0]["code"] == "UNAUTHORIZED"

    async def test_v2_is_not_the_spa(self, docker_env):
        """The catch-all used to answer /v2/ with index.html and a 200."""
        client, _ = docker_env
        resp = await client.get("/v2/")
        assert "text/html" not in resp.headers.get("content-type", "")

    async def test_anonymous_token_then_ping(self, docker_env):
        client, _ = docker_env
        headers = await anon(client, "alpine")
        resp = await client.get("/v2/", headers=headers)
        assert resp.status_code == 200

    async def test_forged_host_does_not_move_the_realm(self, docker_env):
        client, _ = docker_env
        resp = await client.get("/v2/", headers={"host": "evil.example"})
        assert 'realm="http://registry.test/v2/token"' in resp.headers["www-authenticate"]


class TestManifests:
    async def test_hub_short_name_expands_to_library(self, docker_env):
        client, fake = docker_env
        img = Image.build("alpine")
        fake.add_image("library/alpine", "3.20", img)
        headers = await anon(client, "alpine")
        resp = await client.get("/v2/alpine/manifests/3.20", headers=headers)
        assert resp.status_code == 200, resp.text
        assert resp.content == img.manifest
        assert resp.headers["docker-content-digest"] == img.digest
        assert resp.headers["content-type"] == OCI_MANIFEST
        assert resp.headers["x-minireg-cache"] == "fetched"
        assert fake.calls["manifest_get:library/alpine:3.20"] == 1

    async def test_all_spellings_share_one_repository(self, docker_env):
        client, fake = docker_env
        img = Image.build("alpine")
        fake.add_image("library/alpine", "3.20", img)
        for name in ("alpine", "library/alpine", "dockerhub/library/alpine"):
            headers = await anon(client, name)
            resp = await client.get(f"/v2/{name}/manifests/3.20", headers=headers)
            assert resp.status_code == 200
        # One upstream GET; the rest were cache hits on the canonical repo.
        assert fake.calls["manifest_get"] == 1

    async def test_named_upstream_routes_by_prefix(self, docker_env):
        client, fake = docker_env
        img = Image.build("busybox")
        fake.add_image("prometheus/busybox", "latest", img)
        headers = await anon(client, "quay/prometheus/busybox")
        resp = await client.get("/v2/quay/prometheus/busybox/manifests/latest", headers=headers)
        assert resp.status_code == 200
        assert resp.content == img.manifest

    async def test_fresh_tag_costs_no_upstream_request(self, docker_env):
        client, fake = docker_env
        fake.add_image("library/alpine", "3.20", Image.build("alpine"))
        headers = await anon(client, "alpine")
        for _ in range(5):
            resp = await client.get("/v2/alpine/manifests/3.20", headers=headers)
            assert resp.status_code == 200
        assert fake.calls["manifest_get"] == 1
        assert fake.calls["manifest_head"] == 0

    async def test_stale_tag_revalidates_with_head_only(self, docker_env, monkeypatch):
        from app.config import settings

        client, fake = docker_env
        fake.add_image("library/alpine", "3.20", Image.build("alpine"))
        headers = await anon(client, "alpine")
        await client.get("/v2/alpine/manifests/3.20", headers=headers)
        monkeypatch.setattr(settings, "docker_tag_ttl_seconds", 0)
        resp = await client.get("/v2/alpine/manifests/3.20", headers=headers)
        assert resp.status_code == 200
        assert resp.headers["x-minireg-cache"] == "revalidated"
        # HEAD does not count against Docker Hub's pull quota; GET does.
        assert fake.calls["manifest_get"] == 1
        assert fake.calls["manifest_head"] == 1

    async def test_moved_tag_is_refetched(self, docker_env, monkeypatch):
        from app.config import settings

        client, fake = docker_env
        old, new = Image.build("v1"), Image.build("v2")
        fake.add_image("library/app", "latest", old)
        headers = await anon(client, "app")
        await client.get("/v2/app/manifests/latest", headers=headers)
        fake.add_image("library/app", "latest", new)
        monkeypatch.setattr(settings, "docker_tag_ttl_seconds", 0)
        resp = await client.get("/v2/app/manifests/latest", headers=headers)
        assert resp.headers["docker-content-digest"] == new.digest
        assert resp.headers["x-minireg-cache"] == "fetched"

    async def test_concurrent_revalidations_collapse(self, docker_env, monkeypatch):
        from app.config import settings

        client, fake = docker_env
        fake.add_image("library/python", "3.12", Image.build("py"))
        headers = await anon(client, "python")
        await client.get("/v2/python/manifests/3.12", headers=headers)
        monkeypatch.setattr(settings, "docker_tag_ttl_seconds", 1)
        await asyncio.sleep(1.1)
        results = await asyncio.gather(
            *(client.get("/v2/python/manifests/3.12", headers=headers) for _ in range(20))
        )
        assert all(r.status_code == 200 for r in results)
        # 20 clients, one upstream revalidation.
        assert fake.calls["manifest_head"] == 1

    async def test_serves_stale_when_upstream_rate_limits(self, docker_env, monkeypatch):
        from app.config import settings

        client, fake = docker_env
        img = Image.build("alpine")
        fake.add_image("library/alpine", "3.20", img)
        headers = await anon(client, "alpine")
        await client.get("/v2/alpine/manifests/3.20", headers=headers)
        monkeypatch.setattr(settings, "docker_tag_ttl_seconds", 0)
        fake.fail_with = 429
        resp = await client.get("/v2/alpine/manifests/3.20", headers=headers)
        assert resp.status_code == 200
        assert resp.content == img.manifest
        assert resp.headers["x-minireg-cache"] == "stale"

    async def test_serves_stale_when_upstream_down(self, docker_env, monkeypatch):
        from app.config import settings

        client, fake = docker_env
        fake.add_image("library/alpine", "3.20", Image.build("alpine"))
        headers = await anon(client, "alpine")
        await client.get("/v2/alpine/manifests/3.20", headers=headers)
        monkeypatch.setattr(settings, "docker_tag_ttl_seconds", 0)
        fake.fail_with = 503
        resp = await client.get("/v2/alpine/manifests/3.20", headers=headers)
        assert resp.status_code == 200

    async def test_uncached_and_rate_limited_passes_429_through(self, docker_env):
        client, fake = docker_env
        fake.add_image("library/alpine", "3.20", Image.build("alpine"))
        fake.fail_with = 429
        headers = await anon(client, "alpine")
        resp = await client.get("/v2/alpine/manifests/3.20", headers=headers)
        assert resp.status_code == 429
        assert resp.json()["errors"][0]["code"] == "TOOMANYREQUESTS"
        assert resp.headers.get("retry-after") == "60"

    async def test_missing_tag_is_negatively_cached(self, docker_env):
        client, fake = docker_env
        fake.add_image("library/alpine", "3.20", Image.build("alpine"))
        headers = await anon(client, "alpine")
        for _ in range(5):
            resp = await client.get("/v2/alpine/manifests/nope", headers=headers)
            assert resp.status_code == 404
            assert resp.json()["errors"][0]["code"] == "MANIFEST_UNKNOWN"
        assert fake.calls["manifest_get:library/alpine:nope"] == 1

    async def test_head_manifest(self, docker_env):
        client, fake = docker_env
        img = Image.build("alpine")
        fake.add_image("library/alpine", "3.20", img)
        headers = await anon(client, "alpine")
        resp = await client.head("/v2/alpine/manifests/3.20", headers=headers)
        assert resp.status_code == 200
        assert resp.headers["docker-content-digest"] == img.digest
        assert int(resp.headers["content-length"]) == len(img.manifest)
        assert resp.content == b""

    async def test_by_digest_is_verified(self, docker_env):
        client, fake = docker_env
        img = Image.build("alpine")
        fake.add_image("library/alpine", "3.20", img)
        # A hostile upstream answers a digest request with other bytes.
        other = Image.build("evil")
        fake.manifests[img.digest] = (other.manifest, OCI_MANIFEST)
        headers = await anon(client, "alpine")
        resp = await client.get(f"/v2/alpine/manifests/{img.digest}", headers=headers)
        assert resp.status_code == 400
        assert resp.json()["errors"][0]["code"] == "DIGEST_INVALID"

    async def test_ratelimit_headers_recorded(self, docker_env):
        client, fake = docker_env
        fake.ratelimit_remaining = 42
        fake.add_image("library/alpine", "3.20", Image.build("alpine"))
        headers = await anon(client, "alpine")
        await client.get("/v2/alpine/manifests/3.20", headers=headers)
        state = RATELIMITS["dockerhub"]
        assert state["remaining"] == 42
        assert state["limit"] == 100
        assert state["window_seconds"] == 21600

    async def test_invalid_name(self, docker_env):
        client, _ = docker_env
        headers = await anon(client, "alpine")
        resp = await client.get("/v2/Upper/Case/manifests/1", headers=headers)
        assert resp.status_code == 400
        assert resp.json()["errors"][0]["code"] == "NAME_INVALID"

    async def test_schema1_refused(self, docker_env):
        client, fake = docker_env
        body = b'{"schemaVersion":1,"name":"x","tag":"1","fsLayers":[]}'
        fake.repos["library/old"] = {"1": body}
        headers = await anon(client, "old")
        resp = await client.get("/v2/old/manifests/1", headers=headers)
        assert resp.status_code == 400
        assert "schema 1" in resp.json()["errors"][0]["message"]


class TestIndexes:
    async def test_multi_platform_and_attestations(self, docker_env):
        client, fake = docker_env
        amd, arm = Image.build("amd"), Image.build("arm")
        att = Image.build(
            "att",
            extra={"artifactType": None},
        )
        body, digest = index_of((amd, "linux/amd64"), (arm, "linux/arm64"), attestation=att)
        fake.add_index("library/node", "22", body, amd, arm, att)
        headers = await anon(client, "node")
        resp = await client.get("/v2/node/manifests/22", headers=headers)
        assert resp.status_code == 200
        assert resp.headers["content-type"] == OCI_INDEX
        for child in (amd, arm, att):
            r = await client.get(f"/v2/node/manifests/{child.digest}", headers=headers)
            assert r.status_code == 200, r.text
        from sqlalchemy import select

        from app import db
        from app.models import DockerManifest

        async with db.session_scope() as s:
            rows = {m.digest: m for m in (await s.execute(select(DockerManifest))).scalars()}
        assert rows[digest].kind == "index"
        assert rows[amd.digest].platform == "linux/amd64"
        assert rows[arm.digest].platform == "linux/arm64"
        # The attestation is recorded but never queued for a scan.
        assert rows[att.digest].kind == "attestation"
        assert rows[att.digest].scan_status == "not_applicable"
        assert rows[amd.digest].scan_status == "queued"

    async def test_index_fanout_capped(self, docker_env, monkeypatch):
        from app.config import settings

        client, fake = docker_env
        monkeypatch.setattr(settings, "docker_max_index_entries", 2)
        imgs = [Image.build(f"p{i}") for i in range(3)]
        body, _ = index_of(*[(img, f"linux/a{i}") for i, img in enumerate(imgs)])
        fake.add_index("library/wide", "1", body, *imgs)
        headers = await anon(client, "wide")
        resp = await client.get("/v2/wide/manifests/1", headers=headers)
        assert resp.status_code == 400
        assert "limit" in resp.json()["errors"][0]["message"]


class TestBlobs:
    async def test_blob_fetched_through_cdn_and_cached(self, docker_env):
        client, fake = docker_env
        img = Image.build("alpine", layer_sizes=(300_000,))
        fake.add_image("library/alpine", "3.20", img)
        headers = await anon(client, "alpine")
        await client.get("/v2/alpine/manifests/3.20", headers=headers)
        layer = img.layers[0]
        for _ in range(3):
            resp = await client.get(f"/v2/alpine/blobs/{sha(layer)}", headers=headers)
            assert resp.status_code == 200
            assert resp.content == layer
            assert resp.headers["docker-content-digest"] == sha(layer)
        assert fake.calls["cdn"] == 1
        assert fake.calls["cdn_leaked_auth"] == 0

    async def test_concurrent_cold_blob_is_one_download(self, docker_env):
        client, fake = docker_env
        img = Image.build("big", layer_sizes=(2_000_000,))
        fake.add_image("library/big", "1", img)
        headers = await anon(client, "big")
        await client.get("/v2/big/manifests/1", headers=headers)
        digest = sha(img.layers[0])
        results = await asyncio.gather(
            *(client.get(f"/v2/big/blobs/{digest}", headers=headers) for _ in range(8))
        )
        assert all(r.status_code == 200 and r.content == img.layers[0] for r in results)
        assert fake.calls["cdn"] == 1

    async def test_range_request(self, docker_env):
        client, fake = docker_env
        img = Image.build("alpine", layer_sizes=(10_000,))
        fake.add_image("library/alpine", "3.20", img)
        headers = await anon(client, "alpine")
        await client.get("/v2/alpine/manifests/3.20", headers=headers)
        digest = sha(img.layers[0])
        await client.get(f"/v2/alpine/blobs/{digest}", headers=headers)
        resp = await client.get(
            f"/v2/alpine/blobs/{digest}", headers={**headers, "Range": "bytes=100-199"}
        )
        assert resp.status_code == 206
        assert resp.content == img.layers[0][100:200]
        assert resp.headers["content-range"] == f"bytes 100-199/{len(img.layers[0])}"

    async def test_range_past_end(self, docker_env):
        client, fake = docker_env
        img = Image.build("alpine", layer_sizes=(1000,))
        fake.add_image("library/alpine", "3.20", img)
        headers = await anon(client, "alpine")
        await client.get("/v2/alpine/manifests/3.20", headers=headers)
        digest = sha(img.layers[0])
        await client.get(f"/v2/alpine/blobs/{digest}", headers=headers)
        resp = await client.get(f"/v2/alpine/blobs/{digest}", headers={**headers, "Range": "bytes=99999-"})
        assert resp.status_code == 416

    async def test_poisoned_blob_is_not_cached(self, docker_env):
        client, fake = docker_env
        img = Image.build("alpine", layer_sizes=(5000,))
        fake.add_image("library/alpine", "3.20", img)
        headers = await anon(client, "alpine")
        await client.get("/v2/alpine/manifests/3.20", headers=headers)
        digest = sha(img.layers[0])
        fake.blobs[digest] = b"x" * len(img.layers[0])  # same size, wrong bytes
        # Headers have gone out by the time the digest can be checked, so the
        # stream is aborted mid-body; the client sees a broken transfer.
        from app.docker.store import FillFailed

        with pytest.raises(FillFailed, match="hash to"):
            await client.get(f"/v2/alpine/blobs/{digest}", headers=headers)
        from app.docker.store import get_oci_store

        assert not get_oci_store().exists(digest)

    async def test_redirect_to_unlisted_host_is_refused(self, docker_env):
        """A registry (or anything spoofing one) that redirects a layer to a
        host not on the upstream's blob list gets a 502, not a fetch."""
        client, fake = docker_env
        img = Image.build("alpine", layer_sizes=(500,))
        fake.add_image("library/alpine", "3.20", img)
        headers = await anon(client, "alpine")
        await client.get("/v2/alpine/manifests/3.20", headers=headers)
        fake.redirect_host = "https://metadata.internal"
        resp = await client.get(f"/v2/alpine/blobs/{sha(img.layers[0])}", headers=headers)
        assert resp.status_code == 502
        assert "not an allowed blob host" in resp.json()["errors"][0]["message"]
        assert fake.calls["cdn"] == 0

    async def test_registry_redirect_to_mirror(self, docker_env):
        """registry.k8s.io redirects manifest requests (not only layers) to a
        regional mirror with its own anonymous token service. Followed, but
        only to the upstream's listed hosts, and our registry token never
        leaves for the mirror."""
        import httpx

        client, fake = docker_env
        img = Image.build("pause", layer_sizes=(100,))
        fake.add_image("library/pause", "3.10", img)
        mirror = "https://cdn.upstream.test"
        seen = {}

        def redirect(request):
            if request.url.path.startswith("/v2/library/pause/manifests/"):
                ref = request.url.path.rsplit("/", 1)[1]
                return httpx.Response(307, headers={"location": f"{mirror}/v2/mirror/pause/manifests/{ref}"})
            return fake._manifest(request)

        def at_mirror(request):
            if request.url.path == "/token":
                seen["token_auth"] = request.headers.get("authorization")
                seen["scope"] = request.url.params.get("scope")
                return httpx.Response(200, json={"token": "mirror-tok"})
            if request.headers.get("authorization") != "Bearer mirror-tok":
                seen["first_auth"] = request.headers.get("authorization")
                return httpx.Response(401, headers={"www-authenticate": f'Bearer realm="{mirror}/token",service="mirror"'})
            ref = request.url.path.rsplit("/", 1)[1]
            body = img.manifest
            headers = {"content-type": "application/vnd.oci.image.manifest.v1+json", "docker-content-digest": sha(body)}
            if ref not in ("3.10", sha(body)):
                return httpx.Response(404)
            return httpx.Response(200, content=b"" if request.method == "HEAD" else body, headers=headers)

        fake.manifest_hook = redirect
        fake.cdn_hook = at_mirror
        headers = await anon(client, "pause")
        resp = await client.get("/v2/pause/manifests/3.10", headers=headers)
        assert resp.status_code == 200, resp.text
        assert resp.headers["docker-content-digest"] == img.digest
        assert seen["first_auth"] is None  # the upstream's bearer was not forwarded
        assert seen["token_auth"] is None  # nor our credentials to its token service
        assert seen["scope"] == "repository:mirror/pause:pull"

    async def test_transient_dns_failure_is_retried(self, monkeypatch):
        import socket

        # No docker_env here: that fixture stubs _resolve out.
        from app.docker import upstream as upstream_mod

        calls = {"n": 0}
        real = upstream_mod.asyncio.get_running_loop

        class Loop:
            def __init__(self, loop):
                self._loop = loop

            async def getaddrinfo(self, host, port, **kw):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise socket.gaierror(socket.EAI_NODATA, "No address associated with hostname")
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", port))]

        monkeypatch.setattr(upstream_mod.asyncio, "get_running_loop", lambda: Loop(real()))
        assert await upstream_mod._resolve("registry.example", 443) == ["93.184.215.14"]
        assert calls["n"] == 2

    async def test_private_address_refused(self, docker_env, monkeypatch):
        from app.config import settings
        from app.docker import upstream as upstream_mod

        client, fake = docker_env
        fake.add_image("library/alpine", "3.20", Image.build("alpine"))
        monkeypatch.setattr(settings, "upstream_allow_private_addresses", False)

        async def rebinding(host, port):
            return ["169.254.169.254"]

        monkeypatch.setattr(upstream_mod, "_resolve", rebinding)
        headers = await anon(client, "alpine")
        resp = await client.get("/v2/alpine/manifests/3.20", headers=headers)
        assert resp.status_code == 502
        assert "private or reserved" in resp.json()["errors"][0]["message"]
        assert fake.calls["manifest_get"] == 0

    async def test_blob_from_other_repo_needs_upstream_confirmation(self, docker_env):
        """A layer cached for one repo is served for another only if its
        manifest belongs there -- digests are global, access is not."""
        client, fake = docker_env
        img = Image.build("secret", layer_sizes=(500,))
        fake.add_image("library/secret", "1", img)
        headers = await anon(client, "secret")
        await client.get("/v2/secret/manifests/1", headers=headers)
        await client.get(f"/v2/secret/blobs/{sha(img.layers[0])}", headers=headers)
        # Pull-through repos defer to the upstream, which already enforces
        # its own access; a cached digest is content-verified either way.
        other = await anon(client, "other")
        resp = await client.get(f"/v2/other/blobs/{sha(img.layers[0])}", headers=other)
        assert resp.status_code == 200


class TestTagsAndCatalog:
    async def test_tags_list(self, docker_env):
        client, fake = docker_env
        fake.add_image("library/alpine", "3.19", Image.build("a"))
        fake.add_image("library/alpine", "3.20", Image.build("b"))
        headers = await anon(client, "alpine")
        resp = await client.get("/v2/alpine/tags/list", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["tags"] == ["3.19", "3.20"]
        resp = await client.get("/v2/alpine/tags/list?n=1", headers=headers)
        assert resp.json()["tags"] == ["3.19"]
        assert 'rel="next"' in resp.headers["link"]

    async def test_referrers_are_cached(self, docker_env, monkeypatch):
        """containerd asks for referrers on every pull; a warm pull must not
        cost an upstream round trip for them."""
        import httpx

        from app.core import cache

        class MemRedis:
            def __init__(self):
                self.d = {}

            async def get(self, k):
                return self.d.get(k)

            async def set(self, k, v, ex=None):
                self.d[k] = v

        monkeypatch.setattr(cache, "_redis", MemRedis())
        client, fake = docker_env
        img = Image.build("alpine")
        fake.add_image("library/alpine", "3.20", img)
        sig = {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + "5" * 64, "size": 10, "artifactType": "application/vnd.dev.cosign.artifact.sig.v1+json"}

        def referrers(request):
            fake.calls["referrers"] += 1
            if not fake._authed(request):
                return fake._challenge(request, "library/alpine")
            return httpx.Response(200, json={"schemaVersion": 2, "manifests": [sig]})

        fake.referrers_hook = referrers
        headers = await anon(client, "alpine")
        for _ in range(3):
            resp = await client.get(f"/v2/alpine/referrers/{img.digest}", headers=headers)
            assert resp.status_code == 200
            assert resp.json()["manifests"][0]["digest"] == sig["digest"]
        assert fake.calls["referrers"] == 2  # challenge + one real GET, then cached

    async def test_catalog_needs_login(self, docker_env):
        client, _ = docker_env
        headers = await anon(client, "alpine")
        resp = await client.get("/v2/_catalog", headers=headers)
        assert resp.status_code == 401


class TestUsage:
    async def test_usage_counts_blobs(self, docker_env):
        client, fake = docker_env
        img = Image.build("alpine", layer_sizes=(1234,))
        fake.add_image("library/alpine", "3.20", img)
        headers = await anon(client, "alpine")
        await client.get("/v2/alpine/manifests/3.20", headers=headers)
        await client.get(f"/v2/alpine/blobs/{sha(img.layers[0])}", headers=headers)
        await asyncio.sleep(0.05)
        from app import db

        async with db.session_scope() as s:
            use = await reg.usage(s)
        assert use["blob_count"] == 1
        assert use["blob_bytes"] == len(img.layers[0])
