"""Name routing, reserved names, manifest parsing, GC and eviction."""

from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace

import pytest

from app.docker import manifest as mf
from app.docker.errors import RegistryError
from app.docker.naming import parse_v2_path, route, upstream_name_problem, valid_name
from tests.docker_helpers import (
    Image,
    bearer,
    dumps,
    sha,
)


def up(name, url="https://x.test", **extra):
    return SimpleNamespace(name=name, url=url, extra=extra)


HUB = up("dockerhub", "https://registry-1.docker.io")
QUAY = up("quay", "https://quay.io")
UPSTREAMS = {"dockerhub": HUB, "quay": QUAY}


class TestRouting:
    @pytest.mark.parametrize(
        ("name", "canonical", "remote"),
        [
            ("alpine", "dockerhub/library/alpine", "library/alpine"),
            ("library/alpine", "dockerhub/library/alpine", "library/alpine"),
            ("bitnami/redis", "dockerhub/bitnami/redis", "bitnami/redis"),
            ("dockerhub/library/alpine", "dockerhub/library/alpine", "library/alpine"),
            ("dockerhub/alpine", "dockerhub/library/alpine", "library/alpine"),
            ("quay/prometheus/busybox", "quay/prometheus/busybox", "prometheus/busybox"),
            # One segment matching an upstream name is still a Hub image.
            ("quay", "dockerhub/library/quay", "library/quay"),
        ],
    )
    def test_route(self, name, canonical, remote):
        t = route(name, UPSTREAMS, default_upstream=HUB)
        assert (t.canonical, t.remote) == (canonical, remote)

    def test_local(self):
        t = route("local/team/app", UPSTREAMS, default_upstream=HUB)
        assert t.local and t.canonical == "local/team/app" and t.upstream is None

    def test_mirror_host_ignores_upstream_prefixes(self):
        t = route("quay/some/image", UPSTREAMS, default_upstream=HUB, mirror_host=True)
        assert t.canonical == "dockerhub/quay/some/image"

    def test_no_default(self):
        with pytest.raises(LookupError):
            route("alpine", {"quay": QUAY}, default_upstream=None)

    @pytest.mark.parametrize(
        "name", ["alpine", "a/b/c", "my-app", "my_app", "a.b", "x__y", "a" * 200]
    )
    def test_valid_names(self, name):
        assert valid_name(name)

    @pytest.mark.parametrize(
        "name", ["", "Alpine", "a//b", "-a", "a-", "a/", "../etc", "a b", "a" * 300, "a/./b"]
    )
    def test_invalid_names(self, name):
        assert not valid_name(name)


class TestPaths:
    @pytest.mark.parametrize(
        ("path", "endpoint", "name", "ref"),
        [
            ("", "base", None, None),
            ("library/alpine/manifests/3.20", "manifest", "library/alpine", "3.20"),
            # A repository may itself be called "manifests".
            ("org/manifests/manifests/1", "manifest", "org/manifests", "1"),
            ("a/b/blobs/sha256:" + "0" * 64, "blob", "a/b", "sha256:" + "0" * 64),
            ("a/blobs/uploads/", "upload", "a", None),
            ("a/blobs/uploads/abc-123", "upload_session", "a", "abc-123"),
            ("a/b/tags/list", "tags", "a/b", None),
            ("a/referrers/sha256:" + "1" * 64, "referrers", "a", "sha256:" + "1" * 64),
            ("_catalog", "catalog", None, None),
        ],
    )
    def test_parse(self, path, endpoint, name, ref):
        p = parse_v2_path(path)
        assert p is not None
        assert (p.endpoint, p.name, p.reference) == (endpoint, name, ref)


class TestReservedNames:
    @pytest.mark.parametrize("name", ["local", "library", "v2", "token", "_catalog"])
    def test_reserved(self, name):
        assert upstream_name_problem(name, "https://example.com")

    def test_preset_name_pointing_elsewhere(self):
        """An upstream called 'dockerhub' that is not Docker Hub is exactly
        the confusion presets exist to rule out."""
        assert "reserved for the Docker Hub preset" in upstream_name_problem(
            "dockerhub", "https://evil.example"
        )
        assert upstream_name_problem("dockerhub", "https://registry-1.docker.io") is None

    @pytest.mark.parametrize("name", ["Bad", "a_b", "a.b", "-x", "x" * 70])
    def test_shape(self, name):
        assert upstream_name_problem(name, "https://x")

    def test_ordinary(self):
        assert upstream_name_problem("harbor", "https://harbor.internal") is None


class TestManifestParsing:
    def test_image(self):
        img = Image.build("x", layer_sizes=(10, 20))
        p = mf.parse(img.manifest, None)
        assert p.kind == "image" and not p.is_index
        assert p.layer_count == 2
        assert p.total_size == sum(len(b) for b in img.blobs.values())

    def test_artifact(self):
        doc = {
            "schemaVersion": 2,
            "mediaType": mf.OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.cncf.helm.config.v1+json", "digest": "sha256:" + "0" * 64, "size": 1},
            "layers": [],
        }
        assert mf.parse(dumps(doc), None).kind == "artifact"

    def test_foreign_layers_refused(self):
        doc = {
            "schemaVersion": 2,
            "mediaType": mf.DOCKER_MANIFEST,
            "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "digest": "sha256:" + "0" * 64, "size": 1},
            "layers": [{"mediaType": "x", "digest": "sha256:" + "1" * 64, "size": 1, "urls": ["https://evil/x"]}],
        }
        with pytest.raises(RegistryError, match="foreign"):
            mf.parse(dumps(doc), None)

    @pytest.mark.parametrize(
        "body",
        [
            b"[]",
            b"not json",
            b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"md5:x","size":1}}',
            b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:' + b"0" * 64 + b'","size":-1}}',
            b'{"schemaVersion":3,"mediaType":"application/vnd.oci.image.manifest.v1+json"}',
            b'{"schemaVersion":2,"mediaType":"text/html"}',
        ],
    )
    def test_malformed(self, body):
        with pytest.raises(RegistryError):
            mf.parse(body, None)

    def test_size_cap(self, monkeypatch):
        from app.config import settings

        monkeypatch.setattr(settings, "docker_max_manifest_bytes", 50)
        with pytest.raises(RegistryError, match="byte limit"):
            mf.parse(Image.build("x").manifest, None)


class TestGcAndEviction:
    async def test_evicted_images_are_collected(self, docker_env, monkeypatch):
        from datetime import UTC, datetime, timedelta

        from sqlalchemy import select, update

        from app import db
        from app.docker import housekeeping
        from app.docker.store import get_oci_store
        from app.models import DockerBlob, DockerManifest, DockerRepoManifest

        client, fake = docker_env
        images = []
        for i in range(3):
            img = Image.build(f"img{i}", layer_sizes=(50_000,))
            fake.add_image(f"library/img{i}", "1", img)
            headers = await bearer(client, f"repository:img{i}:pull")
            await client.get(f"/v2/img{i}/manifests/1", headers=headers)
            await client.get(f"/v2/img{i}/blobs/{sha(img.layers[0])}", headers=headers)
            images.append(img)
        await asyncio.sleep(0.05)
        old = datetime.now(UTC) - timedelta(days=2)
        async with db.session_scope() as s:
            # img0 is the least recently pulled; everything is past the grace.
            for i, img in enumerate(images):
                m = (await s.execute(select(DockerManifest).where(DockerManifest.digest == img.digest))).scalar_one()
                await s.execute(
                    update(DockerRepoManifest)
                    .where(DockerRepoManifest.manifest_id == m.id)
                    .values(last_pulled_at=old + timedelta(hours=i))
                )
            await s.execute(update(DockerManifest).values(created_at=old))
            await s.execute(update(DockerBlob).values(created_at=old))
            # Budget fits about two images.
            from app.docker.registry import usage

            used = (await usage(s))["total_bytes"]
            result = await housekeeping.evict_to(s, int(used * 0.75), used)
        assert result["evicted"] >= 1
        gc = await housekeeping._gc()
        assert gc["blobs"] >= 1 and gc["manifests"] >= 1
        assert not get_oci_store().exists(sha(images[0].layers[0]))
        assert get_oci_store().exists(sha(images[2].layers[0]))

    async def test_pinned_and_local_are_never_evicted(self, docker_env):
        from sqlalchemy import update

        from app import db
        from app.docker import housekeeping
        from app.models import DockerRepository

        client, fake = docker_env
        img = Image.build("keep", layer_sizes=(10_000,))
        fake.add_image("library/keep", "1", img)
        headers = await bearer(client, "repository:keep:pull")
        await client.get("/v2/keep/manifests/1", headers=headers)
        async with db.session_scope() as s:
            await s.execute(update(DockerRepository).values(pinned=True))
            result = await housekeeping.evict_to(s, 1, 10**9)
        assert result["evicted"] == 0

    async def test_shared_layer_survives_one_image_going(self, docker_env):
        """alpine and an image built on it share a base layer; evicting one
        must not delete bytes the other still needs."""
        from datetime import UTC, datetime, timedelta

        from sqlalchemy import delete, select, update

        from app import db
        from app.docker import housekeeping
        from app.docker.store import get_oci_store
        from app.models import DockerBlob, DockerManifest, DockerRepoManifest

        client, fake = docker_env
        base = Image.build("base", layer_sizes=(20_000,))
        derived = Image.build("derived", layer_sizes=(5_000,))
        derived.layers.insert(0, base.layers[0])
        derived = Image(config=derived.config, layers=derived.layers)
        doc = {
            "schemaVersion": 2,
            "mediaType": mf.OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": sha(derived.config), "size": len(derived.config)},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": sha(b), "size": len(b)} for b in derived.layers],
        }
        derived.manifest = dumps(doc)
        derived.digest = sha(derived.manifest)
        fake.add_image("library/base", "1", base)
        fake.add_image("library/derived", "1", derived)
        for name, img in (("base", base), ("derived", derived)):
            h = await bearer(client, f"repository:{name}:pull")
            await client.get(f"/v2/{name}/manifests/1", headers=h)
            for b in img.layers:
                await client.get(f"/v2/{name}/blobs/{sha(b)}", headers=h)
        await asyncio.sleep(0.05)
        old = datetime.now(UTC) - timedelta(days=2)
        async with db.session_scope() as s:
            m = (await s.execute(select(DockerManifest).where(DockerManifest.digest == base.digest))).scalar_one()
            await s.execute(delete(DockerRepoManifest).where(DockerRepoManifest.manifest_id == m.id))
            await s.execute(update(DockerManifest).values(created_at=old))
            await s.execute(update(DockerBlob).values(created_at=old))
        await housekeeping._gc()
        assert get_oci_store().exists(sha(base.layers[0]))  # still used by derived
        assert not get_oci_store().exists(base.digest)


class TestStoreFill:
    async def test_reader_sees_bytes_before_fill_completes(self, tmp_path):
        """The first client of a cold multi-GB layer must start receiving
        bytes while it is still downloading, or it times out."""
        from app.docker.store import OciStore

        store = OciStore(tmp_path / "oci")
        store.ensure_dirs()
        payload = [b"a" * 1000, b"b" * 1000, b"c" * 1000]
        digest = sha(b"".join(payload))
        gate = asyncio.Event()

        async def slow():
            yield payload[0]
            await gate.wait()
            yield payload[1]
            yield payload[2]

        async def opener():
            return slow()

        chunks = await store.fill_and_stream(digest, opener, expected_size=3000)
        first = await asyncio.wait_for(chunks.__anext__(), timeout=2)
        assert first.startswith(b"a")
        gate.set()
        rest = b"".join([c async for c in chunks])
        assert first + rest == b"".join(payload)
        await asyncio.sleep(0.05)
        assert store.exists(digest)

    async def test_one_upstream_open_for_simultaneous_arrivals(self, tmp_path):
        """Twenty clients arrive while the first is still opening the
        upstream (token exchange, CDN redirect). One upstream request."""
        from app.docker.store import OciStore

        store = OciStore(tmp_path / "oci")
        store.ensure_dirs()
        body = b"L" * 300_000
        digest = sha(body)
        opened = {"n": 0}
        gate = asyncio.Event()

        async def gen():
            for i in range(0, len(body), 65536):
                yield body[i : i + 65536]

        async def opener():
            opened["n"] += 1
            await gate.wait()  # slow first byte
            return gen()

        async def client():
            chunks = await store.fill_and_stream(digest, opener, expected_size=len(body))
            return b"".join([c async for c in chunks])

        tasks = [asyncio.create_task(client()) for _ in range(20)]
        await asyncio.sleep(0.05)
        gate.set()
        results = await asyncio.gather(*tasks)
        assert opened["n"] == 1
        assert all(r == body for r in results)

    async def test_failed_open_does_not_fail_the_waiters(self, tmp_path):
        """The first request's upstream open gets a 429. That is its error;
        a request that was waiting on it tries for itself."""
        from app.docker.store import OciStore

        store = OciStore(tmp_path / "oci")
        store.ensure_dirs()
        body = b"ok" * 1000
        digest = sha(body)
        calls = {"n": 0}
        gate = asyncio.Event()

        async def gen():
            yield body

        async def opener():
            calls["n"] += 1
            if calls["n"] == 1:
                await gate.wait()
                raise ConnectionError("429 from upstream")
            return gen()

        first = asyncio.create_task(store.fill_and_stream(digest, opener, expected_size=len(body)))
        await asyncio.sleep(0.02)

        async def second():
            chunks = await store.fill_and_stream(digest, opener, expected_size=len(body))
            return b"".join([c async for c in chunks])

        waiter = asyncio.create_task(second())
        await asyncio.sleep(0.02)
        gate.set()
        with pytest.raises(ConnectionError):
            await first
        assert await waiter == body
        assert calls["n"] == 2

    async def test_streams_a_peer_replicas_fill(self, tmp_path, monkeypatch):
        """Another replica holds the lease: stream its partial file as it
        grows instead of waiting (minutes, for a large layer) for it to finish."""
        from app.docker import store as store_mod
        from app.docker.store import OciStore

        store = OciStore(tmp_path / "oci")
        store.ensure_dirs()
        body = b"P" * 200_000
        digest = sha(body)

        async def refuse(self, force=False):
            return False

        monkeypatch.setattr(store_mod._Lease, "acquire", refuse)
        partial = store.partial / store.hex_of(digest)

        async def peer():
            with open(partial, "wb") as fh:
                for i in range(0, len(body), 50_000):
                    fh.write(body[i : i + 50_000])
                    fh.flush()
                    await asyncio.sleep(0.05)
            final = store.path_for(digest)
            final.parent.mkdir(parents=True, exist_ok=True)
            os.replace(partial, final)

        async def never():
            raise AssertionError("must not open the upstream while a peer fills")

        writer = asyncio.create_task(peer())
        await asyncio.sleep(0.01)
        chunks = await store.fill_and_stream(digest, never, expected_size=len(body))
        first = await asyncio.wait_for(chunks.__anext__(), timeout=2)
        assert not store.exists(digest)  # got bytes before the peer finished
        rest = b"".join([c async for c in chunks])
        await writer
        assert first + rest == body

    async def test_failed_fill_leaves_nothing(self, tmp_path):
        from app.docker.store import FillFailed, OciStore

        store = OciStore(tmp_path / "oci")
        store.ensure_dirs()

        async def broken():
            yield b"x" * 100
            raise ConnectionError("upstream dropped")

        async def opener():
            return broken()

        chunks = await store.fill_and_stream(sha(b"y" * 200), opener, expected_size=200)
        with pytest.raises(FillFailed):
            async for _ in chunks:
                pass
        await asyncio.sleep(0.05)
        assert not list((tmp_path / "oci" / "partial").iterdir())
        assert not store.exists(sha(b"y" * 200))

    async def test_oversize_declared_blob_aborted(self, tmp_path):
        from app.docker.store import FillFailed, OciStore

        store = OciStore(tmp_path / "oci")
        store.ensure_dirs()

        async def big():
            for _ in range(10):
                yield b"z" * 100

        async def opener():
            return big()

        chunks = await store.fill_and_stream(sha(b"q"), opener, expected_size=300)
        with pytest.raises(FillFailed, match="more than"):
            async for _ in chunks:
                pass


class TestTokenRealm:
    """The realm in a 401 challenge must point where the client can go."""

    async def realm(self, client, host):
        resp = await client.get("/v2/", headers={"Host": host})
        assert resp.status_code == 401
        return resp.headers["www-authenticate"].split('realm="', 1)[1].split('"', 1)[0]

    async def test_public_host(self, docker_env):
        client, _ = docker_env
        assert await self.realm(client, "registry.test") == "http://registry.test/v2/token"

    async def test_forged_host_falls_back_to_public_url(self, docker_env):
        client, _ = docker_env
        assert await self.realm(client, "evil.example") == "http://registry.test/v2/token"

    async def test_internal_origin(self, docker_env, monkeypatch):
        # The scanner sidecar talks to http://minireg:8000 and must not be
        # sent out through the public proxy for its token.
        from app.config import settings

        monkeypatch.setattr(settings, "docker_internal_url", "http://minireg:8000")
        assert await self.realm(client := docker_env[0], "minireg:8000") == "http://minireg:8000/v2/token"
        assert await self.realm(client, "evil.example") == "http://registry.test/v2/token"
