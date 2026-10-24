"""Container registry: blob access follows image policy, and the spec items
(Accept negotiation, tag grammar, the OAuth2 token scope, stale warnings)
plus the store-drift sweep."""

from __future__ import annotations

import os
import time

import pytest
from sqlalchemy import update

from app import db as db_module
from app.models import DockerBlob, DockerManifest, DockerRepository
from tests import test_docker_push as _push
from tests.docker_helpers import (
    OCI_INDEX,
    OCI_MANIFEST,
    Image,
    bearer,
    dumps,
    index_of,
    make_user,
    settle_fills,
    sha,
)
from tests.test_docker_push import push_blob, push_image

no_scan_gate = _push.no_scan_gate  # reused fixture

DOCKER_ACCEPT = ", ".join(
    [
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
    ]
)
# containerd's, with its q-values and the trailing wildcard.
CONTAINERD_ACCEPT = (
    "application/vnd.docker.distribution.manifest.v2+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.oci.image.manifest.v1+json, "
    "application/vnd.oci.image.index.v1+json, */*"
)


async def anon(client, name):
    return await bearer(client, f"repository:{name}:pull")


async def block(digest: str, reason: str = "blocked for the test") -> None:
    async with db_module.session_scope() as session:
        await session.execute(
            update(DockerManifest)
            .where(DockerManifest.digest == digest)
            .values(policy_block_reason=reason)
        )


async def pull(client, name, ref, headers, *, accept=DOCKER_ACCEPT):
    return await client.get(f"/v2/{name}/manifests/{ref}", headers={**headers, "Accept": accept})


# --------------------------------------------------------------------------- #
class TestBlobsFollowImagePolicy:
    async def test_a_normal_multi_platform_pull_end_to_end(self, docker_env):
        """What `docker pull` does: index by tag, the platform's manifest by
        digest, then config and layers -- each layer HEADed and then GETted."""
        client, fake = docker_env
        amd, arm = Image.build("amd"), Image.build("arm")
        body, _ = index_of((amd, "linux/amd64"), (arm, "linux/arm64"))
        fake.add_index("library/app", "1", body, amd, arm)
        headers = await anon(client, "app")

        resp = await pull(client, "app", "1", headers)
        assert resp.status_code == 200 and resp.headers["content-type"] == OCI_INDEX
        resp = await pull(client, "app", amd.digest, headers)
        assert resp.status_code == 200 and resp.content == amd.manifest
        for digest, data in amd.blobs.items():
            head = await client.head(f"/v2/app/blobs/{digest}", headers=headers)
            assert head.status_code == 200, head.text
            got = await client.get(f"/v2/app/blobs/{digest}", headers=headers)
            assert got.status_code == 200, got.text
            assert got.content == data
        await settle_fills()
        # Warm: served from the store, still checked, still allowed.
        for digest, data in amd.blobs.items():
            got = await client.get(f"/v2/app/blobs/{digest}", headers=headers)
            assert got.status_code == 200 and got.content == data

    async def test_layers_of_a_blocked_image_are_refused(self, docker_env):
        client, fake = docker_env
        img = Image.build("bad")
        fake.add_image("library/bad", "1", img)
        headers = await anon(client, "bad")
        assert (await pull(client, "bad", "1", headers)).status_code == 200
        layer = sha(img.layers[0])
        assert (await client.get(f"/v2/bad/blobs/{layer}", headers=headers)).status_code == 200
        await settle_fills()

        await block(img.digest)
        assert (await pull(client, "bad", "1", headers)).status_code == 403
        for digest in img.blobs:
            resp = await client.get(f"/v2/bad/blobs/{digest}", headers=headers)
            assert resp.status_code == 403, digest
            assert resp.json()["errors"][0]["code"] == "DENIED"

    async def test_another_repository_name_is_not_a_way_around_it(self, docker_env):
        """The finding: holding a blocked image's manifest, fetch its layers
        through any other upstream repository name."""
        client, fake = docker_env
        img = Image.build("bad")
        fake.add_image("library/bad", "1", img)
        fake.add_image("library/innocent", "1", Image.build("innocent"))
        headers = await anon(client, "bad")
        await pull(client, "bad", "1", headers)
        for digest in img.blobs:
            await client.get(f"/v2/bad/blobs/{digest}", headers=headers)
        await settle_fills()
        await block(img.digest)

        other = await anon(client, "innocent")
        await pull(client, "innocent", "1", other)
        for name in ("innocent", "quay/library/bad", "never-pulled"):
            hdrs = await anon(client, name)
            for digest in img.blobs:
                resp = await client.get(f"/v2/{name}/blobs/{digest}", headers=hdrs)
                assert resp.status_code == 404, (name, digest, resp.text)
                assert resp.json()["errors"][0]["code"] == "BLOB_UNKNOWN"
                head = await client.head(f"/v2/{name}/blobs/{digest}", headers=hdrs)
                assert head.status_code == 404

    async def test_an_uncached_blob_is_not_fetched_for_a_stranger(self, docker_env):
        client, fake = docker_env
        img = Image.build("never-cached")
        fake.add_image("library/x", "1", img)
        fake.add_image("library/y", "1", Image.build("y"))
        await pull(client, "x", "1", await anon(client, "x"))
        before = fake.calls["blob"]
        resp = await client.get(f"/v2/y/blobs/{sha(img.layers[0])}", headers=await anon(client, "y"))
        assert resp.status_code == 404
        assert fake.calls["blob"] == before

    async def test_a_layer_shared_with_an_allowed_image_still_serves(self, docker_env):
        client, fake = docker_env
        base = b"shared-base-layer" * 50
        good = Image.build("good")
        good.layers.insert(0, base)
        bad = Image.build("bad")
        bad.layers.insert(0, base)
        for img in (good, bad):
            doc = {
                "schemaVersion": 2,
                "mediaType": OCI_MANIFEST,
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                           "digest": sha(img.config), "size": len(img.config)},
                "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                            "digest": sha(b), "size": len(b)} for b in img.layers],
            }
            img.manifest = dumps(doc)
            img.digest = sha(img.manifest)
        fake.add_image("library/mixed", "good", good)
        fake.add_image("library/mixed", "bad", bad)
        headers = await anon(client, "mixed")
        assert (await pull(client, "mixed", "good", headers)).status_code == 200
        assert (await pull(client, "mixed", "bad", headers)).status_code == 200
        await block(bad.digest)

        resp = await client.get(f"/v2/mixed/blobs/{sha(base)}", headers=headers)
        assert resp.status_code == 200 and resp.content == base
        only_bad = sha(bad.layers[1])
        assert (await client.get(f"/v2/mixed/blobs/{only_bad}", headers=headers)).status_code == 403

    async def test_quarantine_covers_blobs(self, docker_env):
        client, fake = docker_env
        img = Image.build("q")
        fake.add_image("library/q", "1", img)
        headers = await anon(client, "q")
        await pull(client, "q", "1", headers)
        async with db_module.session_scope() as session:
            await session.execute(update(DockerRepository).values(quarantined=True))
        resp = await client.get(f"/v2/q/blobs/{sha(img.layers[0])}", headers=headers)
        assert resp.status_code == 403

    async def test_the_scanner_still_reads_blocked_layers(self, docker_env):
        from tests.test_docker_scan import scanner_headers

        client, fake = docker_env
        img = Image.build("scan-me")
        fake.add_image("library/scan-me", "1", img)
        await pull(client, "scan-me", "1", await anon(client, "scan-me"))
        await block(img.digest)
        sh = await scanner_headers(client)
        resp = await client.get(f"/v2/scan-me/blobs/{sha(img.layers[0])}", headers=sh)
        assert resp.status_code == 200

    async def test_strict_mode_answers_like_the_manifest(self, docker_env, monkeypatch):
        """An unscanned image under strict mode: the manifest says 503 with
        Retry-After, and so do its layers."""
        from app.docker import policy

        client, fake = docker_env
        img = Image.build("strict")
        fake.add_image("library/strict", "1", img)
        headers = await anon(client, "strict")
        await pull(client, "strict", "1", headers)
        original = policy.ImagePolicy.from_dict

        def strict(data):
            p = original(data)
            p.strict_mode = True
            return p

        monkeypatch.setattr(policy.ImagePolicy, "from_dict", staticmethod(strict))
        policy._local = None
        await policy.invalidate_policy()
        resp = await client.get(f"/v2/strict/blobs/{sha(img.layers[0])}", headers=headers)
        assert resp.status_code == 503
        assert resp.headers.get("retry-after")


class TestMountFollowsPolicy:
    async def test_a_blocked_local_image_cannot_be_mounted_elsewhere(self, docker_env, no_scan_gate):
        client, _ = docker_env
        token = await make_user()
        headers = await bearer(
            client, "repository:local/team/a:pull,push repository:local/team/b:pull,push", token
        )
        img = Image.build("m")
        assert (await push_image(client, "local/team/a", "1", img, headers)).status_code == 201
        await block(img.digest)
        layer = sha(img.layers[0])
        resp = await client.post(
            f"/v2/local/team/b/blobs/uploads/?mount={layer}&from=local/team/a", headers=headers
        )
        # Not mounted: the client is sent to upload it instead.
        assert resp.status_code == 202
        resp = await client.get(f"/v2/local/team/b/blobs/{layer}", headers=headers)
        assert resp.status_code == 404


# --------------------------------------------------------------------------- #
class TestAcceptNegotiation:
    async def test_real_client_accept_headers_work(self, docker_env):
        client, fake = docker_env
        amd = Image.build("amd")
        body, _ = index_of((amd, "linux/amd64"))
        fake.add_index("library/multi", "1", body, amd)
        headers = await anon(client, "multi")
        for accept in (DOCKER_ACCEPT, CONTAINERD_ACCEPT, "*/*", ""):
            resp = await pull(client, "multi", "1", headers, accept=accept)
            assert resp.status_code == 200, accept
            resp = await pull(client, "multi", amd.digest, headers, accept=accept)
            assert resp.status_code == 200, accept
        # No Accept header at all.
        resp = await client.get("/v2/multi/manifests/1", headers=headers)
        assert resp.status_code == 200

    async def test_an_excluded_media_type_is_unknown(self, docker_env):
        client, fake = docker_env
        amd = Image.build("amd")
        body, _ = index_of((amd, "linux/amd64"))
        fake.add_index("library/multi", "1", body, amd)
        headers = await anon(client, "multi")
        single_only = (
            "application/vnd.oci.image.manifest.v1+json, "
            "application/vnd.docker.distribution.manifest.v2+json"
        )
        resp = await pull(client, "multi", "1", headers, accept=single_only)
        assert resp.status_code == 404
        assert resp.json()["errors"][0]["code"] == "MANIFEST_UNKNOWN"
        head = await client.head(
            "/v2/multi/manifests/1", headers={**headers, "Accept": single_only}
        )
        assert head.status_code == 404
        # The OCI manifest itself, asked for as Docker schema 2 only.
        resp = await pull(
            client, "multi", amd.digest, headers,
            accept="application/vnd.docker.distribution.manifest.v2+json",
        )
        assert resp.status_code == 404
        # q=0 excludes.
        resp = await pull(client, "multi", "1", headers, accept=f"{OCI_INDEX};q=0, {OCI_MANIFEST}")
        assert resp.status_code == 404

    def test_accept_parsing(self):
        from app.api.docker_v2 import _accepts

        assert _accepts(None, OCI_INDEX)
        assert _accepts("application/*", OCI_INDEX)
        assert _accepts(f"{OCI_INDEX.upper()}; q=0.5", OCI_INDEX)
        assert not _accepts("text/html", OCI_INDEX)
        assert not _accepts(f"{OCI_INDEX};q=0", OCI_INDEX)


class TestTagGrammar:
    @pytest.mark.parametrize("tag", ["-leading-dash", ".dot", "a" * 129, "a:b", "with%20space"])
    async def test_bad_tags_are_refused(self, docker_env, no_scan_gate, tag):
        client, _ = docker_env
        token = await make_user()
        headers = await bearer(client, "repository:local/team/t:pull,push", token)
        img = Image.build("t")
        for data in img.blobs.values():
            await push_blob(client, "local/team/t", data, headers)
        resp = await client.put(
            f"/v2/local/team/t/manifests/{tag}",
            content=img.manifest,
            headers={**headers, "Content-Type": OCI_MANIFEST},
        )
        assert resp.status_code == 400, resp.text
        assert resp.json()["errors"][0]["code"] == "TAG_INVALID"

    async def test_good_tags_still_push(self, docker_env, no_scan_gate):
        client, _ = docker_env
        token = await make_user()
        headers = await bearer(client, "repository:local/team/t:pull,push", token)
        for tag in ("1.0", "_x", "v1.2.3-rc.1_build", "a" * 128):
            img = Image.build(f"t-{len(tag)}-{tag[:3]}")
            resp = await push_image(client, "local/team/t", tag, img, headers)
            assert resp.status_code == 201, (tag, resp.text)

    def test_trailing_newline_is_not_a_tag_or_digest(self):
        from app.docker.naming import is_digest, is_tag, valid_name

        assert not is_tag("v1\n")
        assert not is_digest("sha256:" + "a" * 64 + "\n")
        assert not valid_name("library/alpine\n")


class TestTokenEndpoint:
    async def test_oauth2_post_reports_the_granted_scope(self, docker_env):
        client, _ = docker_env
        token = await make_user(username="pusher")
        resp = await client.post(
            "/v2/token",
            data={
                "grant_type": "password",
                "service": "minireg",
                "client_id": "docker",
                "username": "pusher",
                "password": token,
                "scope": "repository:local/team/app:pull,push",
            },
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["scope"] == "repository:local/team/app:pull,push"

    async def test_scope_is_what_was_granted_not_what_was_asked(self, docker_env):
        client, _ = docker_env
        resp = await client.post(
            "/v2/token",
            data={"grant_type": "password", "service": "minireg",
                  "scope": "repository:local/team/app:pull,push"},
        )
        assert resp.status_code == 200, resp.text
        # Anonymous: pull only.
        assert resp.json()["scope"] == "repository:local/team/app:pull"


class TestStaleWarning:
    async def test_stale_manifest_carries_a_warning(self, docker_env, monkeypatch):
        from app.config import settings

        client, fake = docker_env
        fake.add_image("library/alpine", "3.20", Image.build("alpine"))
        headers = await anon(client, "alpine")
        first = await client.get("/v2/alpine/manifests/3.20", headers=headers)
        assert "warning" not in first.headers
        monkeypatch.setattr(settings, "docker_tag_ttl_seconds", 0)
        fake.fail_with = 503
        resp = await client.get("/v2/alpine/manifests/3.20", headers=headers)
        assert resp.status_code == 200
        assert resp.headers["x-minireg-cache"] == "stale"
        assert resp.headers["warning"] == '110 - "Response is Stale"'


# --------------------------------------------------------------------------- #
class TestOrphanFileSweep:
    """A fill whose DockerBlob write failed left a file no row describes:
    invisible to GC and to usage()."""

    async def _age(self, digest: str, seconds: float) -> None:
        from app.docker.store import get_oci_store

        path = get_oci_store().path_for(digest)
        old = time.time() - seconds
        os.utime(path, (old, old))

    async def test_drift_is_recorded_or_removed(self, docker_env):
        from app.docker import housekeeping
        from app.docker import registry as reg
        from app.docker.store import get_oci_store

        client, fake = docker_env
        img = Image.build("drift")
        fake.add_image("library/drift", "1", img)
        headers = await anon(client, "drift")
        await pull(client, "drift", "1", headers)
        for digest in img.blobs:
            await client.get(f"/v2/drift/blobs/{digest}", headers=headers)
        await settle_fills()
        store = get_oci_store()

        # The failure mode: rows lost after the files landed.
        layer = sha(img.layers[0])
        async with db_module.session_scope() as session:
            await session.execute(
                DockerBlob.__table__.delete().where(DockerBlob.digest == layer)
            )
        stray = await store.put_bytes(b"nobody names this file")
        young = await store.put_bytes(b"written a moment ago")
        for digest in (layer, stray, img.digest):
            await self._age(digest, housekeeping.ORPHAN_GRACE_SECONDS + 60)

        async with db_module.session_scope() as session:
            before = await reg.usage(session)
        report = await housekeeping._orphan_files()
        assert report["adopted"] == 1
        assert report["deleted"] == 1

        assert store.exists(layer)
        assert not store.exists(stray)
        assert store.exists(young)  # inside the grace period
        assert store.exists(img.digest)  # a manifest: known by its own table
        async with db_module.session_scope() as session:
            row = await session.get(DockerBlob, layer)
            assert row is not None and row.size == len(img.layers[0])
            assert row.is_local is False
            after = await reg.usage(session)
        assert after["blob_bytes"] == before["blob_bytes"] + len(img.layers[0])

        # Idempotent.
        assert await housekeeping._orphan_files() == {"adopted": 0, "deleted": 0, "freed_bytes": 0}

    async def test_runs_as_a_housekeeping_step(self, docker_env):
        from app.docker import housekeeping

        report = await housekeeping.run_housekeeping()
        assert report["orphans"] == {"adopted": 0, "deleted": 0, "freed_bytes": 0}
