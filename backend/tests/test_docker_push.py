"""Pushing to the local namespace, and who may do it."""

from __future__ import annotations

import pytest

from tests.docker_helpers import (
    Image,
    bearer,
    dumps,
    make_user,
    sha,
)


async def push_blob(client, name, data, headers, *, chunked=False):
    resp = await client.post(f"/v2/{name}/blobs/uploads/", headers=headers)
    assert resp.status_code == 202, resp.text
    location = resp.headers["location"]
    if chunked:
        half = len(data) // 2
        r = await client.patch(
            location,
            content=data[:half],
            headers={**headers, "Content-Range": f"0-{half - 1}", "Content-Type": "application/octet-stream"},
        )
        assert r.status_code == 202, r.text
        r = await client.patch(
            location,
            content=data[half:],
            headers={**headers, "Content-Range": f"{half}-{len(data) - 1}", "Content-Type": "application/octet-stream"},
        )
        assert r.status_code == 202, r.text
        r = await client.put(f"{location}?digest={sha(data)}", headers=headers)
    else:
        r = await client.put(f"{location}?digest={sha(data)}", content=data, headers=headers)
    assert r.status_code == 201, r.text
    assert r.headers["docker-content-digest"] == sha(data)


async def push_image(client, name, tag, img, headers, *, chunked=False):
    for data in img.blobs.values():
        await push_blob(client, name, data, headers, chunked=chunked)
    resp = await client.put(
        f"/v2/{name}/manifests/{tag}",
        content=img.manifest,
        headers={**headers, "Content-Type": "application/vnd.oci.image.manifest.v1+json"},
    )
    return resp


@pytest.fixture
def no_scan_gate(monkeypatch):
    """Push tests do not run a scanner; don't hold pulls waiting for one."""
    from app.docker import policy

    original = policy.ImagePolicy.from_dict

    def patched(data):
        p = original(data)
        p.push_require_scan = False
        return p

    monkeypatch.setattr(policy.ImagePolicy, "from_dict", staticmethod(patched))
    policy._local = None


class TestLogin:
    async def test_token_endpoint_with_api_token(self, docker_env):
        client, _ = docker_env
        token = await make_user()
        resp = await client.get(
            "/v2/token",
            params={"service": "minireg", "scope": "repository:local/team/app:pull,push"},
            auth=("dev", token),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["token"] and body["expires_in"] > 0

    async def test_password_is_refused(self, docker_env):
        client, _ = docker_env
        from app import db
        from app.core.security import hash_password
        from app.models import User

        async with db.session_scope() as s:
            s.add(User(username="pw", password_hash=hash_password("a-long-password-1"), can_publish=True))
        resp = await client.get("/v2/token", params={"scope": "repository:local/x:push"}, auth=("pw", "a-long-password-1"))
        assert resp.status_code == 401
        assert "API token" in resp.json()["errors"][0]["message"]

    async def test_oauth_password_grant(self, docker_env):
        """containerd and newer Docker POST the password to the realm."""
        client, _ = docker_env
        token = await make_user()
        resp = await client.post(
            "/v2/token",
            data={
                "grant_type": "password",
                "username": "dev",
                "password": token,
                "service": "minireg",
                "scope": "repository:local/team/app:pull,push repository:alpine:pull",
            },
        )
        assert resp.status_code == 200
        # Check what the token grants, not only that one came back: a token
        # issued anonymously also "works" until the first push.
        import jwt

        claims = jwt.decode(resp.json()["access_token"], options={"verify_signature": False})
        access = {a["name"]: a["actions"] for a in claims["access"]}
        assert access == {"local/team/app": ["pull", "push"], "alpine": ["pull"]}
        assert claims["tid"]
        # And it pushes.
        headers = {"Authorization": f"Bearer {resp.json()['access_token']}"}
        assert (await push_image(client, "local/team/app", "1", Image.build("oauth"), headers)).status_code == 201

    async def test_oauth_bad_password_is_refused(self, docker_env):
        client, _ = docker_env
        resp = await client.post(
            "/v2/token",
            data={"grant_type": "password", "username": "dev", "password": "mrg_nope", "scope": "repository:local/x:push"},
        )
        assert resp.status_code == 401

    async def test_revoked_token_stops_working_immediately(self, docker_env, no_scan_gate):
        client, _ = docker_env
        token = await make_user()
        headers = await bearer(client, "repository:local/team/app:pull,push", token)
        img = Image.build("app")
        resp = await push_image(client, "local/team/app", "1", img, headers)
        assert resp.status_code == 201
        from sqlalchemy import update

        from app import db
        from app.models import ApiToken

        async with db.session_scope() as s:
            await s.execute(update(ApiToken).values(revoked=True))
        resp = await client.get("/v2/local/team/app/manifests/1", headers=headers)
        assert resp.status_code == 401


class TestPush:
    async def test_push_then_pull(self, docker_env, no_scan_gate):
        client, _ = docker_env
        token = await make_user()
        headers = await bearer(client, "repository:local/team/app:pull,push", token)
        img = Image.build("app")
        resp = await push_image(client, "local/team/app", "1.0", img, headers)
        assert resp.status_code == 201, resp.text
        assert resp.headers["docker-content-digest"] == img.digest
        pull = await bearer(client, "repository:local/team/app:pull")
        resp = await client.get("/v2/local/team/app/manifests/1.0", headers=pull)
        assert resp.status_code == 200
        assert resp.content == img.manifest
        layer = img.layers[0]
        resp = await client.get(f"/v2/local/team/app/blobs/{sha(layer)}", headers=pull)
        assert resp.content == layer

    async def test_chunked_upload(self, docker_env, no_scan_gate):
        client, _ = docker_env
        token = await make_user()
        headers = await bearer(client, "repository:local/team/app:pull,push", token)
        img = Image.build("chunky", layer_sizes=(100_000,))
        resp = await push_image(client, "local/team/app", "c", img, headers, chunked=True)
        assert resp.status_code == 201

    async def test_monolithic_post(self, docker_env):
        client, _ = docker_env
        token = await make_user()
        headers = await bearer(client, "repository:local/team/app:push", token)
        data = b"monolith" * 100
        resp = await client.post(f"/v2/local/team/app/blobs/uploads/?digest={sha(data)}", content=data, headers=headers)
        assert resp.status_code == 201
        assert resp.headers["docker-content-digest"] == sha(data)

    async def test_bad_digest_rejected(self, docker_env):
        client, _ = docker_env
        token = await make_user()
        headers = await bearer(client, "repository:local/team/app:push", token)
        resp = await client.post("/v2/local/team/app/blobs/uploads/", headers=headers)
        loc = resp.headers["location"]
        resp = await client.put(f"{loc}?digest={sha(b'other')}", content=b"actual", headers=headers)
        assert resp.status_code == 400
        assert resp.json()["errors"][0]["code"] == "DIGEST_INVALID"

    async def test_out_of_order_chunk(self, docker_env):
        client, _ = docker_env
        token = await make_user()
        headers = await bearer(client, "repository:local/team/app:push", token)
        resp = await client.post("/v2/local/team/app/blobs/uploads/", headers=headers)
        loc = resp.headers["location"]
        resp = await client.patch(loc, content=b"abc", headers={**headers, "Content-Range": "10-12"})
        assert resp.status_code == 416
        # The error body must be framed by its real length. A Content-Length
        # of 0 on a JSON body desynchronises a kept-alive connection.
        assert int(resp.headers["content-length"]) == len(resp.content) > 0
        assert resp.json()["errors"][0]["code"] == "RANGE_INVALID"
        assert resp.headers["range"] == "0-0"

    async def test_upload_status_needs_push_rights(self, docker_env):
        client, _ = docker_env
        token = await make_user()
        headers = await bearer(client, "repository:local/team/app:push", token)
        loc = (await client.post("/v2/local/team/app/blobs/uploads/", headers=headers)).headers["location"]
        resp = await client.get(loc)
        assert resp.status_code == 401
        assert "www-authenticate" in resp.headers
        assert (await client.get(loc, headers=headers)).status_code == 204

    async def test_manifest_must_reference_uploaded_blobs(self, docker_env):
        """Otherwise a manifest could point at a layer uploaded into someone
        else's repository and read it back through this one."""
        client, _ = docker_env
        alice = await make_user(username="alice")
        bob = await make_user(username="bob")
        a_headers = await bearer(client, "repository:local/alice/secret:pull,push", alice)
        secret = Image.build("secret")
        assert (await push_image(client, "local/alice/secret", "1", secret, a_headers)).status_code == 201
        b_headers = await bearer(client, "repository:local/bob/steal:pull,push", bob)
        resp = await client.put(
            "/v2/local/bob/steal/manifests/1",
            content=secret.manifest,
            headers={**b_headers, "Content-Type": "application/vnd.oci.image.manifest.v1+json"},
        )
        assert resp.status_code == 400
        assert resp.json()["errors"][0]["code"] == "MANIFEST_BLOB_UNKNOWN"
        resp = await client.get(f"/v2/local/bob/steal/blobs/{sha(secret.layers[0])}", headers=b_headers)
        assert resp.status_code == 404

    async def test_first_pusher_owns_the_repository(self, docker_env):
        client, _ = docker_env
        alice = await make_user(username="alice")
        bob = await make_user(username="bob")
        a_headers = await bearer(client, "repository:local/shared/app:push", alice)
        assert (await push_image(client, "local/shared/app", "1", Image.build("a"), a_headers)).status_code == 201
        # Bob's token request is answered without push...
        resp = await client.get("/v2/token", params={"scope": "repository:local/shared/app:pull,push"}, auth=("bob", bob))
        b_headers = {"Authorization": f"Bearer {resp.json()['token']}"}
        resp = await client.post("/v2/local/shared/app/blobs/uploads/", headers=b_headers)
        assert resp.status_code == 401
        # ...and presenting the API token directly is refused on ownership.
        import base64

        basic = {"Authorization": "Basic " + base64.b64encode(f"bob:{bob}".encode()).decode()}
        resp = await client.post("/v2/local/shared/app/blobs/uploads/", headers=basic)
        assert resp.status_code == 403
        assert "belongs to another user" in resp.json()["errors"][0]["message"]

    async def test_push_outside_local_is_refused(self, docker_env):
        client, _ = docker_env
        token = await make_user()
        import base64

        basic = {"Authorization": "Basic " + base64.b64encode(f"dev:{token}".encode()).decode()}
        for name in ("alpine", "library/alpine", "dockerhub/library/alpine", "quay/org/app"):
            resp = await client.post(f"/v2/{name}/blobs/uploads/", headers=basic)
            assert resp.status_code == 403, name
            assert resp.json()["errors"][0]["code"] == "DENIED"

    async def test_anonymous_push_is_challenged(self, docker_env):
        client, _ = docker_env
        headers = await bearer(client, "repository:local/team/app:pull,push")
        resp = await client.post("/v2/local/team/app/blobs/uploads/", headers=headers)
        assert resp.status_code == 401
        assert "www-authenticate" in resp.headers

    async def test_publish_scope_is_not_enough(self, docker_env):
        """npm/PyPI publish tokens do not push images."""
        client, _ = docker_env
        token = await make_user(scopes=("read", "publish"))
        import base64

        basic = {"Authorization": "Basic " + base64.b64encode(f"dev:{token}".encode()).decode()}
        resp = await client.post("/v2/local/team/app/blobs/uploads/", headers=basic)
        assert resp.status_code == 403
        assert "docker:push" in resp.json()["errors"][0]["message"]

    async def test_repo_prefix_restriction(self, docker_env):
        client, _ = docker_env
        token = await make_user(prefixes=("local/ci/",))
        import base64

        basic = {"Authorization": "Basic " + base64.b64encode(f"dev:{token}".encode()).decode()}
        ok = await client.post("/v2/local/ci/app/blobs/uploads/", headers=basic)
        assert ok.status_code == 202
        denied = await client.post("/v2/local/prod/app/blobs/uploads/", headers=basic)
        assert denied.status_code == 403
        assert "local/ci/" in denied.json()["errors"][0]["message"]

    async def test_tag_move_and_delete(self, docker_env, no_scan_gate):
        client, _ = docker_env
        token = await make_user()
        headers = await bearer(client, "repository:local/team/app:pull,push,delete", token)
        one, two = Image.build("one"), Image.build("two")
        await push_image(client, "local/team/app", "latest", one, headers)
        await push_image(client, "local/team/app", "latest", two, headers)
        resp = await client.get("/v2/local/team/app/manifests/latest", headers=headers)
        assert resp.headers["docker-content-digest"] == two.digest
        # The old digest is still addressable (immutable content).
        resp = await client.get(f"/v2/local/team/app/manifests/{one.digest}", headers=headers)
        assert resp.status_code == 200
        resp = await client.delete(f"/v2/local/team/app/manifests/{one.digest}", headers=headers)
        assert resp.status_code == 202
        resp = await client.get(f"/v2/local/team/app/manifests/{one.digest}", headers=headers)
        assert resp.status_code == 404

    async def test_cross_repo_mount(self, docker_env):
        client, _ = docker_env
        token = await make_user()
        headers = await bearer(
            client, "repository:local/team/a:pull,push repository:local/team/b:pull,push", token
        )
        img = Image.build("m")
        await push_image(client, "local/team/a", "1", img, headers)
        layer = sha(img.layers[0])
        resp = await client.post(
            f"/v2/local/team/b/blobs/uploads/?mount={layer}&from=local/team/a", headers=headers
        )
        assert resp.status_code == 201
        # Mount from a repository the caller cannot see falls back to upload.
        resp = await client.post(
            f"/v2/local/team/b/blobs/uploads/?mount={layer}&from=local/other/x", headers=headers
        )
        assert resp.status_code == 202

    async def test_referrers_for_pushed_signature(self, docker_env, no_scan_gate):
        client, _ = docker_env
        token = await make_user()
        headers = await bearer(client, "repository:local/team/app:pull,push", token)
        img = Image.build("app")
        await push_image(client, "local/team/app", "1", img, headers)
        empty = b"{}"
        await push_blob(client, "local/team/app", empty, headers)
        sig_layer = b"signature-bytes"
        await push_blob(client, "local/team/app", sig_layer, headers)
        sig = dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "artifactType": "application/vnd.dev.cosign.artifact.sig.v1+json",
                "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": sha(empty), "size": 2},
                "layers": [{"mediaType": "application/vnd.dev.cosign.simplesigning.v1+json", "digest": sha(sig_layer), "size": len(sig_layer)}],
                "subject": {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": img.digest, "size": len(img.manifest)},
            }
        )
        resp = await client.put(
            f"/v2/local/team/app/manifests/{sha(sig)}",
            content=sig,
            headers={**headers, "Content-Type": "application/vnd.oci.image.manifest.v1+json"},
        )
        assert resp.status_code == 201, resp.text
        assert resp.headers["oci-subject"] == img.digest
        resp = await client.get(f"/v2/local/team/app/referrers/{img.digest}", headers=headers)
        assert resp.status_code == 200
        entries = resp.json()["manifests"]
        assert [e["digest"] for e in entries] == [sha(sig)]
        assert entries[0]["artifactType"] == "application/vnd.dev.cosign.artifact.sig.v1+json"

    async def test_audit_records_push(self, docker_env, no_scan_gate):
        client, _ = docker_env
        token = await make_user()
        headers = await bearer(client, "repository:local/team/app:pull,push", token)
        img = Image.build("audited")
        await push_image(client, "local/team/app", "1", img, headers)
        from sqlalchemy import select

        from app import db
        from app.models import AuditLog

        async with db.session_scope() as s:
            rows = (await s.execute(select(AuditLog).where(AuditLog.action == "registry.docker.push"))).scalars().all()
        assert len(rows) == 1
        assert rows[0].actor_username == "dev"
        assert rows[0].detail["digest"] == img.digest
