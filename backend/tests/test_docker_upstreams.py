"""Managing container upstreams through the admin API."""

from __future__ import annotations

from tests.docker_helpers import Image, bearer, make_user


async def admin(client):
    token = await make_user(username="root", scopes=("admin",), is_admin=True)
    return {"Authorization": f"Bearer {token}"}


def oci(name, **extra):
    return {
        "name": name,
        "ecosystem": "docker",
        "kind": "oci",
        "url": "https://harbor.example.com",
        "extra": {"blob_hosts": ["cdn.harbor.example.com"], **extra},
    }


async def upstream_id(client, headers, name):
    rows = (await client.get("/api/admin/upstreams", headers=headers)).json()["upstreams"]
    return next(u["id"] for u in rows if u["name"] == name)


class TestCreate:
    async def test_custom_registry(self, docker_env):
        client, _ = docker_env
        ah = await admin(client)
        resp = await client.post("/api/admin/upstreams", json=oci("harbor"), headers=ah)
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["extra"]["blob_hosts"] == ["cdn.harbor.example.com"]
        assert body["extra"].get("library_prefix") is None

    async def test_reserved_and_preset_names(self, docker_env):
        client, _ = docker_env
        ah = await admin(client)
        for name in ("local", "library", "v2", "token"):
            resp = await client.post("/api/admin/upstreams", json=oci(name), headers=ah)
            assert resp.status_code == 400, name
        # "ghcr" pointing somewhere other than ghcr.io would hijack every
        # ghcr/... pull.
        resp = await client.post("/api/admin/upstreams", json=oci("ghcr"), headers=ah)
        assert resp.status_code == 400
        assert "reserved" in resp.json()["detail"]

    async def test_broad_or_bogus_cdn_hosts_refused(self, docker_env):
        client, _ = docker_env
        ah = await admin(client)
        for hosts in (["*"], ["*.com"], ["bad host"], ["x/../y"]):
            payload = oci("harbor")
            payload["extra"]["blob_hosts"] = hosts
            resp = await client.post("/api/admin/upstreams", json=payload, headers=ah)
            assert resp.status_code == 400, hosts

    async def test_unknown_extra_keys_dropped(self, docker_env):
        client, _ = docker_env
        ah = await admin(client)
        resp = await client.post("/api/admin/upstreams", json=oci("harbor", evil="x"), headers=ah)
        assert resp.status_code == 201
        assert "evil" not in resp.json()["extra"]

    async def test_gitlab_needs_registry_url(self, docker_env):
        client, _ = docker_env
        ah = await admin(client)
        payload = oci("gitlab")
        payload["kind"] = "gitlab_oci"
        assert (await client.post("/api/admin/upstreams", json=payload, headers=ah)).status_code == 400
        payload["extra"]["registry_url"] = "https://registry.gitlab.example.com"
        resp = await client.post("/api/admin/upstreams", json=payload, headers=ah)
        assert resp.status_code == 201, resp.text
        assert resp.json()["extra"]["registry_url"] == "https://registry.gitlab.example.com"


class TestLifecycle:
    async def test_cannot_rename(self, docker_env):
        client, _ = docker_env
        ah = await admin(client)
        uid = await upstream_id(client, ah, "dockerhub")
        resp = await client.patch(f"/api/admin/upstreams/{uid}", json={"name": "hub"}, headers=ah)
        assert resp.status_code == 400
        assert "cannot be renamed" in resp.json()["detail"]

    async def test_disabled_prefix_is_refused_not_sent_to_hub(self, docker_env):
        """With `quay` switched off, `quay/x/y` must not quietly become the
        Docker Hub image `quay/x/y`, which anyone can register."""
        client, fake = docker_env
        ah = await admin(client)
        uid = await upstream_id(client, ah, "quay")
        resp = await client.patch(f"/api/admin/upstreams/{uid}", json={"enabled": False}, headers=ah)
        assert resp.status_code == 200, resp.text
        fake.add_image("quay/team/app", "1", Image.build("hub-squatter"))
        headers = await bearer(client, "repository:quay/team/app:pull")
        resp = await client.get("/v2/quay/team/app/manifests/1", headers=headers)
        assert resp.status_code == 404
        assert "disabled" in resp.json()["errors"][0]["message"]
        assert fake.calls["manifest_get"] == 0

    async def test_make_default_moves_the_flag(self, docker_env):
        client, _ = docker_env
        ah = await admin(client)
        resp = await client.post("/api/admin/upstreams", json=oci("harbor"), headers=ah)
        hid = resp.json()["id"]
        await client.patch(f"/api/admin/upstreams/{hid}", json={"extra": {"default": True}}, headers=ah)
        rows = (await client.get("/api/admin/upstreams", headers=ah)).json()["upstreams"]
        defaults = [u["name"] for u in rows if u["ecosystem"] == "docker" and u["extra"].get("default")]
        assert defaults == ["harbor"]

    async def test_delete_with_cache_needs_purge(self, docker_env):
        from sqlalchemy import func, select

        from app import db
        from app.models import DockerRepository

        client, fake = docker_env
        ah = await admin(client)
        fake.add_image("library/alpine", "3.20", Image.build("alpine"))
        headers = await bearer(client, "repository:alpine:pull")
        assert (await client.get("/v2/alpine/manifests/3.20", headers=headers)).status_code == 200
        uid = await upstream_id(client, ah, "dockerhub")
        resp = await client.delete(f"/api/admin/upstreams/{uid}", headers=ah)
        assert resp.status_code == 409
        assert "cached repositories" in resp.json()["detail"]
        resp = await client.delete(f"/api/admin/upstreams/{uid}?purge=true", headers=ah)
        assert resp.status_code == 200
        assert resp.json()["purged_repositories"] == 1
        async with db.session_scope() as s:
            n = (await s.execute(select(func.count()).select_from(DockerRepository))).scalar_one()
        # Nothing left that would read as a pushed ("local") repository.
        assert n == 0

    async def test_non_admin_cannot_manage(self, docker_env):
        client, _ = docker_env
        token = await make_user(username="dev2", scopes=("read",))
        resp = await client.post(
            "/api/admin/upstreams", json=oci("harbor"), headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code in (401, 403)
