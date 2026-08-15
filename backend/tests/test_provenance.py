"""Upstream provenance: which upstreams have a package, and where they link to."""

import base64

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import db as db_module
from app.core.security import generate_token, hash_password
from app.models import ApiToken, Ecosystem, Upstream, UpstreamKind, User
from app.services.policy import invalidate_policy_cache
from app.services.resolver import build_provider
from app.services.storage import BlobStore, set_store


def make_upstream(**kwargs):
    defaults = {
        "id": 1,
        "name": "u",
        "ecosystem": Ecosystem.npm,
        "kind": UpstreamKind.npm,
        "url": "https://registry.npmjs.org",
        "tier": 1,
        "priority": 100,
        "enabled": True,
        "auth_type": "none",
        "credential_enc": None,
        "timeout_seconds": 20.0,
        "healthy": True,
        "consecutive_failures": 0,
        "gitlab_project_id": None,
        "gitlab_group_id": None,
        "auth_header_name": None,
        "web_url_template": None,
    }
    defaults.update(kwargs)
    return Upstream(**defaults)


class TestDerivedWebUrls:
    def test_public_npm_links_to_npmjs_com(self):
        provider = build_provider(make_upstream(url="https://registry.npmjs.org"))
        assert provider.package_web_url("lodash") == "https://www.npmjs.com/package/lodash"

    def test_public_npm_scoped_package(self):
        provider = build_provider(make_upstream(url="https://registry.npmjs.org"))
        assert (
            provider.package_web_url("@babel/core") == "https://www.npmjs.com/package/@babel/core"
        )

    def test_yarn_mirror_also_maps_to_npmjs(self):
        provider = build_provider(make_upstream(url="https://registry.yarnpkg.com"))
        assert provider.package_web_url("lodash") == "https://www.npmjs.com/package/lodash"

    def test_public_pypi_links_to_project_page(self):
        provider = build_provider(
            make_upstream(
                ecosystem=Ecosystem.pypi, kind=UpstreamKind.pypi, url="https://pypi.org/simple"
            )
        )
        assert provider.package_web_url("requests") == "https://pypi.org/project/requests/"

    def test_pypi_web_url_is_normalized(self):
        provider = build_provider(
            make_upstream(
                ecosystem=Ecosystem.pypi, kind=UpstreamKind.pypi, url="https://pypi.org/simple"
            )
        )
        # PEP 503 normalization, so the link does not 404 on a redirect chain.
        assert provider.package_web_url("Zope.Interface") == (
            "https://pypi.org/project/zope-interface/"
        )

    def test_unknown_host_has_no_derived_web_url(self):
        provider = build_provider(make_upstream(url="https://npm.internal.example"))
        assert provider.package_web_url("thing") is None

    def test_index_url_is_always_available(self):
        provider = build_provider(make_upstream(url="https://npm.internal.example"))
        assert provider.package_index_url("thing") == "https://npm.internal.example/thing"


class TestConfiguredTemplate:
    def test_template_overrides_the_derived_default(self):
        provider = build_provider(
            make_upstream(
                url="https://registry.npmjs.org",
                web_url_template="https://internal.example/pkg/{name}",
            )
        )
        assert provider.package_web_url("lodash") == "https://internal.example/pkg/lodash"

    def test_normalized_name_placeholder(self):
        provider = build_provider(
            make_upstream(
                ecosystem=Ecosystem.pypi,
                kind=UpstreamKind.pypi,
                url="https://pypi.internal.example/simple",
                web_url_template="https://internal.example/p/{normalized_name}",
            )
        )
        assert provider.package_web_url("My.Package") == "https://internal.example/p/my-package"

    def test_malformed_template_returns_none_rather_than_raising(self):
        provider = build_provider(
            make_upstream(
                url="https://registry.npmjs.org",
                web_url_template="https://internal.example/{nope}",
            )
        )
        assert provider.package_web_url("lodash") is None


class TestGitLabWebUrl:
    def test_project_path_yields_a_packages_page(self):
        provider = build_provider(
            make_upstream(
                kind=UpstreamKind.gitlab_npm,
                url="https://gitlab.example.com",
                gitlab_project_id="mygroup%2Fmyproject",
            )
        )
        assert provider.package_web_url("thing") == (
            "https://gitlab.example.com/mygroup/myproject/-/packages"
        )

    def test_numeric_project_id_cannot_be_resolved_to_a_path(self):
        # GitLab's API does not expose the path from an id, so we do not guess.
        provider = build_provider(
            make_upstream(
                kind=UpstreamKind.gitlab_npm,
                url="https://gitlab.example.com",
                gitlab_project_id="42",
            )
        )
        assert provider.package_web_url("thing") is None
        # ...but the index URL still points at the real API endpoint.
        assert "api/v4/projects/42/packages/npm/thing" in provider.package_index_url("thing")


# --------------------------------------------------------------------------- #
# End to end
# --------------------------------------------------------------------------- #
@pytest_asyncio.fixture
async def client(tmp_path):
    from app.main import app

    db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'prov.db'}")
    await db_module.create_schema()
    store = BlobStore(str(tmp_path / "storage"))
    store.ensure_dirs()
    set_store(store)

    async with db_module.session_scope() as session:
        admin = User(
            username="admin",
            password_hash=hash_password("admin-password-1234"),
            is_admin=True,
            can_publish=True,
        )
        session.add(admin)
        await session.flush()
        full, prefix, token_hash = generate_token()
        session.add(
            ApiToken(
                user_id=admin.id,
                name="t",
                prefix=prefix,
                token_hash=token_hash,
                scopes=["read", "publish", "admin"],
            )
        )
    await invalidate_policy_cache()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://registry.test"
    ) as c:
        c.headers.update({"authorization": f"Bearer {full}"})
        yield c

    await db_module.dispose_engine()
    set_store(None)  # type: ignore[arg-type]


def publish_body(name, version):
    tarball = f"{name}-{version}".encode()
    return {
        "name": name,
        "dist-tags": {"latest": version},
        "versions": {version: {"name": name, "version": version, "dist": {}}},
        "_attachments": {
            f"{name}-{version}.tgz": {
                "content_type": "application/octet-stream",
                "data": base64.b64encode(tarball).decode(),
                "length": len(tarball),
            }
        },
    }


class TestProvenanceEndpoint:
    async def test_locally_published_package_reports_published_here(self, client):
        await client.put("/npm/mine", json=publish_body("mine", "1.0.0"))
        body = (await client.get("/api/packages/npm/mine")).json()

        assert len(body["upstreams"]) == 1
        entry = body["upstreams"][0]
        assert entry["kind"] == "local"
        assert entry["name"] == "Published here"
        assert entry["versions"] == 1
        assert entry["web_url"] is None

    async def test_multiple_upstreams_are_all_listed(self, client):
        # Two upstreams contribute versions of the same package.
        async with db_module.session_scope() as session:
            session.add_all(
                [
                    Upstream(
                        id=10,
                        name="npmjs",
                        ecosystem=Ecosystem.npm,
                        kind=UpstreamKind.npm,
                        url="https://registry.npmjs.org",
                        tier=1,
                    ),
                    Upstream(
                        id=11,
                        name="internal",
                        ecosystem=Ecosystem.npm,
                        kind=UpstreamKind.npm,
                        url="https://npm.internal.example",
                        tier=2,
                    ),
                ]
            )

        await client.put("/npm/shared", json=publish_body("shared", "1.0.0"))
        await client.put("/npm/shared", json=publish_body("shared", "2.0.0"))

        # Attribute one version to each upstream, as a merged/failover fetch would.
        from sqlalchemy import update

        from app.models import PackageVersion

        async with db_module.session_scope() as session:
            await session.execute(
                update(PackageVersion)
                .where(PackageVersion.version == "1.0.0")
                .values(upstream_id=10, is_local=False)
            )
            await session.execute(
                update(PackageVersion)
                .where(PackageVersion.version == "2.0.0")
                .values(upstream_id=11, is_local=False)
            )

        body = (await client.get("/api/packages/npm/shared")).json()
        names = {u["name"] for u in body["upstreams"]}
        assert {"npmjs", "internal"} <= names

        npmjs = next(u for u in body["upstreams"] if u["name"] == "npmjs")
        assert npmjs["versions"] == 1
        assert npmjs["web_url"] == "https://www.npmjs.com/package/shared"
        assert npmjs["index_url"] == "https://registry.npmjs.org/shared"

    async def test_entries_are_ordered_by_tier(self, client):
        async with db_module.session_scope() as session:
            session.add_all(
                [
                    Upstream(
                        id=20, name="tier-three", ecosystem=Ecosystem.npm,
                        kind=UpstreamKind.npm, url="https://c.example", tier=3,
                    ),
                    Upstream(
                        id=21, name="tier-one", ecosystem=Ecosystem.npm,
                        kind=UpstreamKind.npm, url="https://a.example", tier=1,
                    ),
                ]
            )
        await client.put("/npm/ordered", json=publish_body("ordered", "1.0.0"))
        await client.put("/npm/ordered", json=publish_body("ordered", "2.0.0"))

        from sqlalchemy import update

        from app.models import PackageVersion

        async with db_module.session_scope() as session:
            await session.execute(
                update(PackageVersion).where(PackageVersion.version == "1.0.0").values(upstream_id=20)
            )
            await session.execute(
                update(PackageVersion).where(PackageVersion.version == "2.0.0").values(upstream_id=21)
            )

        body = (await client.get("/api/packages/npm/ordered")).json()
        remote = [u for u in body["upstreams"] if u["kind"] != "local"]
        assert [u["name"] for u in remote] == ["tier-one", "tier-three"]

    async def test_deleted_upstream_is_reported_not_dropped(self, client):
        async with db_module.session_scope() as session:
            session.add(
                Upstream(
                    id=30, name="temp", ecosystem=Ecosystem.npm,
                    kind=UpstreamKind.npm, url="https://t.example", tier=1,
                )
            )
        await client.put("/npm/orphan", json=publish_body("orphan", "1.0.0"))

        from sqlalchemy import delete, update

        from app.models import PackageVersion

        async with db_module.session_scope() as session:
            await session.execute(update(PackageVersion).values(upstream_id=30, is_local=False))
        async with db_module.session_scope() as session:
            await session.execute(delete(Upstream).where(Upstream.id == 30))

        body = (await client.get("/api/packages/npm/orphan")).json()
        # The version still exists, so its origin must still be accounted for.
        assert any("deleted" in u["name"] for u in body["upstreams"])

    async def test_admin_package_detail_also_carries_upstreams(self, client):
        await client.put("/npm/mine", json=publish_body("mine", "1.0.0"))
        listing = (await client.get("/api/admin/packages?search=mine")).json()
        package_id = listing["packages"][0]["id"]

        body = (await client.get(f"/api/admin/packages/{package_id}")).json()
        assert "upstreams" in body
        assert body["upstreams"][0]["kind"] == "local"


class TestUpstreamTemplateCrud:
    async def test_template_round_trips(self, client):
        created = await client.post(
            "/api/admin/upstreams",
            json={
                "name": "internal-npm",
                "ecosystem": "npm",
                "kind": "npm",
                "url": "https://npm.internal.example",
                "web_url_template": "https://internal.example/pkg/{name}",
            },
        )
        assert created.status_code == 201
        assert created.json()["web_url_template"] == "https://internal.example/pkg/{name}"

        listed = (await client.get("/api/admin/upstreams")).json()["upstreams"]
        entry = next(u for u in listed if u["name"] == "internal-npm")
        assert entry["web_url_template"] == "https://internal.example/pkg/{name}"

    async def test_template_can_be_updated(self, client):
        created = await client.post(
            "/api/admin/upstreams",
            json={
                "name": "internal-npm",
                "ecosystem": "npm",
                "kind": "npm",
                "url": "https://npm.internal.example",
            },
        )
        upstream_id = created.json()["id"]
        updated = await client.patch(
            f"/api/admin/upstreams/{upstream_id}",
            json={"web_url_template": "https://elsewhere.example/{name}"},
        )
        assert updated.json()["web_url_template"] == "https://elsewhere.example/{name}"
