"""Automatic cache expiry: artifacts and images nobody used for a while.

An expired artifact keeps its metadata and is fetched again on the next
request; files published here, pushed images, pinned repositories and
watched tags are never expired.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update

from app import db as db_module
from app.models import Blob, PackageFile, PackageVersion, Setting
from app.services import artifacts
from tests.docker_helpers import Image, bearer, docker_env, settle_fills, sha  # noqa: F401
from tests.test_integration import app_client, auth, npm_publish_body  # noqa: F401


async def _publish_and_mark_upstream(client, versions=("1.0.0", "2.0.0")):
    for version in versions:
        response = await client.put(
            "/npm/test-pkg",
            json=npm_publish_body(version=version, tarball=f"bytes-{version}".encode()),
            headers=auth(client),
        )
        assert response.status_code in (200, 201)
    # Pretend 1.0.0 came from an upstream, so it is a cached copy that can be
    # fetched again.
    async with db_module.session_scope() as session:
        await session.execute(
            update(PackageVersion).where(PackageVersion.version == "1.0.0").values(is_local=False)
        )
        version_id = (
            await session.execute(
                select(PackageVersion.id).where(PackageVersion.version == "1.0.0")
            )
        ).scalar_one()
        await session.execute(
            update(PackageFile)
            .where(PackageFile.version_id == version_id)
            .values(upstream_url="https://upstream.test/test-pkg/-/test-pkg-1.0.0.tgz")
        )


async def _age_blobs(days: int) -> None:
    async with db_module.session_scope() as session:
        await session.execute(
            update(Blob).values(last_accessed_at=datetime.now(UTC) - timedelta(days=days))
        )


async def _cached() -> dict[str, bool]:
    async with db_module.session_scope() as session:
        rows = (
            await session.execute(
                select(PackageVersion.version, PackageFile.blob_sha256).join(
                    PackageFile, PackageFile.version_id == PackageVersion.id
                )
            )
        ).all()
    return {version: sha is not None for version, sha in rows}


class TestPackageExpiry:
    async def test_defaults(self):
        expiry = artifacts.CacheExpiry.from_dict(None)
        assert expiry.packages_unused_days == 90
        assert expiry.images_unused_days == 90

    async def test_an_unused_cached_artifact_expires_and_a_local_one_never(
        self, app_client  # noqa: F811
    ):
        await _publish_and_mark_upstream(app_client)
        await _age_blobs(91)
        result = await artifacts.expire_unused()
        assert result["expired"] == 1
        assert await _cached() == {"1.0.0": False, "2.0.0": True}

    async def test_an_artifact_from_a_disabled_upstream_stays(self, app_client):  # noqa: F811
        from app.models import Ecosystem, Upstream, UpstreamKind

        await _publish_and_mark_upstream(app_client)
        async with db_module.session_scope() as session:
            upstream = Upstream(
                name="paused",
                ecosystem=Ecosystem.npm,
                kind=UpstreamKind.npm,
                url="https://upstream.test",
                enabled=False,
            )
            session.add(upstream)
            await session.flush()
            await session.execute(
                update(PackageFile)
                .where(PackageFile.upstream_url.is_not(None))
                .values(upstream_id=upstream.id)
            )
        await _age_blobs(365)
        assert (await artifacts.expire_unused())["expired"] == 0
        assert await _cached() == {"1.0.0": True, "2.0.0": True}

    async def test_a_recently_used_artifact_stays(self, app_client):  # noqa: F811
        await _publish_and_mark_upstream(app_client)
        await _age_blobs(30)
        assert (await artifacts.expire_unused())["expired"] == 0
        assert await _cached() == {"1.0.0": True, "2.0.0": True}

    async def test_zero_turns_it_off(self, app_client):  # noqa: F811
        await _publish_and_mark_upstream(app_client)
        await _age_blobs(1000)
        async with db_module.session_scope() as session:
            session.add(
                Setting(
                    key=artifacts.CACHE_EXPIRY_KEY,
                    value={"packages_unused_days": 0, "images_unused_days": 0},
                )
            )
        assert (await artifacts.expire_unused()) == {"unused_days": 0}
        assert await _cached() == {"1.0.0": True, "2.0.0": True}

    async def test_the_settings_api(self, app_client):  # noqa: F811
        admin = auth(app_client, "admin")
        response = await app_client.put(
            "/api/admin/settings/cache-expiry",
            json={"packages_unused_days": 30, "images_unused_days": 0},
            headers=admin,
        )
        assert response.status_code == 200
        settings = (await app_client.get("/api/admin/settings", headers=admin)).json()
        assert settings["cache_expiry"] == {"packages_unused_days": 30, "images_unused_days": 0}
        refused = await app_client.put(
            "/api/admin/settings/cache-expiry",
            json={"packages_unused_days": -1},
            headers=admin,
        )
        assert refused.status_code == 422


class TestImageExpiry:
    async def _pull(self, client, fake, name):
        img = Image.build(name, layer_sizes=(20_000,))
        fake.add_image(f"library/{name}", "1", img)
        headers = await bearer(client, f"repository:{name}:pull")
        await client.get(f"/v2/{name}/manifests/1", headers=headers)
        await client.get(f"/v2/{name}/blobs/{sha(img.layers[0])}", headers=headers)
        return img

    async def _age(self, digest, days):
        from app.models import DockerManifest, DockerRepoManifest

        async with db_module.session_scope() as s:
            m = (
                await s.execute(select(DockerManifest).where(DockerManifest.digest == digest))
            ).scalar_one()
            await s.execute(
                update(DockerRepoManifest)
                .where(DockerRepoManifest.manifest_id == m.id)
                .values(last_pulled_at=datetime.now(UTC) - timedelta(days=days))
            )

    async def test_an_unpulled_image_expires_and_a_recent_one_stays(self, docker_env):  # noqa: F811
        from app.docker import housekeeping
        from app.models import DockerRepoManifest

        client, fake = docker_env
        old = await self._pull(client, fake, "oldimg")
        new = await self._pull(client, fake, "newimg")
        await settle_fills()
        await self._age(old.digest, 120)
        await self._age(new.digest, 10)
        result = await housekeeping._expire()
        assert result["expired"] == 1
        async with db_module.session_scope() as s:
            assert (await s.execute(select(DockerRepoManifest))).scalars().all().__len__() == 1

    async def test_pinned_and_watched_images_never_expire(self, docker_env):  # noqa: F811
        from app.docker import housekeeping
        from app.models import DockerRepository

        client, fake = docker_env
        pinned = await self._pull(client, fake, "pinned")
        watched = await self._pull(client, fake, "watched")
        await settle_fills()
        async with db_module.session_scope() as s:
            await s.execute(
                update(DockerRepository)
                .where(DockerRepository.name.like("%pinned"))
                .values(pinned=True)
            )
            await s.execute(
                update(DockerRepository)
                .where(DockerRepository.name.like("%watched"))
                .values(watched_tags=["1"])
            )
        await self._age(pinned.digest, 365)
        await self._age(watched.digest, 365)
        assert (await housekeeping._expire())["expired"] == 0
