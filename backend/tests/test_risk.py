"""The risk overview: package advisories and image findings, together.

One vulnerability that is both in a cached npm version and in a pulled image
is one row, with both counted; what was served or pulled lately is "in use"
and sorts first.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update

from app import db as db_module
from app.models import (
    Blob,
    DockerFinding,
    DockerManifest,
    DockerRepoManifest,
    Ecosystem,
    KevEntry,
    PackageFile,
    PackageVersion,
    PackageVulnerability,
    Vulnerability,
)
from tests.docker_helpers import Image, bearer, docker_env, make_user, settle_fills, sha  # noqa: F401
from tests.test_integration import npm_publish_body

NOW = datetime.now(UTC)


async def _publish(client, token, version, tarball):
    response = await client.put(
        "/npm/test-pkg",
        json=npm_publish_body(version=version, tarball=tarball),
        headers={"authorization": f"Bearer {token}"},
    )
    assert response.status_code in (200, 201), response.text


async def _advise(version: str, osv_id: str, cve: str, score: float, fixed: str | None) -> None:
    async with db_module.session_scope() as session:
        row = (
            await session.execute(select(PackageVersion).where(PackageVersion.version == version))
        ).scalar_one()
        if await session.get(Vulnerability, osv_id) is None:
            session.add(
                Vulnerability(
                    id=osv_id, cve_id=cve, ecosystem=Ecosystem.npm, cvss_score=score,
                    summary=f"{cve} in test-pkg",
                )
            )
            await session.flush()
        session.add(
            PackageVulnerability(version_id=row.id, vulnerability_id=osv_id, fixed_version=fixed)
        )
        # What the scanner denormalises onto the version, and policy reads.
        row.max_cvss = max(row.max_cvss or 0.0, score)
        row.has_advisories = True
        row.has_fix = row.has_fix or fixed is not None
        row.scanned_at = NOW


async def _served(version: str, when: datetime) -> None:
    async with db_module.session_scope() as session:
        row = (
            await session.execute(select(PackageVersion).where(PackageVersion.version == version))
        ).scalar_one()
        shas = (
            await session.execute(
                select(PackageFile.blob_sha256).where(PackageFile.version_id == row.id)
            )
        ).scalars().all()
        await session.execute(
            update(Blob).where(Blob.sha256.in_(shas)).values(last_accessed_at=when)
        )


async def seed(client):
    admin = await make_user(username="boss", scopes=("admin", "read", "publish"), is_admin=True)
    for version in ("1.0.0", "2.0.0"):
        await _publish(client, admin, version, f"t-{version}".encode())
    # CVE-A: in 1.0.0 (served yesterday) and in an image (pulled long ago).
    await _advise("1.0.0", "GHSA-aaaa", "CVE-2026-0001", 9.8, "2.0.0")
    # CVE-B: only in 2.0.0, never served lately, no fix.
    await _advise("2.0.0", "GHSA-bbbb", "CVE-2026-0002", 7.5, None)
    await _served("1.0.0", NOW - timedelta(days=1))
    await _served("2.0.0", NOW - timedelta(days=200))

    img = Image.build("vulnimg", layer_sizes=(10_000,))
    from tests.docker_helpers import docker_env as _  # noqa: F401

    return admin, img


async def _image(client, fake, img, pulled_days_ago):
    fake.add_image("library/vulnimg", "1", img)
    headers = await bearer(client, "repository:vulnimg:pull")
    await client.get("/v2/vulnimg/manifests/1", headers=headers)
    await settle_fills()
    async with db_module.session_scope() as session:
        manifest = (
            await session.execute(select(DockerManifest).where(DockerManifest.digest == img.digest))
        ).scalar_one()
        await session.execute(
            update(DockerRepoManifest)
            .where(DockerRepoManifest.manifest_id == manifest.id)
            .values(last_pulled_at=NOW - timedelta(days=pulled_days_ago))
        )
        for vuln, sev, kev in (("CVE-2026-0001", "CRITICAL", False), ("CVE-2026-0003", "HIGH", True)):
            session.add(
                DockerFinding(
                    manifest_id=manifest.id, scan_id=1, vuln_id=vuln, pkg_name="openssl",
                    installed_version="3.0.1", fixed_version="3.0.9", severity=sev,
                    cvss=9.1 if sev == "CRITICAL" else 7.2, kev=kev,
                )
            )


async def test_one_row_per_vulnerability_across_packages_and_images(docker_env):  # noqa: F811
    client, fake = docker_env
    admin, img = await seed(client)
    await _image(client, fake, img, pulled_days_ago=60)
    headers = {"authorization": f"Bearer {admin}"}

    response = await client.get(
        "/api/admin/risk", params={"min_severity": "none"}, headers=headers
    )
    assert response.status_code == 200, response.text
    body = response.json()
    items = {i["id"]: i for i in body["items"]}
    assert set(items) == {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}

    both = items["CVE-2026-0001"]
    assert both["packages"]["versions"] == 1 and both["images"]["repositories"] == 1
    assert both["cvss"] == 9.8 and both["severity"] == "critical"
    # 1.0.0 was served yesterday: in use, though the image was pulled long ago.
    assert both["in_use"] is True
    assert both["packages"]["served_recently"] is True
    assert both["images"]["pulled_recently"] is False
    assert both["fix_available"] is True

    assert items["CVE-2026-0002"]["in_use"] is False
    assert items["CVE-2026-0002"]["fix_available"] is False
    assert items["CVE-2026-0003"]["kev"] is True
    # In use sorts first.
    assert body["items"][0]["id"] == "CVE-2026-0001"
    assert body["summary"]["in_use"] == 1
    assert body["summary"]["critical_in_use"] == 1


async def test_filters(docker_env):  # noqa: F811
    client, fake = docker_env
    admin, img = await seed(client)
    await _image(client, fake, img, pulled_days_ago=2)
    headers = {"authorization": f"Bearer {admin}"}

    async def ids(**params):
        r = await client.get("/api/admin/risk", params=params, headers=headers)
        assert r.status_code == 200, r.text
        return {i["id"] for i in r.json()["items"]}

    assert await ids(source="packages", min_severity="none") == {"CVE-2026-0001", "CVE-2026-0002"}
    assert await ids(source="images", min_severity="none") == {"CVE-2026-0001", "CVE-2026-0003"}
    assert await ids(min_severity="critical") == {"CVE-2026-0001"}
    # The image was pulled two days ago now, so its KEV finding is in use.
    assert await ids(only_in_use="true", min_severity="none") == {"CVE-2026-0001", "CVE-2026-0003"}
    assert await ids(search="0002", min_severity="none") == {"CVE-2026-0002"}


async def test_a_kev_listed_package_cve_is_flagged(docker_env):  # noqa: F811
    client, _fake = docker_env
    admin, _img = await seed(client)
    async with db_module.session_scope() as session:
        session.add(KevEntry(cve_id="CVE-2026-0002"))
    r = await client.get(
        "/api/admin/risk", params={"min_severity": "none"},
        headers={"authorization": f"Bearer {admin}"},
    )
    items = {i["id"]: i for i in r.json()["items"]}
    assert items["CVE-2026-0002"]["kev"] is True


async def test_detail_lists_versions_with_their_policy_status_and_images(docker_env):  # noqa: F811
    client, fake = docker_env
    admin, img = await seed(client)
    await _image(client, fake, img, pulled_days_ago=60)
    r = await client.get(
        "/api/admin/risk/detail", params={"id": "CVE-2026-0001"},
        headers={"authorization": f"Bearer {admin}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert [(p["version"], p["fixed_version"]) for p in body["packages"]] == [("1.0.0", "2.0.0")]
    # 9.8 is in the default CVE policy's range: the version is blocked now.
    assert body["packages"][0]["blocked"] is True
    assert "CVSS 9.8" in body["packages"][0]["block_reason"]
    [image] = body["images"]
    assert image["repository"].endswith("vulnimg")
    assert image["tags"] == ["1"]
    assert (image["package"], image["installed_version"], image["fixed_version"]) == (
        "openssl", "3.0.1", "3.0.9",
    )

    missing = await client.get(
        "/api/admin/risk/detail", params={"id": "CVE-1999-0000"},
        headers={"authorization": f"Bearer {admin}"},
    )
    assert missing.status_code == 404


async def test_admin_only(docker_env):  # noqa: F811
    client, _fake = docker_env
    reader = await make_user(username="reader", scopes=("read",))
    r = await client.get("/api/admin/risk", headers={"authorization": f"Bearer {reader}"})
    assert r.status_code in (401, 403)
