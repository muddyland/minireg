"""Image findings grouped by package to upgrade (the tag page's default view)."""

from __future__ import annotations

from sqlalchemy import select

from app import db as db_module
from app.api.docker_api import _highest, group_findings
from app.models import DockerFinding, DockerManifest, DockerRepository
from tests.docker_helpers import Image, bearer, docker_env, index_of, make_user, settle_fills  # noqa: F401


def finding(vuln, pkg, version="1.0", fixed=None, severity="HIGH", kev=False, ptype="debian"):
    return {
        "vuln_id": vuln, "pkg_name": pkg, "pkg_type": ptype, "installed_version": version,
        "fixed_version": fixed, "severity": severity, "cvss": None, "title": None, "url": None,
        "layer_digest": None, "kev": kev, "denied": False, "accepted": False,
    }


def test_sibling_packages_with_the_same_findings_are_one_entry():
    out = group_findings(
        [
            finding("CVE-1", "libc6", "2.36-9", "2.36-9+deb12u4"),
            finding("CVE-1", "libc-bin", "2.36-9", "2.36-9+deb12u4"),
            finding("CVE-2", "libc6", "2.36-9", "2.36-9+deb12u10"),
            finding("CVE-2", "libc-bin", "2.36-9", "2.36-9+deb12u10"),
            # Same name set differs: zlib is its own entry.
            finding("CVE-1", "zlib1g", "1.2.13", None),
        ]
    )
    [glibc] = out["fixable"]
    assert glibc["packages"] == ["libc-bin", "libc6"]
    # Upgrading to the highest fixed version clears both.
    assert glibc["fixed_version"] == "2.36-9+deb12u10"
    # One row per CVE, not one per sibling package.
    assert [f["vuln_id"] for f in glibc["fixable"]["findings"]] == ["CVE-1", "CVE-2"]
    assert glibc["fixable"]["count"] == 2 and glibc["unfixed"]["count"] == 0
    [zlib] = out["unfixed"]
    assert zlib["packages"] == ["zlib1g"] and zlib["fixed_version"] is None
    assert out["total"] == 5 and out["vulnerabilities"] == 2
    assert out["fixable_findings"] == 2 and out["unfixed_findings"] == 1


def test_a_package_with_fixed_and_unfixed_findings_is_in_both_parts():
    out = group_findings(
        [
            finding("CVE-1", "openssl", "3.0.1", "3.0.9", severity="CRITICAL"),
            finding("CVE-2", "openssl", "3.0.1", None, severity="LOW"),
        ]
    )
    assert [g["packages"] for g in out["fixable"]] == [["openssl"]]
    assert [g["packages"] for g in out["unfixed"]] == [["openssl"]]
    assert out["fixable"][0]["fixable"]["worst"] == "CRITICAL"
    assert out["unfixed"][0]["unfixed"]["worst"] == "LOW"


def test_order_is_known_exploited_then_worst_severity_then_count():
    out = group_findings(
        [
            finding("CVE-1", "many", fixed="2", severity="HIGH"),
            finding("CVE-2", "many", fixed="2", severity="HIGH"),
            finding("CVE-3", "many", fixed="2", severity="HIGH"),
            finding("CVE-4", "crit", fixed="2", severity="CRITICAL"),
            finding("CVE-5", "kev", fixed="2", severity="MEDIUM", kev=True),
        ]
    )
    assert [g["packages"][0] for g in out["fixable"]] == ["kev", "crit", "many"]


def test_highest_fixed_version_compares_numbers_not_text():
    assert _highest({"3.0.9", "3.0.15", "3.0.10"}) == "3.0.15"
    assert _highest({"1:1.2.13.dfsg-1+deb12u1", "1:1.2.13.dfsg-1"}) == "1:1.2.13.dfsg-1+deb12u1"
    # Trivy lists one fix per release line; the first is the one to take.
    assert _highest({"3.0.15, 3.1.7", "3.0.12"}) == "3.0.15"
    assert _highest({"", None}) is None


async def test_grouped_findings_endpoint(docker_env):  # noqa: F811
    client, fake = docker_env
    img = Image.build("grouped", layer_sizes=(10_000,))
    fake.add_image("library/grouped", "1", img)
    headers = await bearer(client, "repository:grouped:pull")
    assert (await client.get("/v2/grouped/manifests/1", headers=headers)).status_code == 200
    await settle_fills()
    async with db_module.session_scope() as session:
        manifest = (
            await session.execute(select(DockerManifest).where(DockerManifest.digest == img.digest))
        ).scalar_one()
        for vuln, pkg, fixed, sev in (
            ("CVE-2026-1", "libssl3", "3.0.9", "CRITICAL"),
            ("CVE-2026-1", "openssl", "3.0.9", "CRITICAL"),
            ("CVE-2026-2", "zlib1g", None, "HIGH"),
            ("CVE-2026-3", "bash", "5.2.1", "LOW"),
        ):
            session.add(
                DockerFinding(
                    manifest_id=manifest.id, scan_id=1, vuln_id=vuln, pkg_name=pkg,
                    installed_version="3.0.1", fixed_version=fixed, severity=sev, pkg_type="debian",
                )
            )
    user = await make_user(username="viewer", scopes=("read",))
    auth = {"authorization": f"Bearer {user}"}
    url = f"/api/docker/manifest/{img.digest}/findings"

    r = await client.get(url, params={"group": "package", "severity": "CRITICAL,HIGH"}, headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert [g["packages"] for g in body["fixable"]] == [["libssl3", "openssl"]]
    assert body["fixable"][0]["fixed_version"] == "3.0.9"
    assert [g["packages"] for g in body["unfixed"]] == [["zlib1g"]]
    assert body["total"] == 3 and body["vulnerabilities"] == 2

    # Search narrows, and a LIKE wildcard in it is literal.
    r = await client.get(url, params={"group": "package", "q": "zlib"}, headers=auth)
    assert [g["packages"] for g in r.json()["unfixed"]] == [["zlib1g"]] and not r.json()["fixable"]
    r = await client.get(url, params={"group": "package", "q": "%"}, headers=auth)
    assert r.json()["total"] == 0

    # The flat list is unchanged.
    r = await client.get(url, headers=auth)
    assert r.json()["total"] == 4
    assert (await client.get(url, params={"group": "nope"}, headers=auth)).status_code == 422


async def test_platform_images_of_a_tagged_index_are_not_untagged(docker_env):  # noqa: F811
    """They are reached through the tag (and shown on its page); listing them
    under "Untagged digests" read as stray images."""
    client, fake = docker_env
    amd = Image.build("multi-amd", layer_sizes=(1000,))
    arm = Image.build("multi-arm", layer_sizes=(1000,))
    att = Image.build("multi-att", layer_sizes=(100,))
    body, _ = index_of((amd, "linux/amd64"), (arm, "linux/arm64/v8"), attestation=att)
    fake.add_index("library/multi", "1", body, amd, arm, att)
    stray = Image.build("multi-stray", layer_sizes=(1000,))
    fake.add_image("library/multi", None, stray)
    headers = await bearer(client, "repository:multi:pull")
    for ref in ("1", amd.digest, att.digest, stray.digest):
        assert (await client.get(f"/v2/multi/manifests/{ref}", headers=headers)).status_code == 200
    await settle_fills()

    async with db_module.session_scope() as session:
        [repo_name] = (
            await session.execute(select(DockerRepository.name).where(DockerRepository.name.like("%multi")))
        ).scalars().all()
    user = await make_user(username="viewer", scopes=("read",))
    r = await client.get(
        "/api/docker/repository", params={"name": repo_name},
        headers={"authorization": f"Bearer {user}"},
    )
    assert r.status_code == 200, r.text
    assert [d["digest"] for d in r.json()["digests"]] == [stray.digest]
