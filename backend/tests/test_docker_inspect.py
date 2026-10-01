"""/api/docker/inspect: the lookup behind `minireg info` and `audit --image`."""

from __future__ import annotations

import pytest

from app.api.docker_api import split_reference
from tests.docker_helpers import Image, bearer, index_of, make_user
from tests.test_docker_push import push_image
from tests.test_docker_scan import admin, scanner_headers, set_policy, trivy_report, vuln


async def user(client):
    token = await make_user(username="viewer", scopes=("read",))
    return {"Authorization": f"Bearer {token}"}


async def inspect(client, ref, headers, **params):
    return await client.get("/api/docker/inspect", params={"ref": ref, **params}, headers=headers)


async def scan_all(client, results: dict[str, list[dict]]):
    """Drain the scan queue, answering each job with the findings for its digest."""
    sh = await scanner_headers(client)
    while True:
        claim = await client.post("/api/docker/scanner/claim", json={"worker": "w1"}, headers=sh)
        if claim.status_code == 204:
            return
        job = claim.json()
        r = await client.post(
            f"/api/docker/scanner/jobs/{job['job_id']}/result",
            data={"worker": "w1"},
            files={"report": ("r.json", trivy_report(results.get(job["digest"], [])), "application/json")},
            headers=sh,
        )
        assert r.status_code == 200, r.text


class TestSplitReference:
    @pytest.mark.parametrize(
        ("ref", "expected"),
        [
            ("alpine", ("alpine", None, None)),
            ("alpine:3.20", ("alpine", "3.20", None)),
            ("registry.test/alpine:3.20", ("alpine", "3.20", None)),
            ("ghcr/org/img:1.0", ("ghcr/org/img", "1.0", None)),
            ("alpine@sha256:" + "a" * 64, ("alpine", None, "sha256:" + "a" * 64)),
            ("alpine:3.20@sha256:" + "b" * 64, ("alpine", "3.20", "sha256:" + "b" * 64)),
            # Someone else's host with a port: the colon is not a tag.
            ("other.example:5000/team/app", ("other.example:5000/team/app", None, None)),
        ],
    )
    def test_forms(self, ref, expected):
        assert split_reference(ref) == expected

    def test_the_host_the_client_used_is_ours_too(self):
        assert split_reference("localhost:5055/local/team/app:1", "localhost:5055") == (
            "local/team/app",
            "1",
            None,
        )
        # Only that host: anyone else's stays part of the name.
        assert split_reference("other:5000/app", "localhost:5055") == ("other:5000/app", None, None)


class TestInspect:
    async def test_needs_a_login(self, docker_env):
        client, _ = docker_env
        assert (await inspect(client, "alpine:3.20", {})).status_code == 401

    async def test_uncached_image_is_fetched_and_queued(self, docker_env):
        """`audit --image` must work on an image nobody has pulled yet."""
        client, fake = docker_env
        img = Image.build("alpine")
        fake.add_image("library/alpine", "3.20", img)
        resp = await inspect(client, "registry.test/alpine:3.20", await user(client))
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["repository"] == "dockerhub/library/alpine"
        assert body["pull_reference"] == "registry.test/alpine:3.20"
        assert body["digest"] == img.digest
        assert body["image"]["scan_status"] == "queued"
        assert body["verdict"]["allowed"] is True
        # Manifests only: looking something up must not download its layers.
        assert fake.calls.get("blob", 0) == 0

    async def test_unknown_image_is_404(self, docker_env):
        client, _ = docker_env
        resp = await inspect(client, "nope/nothing:1", await user(client))
        assert resp.status_code == 404

    async def test_scanned_image_reports_findings_worst_first(self, docker_env):
        client, fake = docker_env
        img = Image.build("py")
        fake.add_image("library/python", "3.9", img)
        h = await user(client)
        await inspect(client, "python:3.9", h)
        await scan_all(
            client,
            {
                img.digest: [
                    vuln("CVE-2020-0001", "LOW", pkg="zlib"),
                    vuln("CVE-2024-9999", "CRITICAL", fixed="3.0.1", cvss=9.8),
                    vuln("CVE-2023-5555", "HIGH", cvss=7.5, pkg="libc"),
                ]
            },
        )
        body = (await inspect(client, "python:3.9", h)).json()
        assert body["image"]["scan_status"] == "scanned"
        assert body["findings_total"] == 3
        assert [f["vuln_id"] for f in body["findings"]] == ["CVE-2024-9999", "CVE-2023-5555", "CVE-2020-0001"]
        assert body["findings"][0]["fixed_version"] == "3.0.1"
        counts = {k: v for k, v in body["image"]["severity_counts"].items() if v}
        assert counts == {"CRITICAL": 1, "HIGH": 1, "LOW": 1}
        # Pull severity blocking is off by default.
        assert body["verdict"]["allowed"] is True

    async def test_findings_limit(self, docker_env):
        client, fake = docker_env
        img = Image.build("big")
        fake.add_image("library/big", "1", img)
        h = await user(client)
        await inspect(client, "big:1", h)
        await scan_all(client, {img.digest: [vuln(f"CVE-2024-{i:04d}", "MEDIUM") for i in range(10)]})
        body = (await inspect(client, "big:1", h, findings=3)).json()
        assert body["findings_total"] == 10
        assert len(body["findings"]) == 3

    async def test_policy_block_is_the_verdict(self, docker_env):
        client, fake = docker_env
        img = Image.build("log4j")
        fake.add_image("library/app", "1", img)
        h = await user(client)
        await inspect(client, "app:1", h)
        await scan_all(client, {img.digest: [vuln("CVE-2021-44228", "CRITICAL", fixed="2.17")]})
        await set_policy(client, await admin(client), deny_cves=["CVE-2021-44228"])
        body = (await inspect(client, "app:1", h)).json()
        assert body["verdict"]["allowed"] is False
        assert body["verdict"]["code"] == "DENIED"
        assert "CVE-2021-44228" in body["verdict"]["reason"]
        assert body["findings"][0]["denied"] is True
        # ...and it agrees with what `docker pull` gets.
        pull = await bearer(client, "repository:app:pull")
        assert (await client.get("/v2/app/manifests/1", headers=pull)).status_code == 403

    async def test_quarantined_repository(self, docker_env):
        client, fake = docker_env
        fake.add_image("library/alpine", "3.20", Image.build("alpine"))
        h = await user(client)
        await inspect(client, "alpine:3.20", h)
        await client.patch(
            "/api/docker/repository?name=dockerhub/library/alpine",
            json={"quarantined": True, "quarantine_reason": "incident 42"},
            headers=await admin(client),
        )
        body = (await inspect(client, "alpine:3.20", h)).json()
        assert body["quarantined"] is True
        assert body["verdict"]["allowed"] is False
        assert "incident 42" in body["verdict"]["reason"]


class TestMultiPlatform:
    async def push_multi(self, client, *, bad_platform="linux/amd64"):
        token = await make_user()
        headers = await bearer(client, "repository:local/team-a/multi:pull,push", token)
        amd, arm = Image.build("amd"), Image.build("arm")
        for img in (amd, arm):
            assert (await push_image(client, "local/team-a/multi", img.digest, img, headers)).status_code == 201
        body, digest = index_of((amd, "linux/amd64"), (arm, "linux/arm64"))
        resp = await client.put(
            "/v2/local/team-a/multi/manifests/1",
            content=body,
            headers={**headers, "Content-Type": "application/vnd.oci.image.index.v1+json"},
        )
        assert resp.status_code == 201, resp.text
        bad = amd if bad_platform == "linux/amd64" else arm
        await scan_all(client, {bad.digest: [vuln("CVE-2024-7777", "CRITICAL", fixed="3.0")]})
        return amd, arm, digest

    async def test_picks_the_platform(self, docker_env):
        client, _ = docker_env
        _amd, arm, index = await self.push_multi(client, bad_platform="linux/amd64")
        h = await user(client)
        body = (await inspect(client, "local/team-a/multi:1", h, platform="linux/arm64")).json()
        assert body["is_index"] is True
        assert body["digest"] == index
        assert sorted(body["platforms"]) == ["linux/amd64", "linux/arm64"]
        assert body["image"]["digest"] == arm.digest
        assert body["findings_total"] == 0

    async def test_index_verdict_wins_over_a_clean_platform(self, docker_env):
        """docker pull resolves the tag through the index, which takes its
        worst platform's verdict: a clean arm64 image does not make the tag
        pullable when amd64 is blocked."""
        client, _ = docker_env
        await self.push_multi(client, bad_platform="linux/amd64")
        h = await user(client)
        body = (await inspect(client, "local/team-a/multi:1", h, platform="linux/arm64")).json()
        assert body["verdict"]["allowed"] is False
        assert "linux/amd64" in body["verdict"]["reason"]

    async def test_platform_without_variant_matches_the_variant(self, docker_env):
        """Registries list arm64 as linux/arm64/v8; `docker pull --platform
        linux/arm64` takes it, and so does the lookup."""
        from app.api.docker_api import _pick_platform

        children = [{"platform": "linux/amd64"}, {"platform": "linux/arm64/v8"}, {"platform": "linux/arm/v7"}]
        assert _pick_platform(children, "linux/arm64") == {"platform": "linux/arm64/v8"}
        assert _pick_platform(children, "linux/arm/v7") == {"platform": "linux/arm/v7"}
        assert _pick_platform(children, "linux/arm/v6") is None
        assert _pick_platform(children, "linux/s390x") is None

    async def test_missing_platform_lists_what_exists(self, docker_env):
        client, _ = docker_env
        await self.push_multi(client)
        resp = await inspect(client, "local/team-a/multi:1", await user(client), platform="linux/s390x")
        assert resp.status_code == 404
        assert "linux/amd64" in resp.json()["detail"]


class TestImagesList:
    async def test_list_carries_the_pull_reference(self, docker_env):
        client, fake = docker_env
        fake.add_image("library/alpine", "3.20", Image.build("alpine"))
        h = await user(client)
        await inspect(client, "alpine:3.20", h)
        body = (await client.get("/api/docker/images", params={"q": "alpine"}, headers=h)).json()
        assert body["images"][0]["pull_reference"] == "registry.test/alpine"


class TestScanPlatforms:
    """The scan list's `linux/arm64` must cover `linux/arm64/v8`, which is how
    Docker Hub and most registries publish arm64."""

    def test_matching(self):
        from app.docker.policy import ImagePolicy

        p = ImagePolicy()
        assert p.platforms == ["linux/amd64", "linux/arm64"]
        assert p.scans_platform("linux/amd64")
        assert p.scans_platform("linux/arm64")
        assert p.scans_platform("linux/arm64/v8")
        assert not p.scans_platform("linux/arm/v7")
        assert not p.scans_platform("linux/s390x")
        assert p.scans_platform(None)  # a single-platform image with no index entry
        # A variant on the list matches only itself.
        assert not ImagePolicy(platforms=["linux/arm/v7"]).scans_platform("linux/arm/v6")
        assert ImagePolicy(platforms=[]).scans_platform("linux/s390x")

    async def test_arm64_v8_child_is_queued_for_a_scan(self, docker_env):
        client, fake = docker_env
        amd, arm = Image.build("amd"), Image.build("arm")
        body, _ = index_of((amd, "linux/amd64"), (arm, "linux/arm64/v8"))
        fake.add_index("library/multi", "1", body, amd, arm)
        h = await user(client)
        resp = await inspect(client, "multi:1", h, platform="linux/arm64")
        assert resp.status_code == 200, resp.text
        image = resp.json()["image"]
        assert image["digest"] == arm.digest
        assert image["platform"] == "linux/arm64/v8"
        assert image["scan_status"] == "queued"
