"""Scan queue, worker protocol, report ingestion and image policy."""

from __future__ import annotations

import base64
import json

from app.docker import scanning
from app.docker.policy import GateRules, ImagePolicy
from tests.docker_helpers import (
    Image,
    bearer,
    make_user,
)
from tests.test_docker_push import push_image


def trivy_report(vulns: list[dict], *, os_family="debian", os_name="13.7") -> bytes:
    return json.dumps(
        {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.74.0", "VulnerabilityDB": {"UpdatedAt": "2026-09-29T01:13:17.183597831Z"}},
            "Metadata": {"OS": {"Family": os_family, "Name": os_name}},
            "Results": [{"Target": "img", "Class": "os-pkgs", "Type": os_family, "Vulnerabilities": vulns}],
        }
    ).encode()


def vuln(vid, sev, fixed=None, cvss=None, pkg="openssl"):
    v = {
        "VulnerabilityID": vid,
        "PkgName": pkg,
        "InstalledVersion": "1.0",
        "Severity": sev,
        "Title": f"<script>alert('{vid}')</script>",
        "PrimaryURL": f"https://avd.aquasec.com/nvd/{vid.lower()}",
        "Layer": {"Digest": "sha256:" + "a" * 64},
    }
    if fixed:
        v["FixedVersion"] = fixed
    if cvss is not None:
        v["CVSS"] = {"nvd": {"V3Score": cvss}}
    return v


SBOM = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}).encode()


async def scanner_headers(client):
    token = await make_user(username="scanner-bot", scopes=("scanner",), is_admin=True)
    return {"Authorization": f"Bearer {token}"}


async def pull_image(client, fake, repo="library/alpine", tag="3.20", name="alpine", seed="alpine"):
    img = Image.build(seed)
    fake.add_image(repo, tag, img)
    headers = await bearer(client, f"repository:{name}:pull")
    resp = await client.get(f"/v2/{name}/manifests/{tag}", headers=headers)
    assert resp.status_code == 200, resp.text
    return img, headers


async def run_scan(client, sh, report: bytes, sbom: bytes | None = SBOM):
    claim = await client.post("/api/docker/scanner/claim", json={"worker": "w1"}, headers=sh)
    assert claim.status_code == 200, claim.text
    job = claim.json()
    files = {"report": ("report.json", report, "application/json")}
    if sbom is not None:
        files["sbom"] = ("sbom.json", sbom, "application/json")
    resp = await client.post(
        f"/api/docker/scanner/jobs/{job['job_id']}/result", data={"worker": "w1"}, files=files, headers=sh
    )
    return job, resp


async def set_policy(client, admin_headers, **changes):
    current = (await client.get("/api/docker/policy", headers=admin_headers)).json()
    current.update(changes)
    resp = await client.put("/api/docker/policy", json=current, headers=admin_headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


async def admin(client):
    token = await make_user(username="root", scopes=("admin",), is_admin=True)
    return {"Authorization": f"Bearer {token}"}


class TestQueue:
    async def test_pull_queues_one_scan(self, docker_env):
        client, fake = docker_env
        _img, headers = await pull_image(client, fake)
        for _ in range(3):
            await client.get("/v2/alpine/manifests/3.20", headers=headers)
        from sqlalchemy import func, select

        from app import db
        from app.models import DockerScanJob

        async with db.session_scope() as s:
            n = (await s.execute(select(func.count()).select_from(DockerScanJob))).scalar_one()
        assert n == 1

    async def test_claim_returns_image_reference(self, docker_env):
        client, fake = docker_env
        img, _ = await pull_image(client, fake)
        sh = await scanner_headers(client)
        resp = await client.post("/api/docker/scanner/claim", json={"worker": "w1"}, headers=sh)
        job = resp.json()
        assert job["digest"] == img.digest
        assert job["image"] == f"dockerhub/library/alpine@{img.digest}"
        assert job["mode"] == "image"
        # Nothing else queued.
        resp = await client.post("/api/docker/scanner/claim", json={"worker": "w2"}, headers=sh)
        assert resp.status_code == 204

    async def test_scanner_routes_need_scanner_scope(self, docker_env):
        client, _ = docker_env
        token = await make_user(username="root", scopes=("admin",), is_admin=True)
        resp = await client.post(
            "/api/docker/scanner/claim", json={"worker": "x"}, headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403

    async def test_scanner_can_pull_quarantined(self, docker_env):
        client, fake = docker_env
        await pull_image(client, fake)
        ah = await admin(client)
        await client.patch(
            "/api/docker/repository?name=dockerhub/library/alpine", json={"quarantined": True}, headers=ah
        )
        headers = await bearer(client, "repository:alpine:pull")
        assert (await client.get("/v2/alpine/manifests/3.20", headers=headers)).status_code == 403
        token = await make_user(username="scanner-bot", scopes=("scanner",), is_admin=True)
        basic = {"Authorization": "Basic " + base64.b64encode(f"s:{token}".encode()).decode()}
        assert (await client.get("/v2/alpine/manifests/3.20", headers=basic)).status_code == 200


class TestIngest:
    async def test_findings_recorded_and_sanitised(self, docker_env):
        client, fake = docker_env
        img, _ = await pull_image(client, fake)
        sh = await scanner_headers(client)
        report = trivy_report(
            [
                vuln("CVE-2024-0001", "CRITICAL", fixed="1.1", cvss=9.8),
                vuln("CVE-2024-0002", "HIGH"),
                vuln("CVE-2024-0002", "HIGH"),  # duplicate collapses
                {"VulnerabilityID": "../../etc/passwd", "Severity": "HIGH", "PkgName": "x"},
                vuln("CVE-2024-0003", "LOW"),
            ]
        )
        _job, resp = await run_scan(client, sh, report)
        assert resp.status_code == 200, resp.text
        assert resp.json()["findings"] == 3
        user = {"Authorization": f"Bearer {await make_user(username='viewer', scopes=('read',))}"}
        detail = (await client.get(f"/api/docker/manifest/{img.digest}", headers=user)).json()
        assert detail["scan_status"] == "scanned"
        assert detail["severity_counts"]["CRITICAL"] == 1
        assert detail["fixable_count"] == 1
        assert detail["has_sbom"] is True
        findings = (await client.get(f"/api/docker/manifest/{img.digest}/findings", headers=user)).json()
        ids = [f["vuln_id"] for f in findings["findings"]]
        assert ids[0] == "CVE-2024-0001"  # ordered by CVSS
        assert "../../etc/passwd" not in ids
        # Stored as text; the UI renders it as text, never HTML.
        assert findings["findings"][0]["title"].startswith("<script>")

    async def test_oversized_report_rejected(self, docker_env, monkeypatch):
        client, fake = docker_env
        await pull_image(client, fake)
        sh = await scanner_headers(client)
        monkeypatch.setattr(scanning, "MAX_REPORT_BYTES", 100)
        _job, resp = await run_scan(client, sh, trivy_report([vuln("CVE-2024-0001", "LOW")]))
        assert resp.status_code in (413, 422)

    async def test_not_json_rejected_and_retried(self, docker_env):
        client, fake = docker_env
        _img, _ = await pull_image(client, fake)
        sh = await scanner_headers(client)
        job, resp = await run_scan(client, sh, b"not json at all")
        assert resp.status_code == 422
        from app import db
        from app.models import DockerScanJob

        async with db.session_scope() as s:
            row = await s.get(DockerScanJob, job["job_id"])
        assert row.status == "queued"  # retried, attempts < max
        assert "rejected report" in row.error

    async def test_bad_sbom_rejected(self, docker_env):
        client, fake = docker_env
        await pull_image(client, fake)
        sh = await scanner_headers(client)
        _job, resp = await run_scan(client, sh, trivy_report([]), sbom=b'{"bomFormat":"SPDX"}')
        assert resp.status_code == 422

    async def test_rescan_uses_sbom(self, docker_env):
        client, fake = docker_env
        img, _ = await pull_image(client, fake)
        sh = await scanner_headers(client)
        await run_scan(client, sh, trivy_report([vuln("CVE-2024-0001", "HIGH")]))
        ah = await admin(client)
        resp = await client.post(f"/api/docker/manifest/{img.digest}/rescan", headers=ah)
        assert resp.json() == {"queued": True, "mode": "sbom"}
        claim = (await client.post("/api/docker/scanner/claim", json={"worker": "w1"}, headers=sh)).json()
        assert claim["mode"] == "sbom"
        sbom = await client.get(f"/api/docker/scanner/jobs/{claim['job_id']}/sbom", headers=sh)
        assert sbom.status_code == 200
        assert sbom.json()["bomFormat"] == "CycloneDX"

    async def test_lease_expiry_requeues(self, docker_env):
        client, fake = docker_env
        await pull_image(client, fake)
        sh = await scanner_headers(client)
        claim = (await client.post("/api/docker/scanner/claim", json={"worker": "w1"}, headers=sh)).json()
        from datetime import UTC, datetime, timedelta

        from app import db
        from app.models import DockerScanJob

        async with db.session_scope() as s:
            row = await s.get(DockerScanJob, claim["job_id"])
            row.lease_until = datetime.now(UTC) - timedelta(seconds=1)
        again = await client.post("/api/docker/scanner/claim", json={"worker": "w2"}, headers=sh)
        assert again.status_code == 200
        assert again.json()["job_id"] == claim["job_id"]
        # The first worker's late result is refused.
        resp = await client.post(
            f"/api/docker/scanner/jobs/{claim['job_id']}/result",
            data={"worker": "w1"},
            files={"report": ("r.json", trivy_report([]), "application/json")},
            headers=sh,
        )
        assert resp.status_code == 409


class TestPolicy:
    def test_defaults_are_permissive_for_pulls_strict_for_pushes(self):
        p = ImagePolicy.from_dict(None)
        assert p.pull.block_kev is False and p.pull.block_severity is None
        assert p.push.block_kev is True and p.push.block_severity == "CRITICAL"
        assert p.hold_enabled is False and p.strict_mode is False

    def test_bad_values_are_clamped(self):
        p = ImagePolicy.from_dict({"hold_seconds": 9999, "rescan_hours": -5, "pull": {"block_severity": "nope"}})
        assert p.hold_seconds == 120.0
        assert p.rescan_hours == 1
        assert p.pull.block_severity is None
        assert GateRules.from_dict({"block_severity": "high"}).block_severity == "HIGH"

    async def test_deny_list_blocks_pull_with_reason(self, docker_env):
        client, fake = docker_env
        _img, headers = await pull_image(client, fake)
        sh = await scanner_headers(client)
        await run_scan(client, sh, trivy_report([vuln("CVE-2021-44228", "CRITICAL", cvss=10.0)]))
        ah = await admin(client)
        await set_policy(client, ah, deny_cves=["CVE-2021-44228"])
        resp = await client.get("/v2/alpine/manifests/3.20", headers=headers)
        assert resp.status_code == 403
        err = resp.json()["errors"][0]
        assert err["code"] == "DENIED"
        assert "CVE-2021-44228" in err["message"]

    async def test_kev_blocks_pull_when_enabled(self, docker_env):
        client, fake = docker_env
        _img, headers = await pull_image(client, fake)
        from app import db
        from app.models import KevEntry

        async with db.session_scope() as s:
            s.add(KevEntry(cve_id="CVE-2024-3094", vendor="xz", product="xz"))
        sh = await scanner_headers(client)
        await run_scan(client, sh, trivy_report([vuln("CVE-2024-3094", "CRITICAL", pkg="xz-utils")]))
        assert (await client.get("/v2/alpine/manifests/3.20", headers=headers)).status_code == 200
        ah = await admin(client)
        await set_policy(client, ah, pull={"block_kev": True})
        resp = await client.get("/v2/alpine/manifests/3.20", headers=headers)
        assert resp.status_code == 403
        assert "CISA KEV" in resp.json()["errors"][0]["message"]

    async def test_accepted_risk_does_not_count(self, docker_env):
        client, fake = docker_env
        _img, headers = await pull_image(client, fake)
        sh = await scanner_headers(client)
        await run_scan(client, sh, trivy_report([vuln("CVE-2024-0001", "CRITICAL", fixed="2")]))
        ah = await admin(client)
        await set_policy(client, ah, pull={"block_severity": "CRITICAL"})
        assert (await client.get("/v2/alpine/manifests/3.20", headers=headers)).status_code == 403
        await set_policy(client, ah, allow_cves=["CVE-2024-0001"])
        assert (await client.get("/v2/alpine/manifests/3.20", headers=headers)).status_code == 200

    async def test_strict_mode_503_until_scanned(self, docker_env):
        client, fake = docker_env
        ah = await admin(client)
        await set_policy(client, ah, strict_mode=True)
        img = Image.build("strict")
        fake.add_image("library/strict", "1", img)
        headers = await bearer(client, "repository:strict:pull")
        resp = await client.get("/v2/strict/manifests/1", headers=headers)
        assert resp.status_code == 503
        assert resp.headers["retry-after"] == "15"
        assert resp.json()["errors"][0]["code"] == "UNAVAILABLE"
        sh = await scanner_headers(client)
        await run_scan(client, sh, trivy_report([]))
        assert (await client.get("/v2/strict/manifests/1", headers=headers)).status_code == 200

    async def test_hold_is_size_gated(self, docker_env):
        """A hold on an image over hold_max_bytes would only tie up the
        connection; it is served straight away and scanned in the background."""
        client, fake = docker_env
        ah = await admin(client)
        await set_policy(client, ah, hold_enabled=True, hold_seconds=5, hold_max_bytes=10)
        import time

        img = Image.build("big", layer_sizes=(5000,))
        fake.add_image("library/big", "1", img)
        headers = await bearer(client, "repository:big:pull")
        started = time.monotonic()
        resp = await client.get("/v2/big/manifests/1", headers=headers)
        assert resp.status_code == 200
        assert time.monotonic() - started < 2

    async def test_push_policy_blocks_pushed_image(self, docker_env):
        client, _ = docker_env
        token = await make_user()
        headers = await bearer(client, "repository:local/team/app:pull,push", token)
        img = Image.build("pushed")
        assert (await push_image(client, "local/team/app", "1", img, headers)).status_code == 201
        # Pull waits for the scan; with no worker it answers 503.
        ah = await admin(client)
        await set_policy(client, ah, hold_seconds=0.5)
        resp = await client.get("/v2/local/team/app/manifests/1", headers=headers)
        assert resp.status_code == 503
        sh = await scanner_headers(client)
        await run_scan(client, sh, trivy_report([vuln("CVE-2024-9999", "CRITICAL", fixed="2.0")]))
        resp = await client.get("/v2/local/team/app/manifests/1", headers=headers)
        assert resp.status_code == 403
        assert "push policy" in resp.json()["errors"][0]["message"]
        # Relaxing the push bar re-judges existing images.
        await set_policy(client, ah, push={"block_kev": True, "block_severity": None})
        assert (await client.get("/v2/local/team/app/manifests/1", headers=headers)).status_code == 200

    async def test_blocked_platform_blocks_the_tag(self, docker_env):
        """docker buildx pushes an index. A client that already holds the
        child manifest (the build machine, say) only ever asks for the
        index, so the block has to be enforced there too."""
        from tests.docker_helpers import index_of

        client, _ = docker_env
        token = await make_user()
        headers = await bearer(client, "repository:local/team-a/multi:pull,push", token)
        amd, arm = Image.build("amd-old"), Image.build("arm-ok")
        for img in (amd, arm):
            assert (await push_image(client, "local/team-a/multi", img.digest, img, headers)).status_code == 201
        body, _digest = index_of((amd, "linux/amd64"), (arm, "linux/arm64"))
        resp = await client.put(
            "/v2/local/team-a/multi/manifests/1",
            content=body,
            headers={**headers, "Content-Type": "application/vnd.oci.image.index.v1+json"},
        )
        assert resp.status_code == 201, resp.text
        sh = await scanner_headers(client)
        for _ in range(2):
            claim = (await client.post("/api/docker/scanner/claim", json={"worker": "w1"}, headers=sh)).json()
            vulns = [vuln("CVE-2024-7777", "CRITICAL", fixed="3.0")] if claim["digest"] == amd.digest else []
            r = await client.post(
                f"/api/docker/scanner/jobs/{claim['job_id']}/result",
                data={"worker": "w1"},
                files={"report": ("r.json", trivy_report(vulns), "application/json")},
                headers=sh,
            )
            assert r.status_code == 200, r.text
        resp = await client.get("/v2/local/team-a/multi/manifests/1", headers=headers)
        assert resp.status_code == 403
        assert "linux/amd64" in resp.json()["errors"][0]["message"]
        # The clean platform alone is still fine to pull by digest.
        assert (await client.get(f"/v2/local/team-a/multi/manifests/{arm.digest}", headers=headers)).status_code == 200

    async def test_unfixed_does_not_trip_push_bar(self, docker_env):
        client, _ = docker_env
        token = await make_user()
        headers = await bearer(client, "repository:local/team/app:pull,push", token)
        await push_image(client, "local/team/app", "1", Image.build("nofix"), headers)
        sh = await scanner_headers(client)
        await run_scan(client, sh, trivy_report([vuln("CVE-2024-8888", "CRITICAL")]))
        assert (await client.get("/v2/local/team/app/manifests/1", headers=headers)).status_code == 200

    async def test_denied_pull_is_audited(self, docker_env):
        client, fake = docker_env
        _img, headers = await pull_image(client, fake)
        ah = await admin(client)
        await client.patch(
            "/api/docker/repository?name=dockerhub/library/alpine",
            json={"quarantined": True, "quarantine_reason": "incident 42"},
            headers=ah,
        )
        resp = await client.get("/v2/alpine/manifests/3.20", headers=headers)
        assert resp.status_code == 403
        assert "incident 42" in resp.json()["errors"][0]["message"]


class TestCveSearch:
    async def test_which_images_contain_a_cve(self, docker_env):
        client, fake = docker_env
        img, _ = await pull_image(client, fake)
        sh = await scanner_headers(client)
        await run_scan(client, sh, trivy_report([vuln("CVE-2024-0001", "HIGH", fixed="1.1", cvss=8.1)]))
        user = {"Authorization": f"Bearer {await make_user(username='viewer', scopes=('read',))}"}
        resp = await client.get("/api/docker/vulnerabilities?cve=cve-2024-0001", headers=user)
        body = resp.json()
        assert len(body["images"]) == 1
        assert body["images"][0]["digest"] == img.digest
        assert "dockerhub/library/alpine:3.20" in body["images"][0]["where"]


class TestKev:
    async def test_refresh_and_reflag(self, docker_env, monkeypatch):
        import httpx
        import respx

        client, fake = docker_env
        img, _ = await pull_image(client, fake)
        sh = await scanner_headers(client)
        await run_scan(client, sh, trivy_report([vuln("CVE-2024-3094", "CRITICAL")]))
        from app.config import settings

        monkeypatch.setattr(settings, "kev_feed_url", "https://kev.upstream.test/kev.json")
        monkeypatch.setattr(settings, "upstream_artifact_hosts", settings.upstream_artifact_hosts + ",kev.upstream.test")
        feed = {"vulnerabilities": [{"cveID": "CVE-2024-3094", "vendorProject": "Tukaani", "product": "xz", "knownRansomwareCampaignUse": "Unknown"}]}
        from app import db

        with respx.mock(assert_all_called=False) as r:
            r.get("https://kev.upstream.test/kev.json").mock(return_value=httpx.Response(200, json=feed))
            async with db.session_scope() as s:
                n = await scanning.refresh_kev(s)
        assert n == 1
        from app.models import DockerManifest

        async with db.session_scope() as s:
            from sqlalchemy import select

            m = (await s.execute(select(DockerManifest).where(DockerManifest.digest == img.digest))).scalar_one()
        assert m.kev_count == 1


class TestScannerConfig:
    """Where the worker is told to fetch Trivy's database from."""

    async def add_ghcr(self):
        from app import db as db_module
        from app.models import Ecosystem, Upstream, UpstreamKind

        async with db_module.session_scope() as session:
            session.add(
                Upstream(
                    name="ghcr", ecosystem=Ecosystem.docker, kind=UpstreamKind.oci,
                    url="https://ghcr.io", tier=1, enabled=True, extra={},
                )
            )

    async def test_no_ghcr_upstream_means_trivy_default(self, docker_env):
        client, _ = docker_env
        cfg = (await client.get("/api/docker/scanner/config", headers=await scanner_headers(client))).json()
        assert cfg["db_repository"] is None

    async def test_db_through_the_ghcr_cache_on_the_public_origin(self, docker_env):
        client, _ = docker_env
        await self.add_ghcr()
        cfg = (await client.get("/api/docker/scanner/config", headers=await scanner_headers(client))).json()
        assert cfg["db_repository"] == "registry.test/ghcr/aquasecurity/trivy-db:2"
        assert cfg["insecure"] is True

    async def test_sidecar_on_the_internal_origin_stays_there(self, docker_env, monkeypatch):
        from app.config import settings

        client, _ = docker_env
        monkeypatch.setattr(settings, "docker_internal_url", "http://minireg:8000")
        await self.add_ghcr()
        headers = {**await scanner_headers(client), "Host": "minireg:8000"}
        cfg = (await client.get("/api/docker/scanner/config", headers=headers)).json()
        assert cfg["db_repository"] == "minireg:8000/ghcr/aquasecurity/trivy-db:2"
        assert cfg["registry"] == "http://minireg:8000"
