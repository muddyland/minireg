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


CRITICAL_FIXABLE = [vuln("CVE-2024-9999", "CRITICAL", fixed="2.0")]


class TestUnscannableIsNotAFreePass:
    """An image the scanner could not scan has not been scanned: strict
    mode and the push gate refuse it like any other unscanned image."""

    async def _fail(self, client, sh, *, permanent: bool, error: str):
        claim = await client.post("/api/docker/scanner/claim", json={"worker": "w1"}, headers=sh)
        assert claim.status_code == 200, claim.text
        job = claim.json()
        r = await client.post(
            f"/api/docker/scanner/jobs/{job['job_id']}/fail",
            json={"worker": "w1", "error": error, "permanent": permanent},
            headers=sh,
        )
        assert r.status_code == 200, r.text
        return job

    async def test_a_permanent_worker_failure_does_not_unlock_a_pushed_image(self, docker_env):
        from sqlalchemy import select

        from app import db
        from app.models import DockerManifest

        client, _ = docker_env
        ah = await admin(client)
        await set_policy(client, ah, hold_seconds=0.5)
        token = await make_user()
        ph = await bearer(client, "repository:local/hostile/app:pull,push", token)
        img = Image.build("pushcrash")
        assert (await push_image(client, "local/hostile/app", "1", img, ph)).status_code == 201
        sh = await scanner_headers(client)
        # An error text quoting the repository name ("hostile" contains
        # "os") was enough for the old worker to call it permanent.
        await self._fail(
            client, sh, permanent=True, error="unable to inspect local/hostile/app: unsupported media type"
        )
        async with db.session_scope() as s:
            m = (await s.execute(select(DockerManifest).where(DockerManifest.digest == img.digest))).scalar_one()
            assert m.scan_status == "failed"
        resp = await client.get("/v2/local/hostile/app/manifests/1", headers=ph)
        assert resp.status_code == 503, resp.text
        # ...and the pull queued it again.
        claim = await client.post("/api/docker/scanner/claim", json={"worker": "w1"}, headers=sh)
        assert claim.status_code == 200 and claim.json()["digest"] == img.digest
        for digest in img.blobs:
            r = await client.get(f"/v2/local/hostile/app/blobs/{digest}", headers=ph)
            assert r.status_code == 503, digest

    async def test_strict_mode_refuses_an_image_over_the_scan_limit(self, docker_env):
        client, fake = docker_env
        ah = await admin(client)
        await set_policy(client, ah, strict_mode=True, max_scan_bytes=10)
        img = Image.build("huge")
        fake.add_image("library/huge", "1", img)
        h = await bearer(client, "repository:huge:pull")
        assert (await client.get("/v2/huge/manifests/1", headers=h)).status_code == 503
        sh = await scanner_headers(client)
        claim = await client.post("/api/docker/scanner/claim", json={"worker": "w1"}, headers=sh)
        assert claim.status_code == 204  # skipped: over the limit
        resp = await client.get("/v2/huge/manifests/1", headers=h)
        assert resp.status_code == 403, resp.text
        message = resp.json()["errors"][0]["message"]
        assert "could not be scanned" in message and "scan limit" in message
        # Without strict mode an upstream image is still served unscanned.
        await set_policy(client, ah, strict_mode=False)
        assert (await client.get("/v2/huge/manifests/1", headers=h)).status_code == 200

    async def test_the_push_gate_refuses_a_pushed_image_over_the_scan_limit(self, docker_env):
        client, _ = docker_env
        ah = await admin(client)
        await set_policy(client, ah, max_scan_bytes=10, hold_seconds=0.5)
        token = await make_user()
        ph = await bearer(client, "repository:local/team/huge:pull,push", token)
        assert (await push_image(client, "local/team/huge", "1", Image.build("huge"), ph)).status_code == 201
        sh = await scanner_headers(client)
        assert (await client.post("/api/docker/scanner/claim", json={"worker": "w1"}, headers=sh)).status_code == 204
        resp = await client.get("/v2/local/team/huge/manifests/1", headers=ph)
        assert resp.status_code == 403, resp.text
        assert "could not be scanned" in resp.json()["errors"][0]["message"]
        await set_policy(client, ah, push_require_scan=False)
        assert (await client.get("/v2/local/team/huge/manifests/1", headers=ph)).status_code == 200


class TestWorkerFailureReports:
    def _load_worker(self):
        import importlib.util
        from pathlib import Path

        path = Path(__file__).resolve().parents[2] / "scanner" / "worker.py"
        spec = importlib.util.spec_from_file_location("minireg_scanner_worker", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_no_failure_is_reported_as_permanent(self, monkeypatch):
        """The old guess ("unsupported" and "os" anywhere in the text)
        matched repository names and Trivy's ordinary errors."""
        worker = self._load_worker()
        sent = []

        def fake_api_json(method, path, payload=None):
            if path.endswith("/claim"):
                return {"job_id": 7, "mode": "image", "image": "local/hostile/app@sha256:x", "lease_seconds": 120}
            sent.append((path, payload))
            return {}

        def failing_scan(job, workdir):
            raise RuntimeError(
                "unable to inspect minireg:8000/local/hostile/app@sha256:abc: unsupported media type; unsupported os"
            )

        monkeypatch.setattr(worker, "ensure_db", lambda: None)
        monkeypatch.setattr(worker, "api_json", fake_api_json)
        monkeypatch.setattr(worker, "scan_image", failing_scan)
        assert worker.work_one() is True
        [(path, payload)] = sent
        assert path == "/api/docker/scanner/jobs/7/fail"
        assert not payload.get("permanent")
        assert "unsupported" in payload["error"]


class TestPushBarFollowsTheRepository:
    """The push rules apply to what local/ serves, whatever the bytes'
    origin, and never to what an upstream repository serves. The manifest
    row is shared by every repository holding a digest, so it cannot carry
    the verdict."""

    async def test_upstream_bytes_pushed_here_meet_the_push_bar(self, docker_env):
        client, fake = docker_env
        img = Image.build("upbase")
        fake.add_image("library/upbase", "1", img)
        h = await bearer(client, "repository:upbase:pull")
        assert (await client.get("/v2/upbase/manifests/1", headers=h)).status_code == 200
        sh = await scanner_headers(client)
        _, r = await run_scan(client, sh, trivy_report(CRITICAL_FIXABLE))
        assert r.status_code == 200, r.text
        # The pull rules allow it (the default).
        assert (await client.get("/v2/upbase/manifests/1", headers=h)).status_code == 200

        token = await make_user()
        ph = await bearer(client, "repository:local/team/app:pull,push", token)
        assert (await push_image(client, "local/team/app", "1", img, ph)).status_code == 201
        resp = await client.get("/v2/local/team/app/manifests/1", headers=ph)
        assert resp.status_code == 403, resp.text
        assert "push policy" in resp.json()["errors"][0]["message"]
        # Its layers too, from there.
        layer = img.layers[0]
        from tests.docker_helpers import sha

        assert (await client.get(f"/v2/local/team/app/blobs/{sha(layer)}", headers=ph)).status_code == 403
        # Through the upstream nothing changed.
        assert (await client.get("/v2/upbase/manifests/1", headers=h)).status_code == 200

    async def test_upstream_bytes_pushed_here_wait_for_their_scan(self, docker_env):
        client, fake = docker_env
        ah = await admin(client)
        await set_policy(client, ah, hold_seconds=0.5)
        img = Image.build("unscanned-base")
        fake.add_image("library/unscanned-base", "1", img)
        h = await bearer(client, "repository:unscanned-base:pull")
        # Upstream pulls do not wait for the scan (no strict mode)...
        assert (await client.get("/v2/unscanned-base/manifests/1", headers=h)).status_code == 200
        token = await make_user()
        ph = await bearer(client, "repository:local/team/app:pull,push", token)
        assert (await push_image(client, "local/team/app", "1", img, ph)).status_code == 201
        # ...pulls of a pushed image do.
        resp = await client.get("/v2/local/team/app/manifests/1", headers=ph)
        assert resp.status_code == 503, resp.text
        sh = await scanner_headers(client)
        _, r = await run_scan(client, sh, trivy_report(CRITICAL_FIXABLE))
        assert r.status_code == 200, r.text
        assert (await client.get("/v2/local/team/app/manifests/1", headers=ph)).status_code == 403
        assert (await client.get("/v2/unscanned-base/manifests/1", headers=h)).status_code == 200

    async def test_a_push_does_not_block_upstream_pulls_of_the_same_bytes(self, docker_env):
        client, fake = docker_env
        img = Image.build("newrelease")
        token = await make_user()
        ph = await bearer(client, "repository:local/x/y:pull,push", token)
        assert (await push_image(client, "local/x/y", "1", img, ph)).status_code == 201
        sh = await scanner_headers(client)
        _, r = await run_scan(client, sh, trivy_report(CRITICAL_FIXABLE))
        assert r.status_code == 200, r.text
        assert (await client.get("/v2/local/x/y/manifests/1", headers=ph)).status_code == 403

        # The same bytes are (or later get) published upstream.
        fake.add_image("library/newrelease", "1", img)
        h = await bearer(client, "repository:newrelease:pull")
        resp = await client.get("/v2/newrelease/manifests/1", headers=h)
        assert resp.status_code == 200, resp.text
        assert (await client.get("/v2/local/x/y/manifests/1", headers=ph)).status_code == 403

        # The UI shows the verdict where it applies, and only there.
        viewer = {"Authorization": f"Bearer {await make_user(username='viewer', scopes=('read',))}"}
        local = (await client.get("/api/docker/repository?name=local/x/y", headers=viewer)).json()
        assert "push policy" in local["tags"][0]["manifest"]["policy_block_reason"]
        cached = (
            await client.get("/api/docker/repository?name=dockerhub/library/newrelease", headers=viewer)
        ).json()
        assert cached["tags"][0]["manifest"]["policy_block_reason"] is None
        stats = (await client.get("/api/docker/stats", headers=await admin(client))).json()
        assert stats["push_blocked_images"] == 1

    async def test_old_verdicts_move_to_local_repositories_on_startup(self, docker_env):
        """Before the per-repository column, the verdict sat on the manifest
        row. The startup data fix carries it to the local repositories and
        clears it, so upstream pulls of those bytes stop being refused."""
        from sqlalchemy import select, update

        from app import db
        from app.models import DockerManifest, DockerRepoManifest

        client, fake = docker_env
        img = Image.build("legacy")
        token = await make_user()
        ph = await bearer(client, "repository:local/old/img:pull,push", token)
        assert (await push_image(client, "local/old/img", "1", img, ph)).status_code == 201
        fake.add_image("library/legacy", "1", img)
        sh = await scanner_headers(client)
        _, r = await run_scan(client, sh, trivy_report([]))
        assert r.status_code == 200, r.text
        h = await bearer(client, "repository:legacy:pull")
        assert (await client.get("/v2/legacy/manifests/1", headers=h)).status_code == 200
        async with db.session_scope() as s:
            await s.execute(
                update(DockerManifest)
                .where(DockerManifest.digest == img.digest)
                .values(policy_block_reason="push policy: from the old column")
            )

        await db.create_schema()
        await db.create_schema()  # idempotent

        async with db.session_scope() as s:
            m = (await s.execute(select(DockerManifest).where(DockerManifest.digest == img.digest))).scalar_one()
            assert m.policy_block_reason is None
            reasons = sorted(
                (r or "")
                for r in (
                    await s.execute(
                        select(DockerRepoManifest.push_block_reason).where(DockerRepoManifest.manifest_id == m.id)
                    )
                ).scalars()
            )
        assert reasons == ["", "push policy: from the old column"]
        resp = await client.get("/v2/local/old/img/manifests/1", headers=ph)
        assert resp.status_code == 403
        assert "from the old column" in resp.json()["errors"][0]["message"]
        assert (await client.get("/v2/legacy/manifests/1", headers=h)).status_code == 200


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


class TestScannerToken:
    """Minting the worker's token from the API tokens page."""

    async def mint(self, client, token, scopes):
        return await client.post(
            "/api/auth/tokens",
            json={"name": "scanner", "scopes": scopes},
            headers={"Authorization": f"Bearer {token}"},
        )

    async def test_admin_mints_a_working_scanner_token(self, docker_env):
        client, _ = docker_env
        root = await make_user(username="root", scopes=("admin",), is_admin=True)
        resp = await self.mint(client, root, ["scanner"])
        assert resp.status_code == 201, resp.text
        assert resp.json()["scopes"] == ["scanner"]
        sh = {"Authorization": f"Bearer {resp.json()['token']}"}
        assert (await client.get("/api/docker/scanner/config", headers=sh)).status_code == 200

    async def test_scanner_scope_stands_alone(self, docker_env):
        client, _ = docker_env
        root = await make_user(username="root", scopes=("admin",), is_admin=True)
        for extra in (["admin"], ["read"], ["docker:push"]):
            resp = await self.mint(client, root, ["scanner", *extra])
            assert resp.status_code == 400, extra
            assert "cannot carry other scopes" in resp.json()["detail"]
