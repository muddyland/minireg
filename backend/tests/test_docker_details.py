"""Image details for the tag view: config, build history, layers, SBOM packages."""

from __future__ import annotations

import json

from app.docker import details
from tests.docker_helpers import Image, make_user
from tests.test_docker_inspect import inspect, scan_all, user
from tests.test_docker_scan import scanner_headers, trivy_report, vuln

CONFIG = {
    "architecture": "amd64",
    "os": "linux",
    "created": "2026-09-30T03:30:25Z",
    "config": {
        "Env": ["PATH=/usr/local/bin:/usr/bin", "LANG=C.UTF-8"],
        "Cmd": ["python3"],
        "Entrypoint": ["/entrypoint.sh"],
        "User": "app",
        "WorkingDir": "/srv",
        "ExposedPorts": {"8080/tcp": {}},
        "Labels": {"org.opencontainers.image.source": "https://example.com/app"},
    },
    "history": [
        {"created_by": "/bin/sh -c #(nop) ADD file:abc in /"},
        {"created_by": "/bin/sh -c #(nop)  ENV LANG=C.UTF-8", "empty_layer": True},
        {"created_by": "RUN apt-get install -y python3 # buildkit"},
        {"created_by": '/bin/sh -c #(nop)  CMD ["python3"]', "empty_layer": True},
    ],
    "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "1" * 64, "sha256:" + "2" * 64]},
}


def sbom(layer: str) -> bytes:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "metadata": {
                "timestamp": "2026-09-30T03:33:51+00:00",
                "tools": {"components": [{"name": "trivy", "version": "0.74.0"}]},
            },
            "components": [
                {"type": "operating-system", "name": "debian", "version": "12.7"},
                {
                    "type": "library",
                    "name": "openssl",
                    "version": "1.0",
                    "purl": "pkg:deb/debian/openssl@1.0",
                    "licenses": [{"license": {"id": "Apache-2.0"}}],
                    "properties": [
                        {"name": "aquasecurity:trivy:PkgType", "value": "debian"},
                        {"name": "aquasecurity:trivy:LayerDigest", "value": layer},
                    ],
                },
                {
                    "type": "library",
                    "name": "requests",
                    "version": "2.31.0",
                    "licenses": [{"expression": "Apache-2.0 OR MIT"}],
                    "properties": [
                        {"name": "aquasecurity:trivy:PkgType", "value": "python-pkg"},
                        {"name": "aquasecurity:trivy:FilePath", "value": "usr/lib/python3/requests/METADATA"},
                    ],
                },
            ],
        }
    ).encode()


async def scanned_image(client, fake):
    img = Image.build("app", config=CONFIG)
    fake.add_image("library/app", "1", img)
    h = await user(client)
    await inspect(client, "app:1", h)
    sh = await scanner_headers(client)
    job = (await client.post("/api/docker/scanner/claim", json={"worker": "w1"}, headers=sh)).json()
    from tests.docker_helpers import sha

    layer = sha(img.layers[1])
    r = await client.post(
        f"/api/docker/scanner/jobs/{job['job_id']}/result",
        data={"worker": "w1"},
        files={
            "report": ("r.json", trivy_report([vuln("CVE-2024-1", "HIGH", fixed="1.1")]), "application/json"),
            "sbom": ("s.json", sbom(layer), "application/json"),
        },
        headers=sh,
    )
    assert r.status_code == 200, r.text
    return img, h, layer


class TestConfig:
    async def test_config_and_history_paired_with_layers(self, docker_env):
        client, fake = docker_env
        img, h, _ = await scanned_image(client, fake)
        body = (await client.get(f"/api/docker/manifest/{img.digest}/config", headers=h)).json()
        assert body["available"] is True
        cfg = body["config"]
        assert cfg["entrypoint"] == ["/entrypoint.sh"]
        assert cfg["cmd"] == ["python3"]
        assert cfg["user"] == "app"
        assert cfg["exposed_ports"] == ["8080/tcp"]
        assert cfg["labels"]["org.opencontainers.image.source"] == "https://example.com/app"
        assert len(cfg["history"]) == 4
        # Two layers, two non-empty history steps: paired in order.
        assert [layer["created_by"] for layer in body["layers"]] == [
            "/bin/sh -c #(nop) ADD file:abc in /",
            "RUN apt-get install -y python3 # buildkit",
        ]
        assert body["layers"][1]["diff_id"] == "sha256:" + "2" * 64

    async def test_config_fetched_from_upstream_when_not_cached(self, docker_env):
        """Looking an image up fetches manifests only; the config (a few KB)
        is fetched on demand, not left as 'unavailable'."""
        client, fake = docker_env
        img = Image.build("cold", config=CONFIG)
        fake.add_image("library/cold", "1", img)
        h = await user(client)
        await inspect(client, "cold:1", h)
        assert fake.calls.get("blob", 0) == 0
        body = (await client.get(f"/api/docker/manifest/{img.digest}/config", headers=h)).json()
        assert body["available"] is True
        assert body["config"]["cmd"] == ["python3"]
        assert fake.calls["blob"] == 1  # the config, not the layers

    async def test_index_has_no_config(self, docker_env):
        client, _ = docker_env
        from tests.test_docker_inspect import TestMultiPlatform

        await TestMultiPlatform().push_multi(client)
        h = await user(client)
        index = (await inspect(client, "local/team-a/multi:1", h)).json()["digest"]
        assert (await client.get(f"/api/docker/manifest/{index}/config", headers=h)).status_code == 404

    async def test_needs_a_login(self, docker_env):
        client, fake = docker_env
        img, _h, _ = await scanned_image(client, fake)
        assert (await client.get(f"/api/docker/manifest/{img.digest}/config")).status_code == 401


class TestPackages:
    async def test_sbom_as_a_package_list(self, docker_env):
        client, fake = docker_env
        img, h, layer = await scanned_image(client, fake)
        body = (await client.get(f"/api/docker/manifest/{img.digest}/packages", headers=h)).json()
        assert body["format"] == "CycloneDX 1.7"
        assert body["tool"] == "trivy 0.74.0"
        assert body["os"] == "debian 12.7"
        assert body["total"] == 2
        assert body["by_type"] == {"debian": 1, "python-pkg": 1}
        openssl = next(c for c in body["components"] if c["name"] == "openssl")
        assert openssl["layer_digest"] == layer
        assert openssl["licenses"] == ["Apache-2.0"]
        requests = next(c for c in body["components"] if c["name"] == "requests")
        assert requests["licenses"] == ["Apache-2.0 OR MIT"]
        assert requests["path"].endswith("METADATA")
        # The scan's finding is attached to the package it is in.
        assert body["findings_by_package"] == {"openssl@1.0": {"HIGH": 1}}

    async def test_no_sbom_yet_is_404(self, docker_env):
        client, fake = docker_env
        img = Image.build("new")
        fake.add_image("library/new", "1", img)
        h = await user(client)
        await inspect(client, "new:1", h)
        resp = await client.get(f"/api/docker/manifest/{img.digest}/packages", headers=h)
        assert resp.status_code == 404


class TestParsersOnHostileInput:
    def test_config_garbage(self):
        assert details.parse_config(b"not json") is None
        assert details.parse_config(b"[]") is None
        cfg = details.parse_config(b'{"config": "nope", "history": "nope", "rootfs": 7}')
        assert cfg["history"] == [] and cfg["env"] == [] and cfg["diff_ids"] == []

    def test_history_pairing_refuses_to_guess(self):
        history = [{"created_by": "a"}, {"created_by": "b", "empty_layer": True}]
        assert details.layer_history(1, history) == [{"created_by": "a"}]
        # Squashed or hand-built: counts disagree, so nothing is paired.
        assert details.layer_history(3, history) == [None, None, None]

    def test_long_strings_are_clipped(self):
        cfg = details.parse_config(json.dumps({"config": {"Env": ["X=" + "y" * 100_000]}}).encode())
        assert len(cfg["env"][0]) == 4096

    def test_sbom_garbage(self):
        assert details.summarize_sbom(b"{")["format"] == "unreadable"
        assert details.summarize_sbom(b'{"bomFormat": "SPDX"}')["format"] == "unsupported"
        body = details.summarize_sbom(b'{"bomFormat": "CycloneDX", "components": [1, null, {"name": "x"}]}')
        assert body["total"] == 1

    def test_component_cap(self, monkeypatch):
        monkeypatch.setattr(details, "MAX_COMPONENTS", 3)
        doc = {"bomFormat": "CycloneDX", "components": [{"name": f"p{i}"} for i in range(10)]}
        body = details.summarize_sbom(json.dumps(doc).encode())
        assert body["total"] == 10 and len(body["components"]) == 3 and body["truncated"] is True


async def test_scan_all_helper_still_drains(docker_env):
    # Keeps the shared helper honest for this module's imports.
    client, fake = docker_env
    fake.add_image("library/x", "1", Image.build("x"))
    await inspect(client, "x:1", await user(client))
    await scan_all(client, {})
    await make_user(username="noop")
