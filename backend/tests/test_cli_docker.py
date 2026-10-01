"""CLI 1.3: container images (configure docker, search/info, audit --image).

The server side of these calls is covered by test_docker_inspect.py; here the
HTTP layer is stubbed so the CLI's own decisions (what it runs, what it
prints, which exit code) are pinned.
"""

from __future__ import annotations

import argparse
import importlib.util
import pathlib
import subprocess
import sys

import pytest

CLI_PATH = pathlib.Path(__file__).resolve().parents[2] / "cli" / "minireg.py"
_spec = importlib.util.spec_from_file_location("minireg_cli_docker", CLI_PATH)
cli = importlib.util.module_from_spec(_spec)
sys.modules["minireg_cli_docker"] = cli
_spec.loader.exec_module(cli)

REGISTRY = "https://registry.example"
DIGEST = "sha256:" + "d" * 64


def image_payload(**over):
    image = {
        "digest": "sha256:" + "c" * 64,
        "kind": "image",
        "platform": "linux/amd64",
        "total_size": 3_500_000,
        "layer_count": 1,
        "scan_status": "scanned",
        "scanned_at": "2026-09-30T10:00:00Z",
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        "fixable_count": 0,
        "kev_count": 0,
    }
    image.update(over)
    return image


def inspect_payload(*, image=None, findings=(), allowed=True, code=None, reason=None, total=None):
    findings = list(findings)
    return {
        "reference": "alpine:3.20",
        "repository": "dockerhub/library/alpine",
        "upstream": "dockerhub",
        "local": False,
        "quarantined": False,
        "pull_reference": "registry.example/alpine:3.20",
        "digest": DIGEST,
        "is_index": True,
        "platforms": ["linux/amd64", "linux/arm64"],
        "platform": "linux/amd64",
        "image": image or image_payload(),
        "verdict": {"allowed": allowed, "code": code, "reason": reason, "retry_after": None},
        "findings_total": len(findings) if total is None else total,
        "findings": findings,
        "tags": ["3.20", "latest"],
    }


def finding(vid, severity, *, accepted=False, kev=False, fixed=None):
    return {
        "vuln_id": vid,
        "pkg_name": "openssl",
        "installed_version": "3.0.0",
        "fixed_version": fixed,
        "severity": severity,
        "kev": kev,
        "denied": False,
        "accepted": accepted,
    }


def audit_args(*images, **kw):
    ns = {
        "image": list(images),
        "fail_on": "high",
        "fail_on_unscanned": None,
        "json": False,
        "fix": False,
        "platform": "linux/amd64",
        "wait": 0,
        "insecure": False,
    }
    ns.update(kw)
    return argparse.Namespace(**ns)


@pytest.fixture
def stub(monkeypatch):
    """Route cli.api through a table of path-prefix -> response (or callable)."""
    calls = []
    table = {}

    def fake_api(registry, path, method="GET", body=None, token=None, timeout=None, insecure=False):
        calls.append(path)
        for prefix, answer in table.items():
            if path.startswith(prefix):
                if isinstance(answer, Exception):
                    raise answer
                return answer(path) if callable(answer) else answer
        raise AssertionError(f"unexpected API call {path}")

    monkeypatch.setattr(cli, "api", fake_api)
    fake_api.table = table
    fake_api.calls = calls
    return fake_api


class TestVersion:
    def test_is_1_3_0(self):
        assert cli.__version__ == "1.3.0"

    def test_still_runs_on_python_3_9(self):
        """Shipped verbatim to laptops: no syntax newer than 3.9."""
        import ast

        ast.parse(CLI_PATH.read_text(), feature_version=(3, 9))


class TestAuditImage:
    def test_clean_image_passes(self, stub, capsys):
        stub.table["/api/docker/inspect"] = inspect_payload()
        assert cli.audit_images(audit_args("alpine:3.20"), REGISTRY, "t") == 0
        out = capsys.readouterr().out
        assert "pull allowed" in out
        assert "registry.example/alpine:3.20" in out

    def test_finding_at_threshold_fails_with_2(self, stub):
        stub.table["/api/docker/inspect"] = inspect_payload(findings=[finding("CVE-1", "CRITICAL")])
        assert cli.audit_images(audit_args("x:1", fail_on="high"), REGISTRY, "t") == 2

    def test_finding_below_threshold_passes(self, stub):
        stub.table["/api/docker/inspect"] = inspect_payload(findings=[finding("CVE-1", "MEDIUM")])
        assert cli.audit_images(audit_args("x:1", fail_on="high"), REGISTRY, "t") == 0

    def test_accepted_risk_does_not_count(self, stub):
        """The registry does not count it, so neither does the gate."""
        stub.table["/api/docker/inspect"] = inspect_payload(
            findings=[finding("CVE-1", "CRITICAL", accepted=True)]
        )
        assert cli.audit_images(audit_args("x:1", fail_on="critical"), REGISTRY, "t") == 0

    def test_registry_refusal_fails_whatever_the_threshold(self, stub, capsys):
        stub.table["/api/docker/inspect"] = inspect_payload(
            allowed=False, code="DENIED", reason="denied CVE present: CVE-2021-44228"
        )
        assert cli.audit_images(audit_args("x:1", fail_on="critical"), REGISTRY, "t") == 2
        assert "BLOCKED" in capsys.readouterr().out

    def test_unscanned_image_exits_3(self, stub):
        """Zero findings from an image nobody scanned is not a clean result."""
        stub.table["/api/docker/inspect"] = inspect_payload(image=image_payload(scan_status="unscanned"))
        assert cli.audit_images(audit_args("x:1"), REGISTRY, "t") == 3

    def test_unscanned_can_be_accepted(self, stub):
        stub.table["/api/docker/inspect"] = inspect_payload(image=image_payload(scan_status="unscanned"))
        assert cli.audit_images(audit_args("x:1", fail_on_unscanned=False), REGISTRY, "t") == 0

    def test_waits_for_a_queued_scan(self, stub, monkeypatch):
        monkeypatch.setattr(cli.time, "sleep", lambda _s: None)
        answers = iter(
            [
                inspect_payload(image=image_payload(scan_status="queued")),
                inspect_payload(image=image_payload(scan_status="scanning")),
                inspect_payload(findings=[finding("CVE-1", "HIGH")]),
            ]
        )
        stub.table["/api/docker/inspect"] = lambda _p: next(answers)
        assert cli.audit_images(audit_args("x:1", wait=60), REGISTRY, "t") == 2
        assert len(stub.calls) == 3

    def test_more_findings_than_listed_gates_on_the_counts(self, stub):
        image = image_payload(severity_counts={"CRITICAL": 4, "HIGH": 0})
        stub.table["/api/docker/inspect"] = inspect_payload(
            image=image, findings=[finding("CVE-1", "LOW")], total=500
        )
        assert cli.audit_images(audit_args("x:1", fail_on="critical"), REGISTRY, "t") == 2

    def test_json_still_gates(self, stub, capsys):
        import json

        stub.table["/api/docker/inspect"] = inspect_payload(allowed=False, code="DENIED", reason="kev")
        assert cli.audit_images(audit_args("x:1", json=True), REGISTRY, "t") == 2
        body = json.loads(capsys.readouterr().out)
        assert body["blocked"] is True
        assert body["images"][0]["repository"] == "dockerhub/library/alpine"

    def test_several_images(self, stub):
        stub.table["/api/docker/inspect"] = lambda p: (
            inspect_payload(findings=[finding("CVE-1", "CRITICAL")]) if "bad" in p else inspect_payload()
        )
        assert cli.audit_images(audit_args("good:1", "bad:1"), REGISTRY, "t") == 2

    def test_fix_is_refused_for_images(self, stub):
        with pytest.raises(SystemExit):
            cli.audit_images(audit_args("x:1", fix=True), REGISTRY, "t")

    def test_platform_is_passed_through(self, stub):
        stub.table["/api/docker/inspect"] = inspect_payload()
        cli.audit_images(audit_args("x:1", platform="linux/arm64"), REGISTRY, "t")
        assert "platform=linux%2Farm64" in stub.calls[0]


class TestInfoAndSearch:
    def test_info_renders_findings_and_platforms(self, stub, capsys):
        stub.table["/api/docker/inspect"] = inspect_payload(
            image=image_payload(severity_counts={"CRITICAL": 1}, kev_count=1, fixable_count=1),
            findings=[finding("CVE-2024-3094", "CRITICAL", kev=True, fixed="5.6.1-2")],
        )
        args = argparse.Namespace(
            package="alpine:3.20", ecosystem="docker", limit=20, platform="linux/amd64",
            insecure=False, url=REGISTRY,
        )
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(cli, "require_token", lambda: "t")
            assert cli.cmd_info(args) == 0
        out = capsys.readouterr().out
        assert "linux/amd64, linux/arm64" in out
        assert "CVE-2024-3094" in out
        assert "[KEV]" in out
        assert "1 known-exploited" in out

    def test_search_docker_only(self, stub, capsys):
        stub.table["/api/docker/images"] = {
            "total": 1,
            "images": [
                {
                    "name": "dockerhub/library/alpine",
                    "pull_reference": "registry.example/alpine",
                    "tag_count": 2,
                    "scanned_count": 1,
                    "worst_counts": {"CRITICAL": 0, "HIGH": 2},
                    "upstream": "dockerhub",
                }
            ],
        }
        args = argparse.Namespace(query="alpine", ecosystem="docker", limit=25, insecure=False, url=REGISTRY)
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(cli, "require_token", lambda: "t")
            assert cli.cmd_search(args) == 0
        out = capsys.readouterr().out
        assert "registry.example/alpine" in out
        assert "2 high" in out
        assert stub.calls == ["/api/docker/images?q=alpine&limit=25"]

    def test_search_all_includes_images(self, stub, capsys):
        stub.table["/api/docker/images"] = {"total": 1, "images": [{"name": "local/team/app", "local": True}]}
        stub.table["/api/search"] = {"total": 1, "results": [{"ecosystem": "npm", "name": "app"}]}
        args = argparse.Namespace(query="app", ecosystem=None, limit=25, insecure=False, url=REGISTRY)
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(cli, "require_token", lambda: "t")
            assert cli.cmd_search(args) == 0
        out = capsys.readouterr().out
        assert "local/team/app" in out and "pushed here" in out
        assert "1 of 1 images" in out

    def test_search_all_survives_a_registry_without_images(self, stub, capsys):
        stub.table["/api/docker/images"] = cli.ApiError(404, "Not Found")
        stub.table["/api/search"] = {"total": 1, "results": [{"ecosystem": "npm", "name": "left-pad"}]}
        args = argparse.Namespace(query="pad", ecosystem=None, limit=25, insecure=False, url=REGISTRY)
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(cli, "require_token", lambda: "t")
            assert cli.cmd_search(args) == 0
        assert "left-pad" in capsys.readouterr().out


CLIENT_CONFIG = {
    "host": "registry.example",
    "upstreams": ["dockerhub", "ghcr"],
    "default_upstream": "dockerhub",
    "local_namespace": "local",
    "daemon_json": {"registry-mirrors": ["https://registry.example"]},
    "containerd_path": "/etc/containerd/certs.d/docker.io/hosts.toml",
    "containerd_hosts_toml": 'server = "https://registry-1.docker.io"',
}


class TestConfigureDocker:
    def args(self, **kw):
        ns = {"dry_run": False, "container_cli": None, "insecure": False}
        ns.update(kw)
        return argparse.Namespace(**ns)

    def test_logs_in_with_the_token_on_stdin(self, stub, monkeypatch, capsys):
        stub.table["/api/docker/client-config"] = CLIENT_CONFIG
        stub.table["/api/auth/me"] = {"scopes": ["read", "docker:push"]}
        monkeypatch.setattr(cli.shutil, "which", lambda t: f"/usr/bin/{t}" if t == "docker" else None)
        seen = {}

        def fake_run(cmd, input=None, **kw):
            seen["cmd"], seen["input"] = cmd, input
            return subprocess.CompletedProcess(cmd, 0, b"Login Succeeded", b"")

        monkeypatch.setattr(cli.subprocess, "run", fake_run)
        cli.configure_docker(self.args(), REGISTRY, "mrg_secret", {"username": "alice"})
        assert seen["cmd"] == ["docker", "login", "registry.example", "-u", "alice", "--password-stdin"]
        # Never on the command line, where `ps` shows it to everyone.
        assert "mrg_secret" not in " ".join(seen["cmd"])
        assert seen["input"] == b"mrg_secret"
        out = capsys.readouterr().out
        assert "registry-mirrors" in out
        assert "docker pull registry.example/ghcr/<image>:<tag>" in out

    def test_warns_when_the_token_cannot_push(self, stub, monkeypatch, capsys):
        stub.table["/api/docker/client-config"] = CLIENT_CONFIG
        stub.table["/api/auth/me"] = {"scopes": ["read"]}
        monkeypatch.setattr(cli.shutil, "which", lambda t: "/usr/bin/docker")
        monkeypatch.setattr(
            cli.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, b"", b"")
        )
        cli.configure_docker(self.args(), REGISTRY, "t", {})
        assert "can pull but not push" in capsys.readouterr().err

    def test_falls_back_to_podman(self, stub, monkeypatch):
        stub.table["/api/docker/client-config"] = CLIENT_CONFIG
        stub.table["/api/auth/me"] = {"scopes": ["read", "docker:push"]}
        monkeypatch.setattr(cli.shutil, "which", lambda t: "/usr/bin/podman" if t == "podman" else None)
        ran = []
        monkeypatch.setattr(
            cli.subprocess, "run", lambda cmd, **kw: ran.append(cmd) or subprocess.CompletedProcess(cmd, 0, b"", b"")
        )
        cli.configure_docker(self.args(), REGISTRY, "t", {})
        assert ran[0][0] == "podman"

    def test_dry_run_runs_nothing(self, stub, monkeypatch, capsys):
        stub.table["/api/docker/client-config"] = CLIENT_CONFIG
        monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: pytest.fail("ran a command in --dry-run"))
        cli.configure_docker(self.args(dry_run=True), REGISTRY, "t", {"username": "alice"})
        assert "would run: docker login registry.example -u alice --password-stdin" in capsys.readouterr().out

    def test_failed_login_is_an_error(self, stub, monkeypatch):
        stub.table["/api/docker/client-config"] = CLIENT_CONFIG
        monkeypatch.setattr(cli.shutil, "which", lambda t: "/usr/bin/docker")
        monkeypatch.setattr(
            cli.subprocess,
            "run",
            lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, b"", b"Error: unauthorized: bad token"),
        )
        with pytest.raises(SystemExit):
            cli.configure_docker(self.args(), REGISTRY, "t", {})

    def test_logs_in_where_the_user_reaches_the_registry(self, stub, monkeypatch):
        """PUBLIC_URL may name a host this machine cannot reach (or reaches
        over plain HTTP that docker refuses); the URL given to `minireg login`
        is the one known to work from here."""
        stub.table["/api/docker/client-config"] = {**CLIENT_CONFIG, "host": "public.example"}
        stub.table["/api/auth/me"] = {"scopes": ["read", "docker:push"]}
        monkeypatch.setattr(cli.shutil, "which", lambda t: "/usr/bin/docker")
        ran = []
        monkeypatch.setattr(
            cli.subprocess, "run", lambda cmd, **kw: ran.append(cmd) or subprocess.CompletedProcess(cmd, 0, b"", b"")
        )
        cli.configure_docker(self.args(), "http://localhost:5055", "t", {})
        assert ran[0][2] == "localhost:5055"

    def test_no_docker_prints_the_command(self, stub, monkeypatch, capsys):
        stub.table["/api/docker/client-config"] = CLIENT_CONFIG
        monkeypatch.setattr(cli.shutil, "which", lambda t: None)
        cli.configure_docker(self.args(), REGISTRY, "t", {"username": "alice"})
        assert "docker login registry.example -u alice" in capsys.readouterr().out

    def test_plain_all_does_not_touch_docker(self, stub, monkeypatch, tmp_path):
        """`minireg configure` in CI must not start writing ~/.docker unasked."""
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
        monkeypatch.setenv("CARGO_HOME", str(tmp_path / ".cargo"))
        monkeypatch.setattr(cli, "load_config", lambda: {"registry": REGISTRY, "token": "t"})
        stub.table["/api/client-config"] = {
            "npm": {"registry": f"{REGISTRY}/npm/"},
            "pip": {"index_url": f"{REGISTRY}/pypi/simple/"},
            "cargo": None,
        }
        monkeypatch.setattr(cli, "configure_docker", lambda *a: pytest.fail("configured docker unasked"))
        args = argparse.Namespace(target="all", dry_run=True, url=REGISTRY, insecure=False, container_cli=None)
        assert cli.cmd_configure(args) == 0

    def test_unknown_target_is_refused(self, stub, monkeypatch):
        monkeypatch.setattr(cli, "load_config", lambda: {"registry": REGISTRY, "token": "t"})
        stub.table["/api/client-config"] = {}
        args = argparse.Namespace(target="dokcer", dry_run=True, url=REGISTRY, insecure=False, container_cli=None)
        with pytest.raises(SystemExit):
            cli.cmd_configure(args)


class TestParser:
    def test_new_flags_parse(self):
        p = cli.build_parser()
        a = p.parse_args(["audit", "--image", "a:1", "--image", "b:2", "--platform", "linux/arm64", "--wait", "5"])
        assert a.image == ["a:1", "b:2"] and a.platform == "linux/arm64" and a.wait == 5
        assert p.parse_args(["search", "x", "--ecosystem", "docker"]).ecosystem == "docker"
        assert p.parse_args(["info", "alpine", "--ecosystem", "docker"]).platform == "linux/amd64"
        assert p.parse_args(["configure", "docker", "--container-cli", "podman"]).container_cli == "podman"

    def test_lockfile_audit_is_unchanged_without_image(self):
        assert cli.build_parser().parse_args(["audit"]).image is None
