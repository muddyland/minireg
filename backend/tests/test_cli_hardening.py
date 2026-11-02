"""CLI: argument parsing, terminal output and config writing hardening.

The HTTP layer is stubbed (`cli.api`), so these pin the CLI's own behaviour:
what it accepts on the command line, what it prints from server-supplied
text, and what it writes into the user's package-manager config files.
"""

from __future__ import annotations

import argparse
import importlib.util
import pathlib
import re
import shlex
import sys

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
