"""What `minireg audit` tells CI.

A gate that exits 0 when it could not check anything is decoration. These
tests pin the exit codes so that cannot regress quietly.
"""

from __future__ import annotations

import argparse
import importlib.util
import pathlib
import sys

import pytest

# The CLI is a single stdlib-only script served verbatim to users, so it is
# loaded by path rather than imported as a package.
CLI_PATH = pathlib.Path(__file__).resolve().parents[2] / "cli" / "minireg.py"
_spec = importlib.util.spec_from_file_location("minireg_cli_exit", CLI_PATH)
cli = importlib.util.module_from_spec(_spec)
sys.modules["minireg_cli_exit"] = cli
_spec.loader.exec_module(cli)

audit_exit_code = cli.audit_exit_code


def _args(**kwargs):
    defaults = {"fail_on": "high", "fail_on_unscanned": None, "json": False}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _finding(severity):
    return {"name": "p", "version": "1.0.0", "cves": [{"severity": severity}]}


class TestSeverityGate:
    def test_clean_project_passes(self):
        assert audit_exit_code(_args(), [], False, 0) == 0

    def test_finding_at_threshold_fails(self):
        assert audit_exit_code(_args(), [_finding("high")], False, 0) == 2

    def test_finding_below_threshold_passes(self):
        assert audit_exit_code(_args(), [_finding("low")], False, 0) == 0

    def test_blocked_package_fails_whatever_its_score(self):
        # The registry will refuse to serve it, so the install cannot succeed.
        assert audit_exit_code(_args(), [], True, 0) == 2

    def test_no_threshold_never_fails(self):
        assert audit_exit_code(_args(fail_on="never"), [_finding("critical")], True, 5) == 0


class TestUnscannedGate:
    def test_unscanned_dependencies_fail_by_default(self):
        """OSV down, --offline, or a package the registry has never seen all
        produce zero findings. Exiting 0 there reports "clean" for something
        that was never looked at."""
        assert audit_exit_code(_args(), [], False, 3) == 3

    def test_unscanned_can_be_accepted_explicitly(self):
        assert audit_exit_code(_args(fail_on_unscanned=False), [], False, 3) == 0

    def test_a_real_finding_still_takes_precedence(self):
        assert audit_exit_code(_args(), [_finding("critical")], False, 3) == 2

    def test_unscanned_is_ignored_without_a_threshold(self):
        assert audit_exit_code(_args(fail_on="never"), [], False, 9) == 0


class TestJsonStillGates:
    def test_json_output_does_not_disable_the_gate(self):
        """`--json --fail-on critical` used to return before the threshold was
        ever evaluated, so every machine-readable run exited 0."""
        import inspect

        source = inspect.getsource(cli.cmd_audit)
        json_return = source.index("if args.json:")
        exit_call = source.index("return audit_exit_code(")
        assert exit_call > json_return
        assert "return 0" not in source[json_return : json_return + 400]


@pytest.mark.parametrize("threshold", ["low", "medium", "high", "critical"])
def test_every_documented_threshold_is_understood(threshold):
    assert audit_exit_code(_args(fail_on=threshold), [], False, 0) == 0
