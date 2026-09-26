from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sechelix_runner.cli import build_parser

from sechelix_core.remediation import FAIL, NOT_RUN, PASS
from sechelix_runner.proof import ProofClass
from sechelix_runner.proof_exec import ProofBehavior, ProofExecutionResult
from sechelix_runner.remediation_exec import (
    NamedTestSpec,
    RemediationCheckRunner,
    RemediationExecutionError,
    regression_stage_from_proof,
)
from sechelix_runner.sandbox_exec import SandboxResult


class FakeSandboxRunner:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def run(self, argv, *, workspace=None, timeout=120.0):
        self.calls.append(
            {
                "argv": tuple(argv),
                "workspace": Path(workspace).resolve() if workspace is not None else None,
                "timeout": timeout,
            }
        )
        return self.result


class NamedTestSpecTests(unittest.TestCase):
    def test_only_named_unittest_capability_is_allowed(self) -> None:
        with self.assertRaises(RemediationExecutionError):
            NamedTestSpec("shell", ("tests/test_auth.py",))

    def test_targets_cannot_escape_scratch_workspace(self) -> None:
        for target in ("../outside.py", "../../etc/passwd", "/tmp/outside.py", "--help", ""):
            with self.subTest(target=target):
                with self.assertRaises(RemediationExecutionError):
                    NamedTestSpec("python-unittest", (target,))

    def test_command_shape_is_fixed(self) -> None:
        spec = NamedTestSpec(
            "python-unittest",
            ("tests.test_remediation", "tests/runner/test_tool_gateway.py"),
        )
        self.assertEqual(
            spec.command(),
            (
                "python",
                "-m",
                "unittest",
                "-q",
                "tests.test_remediation",
                "tests/runner/test_tool_gateway.py",
            ),
        )


class RemediationCheckRunnerTests(unittest.TestCase):
    def test_passed_named_test_becomes_pass_stage_and_is_audited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeSandboxRunner(
                SandboxResult(exit_code=0, stdout="ok", stderr="", command=("python",))
            )
            runner = RemediationCheckRunner(tmp, sandbox_runner=fake)
            executed = runner.run_test(
                "existing_tests",
                NamedTestSpec("python-unittest", ("tests.test_remediation",), 42),
            )

            self.assertEqual(executed.stage.status, PASS)
            self.assertEqual(len(fake.calls), 1)
            self.assertEqual(fake.calls[0]["timeout"], 42)
            self.assertEqual(fake.calls[0]["workspace"], Path(tmp).resolve())
            log = Path(tmp) / ".sechelix-remediation-tool-decisions.jsonl"
            self.assertTrue(log.is_file())
            self.assertIn('"tool": "remediation-test"', log.read_text(encoding="utf-8"))

    def test_failed_named_test_blocks_stage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeSandboxRunner(
                SandboxResult(exit_code=1, stdout="", stderr="failed", command=("python",))
            )
            result = RemediationCheckRunner(tmp, sandbox_runner=fake).run_test(
                "vulnerability_regression",
                NamedTestSpec("python-unittest", ("tests.test_remediation",)),
            )
            self.assertEqual(result.stage.status, FAIL)
            self.assertIn("exit code 1", result.stage.detail)

    def test_timeout_is_failure_not_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeSandboxRunner(
                SandboxResult(
                    exit_code=124,
                    stdout="",
                    stderr="timed out",
                    timed_out=True,
                    command=("python",),
                )
            )
            result = RemediationCheckRunner(tmp, sandbox_runner=fake).run_test(
                "existing_tests",
                NamedTestSpec("python-unittest", ("tests.test_remediation",)),
            )
            self.assertEqual(result.stage.status, FAIL)
            self.assertIn("timed out", result.stage.detail)

    def test_only_test_and_regression_stages_are_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeSandboxRunner(
                SandboxResult(exit_code=0, stdout="", stderr="", command=("python",))
            )
            runner = RemediationCheckRunner(tmp, sandbox_runner=fake)
            with self.assertRaises(RemediationExecutionError):
                runner.run_test(
                    "independent_verification",
                    NamedTestSpec("python-unittest", ("tests.test_remediation",)),
                )


class ProofReplayTranslationTests(unittest.TestCase):
    def result(self, behavior: ProofBehavior) -> ProofExecutionResult:
        return ProofExecutionResult(
            finding_id="SHX-F-1",
            proof_class=ProofClass.AUTHORIZATION_IDOR,
            behavior=behavior,
        )

    def test_secure_replay_passes_vulnerability_regression(self) -> None:
        stage = regression_stage_from_proof(self.result(ProofBehavior.SECURE_BEHAVIOR))
        self.assertEqual(stage.status, PASS)

    def test_vulnerable_replay_fails_vulnerability_regression(self) -> None:
        stage = regression_stage_from_proof(self.result(ProofBehavior.VULNERABLE_BEHAVIOR))
        self.assertEqual(stage.status, FAIL)

    def test_inconclusive_or_blocked_replay_never_passes(self) -> None:
        for behavior in (ProofBehavior.INCONCLUSIVE, ProofBehavior.BLOCKED):
            with self.subTest(behavior=behavior):
                stage = regression_stage_from_proof(self.result(behavior))
                self.assertEqual(stage.status, NOT_RUN)


class RemediationCliParserTests(unittest.TestCase):
    def test_fix_check_cli_parses_bounded_inputs(self) -> None:
        args = build_parser().parse_args([
            "fix-check",
            "SHX-F-1",
            "--workspace",
            "/tmp/sechelix-fix",
            "--existing-test",
            "tests.test_remediation",
            "--regression-test",
            "tests.test_security_regression",
            "--patch-review",
            "patch-review.json",
            "--independent-verification",
            "verify.json",
            "--json",
        ])
        self.assertEqual(args.command, "fix-check")
        self.assertEqual(args.finding_id, "SHX-F-1")
        self.assertEqual(args.existing_test, ["tests.test_remediation"])
        self.assertEqual(args.regression_test, ["tests.test_security_regression"])

    def test_fix_check_cli_has_no_generic_command_argument(self) -> None:
        parser = build_parser()
        help_text = parser.format_help()
        self.assertNotIn("--command", help_text)
        self.assertNotIn("--shell", help_text)


if __name__ == "__main__":
    unittest.main()
