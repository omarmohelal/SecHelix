import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from scripts.ci_outcome import RunArtifactError, decide, main


def run_json(**overrides):
    """A minimal recorded run. Satisfied by default; overrides break it."""
    base = {
        "run_id": "run-0001",
        "runner_version": "0.2.1",
        "executor": "claude-code",
        "unsatisfied_mandatory": [],
        "records": {
            "map": {"status": "SUCCEEDED"},
            "verify": {"status": "SUCCEEDED"},
            "gate": {"status": "SUCCEEDED"},
        },
        "findings": [],
    }
    base.update(overrides)
    return base


def finding(**overrides):
    base = {
        "id": "SEC-001",
        "status": "VERIFIED",
        "severity": "HIGH",
        "resolution": "OPEN",
    }
    base.update(overrides)
    return base


class DecideTests(unittest.TestCase):
    def test_clean_run_passes(self):
        self.assertEqual(decide(run_json())["outcome"], "PASS")

    def test_unsatisfied_mandatory_is_incomplete(self):
        result = decide(run_json(unsatisfied_mandatory=["verify", "gate"]))
        self.assertEqual(result["outcome"], "INCOMPLETE")
        self.assertEqual(result["unsatisfied_mandatory"], ["gate", "verify"])

    def test_incomplete_beats_an_empty_finding_list(self):
        """The core rule: nothing examined must never read as nothing found."""
        result = decide(
            run_json(
                unsatisfied_mandatory=["verify"],
                findings=[],
                records={"verify": {"status": "BLOCKED"}},
            )
        )
        self.assertEqual(result["outcome"], "INCOMPLETE")
        self.assertIn("verify=BLOCKED", result["undelivered"])

    def test_incomplete_beats_findings_that_would_otherwise_block(self):
        """An incomplete run cannot be upgraded to a decision by partial output."""
        result = decide(
            run_json(unsatisfied_mandatory=["gate"], findings=[finding(severity="CRITICAL")])
        )
        self.assertEqual(result["outcome"], "INCOMPLETE")

    def test_verified_high_blocks(self):
        result = decide(run_json(findings=[finding()]))
        self.assertEqual(result["outcome"], "BLOCKED")
        self.assertEqual(result["blocking_findings"], ["SEC-001"])

    def test_verified_critical_blocks(self):
        self.assertEqual(
            decide(run_json(findings=[finding(severity="CRITICAL")]))["outcome"], "BLOCKED"
        )

    def test_severity_comparison_is_case_insensitive(self):
        self.assertEqual(
            decide(run_json(findings=[finding(severity="high", status="verified")]))["outcome"],
            "BLOCKED",
        )

    def test_unverified_high_does_not_block(self):
        """A candidate is not a finding. This is the product's whole thesis."""
        result = decide(run_json(findings=[finding(status="HYPOTHESIS")]))
        self.assertEqual(result["outcome"], "PASS_WITH_KNOWN_RISK")

    def test_likely_but_unproven_does_not_block(self):
        self.assertEqual(
            decide(run_json(findings=[finding(status="LIKELY_BUT_UNPROVEN")]))["outcome"],
            "PASS_WITH_KNOWN_RISK",
        )

    def test_fixed_verified_high_does_not_block(self):
        self.assertEqual(
            decide(run_json(findings=[finding(resolution="FIXED")]))["outcome"], "PASS"
        )

    def test_false_positive_does_not_block_or_count_as_open(self):
        result = decide(run_json(findings=[finding(resolution="FALSE_POSITIVE")]))
        self.assertEqual(result["outcome"], "PASS")
        self.assertEqual(result["open_findings"], 0)

    def test_accepted_risk_is_open_but_not_blocking_at_medium(self):
        result = decide(
            run_json(findings=[finding(severity="MEDIUM", resolution="ACCEPTED_RISK")])
        )
        self.assertEqual(result["outcome"], "PASS_WITH_KNOWN_RISK")

    def test_accepted_risk_at_high_still_blocks_here(self):
        """Accepting risk is a policy decision this mapping does not make.

        ``security_gate.py`` grants PASS_WITH_KNOWN_RISK only against a policy
        that says so. Without a policy, an open verified HIGH stays blocking.
        """
        result = decide(run_json(findings=[finding(resolution="ACCEPTED_RISK")]))
        self.assertEqual(result["outcome"], "BLOCKED")

    def test_medium_verified_does_not_block(self):
        self.assertEqual(
            decide(run_json(findings=[finding(severity="MEDIUM")]))["outcome"],
            "PASS_WITH_KNOWN_RISK",
        )

    def test_null_findings_is_treated_as_none(self):
        """The runner writes no ``findings`` key at all; json gives back None."""
        self.assertEqual(decide(run_json(findings=None))["outcome"], "PASS")

    def test_missing_findings_key(self):
        run = run_json()
        del run["findings"]
        self.assertEqual(decide(run)["outcome"], "PASS")

    def test_non_list_findings_is_rejected(self):
        with self.assertRaises(RunArtifactError):
            decide(run_json(findings={"not": "a list"}))

    def test_non_list_unsatisfied_is_rejected(self):
        with self.assertRaises(RunArtifactError):
            decide(run_json(unsatisfied_mandatory="verify"))

    def test_non_mapping_run_is_rejected(self):
        with self.assertRaises(RunArtifactError):
            decide(["not", "an", "object"])

    def test_non_mapping_findings_entries_are_ignored(self):
        self.assertEqual(decide(run_json(findings=["oops", None]))["outcome"], "PASS")


class MainTests(unittest.TestCase):
    def _write(self, payload):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump(payload, handle)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def _run(self, argv):
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue()

    def test_exit_codes_match_security_gate(self):
        for payload, expected in (
            (run_json(), 0),
            (run_json(findings=[finding(severity="MEDIUM")]), 0),
            (run_json(findings=[finding()]), 1),
            (run_json(unsatisfied_mandatory=["verify"]), 2),
        ):
            with self.subTest(expected=expected):
                code, _ = self._run([self._write(payload)])
                self.assertEqual(code, expected)

    def test_unreadable_file_is_incomplete_not_pass(self):
        code, out = self._run(["definitely-not-a-file.json"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["outcome"], "INCOMPLETE")

    def test_malformed_json_is_incomplete_not_pass(self):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        )
        handle.write("{ not json")
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        code, out = self._run([handle.name])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["outcome"], "INCOMPLETE")

    def test_github_output_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out.txt"
            os.environ["GITHUB_OUTPUT"] = str(output)
            self.addCleanup(os.environ.pop, "GITHUB_OUTPUT", None)
            self._run([self._write(run_json(findings=[finding()])), "--github-output"])
            written = dict(
                line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines()
            )
        self.assertEqual(written["outcome"], "BLOCKED")
        self.assertEqual(written["incomplete"], "false")
        self.assertEqual(written["blocking-count"], "1")
        self.assertEqual(written["run-id"], "run-0001")

    def test_github_output_reason_is_single_line(self):
        """A newline in a value would let the reason forge another output key."""
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out.txt"
            os.environ["GITHUB_OUTPUT"] = str(output)
            self.addCleanup(os.environ.pop, "GITHUB_OUTPUT", None)
            self._run([self._write(run_json(unsatisfied_mandatory=["v"])), "--github-output"])
            lines = output.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 5)
        for line in lines:
            self.assertIn("=", line)


if __name__ == "__main__":
    unittest.main()
