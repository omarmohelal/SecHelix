"""The remediation loop must never call an unchecked patch ready."""

import unittest

from sechelix_core.remediation import (
    BLOCKED,
    FAIL,
    INCOMPLETE,
    NOT_RUN,
    PASS,
    READY,
    RISK_CLASSES,
    STAGES,
    RemediationError,
    StageResult,
    assess_remediation_risk,
    run_loop,
)

WORKSPACE = "/tmp/sechelix-scratch/SHX-F-1"


def finding(status="VERIFIED", fid="SHX-F-1"):
    return {"finding_id": fid, "status": status, "severity": "HIGH"}


def passed(name):
    return StageResult(name, PASS, "ok")


def clean_review():
    return {"deltas": [], "overall": "UNCHANGED"}


def all_stages(**over):
    base = {
        "existing_tests": passed("existing_tests"),
        "vulnerability_regression": passed("vulnerability_regression"),
        "patch_diff_review": clean_review(),
        "independent_verification": passed("independent_verification"),
    }
    base.update(over)
    return base


class GatingTests(unittest.TestCase):
    def test_a_fully_checked_patch_is_ready(self):
        result = run_loop(finding(), workspace=WORKSPACE, **all_stages())
        self.assertEqual(result.outcome, READY)
        self.assertTrue(result.ready)

    def test_an_unverified_finding_is_refused(self):
        for status in ("HYPOTHESIS", "LIKELY_BUT_UNPROVEN", "FALSE_POSITIVE"):
            with self.subTest(status):
                with self.assertRaises(RemediationError) as ctx:
                    run_loop(finding(status), workspace=WORKSPACE, **all_stages())
                self.assertIn("nobody established", str(ctx.exception))

    def test_the_caller_working_tree_is_refused_as_a_workspace(self):
        for bad in ("", "   ", ".", "/"):
            with self.subTest(repr(bad)):
                with self.assertRaises(RemediationError):
                    run_loop(finding(), workspace=bad, **all_stages())

    def test_a_missing_finding_id_is_refused(self):
        with self.assertRaises(RemediationError):
            run_loop({"status": "VERIFIED"}, workspace=WORKSPACE, **all_stages())


class NotRunTests(unittest.TestCase):
    """A stage that did not run is not a stage that passed."""

    def test_missing_existing_tests_blocks_readiness(self):
        stages = all_stages()
        del stages["existing_tests"]
        result = run_loop(finding(), workspace=WORKSPACE, **stages)
        self.assertEqual(result.outcome, INCOMPLETE)
        self.assertFalse(result.ready)
        self.assertEqual(result.blocked_at, "existing_tests")

    def test_missing_regression_blocks_readiness(self):
        stages = all_stages()
        del stages["vulnerability_regression"]
        result = run_loop(finding(), workspace=WORKSPACE, **stages)
        self.assertEqual(result.outcome, INCOMPLETE)

    def test_missing_patch_review_blocks_readiness(self):
        stages = all_stages()
        del stages["patch_diff_review"]
        result = run_loop(finding(), workspace=WORKSPACE, **stages)
        self.assertEqual(result.outcome, INCOMPLETE)

    def test_missing_independent_verification_blocks_readiness(self):
        stages = all_stages()
        del stages["independent_verification"]
        result = run_loop(finding(), workspace=WORKSPACE, **stages)
        self.assertEqual(result.outcome, INCOMPLETE)

    def test_nothing_supplied_is_incomplete_and_names_every_gap(self):
        result = run_loop(finding(), workspace=WORKSPACE)
        self.assertEqual(result.outcome, INCOMPLETE)
        self.assertEqual(len([s for s in result.stages if s.status == NOT_RUN]), len(STAGES))

    def test_not_run_is_distinguishable_from_fail(self):
        """'We did not check' and 'we checked and it was fine' are different sentences."""
        result = run_loop(finding(), workspace=WORKSPACE)
        statuses = {s.status for s in result.stages}
        self.assertIn(NOT_RUN, statuses)
        self.assertNotIn(FAIL, statuses)


class FailureTests(unittest.TestCase):
    def test_a_failing_test_stage_blocks(self):
        result = run_loop(finding(), workspace=WORKSPACE,
                          **all_stages(existing_tests=StageResult(
                              "existing_tests", FAIL, "3 tests broke")))
        self.assertEqual(result.outcome, BLOCKED)
        self.assertEqual(result.blocked_at, "existing_tests")

    def test_a_failing_regression_blocks(self):
        result = run_loop(finding(), workspace=WORKSPACE,
                          **all_stages(vulnerability_regression=StageResult(
                              "vulnerability_regression", FAIL, "still exploitable")))
        self.assertEqual(result.outcome, BLOCKED)

    def test_a_failing_verification_blocks(self):
        result = run_loop(finding(), workspace=WORKSPACE,
                          **all_stages(independent_verification=StageResult(
                              "independent_verification", FAIL, "verifier disagrees")))
        self.assertEqual(result.outcome, BLOCKED)

    def test_the_first_failure_is_named(self):
        result = run_loop(finding(), workspace=WORKSPACE,
                          **all_stages(existing_tests=StageResult("existing_tests", FAIL, "x")))
        self.assertIn("blocked at existing_tests", " ".join(result.notes))


class RemediationRiskTests(unittest.TestCase):
    """A fix that opens a new hole is not a fix."""

    def _review(self, kind, path="app/x.py"):
        return {"deltas": [{"direction": "NEW_RISK", "kind": kind,
                            "path": path, "snippet": "..."}]}

    def test_a_patch_that_changes_authorization_is_flagged(self):
        risk = assess_remediation_risk(self._review("authorization_guard"))
        self.assertIn("authorization", risk.introduced)
        self.assertFalse(risk.clean)

    def test_a_patch_that_widens_a_query_is_flagged_as_validation_risk(self):
        risk = assess_remediation_risk(self._review("db_query"))
        self.assertIn("validation", risk.introduced)

    def test_a_patch_touching_payment_state_is_flagged_as_availability_risk(self):
        risk = assess_remediation_risk(self._review("payment_state"))
        self.assertIn("availability", risk.introduced)

    def test_a_risky_patch_blocks_the_loop(self):
        result = run_loop(finding(), workspace=WORKSPACE,
                          **all_stages(patch_diff_review=self._review("authorization_guard")))
        self.assertEqual(result.outcome, BLOCKED)
        self.assertEqual(result.blocked_at, "remediation_risk")

    def test_a_clean_patch_assesses_every_risk_class(self):
        risk = assess_remediation_risk(clean_review())
        self.assertTrue(risk.clean)
        self.assertEqual(risk.as_dict()["unassessed"], [])

    def test_an_unassessed_class_is_not_a_clean_one(self):
        risk = assess_remediation_risk(clean_review(), assessed=["authorization"])
        self.assertFalse(risk.clean)
        self.assertIn("validation", risk.as_dict()["unassessed"])

    def test_risk_reduced_deltas_do_not_count_as_introduced_risk(self):
        review = {"deltas": [{"direction": "RISK_REDUCED", "kind": "authorization_guard",
                              "path": "app/x.py", "snippet": "added guard"}]}
        self.assertTrue(assess_remediation_risk(review).clean)


class OutputTests(unittest.TestCase):
    def test_the_result_is_never_marked_applied(self):
        payload = run_loop(finding(), workspace=WORKSPACE, **all_stages()).as_dict()
        self.assertFalse(payload["applied"])
        self.assertEqual(payload["application_method"], "MANUAL_REVIEW_REQUIRED")

    def test_a_ready_result_says_it_is_a_proposal_not_a_fix(self):
        result = run_loop(finding(), workspace=WORKSPACE, **all_stages())
        self.assertIn("not an applied fix", " ".join(result.notes))

    def test_every_stage_appears_in_the_record(self):
        payload = run_loop(finding(), workspace=WORKSPACE, **all_stages()).as_dict()
        self.assertEqual([s["stage"] for s in payload["stages"]], list(STAGES))

    def test_the_workspace_is_recorded(self):
        payload = run_loop(finding(), workspace=WORKSPACE, **all_stages()).as_dict()
        self.assertEqual(payload["workspace"], WORKSPACE)

    def test_every_risk_class_is_named_in_the_record(self):
        payload = run_loop(finding(), workspace=WORKSPACE, **all_stages()).as_dict()
        self.assertEqual(sorted(payload["remediation_risk"]["assessed"]), sorted(RISK_CLASSES))


if __name__ == "__main__":
    unittest.main()
