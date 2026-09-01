import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from scripts.security_gate import GateInputError, evaluate, main, validate_report


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = ROOT / "policies/default.json"
CHAIN_LINK_NAMES = (
    "attacker_control",
    "reachability",
    "boundary_failure",
    "safe_reproduction",
    "impact",
    "preconditions",
    "root_cause",
)
LEGACY_REPORT = {
    "schema_version": "1.0.0",
    "scope": {"project": "fixture", "mode": "STATIC"},
    "coverage": {"applicable": 1, "not_applicable": 1, "unknown": 0, "blocked": 0, "integrity_critical_unknown": 0},
    "tools": [],
    "findings": [],
    "blocked_checks": [],
    "release_recommendation": "PASS",
}


def gate_evidence(evidence_id: str) -> dict:
    return {
        "schema_version": "1.0",
        "evidence_id": evidence_id,
        "kind": "VERIFICATION",
        "status": "CONFIRMED",
        "source": {
            "type": "TEST",
            "name": "controlled gate fixture",
            "version": "1",
            "collected_at": "2026-01-01T00:00:00Z",
            "provenance": "tests/test_security_gate.py fixture",
        },
        "summary": "Synthetic evidence used to exercise release-gate policy logic.",
        "environment": {"mode": "STATIC", "scope_id": "SCOPE-GATE-FIXTURE", "target_id": "TGT-GATE"},
        "artifacts": [],
        "redactions": [],
    }


def base_report() -> dict:
    """A contract-valid report-v1 baseline with no findings; tests mutate it."""

    return {
        "schema_version": "1.0",
        "report_id": "REPORT-GATE-FIXTURE",
        "scope_id": "SCOPE-GATE-FIXTURE",
        "project": "gate fixture",
        "mode": "STATIC",
        "generated_at": "2026-01-01T00:00:00Z",
        "coverage": {
            "catalog_version": "2.2",
            "APPLICABLE": 1,
            "NOT_APPLICABLE": 545,
            "UNKNOWN": 0,
            "BLOCKED": 0,
            "TOTAL": 546,
            "integrity_critical_unknown": 0,
        },
        "tools": [],
        "evidence": [gate_evidence("EV-GATE-REPRO"), gate_evidence("EV-GATE-VERIFY")],
        "findings": [],
        "rejected_false_positives": [],
        "blocked_checks": [],
        "release_recommendation": "BLOCKED",
        "redaction_summary": [],
    }


def verified_finding(severity: str = "HIGH", resolution: str = "OPEN") -> dict:
    link = {
        "established": True,
        "statement": "Established against the controlled local fixture.",
        "evidence_ids": ["EV-GATE-REPRO"],
    }
    return {
        "schema_version": "1.0",
        "finding_id": "SHX-F-GATE-001",
        "title": "Synthetic verified finding",
        "status": "VERIFIED",
        "severity": severity,
        "confidence": "HIGH",
        "catalog_hypothesis_ids": ["SHX-AUTHZ-L02"],
        "affected_surface": ["controlled fixture endpoint"],
        "evidence_ids": ["EV-GATE-REPRO", "EV-GATE-VERIFY"],
        "evidence_chain": {name: copy.deepcopy(link) for name in CHAIN_LINK_NAMES},
        "verification": {
            "independent": True,
            "outcome": "VERIFIED",
            "verifier": "verifier-2",
            "evidence_ids": ["EV-GATE-VERIFY"],
            "refutation_attempt": "Independent local reconstruction attempted to refute the boundary failure and could not.",
        },
        "regression": {
            "status": "PASS",
            "command": "python -m unittest tests.test_security_gate",
            "assertion": "the security invariant holds",
            "evidence_ids": ["EV-GATE-VERIFY"],
        },
        "resolution": resolution,
    }


def report_with(finding: dict) -> dict:
    report = base_report()
    report["findings"] = [finding]
    return report


class SecurityGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.default = json.loads(DEFAULT_POLICY_PATH.read_text(encoding="utf-8"))

    def test_pass_recomputed_without_trusting_declared_outcome(self):
        report = base_report()
        report["release_recommendation"] = "BLOCKED"
        self.assertEqual(evaluate(report, self.default).outcome, "PASS")

    def test_canonical_example_passes_with_contract_enforced(self):
        report = json.loads((ROOT / "examples/report.example.json").read_text(encoding="utf-8"))
        decision = evaluate(report, self.default, enforce_contract=True)
        self.assertEqual(decision.outcome, "PASS")
        self.assertEqual(decision.exit_code, 0)

    def test_contract_invalid_report_is_incomplete_and_exits_two(self):
        with self.assertRaises(GateInputError):
            evaluate(copy.deepcopy(LEGACY_REPORT), self.default, enforce_contract=True)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy-report.json"
            path.write_text(json.dumps(LEGACY_REPORT), encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main([str(path), "--policy", str(DEFAULT_POLICY_PATH)])
        self.assertEqual(exit_code, 2)
        self.assertIn("INCOMPLETE", stdout.getvalue())
        self.assertIn("canonical report contract", stdout.getvalue())

    def test_unresolved_verified_high_blocks(self):
        decision = evaluate(report_with(verified_finding()), self.default)
        self.assertEqual(decision.outcome, "BLOCKED")
        self.assertEqual(decision.exit_code, 1)
        self.assertIn("unresolved verified HIGH", decision.blockers[0])

    def test_fixed_verified_high_passes(self):
        self.assertEqual(evaluate(report_with(verified_finding(resolution="FIXED")), self.default).outcome, "PASS")

    def test_fixed_verified_high_without_regression_is_incomplete(self):
        finding = verified_finding(resolution="FIXED")
        finding.pop("regression")
        self.assertEqual(evaluate(report_with(finding), self.default).outcome, "INCOMPLETE")

    def test_missing_independent_verification_is_incomplete(self):
        # enforce_contract=False: the canonical contract already forbids a VERIFIED
        # High finding without an independent verifier, so this exercises the gate's
        # own fail-closed behaviour for a report that reached it unvalidated.
        finding = verified_finding()
        finding.pop("verification")
        decision = evaluate(report_with(finding), self.default, enforce_contract=False)
        self.assertEqual(decision.outcome, "INCOMPLETE")
        self.assertEqual(decision.exit_code, 2)
        self.assertIn("independent verification evidence is incomplete", decision.incomplete[0])

    def test_valid_accepted_risk_has_distinct_outcome(self):
        # enforce_contract=False: accepted_risk is a policy-layer record that
        # finding-v1 does not carry; this test is about gate policy logic.
        finding = verified_finding(resolution="ACCEPTED_RISK")
        finding["accepted_risk"] = {
            "reason": "temporary compensating control",
            "approver": "security-owner",
            "approved_at": "2026-08-30T00:00:00Z",
            "expires_at": "2026-09-30T00:00:00Z",
        }
        policy = copy.deepcopy(self.default)
        policy["allow_accepted_risk"] = True
        decision = evaluate(
            report_with(finding), policy, now=datetime(2026, 8, 31, tzinfo=timezone.utc), enforce_contract=False
        )
        self.assertEqual(decision.outcome, "PASS_WITH_KNOWN_RISK")
        self.assertEqual(decision.exit_code, 0)

    def test_expired_accepted_risk_blocks(self):
        finding = verified_finding(resolution="ACCEPTED_RISK")
        finding["accepted_risk"] = {
            "reason": "expired",
            "approver": "security-owner",
            "approved_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-02-01T00:00:00Z",
        }
        policy = copy.deepcopy(self.default)
        policy["allow_accepted_risk"] = True
        decision = evaluate(
            report_with(finding), policy, now=datetime(2026, 8, 31, tzinfo=timezone.utc), enforce_contract=False
        )
        self.assertEqual(decision.outcome, "BLOCKED")
        self.assertEqual(decision.exit_code, 1)

    def test_integrity_unknown_is_incomplete_by_default(self):
        report = base_report()
        report["coverage"]["integrity_critical_unknown"] = 1
        self.assertEqual(evaluate(report, self.default).outcome, "INCOMPLETE")

    def test_legacy_object_blocked_check_integrity_signal_is_incomplete(self):
        # enforce_contract=False: report-v1 carries blocked_checks as hypothesis ID
        # strings. The gate keeps reading the legacy object form fail-closed.
        report = base_report()
        report["blocked_checks"] = [{"id": "SHX-MONEY-001", "status": "BLOCKED", "integrity_critical": True}]
        self.assertEqual(evaluate(report, self.default, enforce_contract=False).outcome, "INCOMPLETE")

    def test_integrity_unknown_can_block_by_policy(self):
        report = base_report()
        report["coverage"]["integrity_critical_unknown"] = 1
        policy = copy.deepcopy(self.default)
        policy["integrity_critical_unknown_outcome"] = "BLOCKED"
        self.assertEqual(evaluate(report, policy).outcome, "BLOCKED")

    def test_required_tool_gap_is_incomplete(self):
        policy = copy.deepcopy(self.default)
        policy["required_tools"] = ["semgrep"]
        self.assertEqual(evaluate(base_report(), policy).outcome, "INCOMPLETE")

    def test_unproven_high_is_incomplete(self):
        finding = verified_finding()
        finding["status"] = "LIKELY_BUT_UNPROVEN"
        finding["verification"]["outcome"] = "LIKELY_BUT_UNPROVEN"
        decision = evaluate(report_with(finding), self.default)
        self.assertEqual(decision.outcome, "INCOMPLETE")
        self.assertIn("HIGH candidate remains LIKELY_BUT_UNPROVEN", decision.incomplete[0])

    def test_empty_coverage_fails_closed(self):
        report = base_report()
        for key in ("APPLICABLE", "NOT_APPLICABLE", "UNKNOWN", "BLOCKED"):
            report["coverage"][key] = 0
        with self.assertRaises(GateInputError):
            validate_report(report)

    def test_lowercase_coverage_keys_fail_closed(self):
        report = base_report()
        report["coverage"] = {"applicable": 1, "not_applicable": 1, "unknown": 0, "blocked": 0, "integrity_critical_unknown": 0}
        with self.assertRaises(GateInputError):
            validate_report(report)

    def test_malformed_report_fails_closed(self):
        with self.assertRaises(GateInputError):
            validate_report({})


if __name__ == "__main__":
    unittest.main()
