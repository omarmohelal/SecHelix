import copy
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.security_gate import GateInputError, evaluate, validate_report


ROOT = Path(__file__).resolve().parents[1]


def base_report():
    return {
        "schema_version": "1.0.0",
        "scope": {"project": "fixture", "mode": "STATIC", "deployment_state": "READY"},
        "coverage": {"applicable": 1, "not_applicable": 1, "unknown": 0, "blocked": 0, "integrity_critical_unknown": 0},
        "tools": [],
        "findings": [],
        "blocked_checks": [],
        "release_recommendation": "BLOCKED",
    }


def verified_finding(severity="HIGH", resolution="OPEN"):
    return {
        "id": "SHX-TEST-001",
        "title": "Synthetic verified finding",
        "severity": severity,
        "status": "VERIFIED",
        "resolution": resolution,
        "independent_verification": {
            "status": "VERIFIED",
            "verifier_id": "verifier-2",
            "verified_at": "2026-08-31T00:00:00Z",
            "evidence": ["independent local reconstruction"],
        },
        "regression": {"result": "PASS", "assertion": "the security invariant holds"},
    }


class SecurityGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.default = json.loads((ROOT / "policies/default.json").read_text(encoding="utf-8"))

    def test_pass_recomputed_without_trusting_declared_outcome(self):
        report = base_report()
        report["release_recommendation"] = "BLOCKED"
        self.assertEqual(evaluate(report, self.default).outcome, "PASS")

    def test_unresolved_verified_high_blocks(self):
        report = base_report()
        report["findings"] = [verified_finding()]
        decision = evaluate(report, self.default)
        self.assertEqual(decision.outcome, "BLOCKED")
        self.assertIn("unresolved verified HIGH", decision.blockers[0])

    def test_fixed_verified_high_passes(self):
        report = base_report()
        report["findings"] = [verified_finding(resolution="FIXED")]
        self.assertEqual(evaluate(report, self.default).outcome, "PASS")

    def test_fixed_verified_high_without_regression_is_incomplete(self):
        report = base_report()
        finding = verified_finding(resolution="FIXED")
        finding.pop("regression")
        report["findings"] = [finding]
        self.assertEqual(evaluate(report, self.default).outcome, "INCOMPLETE")

    def test_missing_independent_verification_is_incomplete(self):
        report = base_report()
        finding = verified_finding()
        finding.pop("independent_verification")
        report["findings"] = [finding]
        self.assertEqual(evaluate(report, self.default).outcome, "INCOMPLETE")

    def test_valid_accepted_risk_has_distinct_outcome(self):
        report = base_report()
        finding = verified_finding(resolution="ACCEPTED_RISK")
        finding["accepted_risk"] = {
            "reason": "temporary compensating control",
            "approver": "security-owner",
            "approved_at": "2026-08-30T00:00:00Z",
            "expires_at": "2026-09-30T00:00:00Z",
        }
        report["findings"] = [finding]
        policy = copy.deepcopy(self.default)
        policy["allow_accepted_risk"] = True
        decision = evaluate(report, policy, now=datetime(2026, 8, 31, tzinfo=timezone.utc))
        self.assertEqual(decision.outcome, "PASS_WITH_KNOWN_RISK")
        self.assertEqual(decision.exit_code, 0)

    def test_expired_accepted_risk_blocks(self):
        report = base_report()
        finding = verified_finding(resolution="ACCEPTED_RISK")
        finding["accepted_risk"] = {
            "reason": "expired",
            "approver": "security-owner",
            "approved_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-02-01T00:00:00Z",
        }
        report["findings"] = [finding]
        policy = copy.deepcopy(self.default)
        policy["allow_accepted_risk"] = True
        self.assertEqual(evaluate(report, policy, now=datetime(2026, 8, 31, tzinfo=timezone.utc)).outcome, "BLOCKED")

    def test_integrity_unknown_is_incomplete_by_default(self):
        report = base_report()
        report["blocked_checks"] = [{"id": "SHX-MONEY-001", "status": "BLOCKED", "integrity_critical": True}]
        self.assertEqual(evaluate(report, self.default).outcome, "INCOMPLETE")

    def test_integrity_unknown_can_block_by_policy(self):
        report = base_report()
        report["coverage"]["integrity_critical_unknown"] = 1
        policy = copy.deepcopy(self.default)
        policy["integrity_critical_unknown_outcome"] = "BLOCKED"
        self.assertEqual(evaluate(report, policy).outcome, "BLOCKED")

    def test_required_tool_gap_is_incomplete(self):
        report = base_report()
        policy = copy.deepcopy(self.default)
        policy["required_tools"] = ["semgrep"]
        self.assertEqual(evaluate(report, policy).outcome, "INCOMPLETE")

    def test_unproven_high_is_incomplete(self):
        report = base_report()
        finding = verified_finding()
        finding["status"] = "LIKELY_BUT_UNPROVEN"
        finding.pop("independent_verification")
        report["findings"] = [finding]
        self.assertEqual(evaluate(report, self.default).outcome, "INCOMPLETE")

    def test_empty_coverage_fails_closed(self):
        report = base_report()
        for key in ("applicable", "not_applicable", "unknown", "blocked"):
            report["coverage"][key] = 0
        with self.assertRaises(GateInputError):
            validate_report(report)

    def test_malformed_report_fails_closed(self):
        with self.assertRaises(GateInputError):
            validate_report({})


if __name__ == "__main__":
    unittest.main()
