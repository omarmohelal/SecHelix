"""A policy pack must decide, record why, and never configure its way to green."""

import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sechelix_core.contracts import validate_contract
from sechelix_core.policy_packs import (
    BLOCK,
    INCOMPLETE,
    WARN,
    PolicyError,
    evaluate,
    load_pack,
    stamp_report,
)

ROOT = Path(__file__).resolve().parents[1]
PROD = ROOT / "policies" / "packs" / "production-default.json"
NOW = datetime(2026, 9, 2, tzinfo=timezone.utc)

PRODUCTION = {"environment": "PRODUCTION", "organization": "omarmohelal",
              "repository": "SecHelix", "branch": "main", "data_sensitivity": "INTERNAL"}


def finding(fid="SHX-F-P1", **over):
    base = {
        "finding_id": fid,
        "title": "t",
        "severity": "HIGH",
        "status": "VERIFIED",
        "resolution": "OPEN",
        "affected_surface": ["app/x.py:1"],
        "catalog_hypothesis_ids": ["SHX-AUTHZ-L02"],
        "verification": {"independent": True, "outcome": "VERIFIED",
                         "evidence_ids": [], "refutation_attempt": "x"},
        "regression": {"status": "PASS", "command": "x", "assertion": "x", "evidence_ids": []},
    }
    base.update(over)
    return base


def report(*findings):
    return {"report_id": "R-1", "findings": list(findings)}


class PackTests(unittest.TestCase):
    def test_the_shipped_pack_validates(self):
        validate_contract("policy-pack", json.loads(PROD.read_text(encoding="utf-8")))

    def test_a_pack_with_no_rules_is_refused(self):
        with self.assertRaises(PolicyError):
            evaluate({"pack_id": "X", "version": "1.0.0", "rules": []},
                     report(), PRODUCTION, now=NOW)

    def test_a_clean_report_passes(self):
        pack = load_pack(PROD)
        decision = evaluate(pack, report(), PRODUCTION, now=NOW)
        self.assertEqual(decision.outcome, "PASS")
        self.assertFalse(decision.blocks_release)


class BlockingTests(unittest.TestCase):
    def setUp(self):
        self.pack = load_pack(PROD)

    def test_an_unresolved_verified_high_blocks(self):
        decision = evaluate(self.pack, report(finding()), PRODUCTION, now=NOW)
        self.assertEqual(decision.outcome, BLOCK)
        self.assertTrue(decision.blocks_release)
        self.assertIn("PROD-NO-UNRESOLVED-HIGH", [f.rule_id for f in decision.fired])

    def test_an_unproven_high_candidate_is_incomplete_not_blocked(self):
        """Neither proven nor refuted is a different statement from 'it fails'."""
        decision = evaluate(self.pack, report(finding(status="HYPOTHESIS")),
                            PRODUCTION, now=NOW)
        self.assertEqual(decision.outcome, INCOMPLETE)
        self.assertTrue(decision.blocks_release)

    def test_a_fixed_high_without_regression_is_incomplete(self):
        f = finding(resolution="FIXED",
                    regression={"status": "NOT_RUN", "command": "x",
                                "assertion": "x", "evidence_ids": []})
        decision = evaluate(self.pack, report(f), PRODUCTION, now=NOW)
        self.assertEqual(decision.outcome, INCOMPLETE)

    def test_a_fixed_high_with_passing_regression_does_not_fire_that_rule(self):
        f = finding(resolution="FIXED")
        decision = evaluate(self.pack, report(f), PRODUCTION, now=NOW)
        self.assertIn("PROD-REGRESSION-REQUIRED", decision.evaluated_not_fired)

    def test_verification_by_the_same_reviewer_is_incomplete(self):
        f = finding(resolution="FIXED",
                    verification={"independent": False, "outcome": "VERIFIED",
                                  "evidence_ids": [], "refutation_attempt": "x"})
        decision = evaluate(self.pack, report(f), PRODUCTION, now=NOW)
        self.assertTrue(decision.blocks_release)

    def test_a_refuted_finding_does_not_block(self):
        f = finding(status="FALSE_POSITIVE", resolution="FALSE_POSITIVE")
        self.assertEqual(evaluate(self.pack, report(f), PRODUCTION, now=NOW).outcome, "PASS")

    def test_a_low_severity_candidate_does_not_block(self):
        f = finding(severity="LOW", status="HYPOTHESIS")
        self.assertEqual(evaluate(self.pack, report(f), PRODUCTION, now=NOW).outcome, "PASS")

    def test_block_outranks_incomplete(self):
        """A known problem outranks an unknown one."""
        decision = evaluate(self.pack,
                            report(finding("SHX-F-A"), finding("SHX-F-B", status="HYPOTHESIS")),
                            PRODUCTION, now=NOW)
        self.assertEqual(decision.outcome, BLOCK)


class DomainRuleTests(unittest.TestCase):
    def setUp(self):
        self.pack = load_pack(PROD)

    def test_an_unproven_money_candidate_requires_review(self):
        f = finding(severity="MEDIUM", status="HYPOTHESIS",
                    affected_surface=["app/payments/refund.py:12"],
                    catalog_hypothesis_ids=["SHX-MONEY-L07"])
        decision = evaluate(self.pack, report(f), PRODUCTION, now=NOW)
        self.assertEqual(decision.outcome, INCOMPLETE)
        self.assertIn("PAYMENT-RACE-REVIEW", [x.rule_id for x in decision.fired])

    def test_an_unproven_mcp_candidate_requires_review(self):
        f = finding(severity="MEDIUM", status="HYPOTHESIS",
                    affected_surface=["agents/mcp_server.py:5"],
                    catalog_hypothesis_ids=["SHX-AI-L03"])
        decision = evaluate(self.pack, report(f), PRODUCTION, now=NOW)
        self.assertIn("MCP-WRITE-AUTHORIZATION", [x.rule_id for x in decision.fired])

    def test_an_unproven_ssrf_candidate_requires_review(self):
        f = finding(severity="MEDIUM", status="HYPOTHESIS",
                    catalog_hypothesis_ids=["SHX-SSRF-L01"])
        decision = evaluate(self.pack, report(f), PRODUCTION, now=NOW)
        self.assertIn("SSRF-FETCHER-REVIEW", [x.rule_id for x in decision.fired])


class AcceptedRiskTests(unittest.TestCase):
    def setUp(self):
        self.pack = load_pack(PROD)

    def _accepted(self, **block):
        base = {"owner": "omar", "reason": "compensating control",
                "approved_at": "2026-09-01T00:00:00Z",
                "expires_at": (NOW + timedelta(days=30)).isoformat()}
        base.update(block)
        return finding(resolution="ACCEPTED_RISK", accepted_risk=base)

    def test_a_complete_acceptance_is_allowed(self):
        self.assertEqual(evaluate(self.pack, report(self._accepted()),
                                  PRODUCTION, now=NOW).outcome, "PASS")

    def test_an_acceptance_without_an_owner_blocks(self):
        decision = evaluate(self.pack, report(self._accepted(owner="")), PRODUCTION, now=NOW)
        self.assertEqual(decision.outcome, BLOCK)

    def test_an_acceptance_without_an_expiry_blocks(self):
        """A permanent exception acquired by writing a sentence."""
        decision = evaluate(self.pack, report(self._accepted(expires_at="")),
                            PRODUCTION, now=NOW)
        self.assertEqual(decision.outcome, BLOCK)

    def test_an_expired_acceptance_blocks(self):
        decision = evaluate(self.pack,
                            report(self._accepted(expires_at="2026-01-01T00:00:00Z")),
                            PRODUCTION, now=NOW)
        self.assertEqual(decision.outcome, BLOCK)
        self.assertTrue(any("expired" in f.finding_ids[0] or "expired" in str(f.finding_ids)
                            for f in decision.fired))

    def test_a_malformed_expiry_blocks_rather_than_passing(self):
        decision = evaluate(self.pack, report(self._accepted(expires_at="soon")),
                            PRODUCTION, now=NOW)
        self.assertEqual(decision.outcome, BLOCK)


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.pack = load_pack(PROD)

    def test_a_non_production_context_does_not_apply(self):
        decision = evaluate(self.pack, report(finding()),
                            dict(PRODUCTION, environment="DEVELOPMENT"), now=NOW)
        self.assertEqual(decision.outcome, "PASS")
        self.assertEqual(decision.scope_match["environments"], "NOT_MATCHED")

    def test_unknown_scope_is_incomplete_not_pass(self):
        """A pack whose applicability cannot be resolved must not quietly decide nothing."""
        decision = evaluate(self.pack, report(finding()), {"repository": "x"}, now=NOW)
        self.assertEqual(decision.outcome, INCOMPLETE)
        self.assertIn("could not be resolved", " ".join(decision.notes))

    def test_scope_resolution_is_recorded(self):
        decision = evaluate(self.pack, report(), PRODUCTION, now=NOW)
        self.assertEqual(decision.scope_match["environments"], "MATCHED")
        self.assertEqual(decision.scope_match["organization"], "UNCONSTRAINED")


class RecordingTests(unittest.TestCase):
    def test_rules_that_did_not_fire_are_recorded(self):
        """A rule that never applied must not look like one that passed."""
        decision = evaluate(load_pack(PROD), report(), PRODUCTION, now=NOW)
        self.assertTrue(decision.evaluated_not_fired)
        self.assertIn("PROD-NO-UNRESOLVED-HIGH", decision.evaluated_not_fired)

    def test_the_decision_names_the_pack_and_version(self):
        decision = evaluate(load_pack(PROD), report(finding()), PRODUCTION, now=NOW)
        payload = decision.as_dict()
        self.assertEqual(payload["policy_pack"]["pack_id"], "PROD-DEFAULT")
        self.assertEqual(payload["policy_pack"]["version"], "1.0.0")

    def test_stamping_puts_the_decision_in_the_report(self):
        decision = evaluate(load_pack(PROD), report(finding()), PRODUCTION, now=NOW)
        stamped = stamp_report(report(finding()), [decision])
        self.assertEqual(len(stamped["policy_decisions"]), 1)
        self.assertEqual(stamped["policy_decisions"][0]["outcome"], BLOCK)

    def test_a_firing_names_the_findings_that_triggered_it(self):
        decision = evaluate(load_pack(PROD), report(finding("SHX-F-Z")), PRODUCTION, now=NOW)
        self.assertIn("SHX-F-Z", decision.fired[0].finding_ids)


if __name__ == "__main__":
    unittest.main()
