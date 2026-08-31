import unittest
from copy import deepcopy

from sechelix_core.applicability import evaluate_applicability
from sechelix_core.contracts import ROOT, load_json
from tests.helpers import applicability_input


class ApplicabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load_json(ROOT / "catalog" / "checks.json")

    def test_all_four_states_are_explainable_and_deterministic(self) -> None:
        request = applicability_input()
        first = evaluate_applicability(self.catalog, request)
        second = evaluate_applicability(self.catalog, request)
        self.assertEqual(first, second)
        self.assertEqual(
            {"APPLICABLE": 25, "NOT_APPLICABLE": 26, "UNKNOWN": 468, "BLOCKED": 27, "TOTAL": 546},
            first["summary"],
        )
        self.assertEqual(
            {"APPLICABLE", "NOT_APPLICABLE", "UNKNOWN", "BLOCKED"},
            {decision["status"] for decision in first["decisions"]},
        )
        self.assertTrue(all(decision["reason"] and decision["reason_code"] for decision in first["decisions"]))

    def test_missing_architecture_evidence_is_unknown_not_not_applicable(self) -> None:
        request = applicability_input()
        request["architecture"]["capabilities"] = {}
        request["blocked_hypotheses"] = []
        result = evaluate_applicability(self.catalog, request)
        self.assertEqual(546, result["summary"]["UNKNOWN"])
        self.assertEqual(0, result["summary"]["NOT_APPLICABLE"])

    def test_unconfirmed_scope_blocks_every_check(self) -> None:
        result = evaluate_applicability(self.catalog, applicability_input(confirmed=False))
        self.assertFalse(result["authorized"])
        self.assertEqual(546, result["summary"]["BLOCKED"])
        self.assertEqual({"SCOPE_NOT_AUTHORIZED"}, {item["reason_code"] for item in result["decisions"]})

    def test_unknown_explicit_block_id_is_rejected(self) -> None:
        request = deepcopy(applicability_input())
        request["blocked_hypotheses"] = [
            {"hypothesis_id": "SHX-AUTH-L99", "reason": "Typographical error in caller input."}
        ]
        with self.assertRaisesRegex(ValueError, "outside the catalog"):
            evaluate_applicability(self.catalog, request)


if __name__ == "__main__":
    unittest.main()
