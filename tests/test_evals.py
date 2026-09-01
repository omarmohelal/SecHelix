import json
import unittest
from pathlib import Path

from evals.run_evals import (
    EvalInputError,
    blind_case_id,
    export_blind_cases,
    load_fixtures,
    score,
)


ROOT = Path(__file__).resolve().parents[1]

# The ten families the evaluation protocol requires for a first public benchmark.
REQUIRED_FAMILY_KEYWORDS = (
    "Authorization",
    "Authentication",
    "Injection",
    "XSS",
    "SSRF",
    "File",
    "Business",
    "Race",
    "Supply",
    "AI",
)


class EvalLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = load_fixtures()

    def test_every_required_family_is_represented(self):
        families = " | ".join(fixture["family"] for fixture in self.fixtures)
        for keyword in REQUIRED_FAMILY_KEYWORDS:
            self.assertIn(keyword, families, f"no fixture covers the {keyword} family")

    def test_fixture_ids_are_unique(self):
        ids = [fixture["id"] for fixture in self.fixtures]
        self.assertEqual(len(ids), len(set(ids)))

    def test_each_fixture_has_vulnerable_and_clean_truth(self):
        for fixture in self.fixtures:
            self.assertEqual(fixture["variants"]["vulnerable"]["expected"], "VULNERABLE")
            self.assertEqual(fixture["variants"]["clean"]["expected"], "CLEAN")

    def test_blind_export_covers_every_case_exactly_once(self):
        exported = export_blind_cases(self.fixtures)
        self.assertEqual(len(exported["cases"]), 2 * len(self.fixtures))
        case_ids = [case["case_id"] for case in exported["cases"]]
        self.assertEqual(len(case_ids), len(set(case_ids)))

    def test_blind_export_discloses_no_ground_truth(self):
        exported = export_blind_cases(self.fixtures)
        for case in exported["cases"]:
            # The identifier must not encode the answer or the fixture it came from.
            self.assertTrue(case["case_id"].startswith("CASE-"))
            self.assertNotIn("vulnerable", case["case_id"].lower())
            self.assertNotIn("clean", case["case_id"].lower())
            self.assertEqual(
                set(case) & {"expected", "rationale", "variant", "fixture_id"},
                set(),
                "blind case exposes a ground-truth field",
            )
        for fixture in self.fixtures:
            self.assertNotIn(fixture["id"], json.dumps(exported))

    def test_blind_case_ids_are_deterministic(self):
        first = export_blind_cases(self.fixtures)
        second = export_blind_cases(self.fixtures)
        self.assertEqual(first, second)
        fixture = self.fixtures[0]
        self.assertEqual(
            blind_case_id(fixture["id"], "vulnerable"),
            blind_case_id(fixture["id"], "vulnerable"),
        )

    def test_scoring_accepts_blind_identifiers(self):
        predictions = []
        for fixture in self.fixtures:
            predictions.append({
                "case_id": blind_case_id(fixture["id"], "vulnerable"),
                "predicted_label": "VULNERABLE",
                "verification_status": "VERIFIED",
            })
            predictions.append({
                "case_id": blind_case_id(fixture["id"], "clean"),
                "predicted_label": "CLEAN",
                "verification_status": "FALSE_POSITIVE",
            })
        result = score({"predictions": predictions, "model": "test-runner"}, self.fixtures)
        self.assertEqual(result["measurement_status"], "MEASURED")
        self.assertEqual(result["metrics"]["precision"], 1.0)
        self.assertEqual(result["metrics"]["detection_recall"], 1.0)
        self.assertEqual(result["metrics"]["false_positive_rate"], 0.0)
        self.assertEqual(result["metrics"]["false_positive_rejection_rate"], 1.0)
        self.assertEqual(result["run"]["time_seconds"], "NOT_MEASURED")

    def test_audit_only_metrics_are_not_silently_reported_as_zero(self):
        predictions = [
            {"case_id": blind_case_id(f["id"], v), "predicted_label": e}
            for f in self.fixtures
            for v, e in (("vulnerable", "VULNERABLE"), ("clean", "CLEAN"))
        ]
        result = score({"predictions": predictions}, self.fixtures)
        for metric in ("applicability_accuracy", "regression_proof_rate", "release_gate_accuracy"):
            self.assertEqual(result["metrics"][metric], "NOT_MEASURED")

    def test_per_family_breakdown_is_reported(self):
        predictions = [
            {"case_id": blind_case_id(f["id"], v), "predicted_label": e}
            for f in self.fixtures
            for v, e in (("vulnerable", "VULNERABLE"), ("clean", "CLEAN"))
        ]
        result = score({"predictions": predictions}, self.fixtures)
        self.assertTrue(result["per_family"])
        for counts in result["per_family"].values():
            self.assertEqual(counts["detection_recall"], 1.0)

    def test_duplicate_prediction_is_rejected(self):
        fixture = self.fixtures[0]
        case_id = blind_case_id(fixture["id"], "vulnerable")
        with self.assertRaises(EvalInputError):
            score({"predictions": [
                {"case_id": case_id, "predicted_label": "VULNERABLE"},
                {"case_id": case_id, "predicted_label": "CLEAN"},
            ]}, self.fixtures)

    def test_missing_prediction_is_rejected(self):
        with self.assertRaises(EvalInputError):
            score({"predictions": []}, self.fixtures)

    def test_committed_result_is_explicitly_not_measured(self):
        placeholder = json.loads((ROOT / "evals/results/not-measured.json").read_text(encoding="utf-8"))
        self.assertEqual(placeholder["measurement_status"], "NOT_MEASURED")
        self.assertTrue(all(value == "NOT_MEASURED" for value in placeholder["metrics"].values()))
        # The blocker must state why no measurement exists rather than leaving it implicit.
        self.assertIn("reason", placeholder["blocker"])
        self.assertTrue(placeholder["blocker"]["what_would_unblock_it"])

    def test_keyword_baseline_result_is_not_presented_as_a_sechelix_score(self):
        baseline = json.loads((ROOT / "evals/results/baseline-keyword-v1.json").read_text(encoding="utf-8"))
        self.assertEqual(baseline["result_kind"], "HARNESS_BASELINE")
        self.assertFalse(baseline["is_sechelix_result"])

    def test_fixture_suite_resists_a_keyword_matcher(self):
        """A pattern matcher must stay near chance, or the fixtures are too easy."""
        import sys

        sys.path.insert(0, str(ROOT / "evals" / "baselines"))
        from keyword_baseline import build_predictions  # noqa: E402

        exported = export_blind_cases(self.fixtures)
        result = score(build_predictions(exported["cases"]), self.fixtures)
        self.assertLess(
            result["metrics"]["precision"], 0.75,
            "a keyword matcher scores too well; the fixtures are not discriminating",
        )


if __name__ == "__main__":
    unittest.main()
