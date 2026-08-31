import json
import unittest
from pathlib import Path

from evals.run_evals import EvalInputError, export_blind_cases, load_fixtures, score


ROOT = Path(__file__).resolve().parents[1]


class EvalLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = load_fixtures()

    def test_eight_required_paired_fixture_families_exist(self):
        self.assertEqual(len(self.fixtures), 8)
        families = {fixture["family"] for fixture in self.fixtures}
        for required in ("Authorization / BOLA / BFLA", "Business Logic", "Race / Idempotency", "Second-order Injection", "SSRF / URL Fetching", "File / Parser", "AI / Agent / MCP", "Supply Chain"):
            self.assertIn(required, families)

    def test_each_fixture_has_vulnerable_and_clean_truth(self):
        for fixture in self.fixtures:
            self.assertEqual(fixture["variants"]["vulnerable"]["expected"], "VULNERABLE")
            self.assertEqual(fixture["variants"]["clean"]["expected"], "CLEAN")

    def test_blind_export_contains_no_expected_labels(self):
        exported = export_blind_cases(self.fixtures)
        self.assertEqual(len(exported["cases"]), 16)
        self.assertNotIn("expected", json.dumps(exported))

    def test_perfect_prediction_packet_scores_without_fake_operational_metrics(self):
        predictions = []
        for fixture in self.fixtures:
            predictions.append({"case_id": f"{fixture['id']}::vulnerable", "predicted_label": "VULNERABLE", "verification_status": "VERIFIED"})
            predictions.append({"case_id": f"{fixture['id']}::clean", "predicted_label": "CLEAN", "verification_status": "FALSE_POSITIVE"})
        result = score({"predictions": predictions, "model": "test-runner"}, self.fixtures)
        self.assertEqual(result["measurement_status"], "MEASURED")
        self.assertEqual(result["metrics"]["precision"], 1.0)
        self.assertEqual(result["metrics"]["recall"], 1.0)
        self.assertEqual(result["metrics"]["false_positive_rate"], 0.0)
        self.assertEqual(result["run"]["time_seconds"], "NOT_MEASURED")

    def test_missing_prediction_is_rejected(self):
        with self.assertRaises(EvalInputError):
            score({"predictions": []}, self.fixtures)

    def test_committed_result_is_explicitly_not_measured(self):
        placeholder = json.loads((ROOT / "evals/results/not-measured.json").read_text(encoding="utf-8"))
        self.assertEqual(placeholder["measurement_status"], "NOT_MEASURED")
        self.assertTrue(all(value == "NOT_MEASURED" for value in placeholder["metrics"].values()))


if __name__ == "__main__":
    unittest.main()
