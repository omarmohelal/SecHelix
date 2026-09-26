from __future__ import annotations

import copy
import unittest

from evals.scanner_ablation_trials import (
    NOT_MEASURED,
    ScannerAblationTrialsError,
    build_scanner_ablation_trials,
)


def matrix(run_id: str, *, cost_missing: bool = False):
    return {
        "schema_version": "sechelix-scanner-ablation-matrix/v1",
        "measurement_status": "MEASURED",
        "result_kind": "CONTROLLED_ISOLATED_SCANNER_ABLATION_MATRIX",
        "ablation_run_id": run_id,
        "matched_conditions": {
            "model": "same-model",
            "provider": "same-provider",
            "agent_host": "same-host",
            "execution_mode": "BLIND_STATIC",
            "prompt_reference": "prompt-v1",
            "cases_sha256": "sha256:abc",
            "fixture_suite_version": "test-v1",
        },
        "scanners": [
            {
                "scanner_source": "semgrep",
                "measurement_status": "MEASURED",
                "delta": {
                    "precision": 0.10,
                    "detection_recall": 0.20,
                    "verified_precision": 0.15,
                    "false_positive_rate": -0.10,
                    "false_positive_rejection_rate": 0.10,
                    "time_seconds": 2,
                    "input_tokens": 20,
                    "output_tokens": 4,
                    "cost": "NOT_MEASURED" if cost_missing else 0.04,
                },
                "changed_cases": {
                    "vulnerable_detections_gained": 2,
                    "vulnerable_detections_lost": 0,
                    "clean_false_positives_removed": 1,
                    "clean_false_positives_introduced": 0,
                    "label_unchanged": 73,
                },
                "control_metrics": {},
                "treatment_metrics": {},
            },
            {
                "scanner_source": "session-token-trust",
                "measurement_status": "MEASURED",
                "delta": {
                    "precision": 0.05,
                    "detection_recall": 0.10,
                    "verified_precision": 0.05,
                    "false_positive_rate": -0.05,
                    "false_positive_rejection_rate": 0.05,
                    "time_seconds": 3,
                    "input_tokens": 30,
                    "output_tokens": 5,
                    "cost": 0.05,
                },
                "changed_cases": {
                    "vulnerable_detections_gained": 1,
                    "vulnerable_detections_lost": 0,
                    "clean_false_positives_removed": 1,
                    "clean_false_positives_introduced": 0,
                    "label_unchanged": 74,
                },
                "control_metrics": {},
                "treatment_metrics": {},
            },
        ],
    }


class ScannerAblationTrialsTests(unittest.TestCase):
    def test_aggregates_repeated_matched_trials_with_spread(self):
        first = matrix("run-1")
        second = matrix("run-2")
        second["scanners"][0]["delta"]["detection_recall"] = 0.30
        second["scanners"][0]["delta"]["time_seconds"] = 4
        second["scanners"][0]["changed_cases"]["vulnerable_detections_gained"] = 3

        result = build_scanner_ablation_trials([first, second])

        self.assertEqual(
            result["result_kind"],
            "REPEATED_ISOLATED_SCANNER_ABLATION_TRIALS",
        )
        self.assertEqual(result["measurement_status"], "MEASURED")
        self.assertEqual(result["trial_count"], 2)
        self.assertEqual(result["run_ids"], ["run-1", "run-2"])
        self.assertEqual(result["scanner_count"], 2)

        by_source = {
            row["scanner_source"]: row for row in result["scanners"]
        }
        semgrep = by_source["semgrep"]
        recall = semgrep["delta_spread"]["detection_recall"]
        self.assertTrue(recall["complete"])
        self.assertEqual(recall["mean"], 0.25)
        self.assertEqual(recall["min"], 0.2)
        self.assertEqual(recall["max"], 0.3)
        self.assertEqual(
            semgrep["changed_case_totals"]["vulnerable_detections_gained"],
            5,
        )
        self.assertEqual(
            semgrep["changed_case_means"]["vulnerable_detections_gained"],
            2.5,
        )

    def test_missing_operational_metric_remains_not_measured(self):
        first = matrix("run-1")
        second = matrix("run-2", cost_missing=True)

        result = build_scanner_ablation_trials([first, second])
        semgrep = {
            row["scanner_source"]: row for row in result["scanners"]
        }["semgrep"]
        cost = semgrep["delta_spread"]["cost"]
        self.assertFalse(cost["complete"])
        self.assertEqual(cost["mean"], NOT_MEASURED)
        self.assertEqual(cost["measured_trials"], 1)
        self.assertEqual(cost["applicable_trials"], 2)

    def test_requires_at_least_two_trials(self):
        with self.assertRaisesRegex(
            ScannerAblationTrialsError,
            "at least two matrices",
        ):
            build_scanner_ablation_trials([matrix("run-1")])

    def test_duplicate_run_id_is_rejected(self):
        with self.assertRaisesRegex(
            ScannerAblationTrialsError,
            "duplicate ablation_run_id",
        ):
            build_scanner_ablation_trials([
                matrix("run-1"),
                matrix("run-1"),
            ])

    def test_mismatched_conditions_are_rejected(self):
        first = matrix("run-1")
        second = matrix("run-2")
        second["matched_conditions"]["model"] = "other-model"
        with self.assertRaisesRegex(
            ScannerAblationTrialsError,
            "identical matched_conditions",
        ):
            build_scanner_ablation_trials([first, second])

    def test_mismatched_scanner_set_is_rejected(self):
        first = matrix("run-1")
        second = matrix("run-2")
        second["scanners"].pop()
        with self.assertRaisesRegex(
            ScannerAblationTrialsError,
            "exact same isolated scanner set",
        ):
            build_scanner_ablation_trials([first, second])

    def test_unmeasured_matrix_is_rejected(self):
        first = matrix("run-1")
        second = matrix("run-2")
        second["measurement_status"] = "NOT_MEASURED"
        with self.assertRaisesRegex(
            ScannerAblationTrialsError,
            "not MEASURED",
        ):
            build_scanner_ablation_trials([first, second])

    def test_result_contains_no_per_case_truth_or_raw_outputs(self):
        first = matrix("run-1")
        second = matrix("run-2")
        first["scanners"][0]["raw_scanner_output"] = "sensitive blob"
        second["scanners"][0]["case_ids"] = ["AUTH-1"]

        result = build_scanner_ablation_trials([first, second])
        rendered = str(result)
        self.assertNotIn("sensitive blob", rendered)
        self.assertNotIn("AUTH-1", rendered)
        self.assertNotIn("expected", rendered.lower())


if __name__ == "__main__":
    unittest.main()
