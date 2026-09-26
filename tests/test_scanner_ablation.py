from __future__ import annotations

import copy
import unittest

from evals.run_evals import blind_case_id
from evals.scanner_ablation import (
    NOT_MEASURED,
    ScannerAblationError,
    build_scanner_ablation,
)


def fixtures():
    return [
        {
            "id": "AUTH-1",
            "family": "Authorization",
            "task": "review auth",
            "variants": {
                "vulnerable": {
                    "expected": "VULNERABLE",
                    "language": "python",
                    "filename": "auth.py",
                    "source": "vuln",
                },
                "clean": {
                    "expected": "CLEAN",
                    "language": "python",
                    "filename": "auth.py",
                    "source": "clean",
                },
            },
        },
        {
            "id": "XSS-1",
            "family": "XSS",
            "task": "review xss",
            "variants": {
                "vulnerable": {
                    "expected": "VULNERABLE",
                    "language": "javascript",
                    "filename": "xss.js",
                    "source": "vuln",
                },
                "clean": {
                    "expected": "CLEAN",
                    "language": "javascript",
                    "filename": "xss.js",
                    "source": "clean",
                },
            },
        },
    ]


def base_packet(*, enabled: bool, sources: list[str]):
    return {
        "ablation_run_id": "scanner-ablation-001",
        "model": "same-model",
        "provider": "same-provider",
        "agent_host": "same-host",
        "execution_mode": "BLIND_STATIC",
        "prompt_reference": "prompt-v1",
        "cases_sha256": "sha256:abc",
        "fixture_suite_version": "test-v1",
        "scanner_ablation": {
            "enabled": enabled,
            "sources": sources,
        },
        "time_seconds": 10,
        "input_tokens": 100,
        "output_tokens": 20,
        "cost": 0.10,
        "predictions": [
            {
                "case_id": blind_case_id("AUTH-1", "vulnerable"),
                "predicted_label": "CLEAN",
                "verification_status": "NOT_RUN",
            },
            {
                "case_id": blind_case_id("AUTH-1", "clean"),
                "predicted_label": "VULNERABLE",
                "verification_status": "NOT_RUN",
            },
            {
                "case_id": blind_case_id("XSS-1", "vulnerable"),
                "predicted_label": "VULNERABLE",
                "verification_status": "VERIFIED",
            },
            {
                "case_id": blind_case_id("XSS-1", "clean"),
                "predicted_label": "CLEAN",
                "verification_status": "FALSE_POSITIVE",
            },
        ],
    }


class ScannerAblationTests(unittest.TestCase):
    def test_measures_bundle_delta_without_individual_credit(self):
        control = base_packet(enabled=False, sources=[])
        treatment = base_packet(
            enabled=True,
            sources=["semgrep", "session-token-trust"],
        )
        treatment["time_seconds"] = 13
        treatment["input_tokens"] = 130
        treatment["output_tokens"] = 24
        treatment["cost"] = 0.16
        treatment["predictions"][0]["predicted_label"] = "VULNERABLE"
        treatment["predictions"][0]["verification_status"] = "VERIFIED"
        treatment["predictions"][1]["predicted_label"] = "CLEAN"
        treatment["predictions"][1]["verification_status"] = "FALSE_POSITIVE"

        result = build_scanner_ablation(
            control,
            treatment,
            fixtures=fixtures(),
        )

        self.assertEqual(result["measurement_status"], "MEASURED")
        self.assertEqual(
            result["result_kind"],
            "CONTROLLED_SCANNER_BUNDLE_ABLATION",
        )
        self.assertEqual(
            result["scanner_bundle"]["sources"],
            ["semgrep", "session-token-trust"],
        )
        self.assertEqual(
            result["scanner_bundle"]["attribution_scope"],
            "bundle-level only",
        )
        self.assertFalse(
            result["scanner_bundle"]["individual_scanner_credit"]
        )
        self.assertEqual(
            result["changed_cases"]["vulnerable_detections_gained"],
            1,
        )
        self.assertEqual(
            result["changed_cases"]["clean_false_positives_removed"],
            1,
        )
        self.assertEqual(result["delta"]["detection_recall"], 0.5)
        self.assertEqual(result["delta"]["false_positive_rate"], -0.5)
        self.assertEqual(result["delta"]["time_seconds"], 3)
        self.assertEqual(result["delta"]["input_tokens"], 30)
        self.assertEqual(result["delta"]["output_tokens"], 4)
        self.assertAlmostEqual(result["delta"]["cost"], 0.06)

    def test_single_scanner_is_labeled_single_declared_scanner(self):
        result = build_scanner_ablation(
            base_packet(enabled=False, sources=[]),
            base_packet(enabled=True, sources=["semgrep"]),
            fixtures=fixtures(),
        )
        self.assertEqual(
            result["scanner_bundle"]["attribution_scope"],
            "single declared scanner",
        )
        self.assertTrue(
            result["scanner_bundle"]["individual_scanner_credit"]
        )

    def test_undeclared_scanner_source_fails_closed(self):
        control = base_packet(enabled=False, sources=[])
        treatment = base_packet(enabled=True, sources=["semgrep"])
        treatment["predictions"][0]["scanner_sources"] = ["other-scanner"]
        with self.assertRaisesRegex(
            ScannerAblationError,
            "undeclared scanner sources",
        ):
            build_scanner_ablation(
                control,
                treatment,
                fixtures=fixtures(),
            )

    def test_mismatched_model_fails_closed(self):
        control = base_packet(enabled=False, sources=[])
        treatment = base_packet(enabled=True, sources=["semgrep"])
        treatment["model"] = "different-model"
        with self.assertRaisesRegex(ScannerAblationError, "matching model"):
            build_scanner_ablation(
                control,
                treatment,
                fixtures=fixtures(),
            )

    def test_mismatched_prompt_fails_closed(self):
        control = base_packet(enabled=False, sources=[])
        treatment = base_packet(enabled=True, sources=["semgrep"])
        treatment["prompt_reference"] = "different-prompt"
        with self.assertRaisesRegex(
            ScannerAblationError,
            "matching prompt_reference",
        ):
            build_scanner_ablation(
                control,
                treatment,
                fixtures=fixtures(),
            )

    def test_control_cannot_contain_scanners(self):
        control = base_packet(enabled=False, sources=["semgrep"])
        treatment = base_packet(enabled=True, sources=["semgrep"])
        with self.assertRaisesRegex(
            ScannerAblationError,
            "control arm must not declare",
        ):
            build_scanner_ablation(
                control,
                treatment,
                fixtures=fixtures(),
            )

    def test_treatment_requires_scanner_source(self):
        control = base_packet(enabled=False, sources=[])
        treatment = base_packet(enabled=True, sources=[])
        with self.assertRaisesRegex(
            ScannerAblationError,
            "at least one scanner source",
        ):
            build_scanner_ablation(
                control,
                treatment,
                fixtures=fixtures(),
            )

    def test_missing_operational_metrics_stay_not_measured(self):
        control = base_packet(enabled=False, sources=[])
        treatment = base_packet(enabled=True, sources=["semgrep"])
        for packet in (control, treatment):
            packet.pop("time_seconds")
            packet.pop("input_tokens")
            packet.pop("output_tokens")
            packet.pop("cost")

        result = build_scanner_ablation(
            control,
            treatment,
            fixtures=fixtures(),
        )
        self.assertEqual(result["delta"]["time_seconds"], NOT_MEASURED)
        self.assertEqual(result["delta"]["input_tokens"], NOT_MEASURED)
        self.assertEqual(result["delta"]["output_tokens"], NOT_MEASURED)
        self.assertEqual(result["delta"]["cost"], NOT_MEASURED)

    def test_case_set_must_match_exactly(self):
        control = base_packet(enabled=False, sources=[])
        treatment = base_packet(enabled=True, sources=["semgrep"])
        treatment = copy.deepcopy(treatment)
        treatment["predictions"].pop()
        with self.assertRaises(ScannerAblationError):
            build_scanner_ablation(
                control,
                treatment,
                fixtures=fixtures(),
            )

    def test_result_does_not_emit_per_case_truth_or_scanner_outputs(self):
        control = base_packet(enabled=False, sources=[])
        treatment = base_packet(enabled=True, sources=["semgrep"])
        treatment["predictions"][0]["scanner_sources"] = ["semgrep"]
        treatment["predictions"][0]["scanner_output"] = "secret raw output"
        result = build_scanner_ablation(
            control,
            treatment,
            fixtures=fixtures(),
        )
        rendered = str(result)
        self.assertNotIn("secret raw output", rendered)
        self.assertNotIn("AUTH-1", rendered)
        self.assertNotIn("XSS-1", rendered)


if __name__ == "__main__":
    unittest.main()
