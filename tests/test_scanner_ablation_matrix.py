from __future__ import annotations

import copy
import unittest

from evals.run_evals import blind_case_id
from evals.scanner_ablation_matrix import (
    NOT_MEASURED,
    ScannerAblationMatrixError,
    build_scanner_ablation_matrix,
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


def packet(*, enabled: bool, sources: list[str]):
    return {
        "ablation_run_id": "scanner-matrix-001",
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
                "scanner_sources": sources if enabled else [],
            },
            {
                "case_id": blind_case_id("AUTH-1", "clean"),
                "predicted_label": "VULNERABLE",
                "verification_status": "NOT_RUN",
                "scanner_sources": sources if enabled else [],
            },
            {
                "case_id": blind_case_id("XSS-1", "vulnerable"),
                "predicted_label": "VULNERABLE",
                "verification_status": "VERIFIED",
                "scanner_sources": sources if enabled else [],
            },
            {
                "case_id": blind_case_id("XSS-1", "clean"),
                "predicted_label": "CLEAN",
                "verification_status": "FALSE_POSITIVE",
                "scanner_sources": sources if enabled else [],
            },
        ],
    }


class ScannerAblationMatrixTests(unittest.TestCase):
    def test_builds_individual_rows_only_from_isolated_treatments(self):
        control = packet(enabled=False, sources=[])

        semgrep = packet(enabled=True, sources=["semgrep"])
        semgrep["time_seconds"] = 12
        semgrep["input_tokens"] = 120
        semgrep["output_tokens"] = 24
        semgrep["cost"] = 0.14
        semgrep["predictions"][0]["predicted_label"] = "VULNERABLE"
        semgrep["predictions"][0]["verification_status"] = "VERIFIED"

        trust = packet(enabled=True, sources=["session-token-trust"])
        trust["time_seconds"] = 13
        trust["input_tokens"] = 130
        trust["output_tokens"] = 25
        trust["cost"] = 0.15
        trust["predictions"][1]["predicted_label"] = "CLEAN"
        trust["predictions"][1]["verification_status"] = "FALSE_POSITIVE"

        result = build_scanner_ablation_matrix(
            control,
            [trust, semgrep],
            fixtures=fixtures(),
        )

        self.assertEqual(
            result["result_kind"],
            "CONTROLLED_ISOLATED_SCANNER_ABLATION_MATRIX",
        )
        self.assertEqual(result["measurement_status"], "MEASURED")
        self.assertEqual(result["scanner_count"], 2)
        self.assertEqual(
            [row["scanner_source"] for row in result["scanners"]],
            ["semgrep", "session-token-trust"],
        )

        by_source = {
            row["scanner_source"]: row for row in result["scanners"]
        }
        self.assertEqual(
            by_source["semgrep"]["changed_cases"]["vulnerable_detections_gained"],
            1,
        )
        self.assertEqual(
            by_source["session-token-trust"]["changed_cases"][
                "clean_false_positives_removed"
            ],
            1,
        )
        self.assertEqual(
            result["operational_delta_totals"]["time_seconds"]["value"],
            5.0,
        )
        self.assertAlmostEqual(
            result["operational_delta_totals"]["cost"]["value"],
            0.09,
        )

    def test_bundle_treatment_is_rejected(self):
        control = packet(enabled=False, sources=[])
        bundle = packet(
            enabled=True,
            sources=["semgrep", "session-token-trust"],
        )
        with self.assertRaisesRegex(
            ScannerAblationMatrixError,
            "exactly one scanner source",
        ):
            build_scanner_ablation_matrix(
                control,
                [bundle],
                fixtures=fixtures(),
            )

    def test_duplicate_scanner_treatment_is_rejected(self):
        control = packet(enabled=False, sources=[])
        first = packet(enabled=True, sources=["semgrep"])
        second = copy.deepcopy(first)
        with self.assertRaisesRegex(
            ScannerAblationMatrixError,
            "duplicate isolated scanner treatment",
        ):
            build_scanner_ablation_matrix(
                control,
                [first, second],
                fixtures=fixtures(),
            )

    def test_confounded_treatment_fails_closed(self):
        control = packet(enabled=False, sources=[])
        treatment = packet(enabled=True, sources=["semgrep"])
        treatment["model"] = "different-model"
        with self.assertRaisesRegex(
            ScannerAblationMatrixError,
            "not a controlled ablation",
        ):
            build_scanner_ablation_matrix(
                control,
                [treatment],
                fixtures=fixtures(),
            )

    def test_missing_operational_value_makes_total_not_measured(self):
        control = packet(enabled=False, sources=[])
        semgrep = packet(enabled=True, sources=["semgrep"])
        trust = packet(enabled=True, sources=["session-token-trust"])
        trust.pop("cost")

        result = build_scanner_ablation_matrix(
            control,
            [semgrep, trust],
            fixtures=fixtures(),
        )
        summary = result["operational_delta_totals"]["cost"]
        self.assertFalse(summary["complete"])
        self.assertEqual(summary["value"], NOT_MEASURED)
        self.assertEqual(summary["measured_arms"], 1)
        self.assertEqual(summary["applicable_arms"], 2)

    def test_empty_matrix_is_rejected(self):
        with self.assertRaisesRegex(
            ScannerAblationMatrixError,
            "at least one treatment",
        ):
            build_scanner_ablation_matrix(
                packet(enabled=False, sources=[]),
                [],
                fixtures=fixtures(),
            )

    def test_result_does_not_emit_case_ids_truth_or_raw_scanner_output(self):
        control = packet(enabled=False, sources=[])
        treatment = packet(enabled=True, sources=["semgrep"])
        treatment["predictions"][0]["scanner_output"] = "sensitive scanner blob"

        result = build_scanner_ablation_matrix(
            control,
            [treatment],
            fixtures=fixtures(),
        )
        rendered = str(result)
        self.assertNotIn("AUTH-1", rendered)
        self.assertNotIn("XSS-1", rendered)
        self.assertNotIn("sensitive scanner blob", rendered)
        self.assertNotIn("expected", rendered.lower())


if __name__ == "__main__":
    unittest.main()
