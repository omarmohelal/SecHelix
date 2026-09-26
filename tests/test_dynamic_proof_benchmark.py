from __future__ import annotations

import json
import unittest

from evals.dynamic_proof_benchmark import run_dynamic_proof_benchmark


class DynamicProofBenchmarkTests(unittest.TestCase):
    def test_paired_dynamic_proofs_are_measured_without_overclaiming(self) -> None:
        result = run_dynamic_proof_benchmark(sechelix_commit="TEST-COMMIT")

        self.assertEqual(result["measurement_status"], "MEASURED")
        self.assertEqual(result["result_kind"], "DYNAMIC_PROOF_PRIMITIVE_BENCHMARK")
        self.assertFalse(result["is_full_sechelix_workflow"])
        self.assertEqual(result["run"]["execution_mode"], "LOCAL")
        self.assertEqual(result["run"]["network_scope"], "literal-loopback-only")
        self.assertEqual(result["run"]["case_count"], 8)
        self.assertEqual(result["metrics"]["case_accuracy"], 1.0)
        self.assertEqual(result["metrics"]["vulnerable_behavior_recall"], 1.0)
        self.assertEqual(result["metrics"]["clean_behavior_rejection_rate"], 1.0)
        self.assertEqual(result["metrics"]["inconclusive_rate"], 0.0)

        families = {row["family"] for row in result["cases"]}
        self.assertEqual(
            families,
            {"state-transition", "payment-invariant", "money-flow-invariant", "workflow-sequence"},
        )
        for row in result["cases"]:
            self.assertTrue(row["correct"])
            self.assertFalse(row["promotes_finding"])
            self.assertGreaterEqual(row["request_count"], 1)
            self.assertGreaterEqual(row["elapsed_ms"], 0)

    def test_benchmark_artifact_contains_no_fixture_credentials_or_raw_secret_inputs(self) -> None:
        rendered = json.dumps(run_dynamic_proof_benchmark())
        for forbidden in (
            "Bearer ",
            "Authorization",
            "Cookie",
            "Idempotency-Key",
            "fixture-auth",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_benchmark_declares_full_workflow_metrics_out_of_scope(self) -> None:
        result = run_dynamic_proof_benchmark()
        limitations = " ".join(result["limitations"]).lower()
        self.assertIn("candidate discovery", limitations)
        self.assertIn("independent-verifier", limitations)
        self.assertIn("release-gate", limitations)
        self.assertNotIn("verified_precision", result["metrics"])
        self.assertNotIn("release_gate_accuracy", result["metrics"])


if __name__ == "__main__":
    unittest.main()
