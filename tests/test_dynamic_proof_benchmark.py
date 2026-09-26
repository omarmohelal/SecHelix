from __future__ import annotations

import json
import unittest

from evals.dynamic_proof_benchmark import run_dynamic_proof_benchmark
from sechelix_runner.proof import ProofClass


class DynamicProofBenchmarkTests(unittest.TestCase):
    def test_paired_dynamic_proofs_are_measured_without_overclaiming(self) -> None:
        result = run_dynamic_proof_benchmark(sechelix_commit="TEST-COMMIT")

        self.assertEqual(result["measurement_status"], "MEASURED")
        self.assertEqual(result["result_kind"], "DYNAMIC_PROOF_PRIMITIVE_BENCHMARK")
        self.assertFalse(result["is_full_sechelix_workflow"])
        self.assertEqual(result["run"]["execution_mode"], "LOCAL")
        self.assertEqual(result["run"]["network_scope"], "literal-loopback-only")
        self.assertEqual(result["run"]["case_count"], 26)
        self.assertEqual(result["run"]["artificial_latency_ms"], 0)
        self.assertEqual(result["run"]["race_concurrency"], 2)
        self.assertEqual(result["metrics"]["case_accuracy"], 1.0)
        self.assertEqual(result["metrics"]["vulnerable_behavior_recall"], 1.0)
        self.assertEqual(result["metrics"]["clean_behavior_rejection_rate"], 1.0)
        self.assertEqual(result["metrics"]["inconclusive_rate"], 0.0)
        self.assertEqual(result["metrics"]["proof_class_coverage"], 1.0)
        self.assertEqual(result["coverage"]["missing_proof_classes"], [])
        self.assertEqual(
            set(result["coverage"]["covered_proof_classes"]),
            {item.value for item in ProofClass},
        )

        families = {row["family"] for row in result["cases"]}
        self.assertEqual(
            families,
            {
                "state-transition",
                "payment-invariant",
                "money-flow-invariant",
                "settlement-refund-sequence",
                "workflow-sequence",
                "authorization-idor",
                "csrf-request",
                "session-revocation",
                "xss-browser-marker",
                "race-idempotency",
                "webhook-signature-replay",
                "path-traversal",
                "ssrf-callback",
            },
        )
        case_ids = {row["case_id"] for row in result["cases"]}
        self.assertIn("SETTLEMENT-REFUND-VULNERABLE", case_ids)
        self.assertIn("SETTLEMENT-REFUND-CLEAN", case_ids)
        for expected_case in (
            "IDOR-VULNERABLE",
            "IDOR-CLEAN",
            "CSRF-VULNERABLE",
            "CSRF-CLEAN",
            "SESSION-VULNERABLE",
            "SESSION-CLEAN",
            "XSS-VULNERABLE",
            "XSS-CLEAN",
            "RACE-VULNERABLE",
            "RACE-CLEAN",
            "WEBHOOK-VULNERABLE",
            "WEBHOOK-CLEAN",
            "TRAVERSAL-VULNERABLE",
            "TRAVERSAL-CLEAN",
            "SSRF-VULNERABLE",
            "SSRF-CLEAN",
        ):
            self.assertIn(expected_case, case_ids)

        for row in result["cases"]:
            self.assertTrue(row["correct"])
            self.assertFalse(row["promotes_finding"])
            self.assertGreaterEqual(row["request_count"], 1)
            self.assertGreaterEqual(row["elapsed_ms"], 0)

    def test_benchmark_supports_declared_latency_and_race_concurrency_profiles(self) -> None:
        result = run_dynamic_proof_benchmark(
            artificial_latency_ms=2,
            race_concurrency=4,
        )
        self.assertEqual(result["run"]["artificial_latency_ms"], 2)
        self.assertEqual(result["run"]["race_concurrency"], 4)
        self.assertEqual(result["metrics"]["case_accuracy"], 1.0)
        race_rows = [
            row for row in result["cases"]
            if row["family"] == "race-idempotency"
        ]
        self.assertEqual({row["request_count"] for row in race_rows}, {4})

    def test_benchmark_rejects_unbounded_profile_parameters(self) -> None:
        with self.assertRaises(ValueError):
            run_dynamic_proof_benchmark(artificial_latency_ms=501)
        with self.assertRaises(ValueError):
            run_dynamic_proof_benchmark(race_concurrency=16)

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
        self.assertIn("deterministic browser fixture adapter", limitations)
        self.assertEqual(
            result["run"]["browser_backend"],
            "deterministic-fixture-adapter-for-xss-pair",
        )


if __name__ == "__main__":
    unittest.main()
