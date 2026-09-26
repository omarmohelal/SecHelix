from __future__ import annotations

import unittest

from evals.dynamic_profile_benchmark import DynamicProfile, run_dynamic_profile_benchmark
from sechelix_runner.proof import ProofClass


class DynamicProfileBenchmarkTests(unittest.TestCase):
    def test_profile_matrix_measures_stability_without_claiming_full_workflow(self) -> None:
        result = run_dynamic_profile_benchmark(
            sechelix_commit="TEST-COMMIT",
            profiles=(
                DynamicProfile("baseline", 0, 2),
                DynamicProfile("light-load", 2, 4),
            ),
        )

        self.assertEqual(result["measurement_status"], "MEASURED")
        self.assertEqual(result["result_kind"], "DYNAMIC_PROOF_PROFILE_BENCHMARK")
        self.assertFalse(result["is_full_sechelix_workflow"])
        self.assertEqual(result["profile_count"], 2)
        self.assertTrue(result["all_profiles_correct"])
        self.assertTrue(result["all_profiles_cover_every_bounded_proof_class"])

        for row in result["profiles"]:
            self.assertEqual(row["metrics"]["case_accuracy"], 1.0)
            self.assertEqual(row["metrics"]["proof_class_coverage"], 1.0)
            self.assertEqual(row["coverage"]["missing_proof_classes"], [])
            self.assertEqual(
                set(row["coverage"]["covered_proof_classes"]),
                {item.value for item in ProofClass},
            )

        limitations = " ".join(result["limitations"]).lower()
        self.assertIn("synthetic", limitations)
        self.assertIn("not production", limitations)
        self.assertIn("independent-verifier", limitations)
        self.assertIn("release-gate", limitations)

    def test_profile_ids_must_be_unique_and_nonempty(self) -> None:
        with self.assertRaises(ValueError):
            run_dynamic_profile_benchmark(profiles=())
        with self.assertRaises(ValueError):
            run_dynamic_profile_benchmark(
                profiles=(
                    DynamicProfile("same", 0, 2),
                    DynamicProfile("same", 1, 4),
                )
            )
        with self.assertRaises(ValueError):
            run_dynamic_profile_benchmark(
                profiles=(DynamicProfile("", 0, 2),)
            )


if __name__ == "__main__":
    unittest.main()
