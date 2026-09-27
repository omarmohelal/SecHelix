import copy
import unittest

from evals.arena_fixture_run_binding import (
    NOT_MEASURED,
    READY,
    ArenaFixtureRunBindingError,
    build_fixture_run_binding,
)


def fixture(tier: str = "STATEFUL_APPLICATION"):
    schema = {
        "STATEFUL_APPLICATION": "sechelix-stateful-application-fixture/v1",
        "COMPOSITE_APPLICATION": "sechelix-composite-application-fixture/v1",
    }[tier]
    return {
        "schema_version": schema,
        "result_kind": f"{tier}_FIXTURE_SELF_TEST",
        "status": "MEASURED",
        "fixture_tier": tier,
        "network_scope": "LOOPBACK_ONLY",
        "checks": [{"name": "contract", "passed": True}],
        "production_effectiveness_established": False,
        "arena_full_workflow_measured": False,
    }


def run_artifact():
    return {
        "run_id": "RUN-ABC123",
        "target_commit": "abc123",
        "scope_id": "SCOPE-FIXTURE",
        "graph_digest": "sha256:" + "1" * 64,
        "unsatisfied_mandatory": [],
        "blocked": [],
        "failed": [],
        "records": {
            "independent-verifier": {
                "role": "INDEPENDENT_VERIFIER",
                "status": "SUCCEEDED",
                "parent_node_ids": ["runtime-verification"],
                "output_digest": "sha256:" + "2" * 64,
                "output_evidence_ids": ["EV-VERIFY"],
            },
            "remediator": {
                "role": "REMEDIATOR",
                "status": "SUCCEEDED",
                "parent_node_ids": ["independent-verifier"],
                "output_digest": "sha256:" + "3" * 64,
                "output_evidence_ids": ["EV-REMEDIATION"],
            },
            "patch-verifier": {
                "role": "PATCH_VERIFIER",
                "status": "SUCCEEDED",
                "parent_node_ids": ["remediator"],
                "output_digest": "sha256:" + "4" * 64,
                "output_evidence_ids": ["EV-INDEPENDENT-PATCH"],
            },
            "release-gate": {
                "role": "RELEASE_GATE",
                "status": "SUCCEEDED",
                "parent_node_ids": ["patch-verifier"],
                "output_digest": "sha256:" + "5" * 64,
                "output_evidence_ids": ["EV-GATE"],
            },
        },
    }


class ArenaFixtureRunBindingTests(unittest.TestCase):
    def test_binds_stateful_fixture_to_complete_full_workflow_without_scoring(self):
        result = build_fixture_run_binding(
            fixture(),
            run_artifact(),
            expected_tier="STATEFUL_APPLICATION",
        )
        self.assertEqual(result["status"], READY)
        self.assertEqual(result["measurement_status"], NOT_MEASURED)
        self.assertEqual(result["fixture"]["tier"], "STATEFUL_APPLICATION")
        self.assertEqual(result["run_identity"]["run_id"], "RUN-ABC123")
        self.assertEqual(
            result["workflow_chain"]["PATCH_VERIFIER"]["output_evidence_ids"],
            ["EV-INDEPENDENT-PATCH"],
        )
        self.assertTrue(result["binding_digest"].startswith("sha256:"))
        self.assertFalse(result["measurement_scope"]["scores_correctness"])
        self.assertTrue(result["measurement_scope"]["requires_prediction_freeze"])
        self.assertTrue(result["measurement_scope"]["requires_independent_assessor"])

    def test_composite_fixture_is_supported(self):
        result = build_fixture_run_binding(
            fixture("COMPOSITE_APPLICATION"),
            run_artifact(),
            expected_tier="COMPOSITE_APPLICATION",
        )
        self.assertEqual(result["fixture"]["tier"], "COMPOSITE_APPLICATION")

    def test_fixture_claim_drift_fails_closed(self):
        broken = fixture()
        broken["production_effectiveness_established"] = True
        with self.assertRaises(ArenaFixtureRunBindingError):
            build_fixture_run_binding(
                broken,
                run_artifact(),
                expected_tier="STATEFUL_APPLICATION",
            )

        broken = fixture()
        broken["checks"][0]["passed"] = False
        with self.assertRaises(ArenaFixtureRunBindingError):
            build_fixture_run_binding(
                broken,
                run_artifact(),
                expected_tier="STATEFUL_APPLICATION",
            )

    def test_missing_or_failed_full_workflow_role_fails_closed(self):
        for role in ("remediator", "patch-verifier", "release-gate"):
            broken = run_artifact()
            broken["records"].pop(role)
            with self.assertRaises(ArenaFixtureRunBindingError):
                build_fixture_run_binding(
                    fixture(),
                    broken,
                    expected_tier="STATEFUL_APPLICATION",
                )

        broken = run_artifact()
        broken["records"]["patch-verifier"]["status"] = "FAILED"
        with self.assertRaises(ArenaFixtureRunBindingError):
            build_fixture_run_binding(
                fixture(),
                broken,
                expected_tier="STATEFUL_APPLICATION",
            )

    def test_dependency_chain_and_runtime_patch_evidence_are_required(self):
        broken = run_artifact()
        broken["records"]["release-gate"]["parent_node_ids"] = ["independent-verifier"]
        with self.assertRaises(ArenaFixtureRunBindingError) as ctx:
            build_fixture_run_binding(
                fixture(),
                broken,
                expected_tier="STATEFUL_APPLICATION",
            )
        self.assertIn("expected PATCH_VERIFIER dependency", str(ctx.exception))

        broken = run_artifact()
        broken["records"]["patch-verifier"]["output_evidence_ids"] = []
        with self.assertRaises(ArenaFixtureRunBindingError) as ctx:
            build_fixture_run_binding(
                fixture(),
                broken,
                expected_tier="STATEFUL_APPLICATION",
            )
        self.assertIn("runtime verification evidence", str(ctx.exception))

    def test_blocked_failed_or_unsatisfied_run_is_not_ready(self):
        for field in ("unsatisfied_mandatory", "blocked", "failed"):
            broken = run_artifact()
            broken[field] = ["node-x"]
            with self.assertRaises(ArenaFixtureRunBindingError):
                build_fixture_run_binding(
                    fixture(),
                    broken,
                    expected_tier="STATEFUL_APPLICATION",
                )

    def test_inputs_are_not_mutated(self):
        fixture_value = fixture()
        run_value = run_artifact()
        fixture_before = copy.deepcopy(fixture_value)
        run_before = copy.deepcopy(run_value)
        build_fixture_run_binding(
            fixture_value,
            run_value,
            expected_tier="STATEFUL_APPLICATION",
        )
        self.assertEqual(fixture_value, fixture_before)
        self.assertEqual(run_value, run_before)


if __name__ == "__main__":
    unittest.main()
