import copy
import unittest

from evals.arena_measurement_bundle import (
    READY,
    ArenaMeasurementBundleError,
    build_measurement_bundle,
)


def run_record():
    return {
        "schema_version": "sechelix-arena-run/v1",
        "agent_host": "isolated-host",
        "provider": "MULTI",
        "model": "MULTI",
        "started_at": "2026-09-26T10:00:00Z",
        "finished_at": "2026-09-26T10:00:05Z",
        "input_tokens": 100,
        "output_tokens": 20,
        "cost": 0.01,
        "elapsed_seconds": 5.0,
        "run_id": "RUN-1",
        "target_commit": "abc123",
        "scope_id": "SCOPE-1",
        "graph_digest": "graph-1",
        "operational_metrics": {
            "telemetry_completeness": {
                "input_tokens": {"complete": True, "measured_nodes": 1, "applicable_nodes": 1},
                "output_tokens": {"complete": True, "measured_nodes": 1, "applicable_nodes": 1},
                "cost_usd": {"complete": True, "measured_nodes": 1, "applicable_nodes": 1},
            },
            "independent_verifier": {
                "present": True,
                "nodes": [{
                    "node_id": "verifier",
                    "status": "SUCCEEDED",
                    "duration_seconds": 2.0,
                    "input_tokens": 80,
                    "output_tokens": 18,
                    "cost_usd": 0.008,
                }],
            },
            "release_gate": {
                "present": True,
                "nodes": [{
                    "node_id": "gate",
                    "status": "SUCCEEDED",
                    "duration_seconds": 0.5,
                    "input_tokens": 20,
                    "output_tokens": 2,
                    "cost_usd": 0.002,
                }],
            },
        },
    }


def workspace_index():
    return {
        "schema_version": "sechelix-arena-workspace-evidence/v1",
        "run_id": "RUN-1",
        "target_commit": "abc123",
        "scope_id": "SCOPE-1",
        "graph_digest": "graph-1",
        "workspace_integrity": "VERIFIED",
        "artifacts": {
            "run.json": "sha256:" + "1" * 64,
            "graph.json": "sha256:" + "2" * 64,
            "replay/outcomes.json": "sha256:" + "3" * 64,
            "manifest.json": "sha256:" + "4" * 64,
        },
        "role_evidence": {
            "INDEPENDENT_VERIFIER": [
                {
                    "node_id": "verifier",
                    "status": "SUCCEEDED",
                    "output_digest": "sha256:" + "5" * 64,
                    "output_evidence_ids": ["E-V"],
                    "artifact_ref": "replay/outcomes.json",
                }
            ],
            "RELEASE_GATE": [
                {
                    "node_id": "gate",
                    "status": "SUCCEEDED",
                    "output_digest": "sha256:" + "6" * 64,
                    "output_evidence_ids": ["E-G"],
                    "artifact_ref": "replay/outcomes.json",
                }
            ],
        },
    }


class ArenaMeasurementBundleTests(unittest.TestCase):
    def test_binds_operational_and_manifest_verified_evidence_without_scoring(self):
        bundle = build_measurement_bundle(run_record(), workspace_index())
        self.assertEqual(bundle["status"], READY)
        self.assertEqual(bundle["run_identity"]["run_id"], "RUN-1")
        self.assertTrue(bundle["bindings"]["arena_run_digest"].startswith("sha256:"))
        self.assertTrue(bundle["bindings"]["workspace_evidence_digest"].startswith("sha256:"))
        self.assertEqual(
            bundle["assessment_targets"]["independent_verifier"][0]["node_id"],
            "verifier",
        )
        self.assertEqual(
            bundle["assessment_targets"]["release_gate"][0]["node_id"],
            "gate",
        )
        self.assertFalse(bundle["measurement_scope"]["scores_correctness"])
        self.assertTrue(bundle["measurement_scope"]["requires_independent_assessor"])
        self.assertEqual(
            bundle["operational_telemetry"]["role_runtime"]["independent_verifier"]["nodes"][0]["duration_seconds"],
            2.0,
        )
        self.assertEqual(
            bundle["operational_telemetry"]["role_runtime"]["release_gate"]["nodes"][0]["duration_seconds"],
            0.5,
        )

    def test_mismatched_run_identity_fails_closed(self):
        workspace = workspace_index()
        workspace["graph_digest"] = "different"
        with self.assertRaises(ArenaMeasurementBundleError) as ctx:
            build_measurement_bundle(run_record(), workspace)
        self.assertIn("graph_digest mismatch", str(ctx.exception))

    def test_unverified_workspace_fails_closed(self):
        workspace = workspace_index()
        workspace["workspace_integrity"] = "FAILED"
        with self.assertRaises(ArenaMeasurementBundleError):
            build_measurement_bundle(run_record(), workspace)

    def test_verifier_and_gate_evidence_are_both_required(self):
        workspace = workspace_index()
        workspace["role_evidence"].pop("INDEPENDENT_VERIFIER")
        with self.assertRaises(ArenaMeasurementBundleError) as ctx:
            build_measurement_bundle(run_record(), workspace)
        self.assertIn("INDEPENDENT_VERIFIER", str(ctx.exception))

        workspace = workspace_index()
        workspace["role_evidence"].pop("RELEASE_GATE")
        with self.assertRaises(ArenaMeasurementBundleError) as ctx:
            build_measurement_bundle(run_record(), workspace)
        self.assertIn("RELEASE_GATE", str(ctx.exception))

    def test_runtime_presence_must_match_workspace_roles(self):
        run = run_record()
        run["operational_metrics"]["release_gate"]["present"] = False
        with self.assertRaises(ArenaMeasurementBundleError) as ctx:
            build_measurement_bundle(run, workspace_index())
        self.assertIn("release gate", str(ctx.exception))

    def test_input_records_are_not_mutated(self):
        run = run_record()
        workspace = workspace_index()
        run_before = copy.deepcopy(run)
        workspace_before = copy.deepcopy(workspace)
        build_measurement_bundle(run, workspace)
        self.assertEqual(run, run_before)
        self.assertEqual(workspace, workspace_before)


if __name__ == "__main__":
    unittest.main()
