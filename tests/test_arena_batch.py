import json
import tempfile
import unittest
from pathlib import Path

from evals.arena import prepare_manifest
from evals.arena_batch import (
    READY_STATUS,
    ArenaBatchHandoffError,
    build_batch_handoff,
)
from sechelix_runner.storage import RunWorkspace


PACKET = {
    "cases": [
        {"case_id": "CASE-AAA111", "task": "opaque"},
        {"case_id": "CASE-BBB222", "task": "opaque"},
    ]
}

PARTICIPANT = {
    "participant_id": "sechelix-v5",
    "display_name": "SecHelix",
    "category": "AGENT_WORKFLOW",
    "source_url": "https://github.com/omarmohelal/SecHelix",
    "version": "v5-test",
    "capability_scope": ["STATIC_REVIEW", "INDEPENDENT_VERIFICATION", "RELEASE_GATE"],
}


class ArenaBatchHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manifest = prepare_manifest(PACKET, PARTICIPANT)

    def _case(
        self,
        case_id: str,
        run_id: str,
        *,
        target_commit: str = "abc123",
        verifier_cost: float | None = 0.01,
    ) -> dict:
        ws = RunWorkspace(self.root, run_id).create()
        run = {
            "run_id": run_id,
            "runner_version": "0.2.0",
            "target_commit": target_commit,
            "scope_id": "SCOPE-" + case_id[-3:],
            "graph_digest": "graph-" + case_id[-3:],
            "executor": "provider-backed",
            "started_at": "2026-09-26T10:00:00Z",
            "finished_at": "2026-09-26T10:00:05Z",
            "unsatisfied_mandatory": [],
            "blocked": [],
            "failed": [],
            "records": {
                "verifier": {
                    "role": "INDEPENDENT_VERIFIER",
                    "status": "SUCCEEDED",
                    "duration_seconds": 2.0,
                    "provider": "provider-a",
                    "model": "model-a",
                    "input_tokens": 100,
                    "output_tokens": 20,
                    "cost_usd": verifier_cost,
                    "output_evidence_ids": ["E-VERIFY-" + case_id],
                },
                "gate": {
                    "role": "RELEASE_GATE",
                    "status": "SUCCEEDED",
                    "duration_seconds": 0.5,
                    "provider": None,
                    "model": None,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cost_usd": 0.0,
                    "output_evidence_ids": ["E-GATE-" + case_id],
                },
            },
        }
        ws.write_json("run.json", run)
        ws.write_json(
            "graph.json",
            {
                "graph_digest": run["graph_digest"],
                "nodes": [
                    {
                        "node_id": "verifier",
                        "role": "INDEPENDENT_VERIFIER",
                        "depends_on": [],
                        "mandatory": True,
                        "node_version": "1",
                    },
                    {
                        "node_id": "gate",
                        "role": "RELEASE_GATE",
                        "depends_on": ["verifier"],
                        "mandatory": True,
                        "node_version": "1",
                    },
                ],
            },
        )
        ws.write_json(
            "replay/outcomes.json",
            {
                "verifier": {
                    "status": "SUCCEEDED",
                    "output": {"candidate": "redacted-workflow-output"},
                    "output_evidence_ids": ["E-VERIFY-" + case_id],
                    "provider": "provider-a",
                    "model": "model-a",
                    "input_tokens": 100,
                    "output_tokens": 20,
                    "cost_usd": verifier_cost,
                },
                "gate": {
                    "status": "SUCCEEDED",
                    "output": {"decision": "PASS"},
                    "output_evidence_ids": ["E-GATE-" + case_id],
                    "provider": None,
                    "model": None,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cost_usd": 0.0,
                },
            },
        )
        ws.write_manifest()
        return {
            "case_id": case_id,
            "run_path": str((ws.path / "run.json").relative_to(self.root)),
            "workspace_root": ".",
            "run_id": run_id,
            "agent_host": "isolated-eval-host",
        }

    def test_complete_packet_builds_manifest_verified_handoff_without_scoring(self) -> None:
        run_map = {
            "cases": [
                self._case("CASE-AAA111", "RUN-ARENA_A"),
                self._case("CASE-BBB222", "RUN-ARENA_B"),
            ]
        }
        result = build_batch_handoff(self.manifest, run_map, base_dir=self.root)

        self.assertEqual(result["status"], READY_STATUS)
        self.assertEqual(result["measurement_status"], "NOT_MEASURED")
        self.assertEqual(result["case_count"], 2)
        self.assertEqual(
            [row["case_id"] for row in result["cases"]],
            ["CASE-AAA111", "CASE-BBB222"],
        )
        self.assertTrue(result["handoff_digest"].startswith("sha256:"))
        self.assertTrue(
            all(row["bundle"]["status"] == "READY_FOR_INDEPENDENT_ASSESSMENT" for row in result["cases"])
        )
        self.assertFalse(result["measurement_scope"]["scores_correctness"])
        self.assertFalse(result["measurement_scope"]["reveals_ground_truth"])
        self.assertTrue(result["measurement_scope"]["requires_independent_assessor"])
        summary = result["operational_summary"]
        self.assertEqual(summary["case_count"], 2)
        self.assertEqual(summary["elapsed_seconds"]["total"], 10.0)
        self.assertEqual(summary["elapsed_seconds"]["mean"], 5.0)
        self.assertEqual(summary["input_tokens"]["total"], 200.0)
        self.assertEqual(summary["output_tokens"]["total"], 40.0)
        self.assertEqual(summary["cost_usd"]["total"], 0.02)
        self.assertEqual(
            summary["independent_verifier"]["duration_seconds"]["total"],
            4.0,
        )
        self.assertEqual(
            summary["release_gate"]["duration_seconds"]["total"],
            1.0,
        )
        self.assertFalse(summary["measurement_scope"]["scores_correctness"])

        rendered = json.dumps(result)
        self.assertNotIn("redacted-workflow-output", rendered)
        self.assertNotIn('"decision": "PASS"', rendered)

    def test_incomplete_batch_cost_telemetry_stays_not_measured(self) -> None:
        run_map = {
            "cases": [
                self._case("CASE-AAA111", "RUN-COST_A", verifier_cost=0.01),
                self._case("CASE-BBB222", "RUN-COST_B", verifier_cost=None),
            ]
        }
        result = build_batch_handoff(self.manifest, run_map, base_dir=self.root)
        summary = result["operational_summary"]
        self.assertFalse(summary["cost_usd"]["complete"])
        self.assertEqual(summary["cost_usd"]["total"], "NOT_MEASURED")
        self.assertFalse(
            summary["independent_verifier"]["cost_usd"]["complete"]
        )
        self.assertEqual(
            summary["independent_verifier"]["cost_usd"]["total"],
            "NOT_MEASURED",
        )
        self.assertEqual(summary["elapsed_seconds"]["total"], 10.0)

    def test_missing_or_extra_case_fails_closed(self) -> None:
        only_one = {"cases": [self._case("CASE-AAA111", "RUN-ONLY_ONE")]}
        with self.assertRaises(ArenaBatchHandoffError) as ctx:
            build_batch_handoff(self.manifest, only_one, base_dir=self.root)
        self.assertIn("missing", str(ctx.exception))

        extra = {
            "cases": [
                self._case("CASE-AAA111", "RUN-EXTRA_A"),
                self._case("CASE-BBB222", "RUN-EXTRA_B"),
                {
                    **self._case("CASE-AAA111", "RUN-EXTRA_C"),
                    "case_id": "CASE-CCC333",
                },
            ]
        }
        with self.assertRaises(ArenaBatchHandoffError):
            build_batch_handoff(self.manifest, extra, base_dir=self.root)

    def test_run_id_cannot_be_reused_across_cases(self) -> None:
        first = self._case("CASE-AAA111", "RUN-SHARED")
        second = self._case("CASE-BBB222", "RUN-B")
        second["run_id"] = "RUN-SHARED"
        with self.assertRaises(ArenaBatchHandoffError) as ctx:
            build_batch_handoff(
                self.manifest,
                {"cases": [first, second]},
                base_dir=self.root,
            )
        self.assertIn("reused", str(ctx.exception))

    def test_path_escape_is_rejected_before_reading_external_artifact(self) -> None:
        first = self._case("CASE-AAA111", "RUN-PATH_A")
        second = self._case("CASE-BBB222", "RUN-PATH_B")
        first["run_path"] = "../outside.json"
        with self.assertRaises(ArenaBatchHandoffError) as ctx:
            build_batch_handoff(
                self.manifest,
                {"cases": [first, second]},
                base_dir=self.root,
            )
        self.assertIn("escapes", str(ctx.exception))

    def test_manifest_drift_in_any_case_blocks_the_entire_handoff(self) -> None:
        first = self._case("CASE-AAA111", "RUN-DRIFT_A")
        second = self._case("CASE-BBB222", "RUN-DRIFT_B")
        ws = RunWorkspace(self.root, "RUN-DRIFT_B")
        (ws.path / "replay" / "outcomes.json").write_text(
            '{"tampered": true}\n',
            encoding="utf-8",
        )
        with self.assertRaises(ArenaBatchHandoffError) as ctx:
            build_batch_handoff(
                self.manifest,
                {"cases": [first, second]},
                base_dir=self.root,
            )
        self.assertIn("manifest", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
