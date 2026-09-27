import hashlib
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

    def _case(self, case_id: str, run_id: str, *, target_commit: str = "abc123") -> dict:
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
                    "cost_usd": 0.01,
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
                    "cost_usd": 0.01,
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

    @staticmethod
    def _canonical_digest(value: object) -> str:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def _attach_fixture_binding(
        self,
        row: dict,
        *,
        tier: str = "STATEFUL_APPLICATION",
    ) -> dict:
        run_path = self.root / row["run_path"]
        run = json.loads(run_path.read_text(encoding="utf-8"))
        binding = {
            "schema_version": "sechelix-arena-fixture-run-binding/v1",
            "status": "READY_FOR_ARENA_FIXTURE_HANDOFF",
            "measurement_status": "NOT_MEASURED",
            "fixture": {
                "tier": tier,
                "schema_version": (
                    "sechelix-stateful-application-fixture/v1"
                    if tier == "STATEFUL_APPLICATION"
                    else "sechelix-composite-application-fixture/v1"
                ),
                "result_kind": f"{tier}_FIXTURE_SELF_TEST",
                "network_scope": "LOOPBACK_ONLY",
                "fixture_result_digest": "sha256:" + "9" * 64,
            },
            "run_identity": {
                field: run[field]
                for field in ("run_id", "target_commit", "scope_id", "graph_digest")
            },
            "workflow_chain": {},
            "run_artifact_digest": self._canonical_digest(run),
            "measurement_scope": {
                "scores_correctness": False,
            },
        }
        binding["binding_digest"] = self._canonical_digest(binding)
        path = self.root / f"{row['run_id']}.fixture-binding.json"
        path.write_text(
            json.dumps(binding, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        row["fixture_binding_path"] = str(path.relative_to(self.root))
        return binding

    def _rewrite_run(self, row: dict, mutate) -> None:
        path = self.root / row["run_path"]
        run = json.loads(path.read_text(encoding="utf-8"))
        mutate(run)
        path.write_text(
            json.dumps(run, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        RunWorkspace(self.root, row["run_id"]).write_manifest()

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

        operational = result["operational_summary"]
        self.assertEqual(operational["case_count"], 2)
        self.assertEqual(operational["agent_hosts"], ["isolated-eval-host"])
        self.assertEqual(operational["providers"], ["provider-a"])
        self.assertEqual(operational["models"], ["model-a"])
        self.assertEqual(operational["case_elapsed_seconds"]["total"], 10.0)
        self.assertEqual(operational["case_elapsed_seconds"]["mean"], 5.0)
        # Both fixture runs occupy the same five-second window. Their summed
        # case wall time is ten seconds, while observed packet span is five.
        self.assertEqual(operational["observed_packet_span_seconds"], 5.0)
        self.assertEqual(operational["input_tokens"]["total"], 200)
        self.assertEqual(operational["output_tokens"]["total"], 40)
        self.assertEqual(operational["cost_usd"]["total"], 0.02)
        self.assertTrue(operational["cost_usd"]["complete"])
        self.assertFalse(operational["measurement_scope"]["scores_correctness"])

        rendered = json.dumps(result)
        self.assertNotIn("redacted-workflow-output", rendered)
        self.assertNotIn('"decision": "PASS"', rendered)

    def test_fixture_bindings_are_carried_into_the_batch_and_bound_to_exact_run_payloads(self) -> None:
        first = self._case("CASE-AAA111", "RUN-FIXTURE_A")
        second = self._case("CASE-BBB222", "RUN-FIXTURE_B")
        self._attach_fixture_binding(first, tier="STATEFUL_APPLICATION")
        self._attach_fixture_binding(second, tier="COMPOSITE_APPLICATION")

        result = build_batch_handoff(
            self.manifest,
            {"cases": [first, second]},
            base_dir=self.root,
        )

        self.assertEqual(result["measurement_status"], "NOT_MEASURED")
        self.assertEqual(result["measurement_scope"]["fixture_bound_case_count"], 2)
        self.assertEqual(
            result["cases"][0]["fixture_binding"]["tier"],
            "STATEFUL_APPLICATION",
        )
        self.assertEqual(
            result["cases"][1]["fixture_binding"]["tier"],
            "COMPOSITE_APPLICATION",
        )
        self.assertTrue(
            result["cases"][0]["bundle"]["bindings"]["run_payload_digest"].startswith(
                "sha256:"
            )
        )

    def test_fixture_binding_identity_or_run_digest_drift_blocks_the_batch(self) -> None:
        first = self._case("CASE-AAA111", "RUN-FIXTURE_DRIFT_A")
        second = self._case("CASE-BBB222", "RUN-FIXTURE_DRIFT_B")
        binding = self._attach_fixture_binding(first)
        self._attach_fixture_binding(second)

        path = self.root / first["fixture_binding_path"]
        broken = dict(binding)
        broken["run_artifact_digest"] = "sha256:" + "0" * 64
        path.write_text(
            json.dumps(broken, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(ArenaBatchHandoffError) as ctx:
            build_batch_handoff(
                self.manifest,
                {"cases": [first, second]},
                base_dir=self.root,
            )
        self.assertIn("canonical run payload", str(ctx.exception))

        self._attach_fixture_binding(first)
        broken = json.loads(path.read_text(encoding="utf-8"))
        broken["run_identity"]["scope_id"] = "SCOPE-OTHER"
        path.write_text(
            json.dumps(broken, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(ArenaBatchHandoffError) as ctx:
            build_batch_handoff(
                self.manifest,
                {"cases": [first, second]},
                base_dir=self.root,
            )
        self.assertIn("scope_id", str(ctx.exception))

    def test_incomplete_cost_stays_not_measured_without_hiding_other_metrics(self) -> None:
        first = self._case("CASE-AAA111", "RUN-COST_A")
        second = self._case("CASE-BBB222", "RUN-COST_B")

        def remove_verifier_cost(run: dict) -> None:
            run["records"]["verifier"].pop("cost_usd", None)

        self._rewrite_run(second, remove_verifier_cost)
        result = build_batch_handoff(
            self.manifest,
            {"cases": [first, second]},
            base_dir=self.root,
        )
        operational = result["operational_summary"]

        self.assertEqual(operational["cost_usd"]["total"], "NOT_MEASURED")
        self.assertFalse(operational["cost_usd"]["complete"])
        self.assertEqual(operational["cost_usd"]["measured_cases"], 1)
        self.assertEqual(operational["cost_usd"]["applicable_cases"], 2)
        self.assertEqual(operational["input_tokens"]["total"], 200)
        self.assertEqual(operational["output_tokens"]["total"], 40)
        self.assertEqual(operational["case_elapsed_seconds"]["total"], 10.0)
        self.assertEqual(result["measurement_status"], "NOT_MEASURED")

    def test_provider_metrics_are_not_applicable_when_no_case_executed_provider_work(self) -> None:
        first = self._case("CASE-AAA111", "RUN-BLOCKED_A")
        second = self._case("CASE-BBB222", "RUN-BLOCKED_B")

        def block_provider_nodes(run: dict) -> None:
            run["records"]["verifier"]["status"] = "BLOCKED"
            run["records"]["gate"]["status"] = "BLOCKED"

        self._rewrite_run(first, block_provider_nodes)
        self._rewrite_run(second, block_provider_nodes)
        result = build_batch_handoff(
            self.manifest,
            {"cases": [first, second]},
            base_dir=self.root,
        )
        operational = result["operational_summary"]

        for field in ("input_tokens", "output_tokens", "cost_usd"):
            self.assertEqual(operational[field]["total"], "NOT_APPLICABLE")
            self.assertTrue(operational[field]["complete"])
            self.assertEqual(operational[field]["measured_cases"], 0)
            self.assertEqual(operational[field]["applicable_cases"], 0)

        # Wall-clock run telemetry still exists even when provider work did not.
        self.assertEqual(operational["case_elapsed_seconds"]["total"], 10.0)
        self.assertEqual(operational["observed_packet_span_seconds"], 5.0)

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
