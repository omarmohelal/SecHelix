import unittest

from evals.arena_run import (
    ArenaRunTelemetryError,
    NOT_APPLICABLE,
    NOT_MEASURED,
    build_arena_run_record,
)


def sample_run():
    return {
        "run_id": "RUN-ABC",
        "runner_version": "0.2.0",
        "target_commit": "abc123",
        "scope_id": "SCOPE-1",
        "graph_digest": "digest-1",
        "executor": "provider-backed",
        "started_at": "2026-09-26T10:00:00Z",
        "finished_at": "2026-09-26T10:00:05Z",
        "unsatisfied_mandatory": [],
        "blocked": [],
        "failed": [],
        "records": {
            "authz": {
                "role": "AUTHORIZATION",
                "status": "SUCCEEDED",
                "duration_seconds": 1.0,
                "provider": "p1",
                "model": "m1",
                "input_tokens": 100,
                "output_tokens": 20,
                "cost_usd": 0.01,
                "output_evidence_ids": ["E-A"],
            },
            "verifier": {
                "role": "INDEPENDENT_VERIFIER",
                "status": "SUCCEEDED",
                "duration_seconds": 2.0,
                "provider": "p2",
                "model": "m2",
                "input_tokens": 200,
                "output_tokens": 50,
                "cost_usd": 0.02,
                "output_evidence_ids": ["E-V"],
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
                "output_evidence_ids": ["E-G"],
            },
            "optional-skip": {
                "role": "BROWSER",
                "status": "SKIPPED",
                "duration_seconds": 0.0,
                "provider": None,
                "model": None,
                "input_tokens": None,
                "output_tokens": None,
                "cost_usd": None,
                "output_evidence_ids": [],
            },
        },
    }


class ArenaRunTelemetryTests(unittest.TestCase):
    def test_builds_cost_time_and_verifier_gate_telemetry(self):
        record = build_arena_run_record(
            sample_run(),
            agent_host="isolated-host",
            artifact_digest="sha256:" + "a" * 64,
        )
        self.assertEqual(record["schema_version"], "sechelix-arena-run/v1")
        self.assertEqual(record["elapsed_seconds"], 5.0)
        self.assertEqual(record["input_tokens"], 300)
        self.assertEqual(record["output_tokens"], 70)
        self.assertEqual(record["cost"], 0.03)
        self.assertEqual(record["provider"], "MULTI")
        self.assertEqual(record["model"], "MULTI")
        self.assertEqual(record["operational_metrics"]["providers"], ["p1", "p2"])
        self.assertTrue(record["operational_metrics"]["independent_verifier"]["present"])
        self.assertTrue(record["operational_metrics"]["release_gate"]["present"])
        verifier = record["operational_metrics"]["independent_verifier"]["nodes"][0]
        self.assertEqual(verifier["status"], "SUCCEEDED")
        self.assertEqual(verifier["output_evidence_ids"], ["E-V"])
        self.assertEqual(record["run_artifact_digest"], "sha256:" + "a" * 64)

    def test_missing_cost_on_one_executed_node_is_not_silently_summed(self):
        run = sample_run()
        run["records"]["verifier"]["cost_usd"] = None
        record = build_arena_run_record(run, agent_host="host")
        self.assertEqual(record["cost"], NOT_MEASURED)
        completeness = record["operational_metrics"]["telemetry_completeness"]["cost_usd"]
        self.assertFalse(completeness["complete"])
        self.assertEqual(completeness["measured_nodes"], 2)
        self.assertEqual(completeness["applicable_nodes"], 3)

    def test_skipped_and_blocked_nodes_do_not_make_provider_telemetry_incomplete(self):
        run = sample_run()
        run["records"]["blocked"] = {
            "role": "RUNTIME_VERIFICATION",
            "status": "BLOCKED",
            "duration_seconds": 0.0,
            "provider": None,
            "model": None,
            "input_tokens": None,
            "output_tokens": None,
            "cost_usd": None,
            "output_evidence_ids": [],
            "blocker": "missing fixture",
        }
        record = build_arena_run_record(run, agent_host="host")
        self.assertEqual(record["input_tokens"], 300)
        self.assertEqual(record["output_tokens"], 70)
        self.assertEqual(record["cost"], 0.03)
        self.assertEqual(record["operational_metrics"]["status_counts"]["BLOCKED"], 1)

    def test_no_applicable_provider_work_is_not_applicable_not_zero(self):
        run = sample_run()
        run["records"] = {
            "skipped": {
                "role": "BROWSER",
                "status": "SKIPPED",
                "duration_seconds": 0.0,
                "provider": None,
                "model": None,
                "input_tokens": None,
                "output_tokens": None,
                "cost_usd": None,
            },
            "blocked": {
                "role": "RELEASE_GATE",
                "status": "BLOCKED",
                "duration_seconds": 0.0,
                "provider": None,
                "model": None,
                "input_tokens": None,
                "output_tokens": None,
                "cost_usd": None,
            },
        }
        record = build_arena_run_record(run, agent_host="host")
        self.assertEqual(record["input_tokens"], NOT_APPLICABLE)
        self.assertEqual(record["output_tokens"], NOT_APPLICABLE)
        self.assertEqual(record["cost"], NOT_APPLICABLE)
        self.assertEqual(record["provider"], NOT_APPLICABLE)
        self.assertEqual(record["model"], NOT_APPLICABLE)

    def test_failed_executed_node_with_missing_telemetry_stays_not_measured(self):
        run = sample_run()
        run["records"]["authz"]["status"] = "FAILED"
        run["records"]["authz"]["input_tokens"] = None
        run["records"]["authz"]["output_tokens"] = None
        run["records"]["authz"]["cost_usd"] = None
        record = build_arena_run_record(run, agent_host="host")
        self.assertEqual(record["input_tokens"], NOT_MEASURED)
        self.assertEqual(record["output_tokens"], NOT_MEASURED)
        self.assertEqual(record["cost"], NOT_MEASURED)

    def test_rejects_bad_time_order_and_empty_records(self):
        run = sample_run()
        run["finished_at"] = "2026-09-26T09:59:59Z"
        with self.assertRaises(ArenaRunTelemetryError):
            build_arena_run_record(run, agent_host="host")

        run = sample_run()
        run["records"] = {}
        with self.assertRaises(ArenaRunTelemetryError):
            build_arena_run_record(run, agent_host="host")


if __name__ == "__main__":
    unittest.main()
