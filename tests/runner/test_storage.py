import json
import tempfile
import unittest
from pathlib import Path

from sechelix_runner.executor import MockExecutor, NodeOutcome
from sechelix_runner.graph import GraphNode, ReasonerGraph
from sechelix_runner.roles import NodeRole, NodeStatus
from sechelix_runner.runner import Runner
from sechelix_runner.storage import (
    REDACTED,
    RunWorkspace,
    list_runs,
    persist_run,
    redact,
)


def world() -> dict:
    return {
        "target": {"repo": "demo"},
        "file_index": ["app.py"],
        "identities": ["u"],
        "roles": ["r"],
        "ownership_model": {"f": "uid"},
        "auth_middleware": ["mw"],
        "candidates": [{"id": "C1"}],
        "findings": [],
        "node_records": [],
    }


def pipeline() -> ReasonerGraph:
    return ReasonerGraph(
        [
            GraphNode("map", NodeRole.MAPPER, (), mandatory=True),
            GraphNode("authorization", NodeRole.AUTHORIZATION, ("map",)),
            GraphNode("verify", NodeRole.INDEPENDENT_VERIFIER, ("authorization",), mandatory=True),
            GraphNode("gate", NodeRole.RELEASE_GATE, ("verify",), mandatory=True),
        ]
    )


class RedactionTests(unittest.TestCase):
    def test_scalar_secrets_are_replaced(self) -> None:
        result = redact({"Authorization": "Bearer x", "cookie": "a=b", "api_key": "k"})
        self.assertEqual(set(result.values()), {REDACTED})

    def test_structure_is_preserved_so_presence_stays_visible(self) -> None:
        result = redact({"headers": {"Authorization": "Bearer x"}})
        self.assertIn("Authorization", result["headers"])

    def test_token_counts_are_not_redacted(self) -> None:
        """`input_tokens` contains "token" but is telemetry the budget reads back.

        Regression: redacting it wrote "[REDACTED]" into the run record, and
        replay then fed that string to the budget governor.
        """
        result = redact(
            {"input_tokens": 1500, "output_tokens": 300, "max_total_tokens": 9000}
        )
        self.assertEqual(result["input_tokens"], 1500)
        self.assertEqual(result["output_tokens"], 300)
        self.assertEqual(result["max_total_tokens"], 9000)

    def test_a_container_named_like_a_secret_is_recursed_not_replaced(self) -> None:
        """Regression: run records are keyed by node id, and one node is
        `authorization`. A name-only rule replaced that whole record with a
        marker, and replay could not reconstruct the run."""
        result = redact(
            {"records": {"authorization": {"status": "BLOCKED", "input_tokens": 50}}}
        )
        self.assertEqual(result["records"]["authorization"]["status"], "BLOCKED")
        self.assertEqual(result["records"]["authorization"]["input_tokens"], 50)

    def test_secrets_nested_in_lists_are_still_redacted(self) -> None:
        result = redact({"items": [{"token": "t", "count": 3}]})
        self.assertEqual(result["items"][0]["token"], REDACTED)
        self.assertEqual(result["items"][0]["count"], 3)


class WorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        result = Runner(
            executor=MockExecutor(
                {"authorization": NodeOutcome(status=NodeStatus.FAILED, error="boom")}
            ),
            target_commit="abc123",
            scope_id="S1",
        ).run(pipeline(), world())
        self.result = result
        self.workspace = persist_run(self.tmp, result, pipeline())

    def test_expected_artifacts_are_written(self) -> None:
        names = {
            str(p.relative_to(self.workspace.path)).replace("\\", "/")
            for p in self.workspace.files()
        }
        self.assertEqual(
            names, {"run.json", "graph.json", "events.jsonl", "replay/outcomes.json"}
        )

    def test_fresh_workspace_verifies_clean(self) -> None:
        self.assertEqual(self.workspace.verify(), [])

    def test_changed_content_is_detected(self) -> None:
        path = self.workspace.path / "run.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["records"]["authorization"]["status"] = "SUCCEEDED"
        path.write_text(json.dumps(data), encoding="utf-8")
        self.assertIn("run.json: content changed", self.workspace.verify())

    def test_added_file_is_detected(self) -> None:
        (self.workspace.path / "smuggled.json").write_text("{}", encoding="utf-8")
        self.assertTrue(
            any("not in manifest" in p for p in self.workspace.verify())
        )

    def test_removed_file_is_detected(self) -> None:
        (self.workspace.path / "graph.json").unlink()
        self.assertIn("graph.json: missing", self.workspace.verify())

    def test_events_are_ordered_and_complete(self) -> None:
        events = self.workspace.events()
        self.assertEqual([e["node_id"] for e in events], pipeline().topological_order())

    def test_failed_node_is_present_in_the_record(self) -> None:
        data = self.workspace.read_json("run.json")
        self.assertEqual(data["records"]["authorization"]["status"], "FAILED")
        self.assertEqual(len(data["records"]), 4)

    def test_run_is_listed(self) -> None:
        self.assertIn(self.result.run_id, list_runs(self.tmp))

    def test_missing_manifest_is_a_problem_not_a_pass(self) -> None:
        (self.workspace.path / "manifest.json").unlink()
        self.assertEqual(self.workspace.verify(), ["manifest.json: missing"])


if __name__ == "__main__":
    unittest.main()
