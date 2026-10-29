from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from sechelix_runner.budget import BudgetGovernor, BudgetLimits
from sechelix_runner.checkpoint import CheckpointError, load_checkpoint
from sechelix_runner.executor import NodeOutcome
from sechelix_runner.graph import GraphNode, ReasonerGraph
from sechelix_runner.roles import NodeRole, NodeStatus
from sechelix_runner.runner import Runner


def checkpoint_world() -> dict:
    return {
        "target": {"repo": "demo"},
        "file_index": ["app.py"],
        "identities": ["user", "admin"],
        "roles": ["reader"],
        "ownership_model": {"owner_field": "user_id"},
        "auth_middleware": ["require_auth"],
        "candidates": [{"id": "C1"}],
        "findings": [],
        "node_records": [],
    }


def checkpoint_graph() -> ReasonerGraph:
    return ReasonerGraph(
        [
            GraphNode("map", NodeRole.MAPPER, (), mandatory=True),
            GraphNode("authz", NodeRole.AUTHORIZATION, ("map",)),
            GraphNode(
                "verify",
                NodeRole.INDEPENDENT_VERIFIER,
                ("authz",),
                mandatory=True,
            ),
            GraphNode(
                "gate",
                NodeRole.RELEASE_GATE,
                ("verify",),
                mandatory=True,
            ),
        ]
    )


class RecordingExecutor:
    def __init__(self, name: str, provider: str) -> None:
        self.name = name
        self.provider = provider
        self.calls: list[str] = []

    def execute(self, node, view):
        self.calls.append(node.node_id)
        return NodeOutcome(
            status=NodeStatus.SUCCEEDED,
            output={"node": node.node_id},
            provider=self.provider,
            model=f"{self.provider}-model",
            input_tokens=3,
            output_tokens=2,
            cost_usd=0.01,
        )


class CrashAfterCheckpointRunner(Runner):
    def __init__(self, *args, crash_after: int = 1, **kwargs):
        super().__init__(*args, **kwargs)
        self._checkpoint_writes = 0
        self._crash_after = crash_after

    def _write_checkpoint(self, path, result, world_digest, done):
        super()._write_checkpoint(path, result, world_digest, done)
        self._checkpoint_writes += 1
        if self._checkpoint_writes == self._crash_after:
            raise RuntimeError("simulated host interruption")


class NodeCheckpointResumeTests(unittest.TestCase):
    def test_resume_keeps_completed_evidence_and_runs_only_remaining_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkpoint = Path(tmp) / "checkpoint.json"
            first_executor = RecordingExecutor("provider-a-executor", "provider-a")
            first = CrashAfterCheckpointRunner(
                executor=first_executor,
                target_commit="abc123",
                scope_id="SCOPE-1",
                budget=BudgetGovernor(
                    BudgetLimits(max_nodes=10, max_cost_usd=1.0)
                ),
            )
            with self.assertRaisesRegex(RuntimeError, "simulated host interruption"):
                first.run(
                    checkpoint_graph(),
                    checkpoint_world(),
                    checkpoint_path=checkpoint,
                )

            sealed = load_checkpoint(checkpoint)
            self.assertEqual(sealed.completed_node_ids, ("map",))
            self.assertEqual(first_executor.calls, ["map"])

            second_executor = RecordingExecutor("provider-b-executor", "provider-b")
            resumed = Runner(
                executor=second_executor,
                target_commit="abc123",
                scope_id="SCOPE-1",
                budget=BudgetGovernor(
                    BudgetLimits(max_nodes=10, max_cost_usd=1.0)
                ),
            ).run(
                checkpoint_graph(),
                checkpoint_world(),
                resume_from=checkpoint,
                checkpoint_path=checkpoint,
            )

            self.assertEqual(
                second_executor.calls,
                ["authz", "verify", "gate"],
            )
            self.assertEqual(resumed.run_id, sealed.run_id)
            self.assertEqual(resumed.records["map"].provider, "provider-a")
            self.assertEqual(resumed.records["authz"].provider, "provider-b")
            self.assertEqual(resumed.records["map"].model, "provider-a-model")
            self.assertEqual(resumed.records["gate"].model, "provider-b-model")
            self.assertEqual(resumed.unsatisfied_mandatory, [])
            self.assertEqual(
                resumed.budget_snapshot["usage"]["max_nodes"]["reserved"],
                4.0,
            )
            self.assertAlmostEqual(
                resumed.budget_snapshot["usage"]["max_cost_usd"]["actual"],
                0.04,
            )

    def test_resume_refuses_changed_world(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkpoint = Path(tmp) / "checkpoint.json"
            first = CrashAfterCheckpointRunner(
                executor=RecordingExecutor("a", "a"),
                target_commit="abc123",
                scope_id="SCOPE-1",
            )
            with self.assertRaises(RuntimeError):
                first.run(
                    checkpoint_graph(),
                    checkpoint_world(),
                    checkpoint_path=checkpoint,
                )

            changed = checkpoint_world()
            changed["roles"] = ["reader", "owner"]
            with self.assertRaisesRegex(CheckpointError, "input world changed"):
                Runner(
                    executor=RecordingExecutor("b", "b"),
                    target_commit="abc123",
                    scope_id="SCOPE-1",
                ).run(checkpoint_graph(), changed, resume_from=checkpoint)

    def test_resume_refuses_graph_scope_and_commit_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkpoint = Path(tmp) / "checkpoint.json"
            first = CrashAfterCheckpointRunner(
                executor=RecordingExecutor("a", "a"),
                target_commit="abc123",
                scope_id="SCOPE-1",
            )
            with self.assertRaises(RuntimeError):
                first.run(
                    checkpoint_graph(),
                    checkpoint_world(),
                    checkpoint_path=checkpoint,
                )

            altered_graph = ReasonerGraph(
                [
                    GraphNode("map", NodeRole.MAPPER, (), mandatory=True),
                    GraphNode("gate", NodeRole.RELEASE_GATE, ("map",), mandatory=True),
                ]
            )
            with self.assertRaisesRegex(CheckpointError, "graph"):
                Runner(
                    executor=RecordingExecutor("b", "b"),
                    target_commit="abc123",
                    scope_id="SCOPE-1",
                ).run(altered_graph, checkpoint_world(), resume_from=checkpoint)

            with self.assertRaisesRegex(CheckpointError, "scope"):
                Runner(
                    executor=RecordingExecutor("b", "b"),
                    target_commit="abc123",
                    scope_id="SCOPE-2",
                ).run(checkpoint_graph(), checkpoint_world(), resume_from=checkpoint)

            with self.assertRaisesRegex(CheckpointError, "target commit"):
                Runner(
                    executor=RecordingExecutor("b", "b"),
                    target_commit="different",
                    scope_id="SCOPE-1",
                ).run(checkpoint_graph(), checkpoint_world(), resume_from=checkpoint)

    def test_tampered_checkpoint_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkpoint = Path(tmp) / "checkpoint.json"
            first = CrashAfterCheckpointRunner(
                executor=RecordingExecutor("a", "a"),
                target_commit="abc123",
                scope_id="SCOPE-1",
            )
            with self.assertRaises(RuntimeError):
                first.run(
                    checkpoint_graph(),
                    checkpoint_world(),
                    checkpoint_path=checkpoint,
                )

            envelope = json.loads(checkpoint.read_text(encoding="utf-8"))
            envelope["payload"]["scope_id"] = "SCOPE-TAMPERED"
            checkpoint.write_text(json.dumps(envelope), encoding="utf-8")
            with self.assertRaisesRegex(CheckpointError, "digest mismatch"):
                load_checkpoint(checkpoint)


if __name__ == "__main__":
    unittest.main()
