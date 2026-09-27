from __future__ import annotations

import tempfile
import unittest

from sechelix_runner.executor import NodeOutcome
from sechelix_runner.graph import GraphNode, ReasonerGraph
from sechelix_runner.pentest import (
    PromotionCheckpointError,
    build_promotion_checkpoint,
)
from sechelix_runner.providers.reasoning import verifier_view
from sechelix_runner.roles import NodeRole, NodeStatus
from sechelix_runner.runner import RunResult
from sechelix_runner.storage import RunWorkspace, persist_run
from sechelix_runner.telemetry import NodeRecord


def graph() -> ReasonerGraph:
    return ReasonerGraph(
        [
            GraphNode("authorization", NodeRole.AUTHORIZATION, mandatory=True),
            GraphNode(
                "independent-verifier",
                NodeRole.INDEPENDENT_VERIFIER,
                depends_on=("authorization",),
                mandatory=True,
            ),
            GraphNode(
                "release-gate",
                NodeRole.RELEASE_GATE,
                depends_on=("independent-verifier",),
                mandatory=True,
            ),
        ]
    )


def candidate() -> dict[str, object]:
    return {
        "claim": "Buyer A can read Buyer B order",
        "location": "GET /api/orders/{id}",
        "why": "Observed controlled cross-owner response.",
        "hypothesis_ids": ["SHX-AUTHZ-L02"],
    }


def persisted(root: str, *, classification: str = "VERIFIED") -> str:
    row = candidate()
    ref = verifier_view(row)["candidate_ref"]
    result = RunResult(
        run_id="RUN-CHECKPOINT1",
        target_commit="abc123",
        scope_id="SCOPE-1",
        graph_digest="",
        executor_name="mock",
    )
    g = graph()
    from sechelix_runner.digests import digest

    result.graph_digest = digest(
        [
            {
                "node_id": n.node_id,
                "role": n.role.value,
                "depends_on": sorted(n.depends_on),
                "mandatory": n.mandatory,
                "node_version": n.node_version,
            }
            for n in g.nodes
        ]
    )
    for node in g.nodes:
        result.records[node.node_id] = NodeRecord(
            run_id=result.run_id,
            node_id=node.node_id,
            role=node.role,
            node_version=node.node_version,
            target_commit=result.target_commit,
            scope_id=result.scope_id,
            status=NodeStatus.SUCCEEDED,
        )
    result.outputs = {
        "authorization": {"candidates": [row]},
        "independent-verifier": {
            "assessments": [
                {
                    "candidate_ref": ref,
                    "classification": classification,
                    "claim": row["claim"],
                    "location": row["location"],
                    "evidence_ids": ["EV-VERIFY-001"],
                    "refutation_attempt": "Tried an isolated owner session.",
                }
            ]
        },
        "release-gate": {},
    }
    persist_run(root, result, g)
    return result.run_id


class PromotionCheckpointTests(unittest.TestCase):
    def test_checkpoint_reconstructs_exact_candidate_and_assessment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_id = persisted(tmp)
            checkpoint = build_promotion_checkpoint(tmp, run_id)

        self.assertEqual(checkpoint.status, "WAITING_FOR_PROMOTION_INPUT")
        self.assertEqual(len(checkpoint.candidates), 1)
        self.assertEqual(len(checkpoint.assessments), 1)
        self.assertEqual(
            checkpoint.candidates[0]["candidate_ref"],
            checkpoint.assessments[0]["candidate_ref"],
        )
        self.assertTrue(checkpoint.checkpoint_digest.startswith("sha256:"))

    def test_nonverified_packet_needs_no_promotion_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_id = persisted(tmp, classification="REFUTED")
            checkpoint = build_promotion_checkpoint(tmp, run_id)
        self.assertEqual(checkpoint.status, "NO_VERIFIED_CANDIDATES")

    def test_workspace_drift_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_id = persisted(tmp)
            workspace = RunWorkspace(tmp, run_id)
            (workspace.path / "replay" / "outcomes.json").write_text(
                "{}\n",
                encoding="utf-8",
            )
            with self.assertRaises(PromotionCheckpointError):
                build_promotion_checkpoint(tmp, run_id)


if __name__ == "__main__":
    unittest.main()
