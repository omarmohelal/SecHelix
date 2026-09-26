import json
import tempfile
import unittest
from pathlib import Path

from evals.arena_workspace import (
    ArenaWorkspaceEvidenceError,
    build_workspace_evidence_index,
)
from sechelix_runner.storage import RunWorkspace


class ArenaWorkspaceEvidenceTests(unittest.TestCase):
    def _workspace(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        ws = RunWorkspace(root, "RUN-ARENA1").create()
        ws.write_json(
            "run.json",
            {
                "run_id": "RUN-ARENA1",
                "target_commit": "abc123",
                "scope_id": "SCOPE-1",
                "graph_digest": "graph-digest",
            },
        )
        ws.write_json(
            "graph.json",
            {
                "graph_digest": "graph-digest",
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
                    {
                        "node_id": "authz",
                        "role": "AUTHORIZATION",
                        "depends_on": [],
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
                    "output": {"candidates": [{"id": "C-1", "status": "VERIFIED"}]},
                    "output_evidence_ids": ["E-VERIFY-1"],
                    "provider": "provider-a",
                    "model": "model-a",
                    "input_tokens": 100,
                    "output_tokens": 20,
                    "cost_usd": 0.01,
                },
                "gate": {
                    "status": "SUCCEEDED",
                    "output": {"decision": "PASS"},
                    "output_evidence_ids": ["E-GATE-1"],
                    "provider": None,
                    "model": None,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cost_usd": 0.0,
                },
                "authz": {
                    "status": "SUCCEEDED",
                    "output": {"private": "do-not-copy-into-index"},
                    "output_evidence_ids": [],
                },
            },
        )
        ws.write_manifest()
        return tmp, root, ws

    def test_verified_workspace_emits_digest_only_role_index(self):
        tmp, root, ws = self._workspace()
        self.addCleanup(tmp.cleanup)

        result = build_workspace_evidence_index(root, ws.run_id)
        self.assertEqual(result["workspace_integrity"], "VERIFIED")
        self.assertEqual(result["run_id"], "RUN-ARENA1")
        self.assertIn("run.json", result["artifacts"])
        self.assertIn("manifest.json", result["artifacts"])
        verifier = result["role_evidence"]["INDEPENDENT_VERIFIER"][0]
        gate = result["role_evidence"]["RELEASE_GATE"][0]
        self.assertEqual(verifier["node_id"], "verifier")
        self.assertEqual(verifier["output_evidence_ids"], ["E-VERIFY-1"])
        self.assertTrue(verifier["output_digest"].startswith("sha256:"))
        self.assertEqual(gate["status"], "SUCCEEDED")

        rendered = json.dumps(result)
        self.assertNotIn("do-not-copy-into-index", rendered)
        self.assertNotIn('"decision": "PASS"', rendered)
        self.assertNotIn('"status": "VERIFIED"', rendered)

    def test_manifest_drift_is_a_hard_failure(self):
        tmp, root, ws = self._workspace()
        self.addCleanup(tmp.cleanup)
        (ws.path / "replay" / "outcomes.json").write_text(
            '{"tampered":true}\n',
            encoding="utf-8",
        )
        with self.assertRaises(ArenaWorkspaceEvidenceError) as ctx:
            build_workspace_evidence_index(root, ws.run_id)
        self.assertIn("manifest verification failed", str(ctx.exception))

    def test_missing_required_artifact_fails_after_valid_manifest(self):
        tmp, root, ws = self._workspace()
        self.addCleanup(tmp.cleanup)
        (ws.path / "replay" / "outcomes.json").unlink()
        ws.write_manifest()
        with self.assertRaises(ArenaWorkspaceEvidenceError) as ctx:
            build_workspace_evidence_index(root, ws.run_id)
        self.assertIn("replay/outcomes.json missing", str(ctx.exception))

    def test_role_mapping_comes_from_graph_not_node_id_names(self):
        tmp, root, ws = self._workspace()
        self.addCleanup(tmp.cleanup)
        graph = json.loads((ws.path / "graph.json").read_text(encoding="utf-8"))
        graph["nodes"][0]["node_id"] = "not-obviously-a-verifier"
        replay = json.loads((ws.path / "replay" / "outcomes.json").read_text(encoding="utf-8"))
        replay["not-obviously-a-verifier"] = replay.pop("verifier")
        ws.write_json("graph.json", graph)
        ws.write_json("replay/outcomes.json", replay)
        ws.write_manifest()

        result = build_workspace_evidence_index(root, ws.run_id)
        row = result["role_evidence"]["INDEPENDENT_VERIFIER"][0]
        self.assertEqual(row["node_id"], "not-obviously-a-verifier")


if __name__ == "__main__":
    unittest.main()
