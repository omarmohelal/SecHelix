"""Regression tests for defects found by auditing the runner itself.

Phase 30 of the V4 plan: point SecHelix at the runtime SecHelix ships. The
findings below were real and are fixed; these tests keep them fixed.
"""

import json
import tempfile
import unittest
from pathlib import Path

from sechelix_runner import cli
from sechelix_runner.coverage import CoverageLedger, TargetIdentity
from sechelix_runner.digests import digest
from sechelix_runner.replay import load_graph
from sechelix_runner.storage import InvalidRunId, RunWorkspace


class RunIdTraversalTests(unittest.TestCase):
    """A run id is an identifier, never a path fragment.

    Found by self-audit: run_id arrives from the command line and was joined
    straight onto the runs directory, so '../../outside.json' resolved outside
    the workspace and 'sechelix report' would read and print it.
    """

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        (self.root / ".sechelix" / "runs").mkdir(parents=True)
        (self.root / "outside.json").write_text('{"secret": true}', encoding="utf-8")

    def test_a_well_formed_run_id_is_accepted(self) -> None:
        workspace = RunWorkspace(self.root, "RUN-ABC123")
        self.assertEqual(workspace.path.name, "RUN-ABC123")

    def test_relative_traversal_is_refused(self) -> None:
        for run_id in ("../..", "../../outside.json", r"..\..\outside.json"):
            with self.subTest(run_id=run_id):
                with self.assertRaises(InvalidRunId):
                    RunWorkspace(self.root, run_id)

    def test_traversal_embedded_after_a_valid_prefix_is_refused(self) -> None:
        with self.assertRaises(InvalidRunId):
            RunWorkspace(self.root, "RUN-A/../../B")

    def test_empty_and_lowercase_ids_are_refused(self) -> None:
        for run_id in ("", "run-lower", "RUN ", "RUN-!"):
            with self.subTest(run_id=run_id):
                with self.assertRaises(InvalidRunId):
                    RunWorkspace(self.root, run_id)

    def test_resolved_path_always_stays_inside_the_runs_directory(self) -> None:
        base = (self.root / ".sechelix" / "runs").resolve()
        workspace = RunWorkspace(self.root, "RUN-OK")
        self.assertTrue(str(workspace.path.resolve()).startswith(str(base)))

    def test_cli_reports_a_usage_error_rather_than_a_traceback(self) -> None:
        self.assertEqual(cli.main(["replay", "../../etc", str(self.root)]), cli.EXIT_USAGE)
        self.assertEqual(cli.main(["report", "run-lower", "--path", str(self.root)]),
                         cli.EXIT_USAGE)


class HostileArtifactTests(unittest.TestCase):
    """Run artifacts are read back from disk and may be malformed or hostile."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.workspace = RunWorkspace(self.root, "RUN-HOSTILE").create()

    def test_unknown_node_role_in_a_recorded_graph_is_refused(self) -> None:
        self.workspace.write_json("graph.json", {
            "graph_digest": "x",
            "nodes": [{"node_id": "n", "role": "NOT_A_ROLE", "depends_on": [],
                       "mandatory": True, "node_version": "1"}],
            "topological_order": ["n"],
        })
        with self.assertRaises(ValueError):
            load_graph(self.workspace)

    def test_a_cycle_smuggled_into_a_recorded_graph_is_refused(self) -> None:
        self.workspace.write_json("graph.json", {
            "graph_digest": "x",
            "nodes": [
                {"node_id": "a", "role": "MAPPER", "depends_on": ["b"],
                 "mandatory": True, "node_version": "1"},
                {"node_id": "b", "role": "MAPPER", "depends_on": ["a"],
                 "mandatory": True, "node_version": "1"},
            ],
            "topological_order": ["a", "b"],
        })
        with self.assertRaises(ValueError):
            load_graph(self.workspace)

    def test_unknown_fields_in_a_coverage_ledger_are_ignored(self) -> None:
        path = self.root / "cov.json"
        path.write_text(json.dumps({
            "identity": {"target_id": None},
            "items": {"file:x": {"kind": "file", "identifier": "x", "evil": 1}},
        }), encoding="utf-8")
        ledger = CoverageLedger.load(path, TargetIdentity("o", "n", "c", "b"))
        item = ledger.items["file:x"]
        self.assertEqual(item.kind, "file")
        self.assertFalse(hasattr(item, "evil"))

    def test_deeply_nested_structures_do_not_break_digesting(self) -> None:
        deep: dict = {}
        cursor = deep
        for _ in range(120):
            cursor["n"] = {}
            cursor = cursor["n"]
        self.assertTrue(digest(deep).startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
