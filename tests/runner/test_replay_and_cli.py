import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from sechelix_runner import cli
from sechelix_runner.executor import MockExecutor, NodeOutcome
from sechelix_runner.graph import GraphNode, ReasonerGraph
from sechelix_runner.replay import ReplayError, replay_run
from sechelix_runner.roles import NodeRole, NodeStatus
from sechelix_runner.runner import Runner
from sechelix_runner.storage import persist_run
from sechelix_runner.world import build_world, describe_target, walk_files


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


class ReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        executor = MockExecutor(
            {
                "map": NodeOutcome(
                    status=NodeStatus.SUCCEEDED,
                    input_tokens=1200,
                    output_tokens=300,
                    cost_usd=0.012,
                ),
                "authorization": NodeOutcome(status=NodeStatus.FAILED, error="boom"),
            }
        )
        self.result = Runner(
            executor=executor, target_commit="abc123", scope_id="S1"
        ).run(pipeline(), world())
        self.workspace = persist_run(self.tmp, self.result, pipeline())

    def test_replay_reproduces_every_status(self) -> None:
        replayed, comparison = replay_run(self.tmp, self.result.run_id, world())
        self.assertTrue(comparison.faithful, comparison.differences)
        self.assertEqual(
            {n: r.status for n, r in replayed.records.items()},
            {n: r.status for n, r in self.result.records.items()},
        )

    def test_replay_reconstructs_why_a_node_was_blocked(self) -> None:
        replayed, _ = replay_run(self.tmp, self.result.run_id, world())
        self.assertIn("authorization", replayed.records["verify"].blocker)

    def test_replay_reproduces_the_gate_state(self) -> None:
        replayed, comparison = replay_run(self.tmp, self.result.run_id, world())
        self.assertTrue(comparison.unsatisfied_matches)
        self.assertEqual(
            replayed.unsatisfied_mandatory, self.result.unsatisfied_mandatory
        )

    def test_telemetry_survives_the_round_trip(self) -> None:
        replayed, _ = replay_run(self.tmp, self.result.run_id, world())
        self.assertEqual(replayed.records["map"].input_tokens, 1200)
        self.assertEqual(replayed.records["map"].cost_usd, 0.012)

    def test_tampered_workspace_is_refused(self) -> None:
        path = self.workspace.path / "run.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["records"]["authorization"]["status"] = "SUCCEEDED"
        path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(ReplayError) as caught:
            replay_run(self.tmp, self.result.run_id, world())
        self.assertIn("integrity", str(caught.exception))

    def test_unknown_run_is_refused(self) -> None:
        with self.assertRaises(ReplayError):
            replay_run(self.tmp, "RUN-DOES-NOT-EXIST", world())

    def test_replay_of_a_partial_recording_fails_rather_than_inventing(self) -> None:
        path = self.workspace.path / "replay" / "outcomes.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        # `map` SUCCEEDED originally, so losing its recording changes the status
        # and the comparison must notice. Dropping an already-FAILED node would
        # coincidentally match and hide the gap.
        del data["map"]
        path.write_text(json.dumps(data), encoding="utf-8")
        self.workspace.write_manifest()
        replayed, comparison = replay_run(self.tmp, self.result.run_id, world())
        self.assertFalse(comparison.faithful)
        self.assertIn("no recorded outcome", replayed.records["map"].error)
        self.assertIn("map", " ".join(comparison.differences))


class WorldTests(unittest.TestCase):
    def test_walk_skips_vendored_trees(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        (tmp / "node_modules").mkdir()
        (tmp / "node_modules" / "junk.js").write_text("x", encoding="utf-8")
        (tmp / "app.py").write_text("x", encoding="utf-8")
        files = walk_files(tmp, 100)
        self.assertIn("app.py", files)
        self.assertFalse(any("node_modules" in f for f in files))

    def test_depth_limits_the_walk(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        for index in range(30):
            (tmp / f"file{index}.py").write_text("x", encoding="utf-8")
        self.assertEqual(len(walk_files(tmp, 5)), 5)

    def test_absent_slices_are_absent_not_empty(self) -> None:
        """An empty list claims "looked and found none"; absence claims nothing."""
        tmp = Path(tempfile.mkdtemp())
        (tmp / "readme.md").write_text("hello", encoding="utf-8")
        built = build_world(tmp, depth="quick")
        self.assertNotIn("manifests", built)
        self.assertNotIn("lockfiles", built)

    def test_manifests_are_detected_when_present(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        (tmp / "package.json").write_text("{}", encoding="utf-8")
        (tmp / "package-lock.json").write_text("{}", encoding="utf-8")
        built = build_world(tmp, depth="quick")
        self.assertEqual(built["manifests"], ["package.json"])
        self.assertEqual(built["lockfiles"], ["package-lock.json"])

    def test_non_git_target_reports_unknown_rather_than_inventing(self) -> None:
        target = describe_target(Path(tempfile.mkdtemp()))
        self.assertEqual(target["commit"], "UNKNOWN")


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "app.py").write_text("def handler(request): pass\n", encoding="utf-8")
        (self.tmp / "routes.py").write_text("ROUTES = []\n", encoding="utf-8")

    def _run(self, argv: list[str]) -> tuple[int, str]:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.main(argv)
        return code, buffer.getvalue()

    def test_doctor_reports_without_requiring_optional_components(self) -> None:
        code, out = self._run(["doctor", str(self.tmp), "--json"])
        self.assertEqual(code, cli.EXIT_OK)
        report = json.loads(out)
        self.assertTrue(report["core_contracts"])
        self.assertEqual(report["network_mode"], "DENY (static default)")

    def test_audit_without_a_reasoning_executor_is_not_clean(self) -> None:
        """The honest default: nothing was analysed, so nothing may be claimed."""
        code, out = self._run(["audit", str(self.tmp), "--depth", "quick"])
        self.assertEqual(code, cli.EXIT_NOT_CLEAN)
        self.assertIn("INCOMPLETE", out)
        self.assertIn("No security claim can be made", out)

    def test_audit_blocks_reasoning_nodes_rather_than_passing_them(self) -> None:
        code, out = self._run(["audit", str(self.tmp), "--depth", "quick", "--json"])
        data = json.loads(out)
        reasoning = [
            r for r in data["records"].values()
            if r["role"] not in ("MAPPER", "RELEASE_GATE")
        ]
        self.assertTrue(reasoning)
        for record in reasoning:
            self.assertNotEqual(record["status"], "SUCCEEDED")

    def test_audit_then_runs_then_replay_round_trip(self) -> None:
        self._run(["audit", str(self.tmp), "--depth", "quick"])
        code, out = self._run(["runs", str(self.tmp), "--json"])
        run_id = json.loads(out)["runs"][-1]
        code, out = self._run(["replay", run_id, str(self.tmp), "--json"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertTrue(json.loads(out)["faithful"])

    def test_report_renders_a_recorded_run(self) -> None:
        self._run(["audit", str(self.tmp), "--depth", "quick"])
        code, out = self._run(["report", "--path", str(self.tmp), "--format", "markdown"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("# SecHelix run", out)
        self.assertIn("INCOMPLETE", out)

    def test_report_json_is_machine_readable(self) -> None:
        self._run(["audit", str(self.tmp), "--depth", "quick"])
        code, out = self._run(["report", "--path", str(self.tmp), "--format", "json"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("records", json.loads(out))

    def test_coverage_requires_a_prior_run(self) -> None:
        code, _ = self._run(["coverage", str(self.tmp)])
        self.assertEqual(code, cli.EXIT_ERROR)

    def test_blocked_lanes_credit_no_coverage(self) -> None:
        """Nothing was examined, so nothing may be recorded as covered.

        Crediting a BLOCKED lane would turn this run's gap into next run's
        false reassurance.
        """
        self._run(["audit", str(self.tmp), "--depth", "quick"])
        code, out = self._run(["coverage", str(self.tmp), "--json"])
        self.assertEqual(code, cli.EXIT_OK)
        report = json.loads(out)
        self.assertEqual(report["totals"]["REUSED"], 0)
        self.assertGreater(report["totals"]["NEVER_COVERED"], 0)
        self.assertTrue(report["blind_spots"])

    def test_audit_json_carries_the_coverage_report(self) -> None:
        code, out = self._run(["audit", str(self.tmp), "--depth", "quick", "--json"])
        self.assertIn("coverage", json.loads(out))

    def test_replay_of_unknown_run_exits_error(self) -> None:
        code, _ = self._run(["replay", "RUN-NOPE", str(self.tmp)])
        self.assertEqual(code, cli.EXIT_ERROR)

    def test_budget_limit_blocks_nodes_and_keeps_the_run_not_clean(self) -> None:
        code, out = self._run(
            ["audit", str(self.tmp), "--depth", "quick", "--max-nodes", "2", "--json"]
        )
        self.assertEqual(code, cli.EXIT_NOT_CLEAN)
        data = json.loads(out)
        self.assertTrue(data["budget"]["exhausted"])
        self.assertTrue(data["unsatisfied_mandatory"])


if __name__ == "__main__":
    unittest.main()
