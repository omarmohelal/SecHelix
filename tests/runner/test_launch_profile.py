from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import unittest

from sechelix_runner.graph import GraphNode
from sechelix_runner.launch_profile import (
    LAUNCH_EXECUTION_STATES,
    LaunchContextBuilder,
    build_launch_graph,
    load_launch_checks,
    summarize_launch_run,
)
from sechelix_runner.proof import ProofClass
from sechelix_runner.providers.reasoning import build_prompt
from sechelix_runner.roles import NodeRole, NodeStatus


ROOT = Path(__file__).resolve().parents[2]
CANONICAL = ROOT / "catalog" / "launch-checks.json"
PORTABLE = ROOT / "skills" / "sechelix" / "catalog" / "launch-checks.json"


class LaunchProfileTests(unittest.TestCase):
    def test_checks_19_through_36_are_complete_and_ordered(self) -> None:
        checks = load_launch_checks(CANONICAL)
        self.assertEqual(
            [check.id for check in checks],
            [f"LAUNCH-{number:02d}" for number in range(19, 37)],
        )
        self.assertEqual(len(checks), 18)

    def test_every_check_has_evidence_refutation_and_safe_test(self) -> None:
        for check in load_launch_checks(CANONICAL):
            self.assertTrue(check.evidence_required.strip(), check.id)
            self.assertTrue(check.refuted_if.strip(), check.id)
            self.assertTrue(check.safe_test.strip(), check.id)
            rendered = " ".join(
                (check.evidence_required, check.refuted_if, check.safe_test)
            ).lower()
            self.assertNotIn("brute force", rendered.replace("no brute force", ""))
            self.assertNotIn("denial of service", rendered)

    def test_every_declared_proof_class_is_real(self) -> None:
        known = {item.value for item in ProofClass}
        for check in load_launch_checks(CANONICAL):
            self.assertFalse(set(check.proof_classes) - known, check.id)

    def test_every_declared_eval_fixture_exists(self) -> None:
        fixture_ids = set()
        for path in (ROOT / "evals" / "fixtures").glob("*.json"):
            payload = json.loads(path.read_text(encoding="utf-8"))
            fixture_id = payload.get("id")
            if isinstance(fixture_id, str):
                fixture_ids.add(fixture_id)
        for check in load_launch_checks(CANONICAL):
            self.assertFalse(set(check.fixture_ids) - fixture_ids, check.id)

    def test_portable_profile_is_byte_identical(self) -> None:
        self.assertEqual(
            CANONICAL.read_bytes(),
            PORTABLE.read_bytes(),
        )

    def test_context_builder_only_exposes_owned_launch_checks(self) -> None:
        checks = load_launch_checks(CANONICAL)
        builder = LaunchContextBuilder({"client_entrypoints": ["app.js"]}, checks)
        view = builder.build("launch-browser", NodeRole.BROWSER)
        ids = {row["id"] for row in view.payload["launch_checks"]}
        self.assertEqual(ids, {"LAUNCH-19", "LAUNCH-20", "LAUNCH-27"})
        self.assertNotIn("LAUNCH-33", ids)

    def test_launch_graph_keeps_specialists_and_verifier_structurally_separate(self) -> None:
        graph = build_launch_graph(load_launch_checks(CANONICAL))
        self.assertIn("launch-verify", {node.node_id for node in graph.nodes})
        verifier = graph["launch-verify"]
        self.assertEqual(verifier.role, NodeRole.INDEPENDENT_VERIFIER)
        self.assertGreaterEqual(len(verifier.depends_on), 1)
        self.assertNotIn("launch-verify", verifier.depends_on)

    def test_reasoning_prompt_requires_exact_launch_ids(self) -> None:
        prompt = build_prompt(
            GraphNode("launch-browser", NodeRole.BROWSER, ("map",)),
            {
                "client_entrypoints": ["app.js"],
                "launch_checks": [
                    {
                        "id": "LAUNCH-19",
                        "title": "XSS",
                        "families": ["WEB", "INJ"],
                    }
                ],
            },
        )
        self.assertIn("Evaluate every assigned launch check explicitly: LAUNCH-19", prompt)
        self.assertIn("Put every assigned LAUNCH-XX id in examined exactly once", prompt)
        self.assertIn("hypothesis_ids", prompt)
        self.assertIn("not PASS", prompt)

    def test_summary_never_promotes_no_candidate_to_pass(self) -> None:
        checks = tuple(
            check for check in load_launch_checks(CANONICAL)
            if check.id in {"LAUNCH-19", "LAUNCH-20"}
        )
        result = SimpleNamespace(
            records={
                "launch-browser": SimpleNamespace(status=NodeStatus.SUCCEEDED),
            },
            outputs={
                "launch-browser": {
                    "candidates": [
                        {
                            "claim": "candidate",
                            "hypothesis_ids": ["LAUNCH-19"],
                        }
                    ],
                    "examined": ["LAUNCH-19", "LAUNCH-20"],
                }
            },
        )
        summary = summarize_launch_run(result, checks)
        states = {row["id"]: row["execution_state"] for row in summary["checks"]}
        self.assertEqual(states["LAUNCH-19"], "CANDIDATE")
        self.assertEqual(states["LAUNCH-20"], "ASSESSED_NO_CANDIDATE")
        self.assertFalse(summary["pass_emitted"])
        self.assertNotIn("PASS", LAUNCH_EXECUTION_STATES)

    def test_blocked_lane_stays_blocked(self) -> None:
        check = next(
            item for item in load_launch_checks(CANONICAL)
            if item.id == "LAUNCH-33"
        )
        result = SimpleNamespace(
            records={
                "launch-authorization": SimpleNamespace(status=NodeStatus.BLOCKED),
            },
            outputs={},
        )
        summary = summarize_launch_run(result, (check,))
        self.assertEqual(summary["checks"][0]["execution_state"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
