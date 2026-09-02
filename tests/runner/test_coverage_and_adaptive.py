import tempfile
import unittest
from pathlib import Path

from sechelix_runner.adaptive import (
    Action,
    AdaptiveOrchestrator,
    AdaptivePolicy,
    Observation,
    Signal,
)
from sechelix_runner.coverage import (
    CoverageLedger,
    CoverageStatus,
    LedgerMismatch,
    TargetIdentity,
    observe_world,
)
from sechelix_runner.graph import GraphNode, ReasonerGraph
from sechelix_runner.roles import NodeRole


def identity(commit: str = "AAA") -> TargetIdentity:
    return TargetIdentity(origin="git@example/repo.git", name="repo", commit=commit, branch="main")


class CoverageStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = CoverageLedger(identity())
        for name, digest in (("a.py", "h1"), ("b.py", "h2"), ("c.py", "h3")):
            self.ledger.observe("file", name, digest)

    def test_observing_is_not_covering(self) -> None:
        """Seeing that a route exists is not the same as examining it."""
        self.assertEqual(
            self.ledger.classify("file:a.py", covered_this_run=False),
            CoverageStatus.NEVER_COVERED,
        )

    def test_never_covered_is_reported_as_a_blind_spot(self) -> None:
        self.ledger.cover("file", "a.py", "RUN-1")
        report = self.ledger.report(covered_keys={"file:a.py"})
        self.assertEqual(report["blind_spots"], ["file:b.py", "file:c.py"])

    def test_first_coverage_of_a_known_item_is_new(self) -> None:
        self.assertEqual(
            self.ledger.classify("file:a.py", covered_this_run=True), CoverageStatus.NEW
        )

    def test_unchanged_and_reexamined_is_reused(self) -> None:
        self.ledger.cover("file", "a.py", "RUN-1")
        self.assertEqual(
            self.ledger.classify("file:a.py", covered_this_run=True), CoverageStatus.REUSED
        )

    def test_examined_then_skipped_is_not_revisited(self) -> None:
        self.ledger.cover("file", "a.py", "RUN-1")
        self.assertEqual(
            self.ledger.classify("file:a.py", covered_this_run=False),
            CoverageStatus.NOT_REVISITED,
        )

    def test_stale_coverage_does_not_carry_forward(self) -> None:
        """Examined at commit A, contents moved by commit B, nobody looked again."""
        self.ledger.cover("file", "a.py", "RUN-1")
        self.ledger.identity = identity("BBB")
        self.ledger.observe("file", "a.py", "h1-CHANGED")
        self.assertEqual(
            self.ledger.classify("file:a.py", covered_this_run=False), CoverageStatus.STALE
        )

    def test_reexamination_after_drift_is_changed_not_reused(self) -> None:
        self.ledger.cover("file", "a.py", "RUN-1")
        self.ledger.identity = identity("BBB")
        self.ledger.observe("file", "a.py", "h1-CHANGED")
        self.ledger.cover("file", "a.py", "RUN-2")
        self.assertEqual(
            self.ledger.classify("file:a.py", covered_this_run=True), CoverageStatus.CHANGED
        )

    def test_unknown_item_is_unknown(self) -> None:
        self.assertEqual(
            self.ledger.classify("file:ghost.py", covered_this_run=False),
            CoverageStatus.UNKNOWN,
        )

    def test_stale_items_are_blind_spots_too(self) -> None:
        self.ledger.cover("file", "a.py", "RUN-1")
        self.ledger.identity = identity("BBB")
        self.ledger.observe("file", "a.py", "h1-CHANGED")
        report = self.ledger.report(covered_keys=set())
        self.assertIn("file:a.py", report["blind_spots"])


class CoveragePersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.path = Path(tempfile.mkdtemp()) / "coverage.json"

    def test_round_trip_preserves_state(self) -> None:
        ledger = CoverageLedger(identity())
        ledger.observe("file", "a.py", "h1")
        ledger.cover("file", "a.py", "RUN-1")
        ledger.save(self.path)
        loaded = CoverageLedger.load(self.path, identity())
        self.assertEqual(
            loaded.classify("file:a.py", covered_this_run=False),
            CoverageStatus.NOT_REVISITED,
        )

    def test_changed_state_survives_a_round_trip(self) -> None:
        ledger = CoverageLedger(identity())
        ledger.observe("file", "a.py", "h1")
        ledger.cover("file", "a.py", "RUN-1")
        ledger.identity = identity("BBB")
        ledger.observe("file", "a.py", "h2")
        ledger.cover("file", "a.py", "RUN-2")
        ledger.save(self.path)
        loaded = CoverageLedger.load(self.path, identity("BBB"))
        self.assertEqual(
            loaded.classify("file:a.py", covered_this_run=True), CoverageStatus.CHANGED
        )

    def test_a_ledger_from_another_project_is_refused(self) -> None:
        CoverageLedger(identity()).save(self.path)
        other = TargetIdentity(origin="git@other/x.git", name="other", commit="AAA", branch="main")
        with self.assertRaises(LedgerMismatch):
            CoverageLedger.load(self.path, other)

    def test_missing_ledger_starts_empty_rather_than_failing(self) -> None:
        ledger = CoverageLedger.load(Path(tempfile.mkdtemp()) / "absent.json", identity())
        self.assertEqual(ledger.items, {})

    def test_observe_world_hashes_real_files(self) -> None:
        root = Path(tempfile.mkdtemp())
        (root / "a.py").write_text("print(1)\n", encoding="utf-8")
        ledger = CoverageLedger(identity())
        observe_world(ledger, {"file_index": ["a.py"]}, root=root)
        self.assertIsNotNone(ledger.items["file:a.py"].content_hash)

    def test_unreadable_file_is_observed_without_a_fabricated_hash(self) -> None:
        ledger = CoverageLedger(identity())
        observe_world(ledger, {"file_index": ["gone.py"]}, root=Path(tempfile.mkdtemp()))
        self.assertIsNone(ledger.items["file:gone.py"].content_hash)


class AdaptiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.graph = ReasonerGraph(
            [
                GraphNode("map", NodeRole.MAPPER, (), mandatory=True),
                GraphNode("authz", NodeRole.AUTHORIZATION, ("map",)),
            ]
        )

    def test_disabled_policy_changes_nothing_at_all(self) -> None:
        orchestrator = AdaptiveOrchestrator()
        adapted, decisions = orchestrator.adapt(
            self.graph,
            Observation(architecture_signals=["payment_state_machine"], budget_fraction_used=0.99),
        )
        self.assertIs(adapted, self.graph)
        self.assertEqual(decisions, [])
        self.assertEqual(orchestrator.decisions, [])

    def test_architecture_signal_deepens_the_lane_it_maps_to(self) -> None:
        orchestrator = AdaptiveOrchestrator(AdaptivePolicy(enabled=True))
        adapted, decisions = orchestrator.adapt(
            self.graph, Observation(architecture_signals=["payment_state_machine"])
        )
        self.assertGreater(len(adapted), len(self.graph))
        decision = decisions[0]
        self.assertIs(decision.signal, Signal.ARCHITECTURE_SIGNAL)
        self.assertIs(decision.action, Action.DEEPEN_LANE)
        self.assertEqual(decision.target, NodeRole.BUSINESS_LOGIC.value)

    def test_unmapped_architecture_signal_does_not_spend_budget(self) -> None:
        """"We saw a word" is not a reason to add a node."""
        orchestrator = AdaptiveOrchestrator(AdaptivePolicy(enabled=True))
        adapted, decisions = orchestrator.adapt(
            self.graph, Observation(architecture_signals=["something_unmapped"])
        )
        self.assertIs(adapted, self.graph)
        self.assertEqual(decisions, [])

    def test_high_refutation_rate_tightens_the_lane(self) -> None:
        orchestrator = AdaptiveOrchestrator(AdaptivePolicy(enabled=True))
        _, decisions = orchestrator.adapt(
            self.graph,
            Observation(lane_findings={"injection": 10}, lane_refutations={"injection": 8}),
        )
        tighten = [d for d in decisions if d.action is Action.TIGHTEN_LANE]
        self.assertEqual(len(tighten), 1)
        self.assertEqual(tighten[0].value, 0.8)

    def test_a_rate_from_too_few_findings_is_not_a_rate(self) -> None:
        """3 of 3 refuted is 100%, and it is still not enough to act on."""
        orchestrator = AdaptiveOrchestrator(AdaptivePolicy(enabled=True))
        _, decisions = orchestrator.adapt(
            self.graph,
            Observation(lane_findings={"browser": 3}, lane_refutations={"browser": 3}),
        )
        self.assertEqual([d for d in decisions if d.action is Action.TIGHTEN_LANE], [])

    def test_coverage_gap_schedules_a_variant_hunter(self) -> None:
        orchestrator = AdaptiveOrchestrator(AdaptivePolicy(enabled=True))
        adapted, decisions = orchestrator.adapt(
            self.graph, Observation(coverage_never_covered=60, coverage_total=100)
        )
        self.assertIn("variant_hunter", adapted)
        self.assertTrue(any(d.signal is Signal.COVERAGE_GAP for d in decisions))

    def test_budget_pressure_prioritises_and_never_adds_work(self) -> None:
        orchestrator = AdaptiveOrchestrator(AdaptivePolicy(enabled=True))
        adapted, decisions = orchestrator.adapt(
            self.graph, Observation(budget_fraction_used=0.9)
        )
        self.assertEqual(len(adapted), len(self.graph))
        pressure = [d for d in decisions if d.signal is Signal.BUDGET_PRESSURE]
        self.assertEqual(pressure[0].action, Action.PRIORITISE)

    def test_tool_failure_is_surfaced_not_absorbed(self) -> None:
        orchestrator = AdaptiveOrchestrator(AdaptivePolicy(enabled=True))
        _, decisions = orchestrator.adapt(self.graph, Observation(tool_failures=["semgrep"]))
        failure = [d for d in decisions if d.signal is Signal.TOOL_FAILURE]
        self.assertEqual(len(failure), 1)
        self.assertIn("UNKNOWN", failure[0].reason)

    def test_every_decision_records_signal_value_and_threshold(self) -> None:
        orchestrator = AdaptiveOrchestrator(AdaptivePolicy(enabled=True))
        _, decisions = orchestrator.adapt(
            self.graph,
            Observation(
                architecture_signals=["multi_tenant"],
                coverage_never_covered=90,
                coverage_total=100,
                budget_fraction_used=0.95,
            ),
        )
        self.assertTrue(decisions)
        for decision in decisions:
            data = decision.to_dict()
            for key in ("signal", "value", "threshold", "action", "target", "reason"):
                self.assertIn(key, data)
            self.assertTrue(data["reason"])

    def test_adapted_graph_stays_acyclic_and_orderable(self) -> None:
        orchestrator = AdaptiveOrchestrator(AdaptivePolicy(enabled=True))
        adapted, _ = orchestrator.adapt(
            self.graph,
            Observation(
                architecture_signals=["payment_state_machine", "multi_tenant", "mcp_server"],
                coverage_never_covered=80,
                coverage_total=100,
            ),
        )
        order = adapted.topological_order()
        self.assertEqual(len(order), len(adapted))
        self.assertEqual(order[0], "map")


if __name__ == "__main__":
    unittest.main()
