import unittest

from sechelix_runner.budget import BudgetGovernor, BudgetLimits
from sechelix_runner.executor import MockExecutor, NodeOutcome, ReplayExecutor
from sechelix_runner.graph import GraphNode, ReasonerGraph
from sechelix_runner.roles import NodeRole, NodeStatus
from sechelix_runner.runner import Runner


def world() -> dict:
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


def pipeline() -> ReasonerGraph:
    return ReasonerGraph(
        [
            GraphNode("map", NodeRole.MAPPER, (), mandatory=True),
            GraphNode("authz", NodeRole.AUTHORIZATION, ("map",)),
            GraphNode("verify", NodeRole.INDEPENDENT_VERIFIER, ("authz",), mandatory=True),
            GraphNode("gate", NodeRole.RELEASE_GATE, ("verify",), mandatory=True),
        ]
    )


def runner(**kwargs) -> Runner:
    kwargs.setdefault("executor", MockExecutor())
    kwargs.setdefault("target_commit", "abc123")
    kwargs.setdefault("scope_id", "SCOPE-1")
    return Runner(**kwargs)


class CleanRunTests(unittest.TestCase):
    def test_every_node_succeeds_and_is_recorded(self) -> None:
        result = runner().run(pipeline(), world())
        self.assertEqual(len(result.records), 4)
        self.assertEqual(result.unsatisfied_mandatory, [])
        for record in result.records.values():
            self.assertIs(record.status, NodeStatus.SUCCEEDED)

    def test_records_carry_target_identity(self) -> None:
        result = runner().run(pipeline(), world())
        for record in result.records.values():
            self.assertEqual(record.target_commit, "abc123")
            self.assertEqual(record.scope_id, "SCOPE-1")
            self.assertEqual(record.run_id, result.run_id)

    def test_graph_digest_is_stable_for_the_same_graph(self) -> None:
        first = runner().run(pipeline(), world())
        second = runner().run(pipeline(), world())
        self.assertEqual(first.graph_digest, second.graph_digest)


class FailurePropagationTests(unittest.TestCase):
    """A node that did not deliver must not let its dependents claim success."""

    def setUp(self) -> None:
        executor = MockExecutor({"authz": NodeOutcome(status=NodeStatus.FAILED, error="boom")})
        self.result = runner(executor=executor).run(pipeline(), world())

    def test_dependents_are_blocked_not_run(self) -> None:
        self.assertIs(self.result.records["verify"].status, NodeStatus.BLOCKED)
        self.assertIn("authz", self.result.records["verify"].blocker)

    def test_blocking_is_transitive(self) -> None:
        self.assertIs(self.result.records["gate"].status, NodeStatus.BLOCKED)

    def test_failed_node_does_not_disappear_from_the_report(self) -> None:
        self.assertEqual(len(self.result.records), 4)
        self.assertEqual(self.result.failed, ["authz"])
        self.assertEqual(self.result.blocked, ["gate", "verify"])

    def test_mandatory_nodes_are_reported_unsatisfied(self) -> None:
        self.assertEqual(self.result.unsatisfied_mandatory, ["gate", "verify"])


class BudgetFailClosedTests(unittest.TestCase):
    """Exhausting the budget must never turn into a silent PASS.

    This is the invariant the whole governor exists for: the verifier is
    unaffordable, so it is BLOCKED with the limit named, the gate is blocked
    behind it, and a mandatory node is left unsatisfied.
    """

    def setUp(self) -> None:
        governor = BudgetGovernor(BudgetLimits(max_cost_usd=0.10))
        self.result = runner(
            budget=governor,
            node_cost_estimates={"map": 0.05, "authz": 0.05, "verify": 0.50, "gate": 0.01},
        ).run(pipeline(), world())

    def test_unaffordable_verifier_is_blocked(self) -> None:
        record = self.result.records["verify"]
        self.assertIs(record.status, NodeStatus.BLOCKED)
        self.assertIn("max_cost_usd", record.blocker)

    def test_verifier_is_blocked_rather_than_skipped(self) -> None:
        """SKIPPED would mean the lane did not apply, which is a different claim."""
        self.assertIsNot(self.result.records["verify"].status, NodeStatus.SKIPPED)
        self.assertFalse(self.result.records["verify"].satisfied)

    def test_gate_cannot_report_a_clean_run(self) -> None:
        self.assertIn("verify", self.result.unsatisfied_mandatory)
        self.assertIn("gate", self.result.unsatisfied_mandatory)

    def test_budget_refusal_is_durable(self) -> None:
        refusals = self.result.budget_snapshot["decisions"]
        self.assertTrue(any(not d["admitted"] for d in refusals))
        self.assertTrue(self.result.budget_snapshot["exhausted"])


class ContextIsolationTests(unittest.TestCase):
    def test_each_node_gets_only_its_own_slices(self) -> None:
        result = runner().run(pipeline(), world())
        authz = result.context_views["authz"]["source_ids"]
        self.assertIn("ownership_model", authz)
        self.assertNotIn("candidates", authz)

        verify = result.context_views["verify"]["source_ids"]
        self.assertIn("candidates", verify)
        self.assertNotIn("ownership_model", verify)

    def test_views_are_smaller_than_the_whole_world(self) -> None:
        from sechelix_runner.context import ContextBuilder

        full = ContextBuilder(world()).full_world_tokens()
        result = runner().run(pipeline(), world())
        for node_id, view in result.context_views.items():
            self.assertLess(view["approx_tokens"], full, node_id)

    def test_missing_required_context_blocks_rather_than_guesses(self) -> None:
        thin = {k: v for k, v in world().items() if k != "ownership_model"}
        result = runner().run(pipeline(), thin)
        record = result.records["authz"]
        self.assertIs(record.status, NodeStatus.BLOCKED)
        self.assertIn("ownership_model", record.blocker)

    def test_omitted_context_is_recorded_not_hidden(self) -> None:
        result = runner().run(pipeline(), world())
        self.assertIn("omitted_optional", result.context_views["authz"])


class EvidencePromotionTests(unittest.TestCase):
    def test_specialist_candidate_reaches_downstream_verifier(self) -> None:
        thin_world = world()
        thin_world.pop("candidates")

        candidate = {
            "claim": "cross-account read",
            "location": "GET /orders/{id}",
            "why": "owner boundary was not observed",
        }
        executor = MockExecutor(
            {
                "authz": NodeOutcome(
                    status=NodeStatus.SUCCEEDED,
                    output={"candidates": [candidate]},
                )
            }
        )
        result = runner(executor=executor).run(pipeline(), thin_world)

        self.assertIs(result.records["verify"].status, NodeStatus.SUCCEEDED)
        self.assertIn("candidates", result.context_views["verify"]["source_ids"])

    def test_verifier_assessments_reach_gate_without_becoming_findings(self) -> None:
        assessment = {
            "candidate_ref": "sha256:" + "c" * 64,
            "classification": "VERIFIED",
            "claim": "cross-account read",
            "location": "GET /orders/{id}",
            "why": "the supplied boundary could not be refuted",
            "refutation_attempt": "reconstructed the ownership path independently",
        }
        executor = MockExecutor(
            {
                "verify": NodeOutcome(
                    status=NodeStatus.SUCCEEDED,
                    output={"assessments": [assessment]},
                )
            }
        )
        result = runner(executor=executor).run(pipeline(), world())

        self.assertIs(result.records["gate"].status, NodeStatus.SUCCEEDED)
        self.assertIn(
            "verifier_assessments",
            result.context_views["gate"]["source_ids"],
        )
        # A typed VERIFIED assessment is still not a canonical finding-v1 record.
        self.assertEqual(world()["findings"], [])

    def test_result_surfaces_canonical_verified_findings(self) -> None:
        finding = {
            "schema_version": "1.0",
            "finding_id": "SHX-F-LIVE-CROSSACCT",
            "status": "VERIFIED",
            "severity": "HIGH",
        }
        executor = MockExecutor(
            {
                "verify": NodeOutcome(
                    status=NodeStatus.SUCCEEDED,
                    output={"verified_findings": [finding]},
                )
            }
        )
        result = runner(executor=executor).run(pipeline(), world())
        # The promoted records reach the result and its persisted form without
        # a reader walking per-node outputs.
        self.assertEqual(result.verified_findings, [finding])
        self.assertEqual(result.to_dict()["verified_findings"], [finding])

    def test_result_has_no_findings_when_none_were_promoted(self) -> None:
        result = runner(executor=MockExecutor({})).run(pipeline(), world())
        self.assertEqual(result.verified_findings, [])
        self.assertEqual(result.to_dict()["verified_findings"], [])

    def test_promotion_does_not_mutate_caller_world(self) -> None:
        original = world()
        original.pop("candidates")
        before = dict(original)
        executor = MockExecutor(
            {
                "authz": NodeOutcome(
                    status=NodeStatus.SUCCEEDED,
                    output={
                        "candidates": [
                            {
                                "claim": "c",
                                "location": "l",
                                "why": "w",
                            }
                        ]
                    },
                )
            }
        )
        runner(executor=executor).run(pipeline(), original)
        self.assertEqual(original, before)


class VerifierApplicabilityTests(unittest.TestCase):
    """A clean run (nothing to verify) must not fail because the verifier ran dry."""

    def _world_without_candidates(self) -> dict:
        thin = world()
        thin.pop("candidates")
        return thin

    def test_verifier_is_skipped_when_there_are_no_candidates(self) -> None:
        result = runner().run(pipeline(), self._world_without_candidates())
        self.assertIs(result.records["verify"].status, NodeStatus.SKIPPED)
        # SKIPPED counts as satisfied: an inapplicable lane owes no evidence.
        self.assertTrue(result.records["verify"].satisfied)

    def test_skipped_verifier_lets_the_gate_run_and_the_run_is_clean(self) -> None:
        result = runner().run(pipeline(), self._world_without_candidates())
        self.assertIs(result.records["gate"].status, NodeStatus.SUCCEEDED)
        self.assertEqual(result.unsatisfied_mandatory, [])

    def test_managed_node_records_include_the_skipped_verifier(self) -> None:
        # When the runner manages node_records (live flow), the gate must still
        # see a complete record set, including the skipped verifier.
        thin = self._world_without_candidates()
        thin.pop("node_records")
        result = runner().run(pipeline(), thin)
        self.assertIs(result.records["gate"].status, NodeStatus.SUCCEEDED)
        self.assertEqual(result.unsatisfied_mandatory, [])

    def test_a_produced_candidate_still_forces_verification(self) -> None:
        # Skipping applies only when there is genuinely nothing to verify: a
        # candidate produced upstream must still reach the verifier.
        executor = MockExecutor(
            {
                "authz": NodeOutcome(
                    status=NodeStatus.SUCCEEDED,
                    output={"candidates": [{"claim": "x", "location": "l", "why": "w"}]},
                )
            }
        )
        result = runner(executor=executor).run(
            pipeline(), self._world_without_candidates()
        )
        self.assertIs(result.records["verify"].status, NodeStatus.SUCCEEDED)

    def test_failed_upstream_blocks_the_verifier_rather_than_skipping_it(self) -> None:
        # A failed dependency leaves the question unanswered (BLOCKED); it must
        # never be mistaken for an inapplicable lane (SKIPPED), even with no
        # candidates present.
        executor = MockExecutor(
            {"authz": NodeOutcome(status=NodeStatus.FAILED, error="boom")}
        )
        result = runner(executor=executor).run(
            pipeline(), self._world_without_candidates()
        )
        self.assertIs(result.records["verify"].status, NodeStatus.BLOCKED)
        self.assertIn("verify", result.unsatisfied_mandatory)


class ExecutorContractTests(unittest.TestCase):
    def test_executor_exception_fails_the_node_without_killing_the_run(self) -> None:
        class Exploding:
            name = "exploding"

            def execute(self, node, view):
                raise RuntimeError("provider melted")

        result = runner(executor=Exploding()).run(pipeline(), world())
        self.assertIs(result.records["map"].status, NodeStatus.FAILED)
        self.assertIn("provider melted", result.records["map"].error)
        self.assertEqual(len(result.records), 4)

    def test_replay_refuses_to_invent_a_missing_node(self) -> None:
        executor = ReplayExecutor({"map": {"status": "SUCCEEDED", "output": {}}})
        result = runner(executor=executor).run(pipeline(), world())
        self.assertIs(result.records["map"].status, NodeStatus.SUCCEEDED)
        self.assertIs(result.records["authz"].status, NodeStatus.FAILED)
        self.assertIn("no recorded outcome", result.records["authz"].error)

    def test_unmeasured_cost_stays_none_rather_than_zero(self) -> None:
        result = runner().run(pipeline(), world())
        self.assertIsNone(result.records["map"].cost_usd)
        self.assertIsNone(result.records["map"].input_tokens)


if __name__ == "__main__":
    unittest.main()
