import json
import unittest

from sechelix_runner.budget import (
    BudgetExceeded,
    BudgetGovernor,
    BudgetLimits,
    BudgetUnenforceable,
    LIMIT_NAMES,
)


class BudgetAccountingTests(unittest.TestCase):
    def test_unset_limit_is_unlimited_not_zero(self) -> None:
        governor = BudgetGovernor(BudgetLimits())
        self.assertEqual(governor.remaining("max_cost_usd"), float("inf"))
        self.assertTrue(governor.can_afford("max_cost_usd", 10**9))

    def test_zero_limit_admits_nothing(self) -> None:
        governor = BudgetGovernor(BudgetLimits(max_cost_usd=0.0))
        with self.assertRaises(BudgetExceeded):
            governor.reserve("max_cost_usd", 0.01, "node")

    def test_settle_converts_reservation_into_actual_spend(self) -> None:
        governor = BudgetGovernor(BudgetLimits(max_cost_usd=1.0))
        governor.reserve("max_cost_usd", 0.60, "a")
        governor.settle("max_cost_usd", 0.60, 0.55)
        self.assertAlmostEqual(governor.actual("max_cost_usd"), 0.55)
        self.assertAlmostEqual(governor.reserved("max_cost_usd"), 0.0)

    def test_reservation_closes_the_double_admission_hole(self) -> None:
        """Two nodes that each fit the remainder must not both be admitted."""
        governor = BudgetGovernor(BudgetLimits(max_cost_usd=1.0))
        governor.reserve("max_cost_usd", 0.60, "a")
        with self.assertRaises(BudgetExceeded):
            governor.reserve("max_cost_usd", 0.60, "b")

    def test_release_returns_an_unused_reservation(self) -> None:
        governor = BudgetGovernor(BudgetLimits(max_cost_usd=1.0))
        governor.reserve("max_cost_usd", 0.60, "a")
        governor.release("max_cost_usd", 0.60)
        governor.reserve("max_cost_usd", 0.60, "b")

    def test_release_never_goes_negative(self) -> None:
        governor = BudgetGovernor(BudgetLimits(max_cost_usd=1.0))
        governor.release("max_cost_usd", 5.0)
        self.assertEqual(governor.reserved("max_cost_usd"), 0.0)

    def test_estimates_do_not_gate_admission(self) -> None:
        governor = BudgetGovernor(BudgetLimits(max_cost_usd=1.0))
        governor.estimate("max_cost_usd", 100.0)
        governor.reserve("max_cost_usd", 0.5, "a")
        self.assertEqual(governor.estimated("max_cost_usd"), 100.0)


class BudgetRecordTests(unittest.TestCase):
    def test_every_refusal_is_recorded(self) -> None:
        governor = BudgetGovernor(BudgetLimits(max_verifiers=1))
        governor.reserve("max_verifiers", 1, "v1")
        with self.assertRaises(BudgetExceeded):
            governor.reserve("max_verifiers", 1, "v2")
        self.assertEqual(len(governor.refusals), 1)
        self.assertEqual(governor.refusals[0].node_id, "v2")

    def test_exhausted_flag_is_sticky(self) -> None:
        governor = BudgetGovernor(BudgetLimits(max_nodes=0))
        self.assertFalse(governor.exhausted)
        with self.assertRaises(BudgetExceeded):
            governor.reserve("max_nodes", 1, "a")
        self.assertTrue(governor.exhausted)

    def test_snapshot_covers_every_limit(self) -> None:
        snapshot = BudgetGovernor(BudgetLimits()).snapshot()
        for name in LIMIT_NAMES:
            self.assertIn(name, snapshot["usage"])
            self.assertIn(name, snapshot["limits"])

    def test_snapshot_distinguishes_unlimited_from_zero_remaining(self) -> None:
        snapshot = BudgetGovernor(BudgetLimits(max_cost_usd=None)).snapshot()
        self.assertIsNone(snapshot["usage"]["max_cost_usd"]["remaining"])


class UnknownCostTests(unittest.TestCase):
    """Spend the governor cannot see must still be bounded or refused."""

    def test_zero_estimate_needs_headroom_when_asked(self) -> None:
        governor = BudgetGovernor(BudgetLimits(max_cost_usd=0.50))
        governor.spend("max_cost_usd", 0.50)
        governor.reserve("max_cost_usd", 0.0, "free")  # a known-free node still runs
        with self.assertRaises(BudgetExceeded):
            governor.reserve("max_cost_usd", 0.0, "unknown", require_headroom=True)

    def test_headroom_is_irrelevant_without_a_limit(self) -> None:
        BudgetGovernor().reserve("max_cost_usd", 0.0, "n", require_headroom=True)

    def test_unmeasured_spend_charges_the_reservation(self) -> None:
        governor = BudgetGovernor(BudgetLimits(max_cost_usd=1.0))
        governor.reserve("max_cost_usd", 0.30, "a")
        governor.settle_unmeasured("max_cost_usd", 0.30, "a")
        self.assertAlmostEqual(governor.actual("max_cost_usd"), 0.30)
        self.assertAlmostEqual(governor.reserved("max_cost_usd"), 0.0)
        self.assertIn("charged the reserved estimate", governor.decisions[-1].reason)
        self.assertIsNone(governor.unenforceable("max_cost_usd"))

    def test_unmeasured_spend_with_nothing_reserved_refuses_all_later_work(self) -> None:
        governor = BudgetGovernor(BudgetLimits(max_cost_usd=100.0))
        governor.reserve("max_cost_usd", 0.0, "a", require_headroom=True)
        governor.settle_unmeasured("max_cost_usd", 0.0, "a")
        self.assertIsNotNone(governor.unenforceable("max_cost_usd"))
        # Even a tiny, explicitly estimated node: the true remainder is unknown.
        with self.assertRaises(BudgetUnenforceable) as caught:
            governor.reserve("max_cost_usd", 0.01, "b")
        self.assertIn("max_cost_usd", str(caught.exception))
        self.assertTrue(governor.exhausted)
        self.assertFalse(governor.decisions[-1].admitted)

    def test_unenforceable_is_a_budget_refusal_the_runner_already_handles(self) -> None:
        self.assertTrue(issubclass(BudgetUnenforceable, BudgetExceeded))

    def test_resume_cannot_lift_an_unenforceable_limit(self) -> None:
        limits = BudgetLimits(max_cost_usd=100.0)
        first = BudgetGovernor(limits)
        first.settle_unmeasured("max_cost_usd", 0.0, "a")
        snapshot = json.loads(json.dumps(first.snapshot()))  # as a checkpoint stores it
        resumed = BudgetGovernor(limits)
        resumed.restore(snapshot)
        with self.assertRaises(BudgetUnenforceable):
            resumed.reserve("max_cost_usd", 0.01, "b")

    def test_checkpoints_from_before_this_state_still_restore(self) -> None:
        limits = BudgetLimits(max_cost_usd=1.0)
        snapshot = BudgetGovernor(limits).snapshot()
        del snapshot["unenforceable"]
        BudgetGovernor(limits).restore(snapshot)

    def test_malformed_unenforceable_state_is_refused(self) -> None:
        limits = BudgetLimits(max_cost_usd=1.0)
        snapshot = BudgetGovernor(limits).snapshot()
        snapshot["unenforceable"] = {"not_a_limit": "x"}
        with self.assertRaises(ValueError):
            BudgetGovernor(limits).restore(snapshot)


if __name__ == "__main__":
    unittest.main()
