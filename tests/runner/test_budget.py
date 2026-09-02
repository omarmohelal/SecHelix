import unittest

from sechelix_runner.budget import (
    BudgetExceeded,
    BudgetGovernor,
    BudgetLimits,
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


if __name__ == "__main__":
    unittest.main()
