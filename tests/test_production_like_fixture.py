from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from evals.production_like_fixture import (
    ORDER_ID,
    REFUND_ID,
    RefundWorkflowStore,
    run_fixture_self_test,
)


class StatefulApplicationFixtureTests(unittest.TestCase):
    def test_self_test_exercises_stateful_multi_persona_contract(self) -> None:
        with TemporaryDirectory() as tmp:
            result = run_fixture_self_test(Path(tmp) / "fixture.sqlite3")

        self.assertEqual(result["status"], "MEASURED")
        self.assertEqual(result["fixture_tier"], "STATEFUL_APPLICATION")
        self.assertTrue(result["properties"]["durable_state"])
        self.assertTrue(result["properties"]["multi_step_workflow"])
        self.assertTrue(result["properties"]["deterministic_reset"])
        self.assertEqual(result["properties"]["auth_personas"], 3)
        self.assertFalse(result["production_effectiveness_established"])
        self.assertFalse(result["arena_full_workflow_measured"])
        self.assertTrue(all(item["passed"] for item in result["checks"]))

    def test_reset_restores_exact_seed_and_removes_workflow_state(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.sqlite3"
            store = RefundWorkflowStore(path)
            store.reset()

            requested = store.request_refund(ORDER_ID, "customer")
            self.assertEqual(requested.status, 201)
            self.assertIsNotNone(store.refund(REFUND_ID))

            store.reset()

            self.assertIsNone(store.refund(REFUND_ID))
            order = store.order_for_persona(ORDER_ID, "customer")
            self.assertIsNotNone(order)
            assert order is not None
            self.assertEqual(order["total_minor"], 5000)

    def test_workflow_roles_and_prerequisites_fail_closed(self) -> None:
        with TemporaryDirectory() as tmp:
            store = RefundWorkflowStore(Path(tmp) / "fixture.sqlite3")
            store.reset()

            self.assertEqual(store.request_refund(ORDER_ID, "finance").status, 403)
            self.assertEqual(store.settle_refund(REFUND_ID, "finance").status, 404)

            self.assertEqual(store.request_refund(ORDER_ID, "customer").status, 201)
            self.assertEqual(store.approve_refund(REFUND_ID, "finance").status, 403)
            self.assertEqual(store.settle_refund(REFUND_ID, "finance").status, 409)

            self.assertEqual(store.approve_refund(REFUND_ID, "reviewer").status, 200)
            self.assertEqual(store.settle_refund(REFUND_ID, "reviewer").status, 403)
            self.assertEqual(store.settle_refund(REFUND_ID, "finance").status, 200)


if __name__ == "__main__":
    unittest.main()
