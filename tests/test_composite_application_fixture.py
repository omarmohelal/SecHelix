from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from evals.composite_application_fixture import (
    CompositeStore,
    EVENT_ID,
    run_composite_self_test,
)


class CompositeApplicationFixtureTests(unittest.TestCase):
    def test_self_test_proves_two_service_async_fixture_contract(self) -> None:
        with TemporaryDirectory() as tmp:
            result = run_composite_self_test(Path(tmp) / "fixture.sqlite3")

        self.assertEqual(result["status"], "MEASURED")
        self.assertEqual(result["fixture_tier"], "COMPOSITE_APPLICATION")
        self.assertEqual(result["properties"]["service_count"], 2)
        self.assertTrue(result["properties"]["async_boundary"])
        self.assertTrue(result["properties"]["durable_state"])
        self.assertTrue(result["properties"]["deterministic_reset"])
        self.assertFalse(result["production_effectiveness_established"])
        self.assertFalse(result["arena_full_workflow_measured"])
        self.assertTrue(all(check["passed"] for check in result["checks"]))

    def test_outbox_boundary_applies_financial_effect_once(self) -> None:
        with TemporaryDirectory() as tmp:
            store = CompositeStore(Path(tmp) / "fixture.sqlite3")
            store.reset()

            self.assertEqual(store.request_refund("customer").status, 201)
            self.assertEqual(store.approve_refund("reviewer").status, 200)
            self.assertEqual(store.queue_settlement("finance").status, 202)

            before = store.snapshot()
            self.assertEqual(before["event_status"], "PENDING")
            self.assertEqual(before["ledger_entry_count"], 0)

            self.assertEqual(store.consume_one().status, 200)
            once = store.snapshot()
            self.assertEqual(once["event_status"], "CONSUMED")
            self.assertEqual(once["ledger_entry_count"], 1)
            self.assertEqual(once["ledger_total_minor"], 5000)

            self.assertEqual(store.consume_one().status, 204)
            twice = store.snapshot()
            self.assertEqual(twice["ledger_entry_count"], 1)
            self.assertEqual(twice["ledger_total_minor"], 5000)

    def test_reset_clears_outbox_and_ledger(self) -> None:
        with TemporaryDirectory() as tmp:
            store = CompositeStore(Path(tmp) / "fixture.sqlite3")
            store.reset()
            store.request_refund("customer")
            store.approve_refund("reviewer")
            store.queue_settlement("finance")
            self.assertEqual(store.snapshot()["event_status"], "PENDING")

            store.reset()
            snapshot = store.snapshot()
            self.assertIsNone(snapshot["refund_status"])
            self.assertIsNone(snapshot["event_status"])
            self.assertEqual(snapshot["ledger_entry_count"], 0)
            self.assertEqual(snapshot["ledger_total_minor"], 0)


if __name__ == "__main__":
    unittest.main()
