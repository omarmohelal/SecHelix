from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from evals.fixture_tiers import (
    FixtureTierError,
    SCHEMA_VERSION,
    summarize_registry,
    validate_registry,
)


ROOT = Path(__file__).resolve().parents[1]


class FixtureTierRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = json.loads(
            (ROOT / "evals" / "fixture-tiers.json").read_text(encoding="utf-8")
        )

    def test_repository_registry_is_valid_and_never_claims_production_effectiveness(self) -> None:
        validated = validate_registry(self.registry)
        summary = summarize_registry(validated)

        self.assertEqual(validated["schema_version"], SCHEMA_VERSION)
        self.assertGreaterEqual(summary["benchmark_count"], 4)
        self.assertFalse(summary["production_effectiveness_established"])
        self.assertEqual(summary["highest_declared_tier"], "COMPOSITE_APPLICATION")
        self.assertNotEqual(summary["highest_measured_tier"], "COMPOSITE_APPLICATION")

    def test_stateful_tier_requires_durable_multi_step_reset_and_two_personas(self) -> None:
        broken = copy.deepcopy(self.registry)
        item = next(
            row
            for row in broken["benchmarks"]
            if row["tier"] == "STATEFUL_APPLICATION"
        )
        item["properties"]["auth_personas"] = 1

        with self.assertRaises(FixtureTierError) as ctx:
            validate_registry(broken)
        self.assertIn("auth_personas", str(ctx.exception))

    def test_composite_tier_requires_async_boundary_and_multiple_services(self) -> None:
        broken = copy.deepcopy(self.registry)
        item = next(
            row
            for row in broken["benchmarks"]
            if row["tier"] == "COMPOSITE_APPLICATION"
        )
        item["properties"]["async_boundary"] = False

        with self.assertRaises(FixtureTierError) as ctx:
            validate_registry(broken)
        self.assertIn("async_boundary", str(ctx.exception))

        broken = copy.deepcopy(self.registry)
        item = next(
            row
            for row in broken["benchmarks"]
            if row["tier"] == "COMPOSITE_APPLICATION"
        )
        item["properties"]["service_count"] = 1

        with self.assertRaises(FixtureTierError) as ctx:
            validate_registry(broken)
        self.assertIn("service_count", str(ctx.exception))

    def test_browser_tier_cannot_be_claimed_without_real_browser(self) -> None:
        broken = copy.deepcopy(self.registry)
        item = next(
            row
            for row in broken["benchmarks"]
            if row["benchmark_id"] == "real-browser-xss"
        )
        item["properties"]["real_browser"] = False

        with self.assertRaises(FixtureTierError) as ctx:
            validate_registry(broken)
        self.assertIn("real_browser", str(ctx.exception))

    def test_duplicate_ids_and_path_escape_fail_closed(self) -> None:
        broken = copy.deepcopy(self.registry)
        broken["benchmarks"][1]["benchmark_id"] = broken["benchmarks"][0]["benchmark_id"]
        with self.assertRaises(FixtureTierError):
            validate_registry(broken)

        broken = copy.deepcopy(self.registry)
        broken["benchmarks"][0]["runner"] = "../outside.py"
        with self.assertRaises(FixtureTierError):
            validate_registry(broken)

    def test_scope_note_must_disclaim_production_claims(self) -> None:
        broken = copy.deepcopy(self.registry)
        broken["scope_note"] = "Fixture tier registry."
        with self.assertRaises(FixtureTierError) as ctx:
            validate_registry(broken)
        self.assertIn("production", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
