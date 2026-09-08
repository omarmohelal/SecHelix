from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "references" / "ai-built-app-launch.md"
PORTABLE_PROFILE = ROOT / "skills" / "sechelix" / "references" / "ai-built-app-launch.md"
CATALOG = ROOT / "catalog" / "checks.json"


class AiBuiltLaunchProfileTests(unittest.TestCase):
    def test_profile_contains_exactly_checks_01_through_36(self) -> None:
        text = PROFILE.read_text(encoding="utf-8")
        ids = re.findall(r"^\| (\d{2}) \|", text, flags=re.MULTILINE)
        self.assertEqual(ids, [f"{n:02d}" for n in range(1, 37)])

    def test_profile_uses_known_catalog_families(self) -> None:
        text = PROFILE.read_text(encoding="utf-8")
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        known = {family["id"] for family in catalog["families"]}

        rows = [line for line in text.splitlines() if re.match(r"^\| \d{2} \|", line)]
        self.assertEqual(len(rows), 36)
        for row in rows:
            family_cell = row.split("|")[3]
            used = set(re.findall(r"`([A-Z]+)`", family_cell))
            self.assertTrue(used, row)
            self.assertFalse(used - known, f"unknown family ids in row: {row}")

    def test_portable_skill_mirror_matches_canonical_profile(self) -> None:
        self.assertEqual(
            PROFILE.read_text(encoding="utf-8"),
            PORTABLE_PROFILE.read_text(encoding="utf-8"),
        )

    def test_profile_keeps_evidence_gated_result_contract(self) -> None:
        text = PROFILE.read_text(encoding="utf-8")
        for token in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE", "BLOCKED"):
            self.assertIn(f"`{token}`", text)
        self.assertIn("Do not mark a launch check PASS", text)
        self.assertIn("AUDIT", text)
        self.assertIn("FIX", text)
        self.assertIn("VERIFY", text)
        self.assertIn("RE-RUN", text)


if __name__ == "__main__":
    unittest.main()
