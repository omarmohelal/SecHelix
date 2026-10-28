"""Tests for shaping normalized scanner records into verifier candidates."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sechelix_runner.candidate_seed import (
    SeedError,
    candidate_from_record,
    candidates_from_payload,
    load_seed_candidates,
)
from sechelix_runner.providers.reasoning import FORBIDDEN_VERIFIER_FIELDS, verifier_view

_REC = {
    "claim": "GHSA-DEMO-0001 reported for demo-package",
    "location": {"path": "package-lock.json"},
    "rule_id": "GHSA-DEMO-0001",
    "source": {"tool": "osv", "type": "dependency-analysis"},
    "observations": ["Demonstration advisory"],
    "evidence_id": "obs:399360e60bce60ed6ba1da40",
    "severity": "UNASSESSED",
    "assessment": "UNASSESSED",
    "tool_signal": {"severity": "CRITICAL", "trusted_for_assessment": False},
}


class MapTests(unittest.TestCase):
    def test_basic_mapping(self) -> None:
        c = candidate_from_record(_REC)
        self.assertEqual(c["claim"], _REC["claim"])
        self.assertEqual(c["location"], "package-lock.json")
        self.assertIn("reported by osv", c["why"])
        self.assertIn("rule GHSA-DEMO-0001", c["why"])
        self.assertEqual(c["scanner"], "osv")
        self.assertEqual(c["rule_id"], "GHSA-DEMO-0001")
        # The adapter's observation id must NOT ride along: it is not a registered
        # SecHelix evidence id, and the verifier citing it would fail the binding.
        self.assertNotIn("evidence_id", c)

    def test_scanner_severity_never_carried(self) -> None:
        c = candidate_from_record(_REC)
        self.assertNotIn("severity", c)
        self.assertNotIn("tool_signal", c)
        self.assertNotIn("assessment", c)
        # And nothing the verifier is forbidden to see survives into its view.
        view = verifier_view(c)
        for forbidden in FORBIDDEN_VERIFIER_FIELDS:
            self.assertNotIn(forbidden, view)

    def test_location_with_line(self) -> None:
        c = candidate_from_record({**_REC, "location": {"path": "app.py", "line": 42}})
        self.assertEqual(c["location"], "app.py:42")

    def test_string_location(self) -> None:
        c = candidate_from_record({**_REC, "location": "auth.py:10"})
        self.assertEqual(c["location"], "auth.py:10")

    def test_missing_claim_fails_closed(self) -> None:
        with self.assertRaises(SeedError):
            candidate_from_record({**_REC, "claim": "  "})

    def test_missing_location_fails_closed(self) -> None:
        with self.assertRaises(SeedError):
            candidate_from_record({**_REC, "location": {}})


class PayloadTests(unittest.TestCase):
    def test_adapter_envelope(self) -> None:
        cands = candidates_from_payload({"adapter": "osv", "records": [_REC], "trust_boundary": "x"})
        self.assertEqual(len(cands), 1)

    def test_bare_list(self) -> None:
        self.assertEqual(len(candidates_from_payload([_REC, _REC])), 2)

    def test_candidates_key(self) -> None:
        self.assertEqual(len(candidates_from_payload({"candidates": [_REC]})), 1)

    def test_empty_fails_closed(self) -> None:
        with self.assertRaises(SeedError):
            candidates_from_payload({"records": []})

    def test_non_list_fails_closed(self) -> None:
        with self.assertRaises(SeedError):
            candidates_from_payload("nope")


class LoadTests(unittest.TestCase):
    def test_roundtrip_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "osv.json"
            p.write_text(json.dumps({"records": [_REC]}), encoding="utf-8")
            cands = load_seed_candidates(p)
        self.assertEqual(cands[0]["location"], "package-lock.json")

    def test_bad_json_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text("{not json", encoding="utf-8")
            with self.assertRaises(SeedError):
                load_seed_candidates(p)

    def test_missing_file_fails_closed(self) -> None:
        with self.assertRaises(SeedError):
            load_seed_candidates("/nonexistent/seed/file.json")


if __name__ == "__main__":
    unittest.main()
