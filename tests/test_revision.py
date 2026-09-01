"""A report must never be presented as describing code it did not inspect."""

import json
import unittest
from pathlib import Path

from sechelix_core.contracts import validate_contract
from sechelix_core.revision import (
    FRESH,
    STALE,
    UNKNOWN_FRESHNESS,
    RevisionError,
    assess_freshness,
    bind_report,
)

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "06ab8ca680d477b8005805d67ab44d11507e3321"
OTHER = "a7f1f4799234c5410c872a54de18f3dbbcc316cc"


def bound(**kwargs):
    report = {"schema_version": "1.0"}
    defaults = {"repository": "omarmohelal/example", "commit": COMMIT}
    defaults.update(kwargs)
    return bind_report(report, **defaults)


class BindingTests(unittest.TestCase):
    def test_binding_records_the_tree(self):
        report = bound(branch="main")
        revision = report["target_revision"]
        self.assertEqual(revision["commit"], COMMIT)
        self.assertEqual(revision["working_tree"], "CLEAN")
        self.assertEqual(revision["branch"], "main")

    def test_a_non_hex_commit_is_refused(self):
        with self.assertRaises(RevisionError):
            bound(commit="not-a-sha")

    def test_an_invalid_working_tree_state_is_refused(self):
        with self.assertRaises(RevisionError):
            bound(working_tree="PROBABLY_FINE")

    def test_bound_report_satisfies_the_contract(self):
        report = json.loads((ROOT / "examples/report.example.json").read_text(encoding="utf-8"))
        bind_report(report, repository="omarmohelal/gamingops-store", commit=COMMIT, branch="main")
        validate_contract("report", report)


class FreshnessTests(unittest.TestCase):
    def test_same_commit_is_fresh(self):
        verdict = assess_freshness(bound(), current_commit=COMMIT)
        self.assertEqual(verdict.state, FRESH)
        self.assertTrue(verdict.usable)

    def test_short_and_long_sha_still_match(self):
        verdict = assess_freshness(bound(commit=COMMIT[:12]), current_commit=COMMIT)
        self.assertEqual(verdict.state, FRESH)

    def test_different_commit_is_stale(self):
        verdict = assess_freshness(bound(), current_commit=OTHER)
        self.assertEqual(verdict.state, STALE)
        self.assertFalse(verdict.usable)
        self.assertIn("06ab8ca680d4", verdict.reason)

    def test_a_dirty_report_tree_is_stale_immediately(self):
        """A commit does not describe a tree that had uncommitted edits."""
        report = bound(working_tree="DIRTY", dirty_paths=["src/auth.py"])
        verdict = assess_freshness(report, current_commit=COMMIT)
        self.assertEqual(verdict.state, STALE)
        self.assertIn("dirty working tree", verdict.reason)

    def test_a_dirty_current_tree_is_stale(self):
        verdict = assess_freshness(bound(), current_commit=COMMIT, current_working_tree="DIRTY")
        self.assertEqual(verdict.state, STALE)
        self.assertIn("uncommitted changes", verdict.reason)

    def test_missing_revision_is_unknown_not_fresh(self):
        verdict = assess_freshness({"schema_version": "1.0"}, current_commit=COMMIT)
        self.assertEqual(verdict.state, UNKNOWN_FRESHNESS)
        self.assertFalse(verdict.usable, "unknown freshness must never read as usable")

    def test_missing_current_commit_is_unknown_not_fresh(self):
        verdict = assess_freshness(bound())
        self.assertEqual(verdict.state, UNKNOWN_FRESHNESS)
        self.assertFalse(verdict.usable)

    def test_posture_changes_are_named_in_the_reason(self):
        verdict = assess_freshness(
            bound(), current_commit=OTHER,
            changed_paths=["README.md", "next.config.ts", ".github/workflows/ci.yml"],
        )
        self.assertEqual(verdict.state, STALE)
        self.assertIn("next.config.ts", verdict.posture_changed)
        self.assertIn(".github/workflows/ci.yml", verdict.posture_changed)
        self.assertNotIn("README.md", verdict.posture_changed)
        self.assertIn("security-posture", verdict.reason)

    def test_only_fresh_is_usable(self):
        for state_report, current in [
            (bound(), COMMIT),                                   # FRESH
            (bound(), OTHER),                                    # STALE
            ({"schema_version": "1.0"}, COMMIT),                 # UNKNOWN
        ]:
            verdict = assess_freshness(state_report, current_commit=current)
            self.assertEqual(verdict.usable, verdict.state == FRESH)


class GateIntegrationTests(unittest.TestCase):
    """The release gate must refuse a report that describes another tree."""

    def _report(self, commit):
        report = json.loads((ROOT / "examples/report.example.json").read_text(encoding="utf-8"))
        return bind_report(report, repository="omarmohelal/example", commit=commit)

    def test_matching_revision_passes(self):
        import scripts.security_gate as gate
        policy = json.loads((ROOT / "policies/default.json").read_text(encoding="utf-8"))
        verdict = assess_freshness(self._report(COMMIT), current_commit=COMMIT)
        self.assertTrue(verdict.usable)
        decision = gate.evaluate(self._report(COMMIT), policy)
        self.assertEqual(decision.exit_code, 0)

    def test_mismatched_revision_is_not_usable(self):
        verdict = assess_freshness(self._report(COMMIT), current_commit=OTHER)
        self.assertFalse(verdict.usable)
        self.assertEqual(verdict.state, STALE)


if __name__ == "__main__":
    unittest.main()
