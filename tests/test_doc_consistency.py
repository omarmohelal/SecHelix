"""The drift gate must catch real drift without firing on ordinary prose.

Both failure modes end the same way. A rule that misses drift guards nothing; a
rule that fires on legitimate sentences gets deleted by whoever it blocks, and
then it also guards nothing.
"""

import tempfile
import unittest
from pathlib import Path

import scripts.check_doc_consistency as checker

FACTS = {
    "gold_packs": 18,
    "fixtures": 38,
    "cases": 76,
    "blind_cases": 76,
    "families": 21,
    "lenses": 26,
    "hypotheses": 546,
    "adapters": 11,
    "schemas": 15,
    "agents": 17,
    "lesson_cards": 11,
}


class RuleTests(unittest.TestCase):
    def _check(self, body):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = checker.ROOT
            checker.ROOT = root
            try:
                doc = root / "doc.md"
                doc.write_text(body, encoding="utf-8")
                return checker.check_document(doc, FACTS)
            finally:
                checker.ROOT = original

    def assertFlagged(self, body):
        self.assertTrue(self._check(body), f"expected a finding for {body!r}")

    def assertClean(self, body):
        self.assertEqual(self._check(body), [], f"unexpected finding for {body!r}")

    def test_correct_counts_pass(self):
        for body in [
            "18 Gold Check Packs ship today.\n",
            "38 paired fixtures cover the suite.\n",
            "76 cases across 10 families.\n",
            "546 structured hypotheses across 21 families × 26 lenses.\n",
            "11 evidence adapters normalize scanner output.\n",
            "15 JSON Schema contracts.\n",
            "17 specialist role profiles.\n",
            "11 lesson cards.\n",
        ]:
            with self.subTest(body):
                self.assertClean(body)

    def test_stale_counts_are_caught(self):
        for body in [
            "12 Gold Check Packs ship today.\n",
            "33 paired fixtures cover the suite.\n",
            "66 cases across 10 families.\n",
            "9 evidence adapters normalize scanner output.\n",
            "7 lesson cards.\n",
        ]:
            with self.subTest(body):
                self.assertFlagged(body)

    def test_the_lens_count_is_checked_not_just_the_family_count(self):
        """CLAUDE.md pins 21 x 26; a wrong lens count used to pass silently."""
        self.assertFlagged("Coverage is 21 families × 20 lenses.\n")
        self.assertClean("Coverage is 21 families × 26 lenses.\n")

    def test_a_product_expression_is_not_read_as_a_hypothesis_total(self):
        """"21 x 26 structured hypothesis catalog" states no total."""
        self.assertClean("- 21 × 26 structured hypothesis catalog;\n")
        self.assertClean("- 21 x 26 structured hypothesis catalog;\n")

    def test_ordinary_prose_about_hypotheses_does_not_fire(self):
        self.assertClean("The reviewer raised 3 hypotheses and refuted two.\n")

    def test_a_declared_snapshot_is_exempt(self):
        stale = "12 Gold Check Packs.\n"
        self.assertFlagged(stale)
        self.assertClean(checker.SNAPSHOT_MARKER + "\n" + stale)


class GroundTruthTests(unittest.TestCase):
    def test_ground_truth_reads_the_real_tree(self):
        facts = checker.ground_truth()
        for key in ("gold_packs", "fixtures", "cases", "families", "lenses",
                    "hypotheses", "adapters", "schemas", "agents", "lesson_cards"):
            self.assertIn(key, facts)
            self.assertGreater(facts[key], 0)

    def test_the_catalog_invariant_holds(self):
        facts = checker.ground_truth()
        self.assertEqual(facts["families"], 21)
        self.assertEqual(facts["lenses"], 26)
        self.assertEqual(facts["hypotheses"], 546)

    def test_every_computed_fact_has_at_least_one_rule(self):
        """A fact nobody checks is a fact that silently drifts."""
        covered = {fact for fact, _ in checker.RULES}
        uncovered = set(checker.ground_truth()) - covered
        self.assertEqual(
            uncovered, {"eval_families"},
            "computed facts must be checked by a rule, or deliberately excluded here",
        )

    def test_the_repository_is_currently_consistent(self):
        self.assertEqual(checker.main([]), 0)


if __name__ == "__main__":
    unittest.main()
