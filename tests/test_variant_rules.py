"""A generated rule must never inherit the verification or severity of its seed."""

import unittest

from sechelix_core.variant_rules import (
    UNVALIDATED,
    VariantRuleError,
    generate_rule,
    generate_rules,
    infer_language,
)

PATTERNS = ["db.get($ID)", "session.query($M).get($ID)"]


def seed(fid="SHX-F-1", status="VERIFIED", **extra):
    base = {
        "finding_id": fid,
        "title": "Report lookup omits the tenant predicate",
        "status": status,
        "severity": "CRITICAL",
        "affected_surface": ["app/reports.py:41"],
        "remediation": {"root_cause_fix": "Scope the lookup by the session tenant.",
                        "evidence_ids": ["EV-001"]},
    }
    base.update(extra)
    return base


class GatingTests(unittest.TestCase):
    def test_a_verified_finding_seeds_a_rule(self):
        rule = generate_rule(seed(), PATTERNS)
        self.assertEqual(rule.seed_finding_id, "SHX-F-1")
        self.assertEqual(rule.language, "python")
        self.assertEqual(rule.status, UNVALIDATED)

    def test_an_unverified_seed_is_refused(self):
        with self.assertRaises(VariantRuleError) as ctx:
            generate_rule(seed(status="HYPOTHESIS"), PATTERNS)
        self.assertIn("propagate a guess", str(ctx.exception))

    def test_a_rule_needs_at_least_one_pattern(self):
        with self.assertRaises(VariantRuleError):
            generate_rule(seed(), [])

    def test_blank_patterns_do_not_count(self):
        with self.assertRaises(VariantRuleError):
            generate_rule(seed(), ["  ", ""])

    def test_an_undeterminable_language_is_refused(self):
        with self.assertRaises(VariantRuleError) as ctx:
            generate_rule(seed(affected_surface=["config/settings.conf"]), PATTERNS)
        self.assertIn("matches nothing", str(ctx.exception))


class HonestyTests(unittest.TestCase):
    def test_rule_severity_is_not_inherited_from_the_seed(self):
        """The seed is CRITICAL; a syntactic match has earned none of that."""
        rule = generate_rule(seed(), PATTERNS)
        emitted = rule.as_semgrep()["rules"][0]
        self.assertEqual(emitted["severity"], "INFO")

    def test_a_hit_is_a_hypothesis(self):
        emitted = generate_rule(seed(), PATTERNS).as_semgrep()["rules"][0]
        self.assertEqual(emitted["metadata"]["claim_status"], "HYPOTHESIS")
        self.assertEqual(emitted["metadata"]["confidence"], "LOW")

    def test_a_generated_rule_is_unvalidated_until_run(self):
        emitted = generate_rule(seed(), PATTERNS).as_semgrep()["rules"][0]
        self.assertEqual(emitted["metadata"]["sechelix_rule_status"], UNVALIDATED)

    def test_the_message_tells_the_reader_it_is_unconfirmed(self):
        rule = generate_rule(seed(), PATTERNS)
        self.assertIn("unverified candidate", rule.message)

    def test_the_rule_cites_its_seed(self):
        emitted = generate_rule(seed(), PATTERNS).as_semgrep()["rules"][0]
        self.assertEqual(emitted["metadata"]["sechelix_seed_finding"], "SHX-F-1")


class LanguageTests(unittest.TestCase):
    def test_language_is_inferred_from_the_surface_extension(self):
        for surface, expected in [
            ("app/routes.ts:10", "typescript"),
            ("src/main.go:4", "go"),
            ("lib/User.java:88", "java"),
            ("app/x.rb:1", "ruby"),
        ]:
            with self.subTest(surface):
                self.assertEqual(infer_language(seed(affected_surface=[surface])), expected)

    def test_a_declared_language_wins(self):
        self.assertEqual(infer_language(seed(language="TypeScript")), "typescript")

    def test_an_unknown_extension_infers_nothing(self):
        self.assertIsNone(infer_language(seed(affected_surface=["a/b.zzz"])))


class BatchTests(unittest.TestCase):
    def test_seeds_without_patterns_are_refused_not_guessed(self):
        result = generate_rules([seed()], {})
        self.assertEqual(result["generated_count"], 0)
        self.assertIn("match this incident", result["refusals"][0]["refused_because"])

    def test_unverified_seeds_are_refused_with_reasons(self):
        result = generate_rules(
            [seed("SHX-F-1"), seed("SHX-F-2", status="LIKELY_BUT_UNPROVEN")],
            {"SHX-F-1": PATTERNS, "SHX-F-2": PATTERNS},
        )
        self.assertEqual(result["generated_count"], 1)
        self.assertEqual(result["refused_count"], 1)
        self.assertEqual(result["refusals"][0]["seed_finding_id"], "SHX-F-2")

    def test_the_batch_states_that_rules_under_match(self):
        notes = " ".join(generate_rules([seed()], {"SHX-F-1": PATTERNS})["notes"])
        self.assertIn("under-match", notes)
        self.assertIn("HYPOTHESIS", notes)


if __name__ == "__main__":
    unittest.main()
