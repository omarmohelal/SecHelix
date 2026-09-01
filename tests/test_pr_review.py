"""PR bot mode: say something only when it matters, and never oversell it."""

import unittest

from sechelix_core.diff_review import NEW_RISK, review_diff
from sechelix_core.pr_review import (
    BASE_REPORT,
    BLOCKED,
    DEGRADED,
    FAVOURABILITY,
    HEAD_REPORT,
    INCOMPLETE,
    MAX_ROWS,
    NO_REPORT,
    PASS,
    PASS_WITH_KNOWN_RISK,
    RELEASE_OUTCOMES,
    UNADDRESSED,
    PullRequestReviewError,
    render_comment,
    review_pull_request,
    worst,
)


def diff(path: str, added=None, removed=None) -> str:
    body = [f"diff --git a/{path} b/{path}", f"--- a/{path}", f"+++ b/{path}", "@@ -1,3 +1,4 @@"]
    body += [f"-{line}" for line in (removed or [])]
    body += [f"+{line}" for line in (added or [])]
    return "\n".join(body) + "\n"


NEW_ROUTE = diff("api/orders.py", added=["@app.get('/orders/<order_id>')"])
TYPO = diff("README.md", added=["Fixed a typo in the introduction."])
ADDED_HEADER = diff("next.config.ts", added=["  'X-Frame-Options': 'DENY',"])


def coverage(**overrides):
    base = {
        "catalog_version": "2.0",
        "APPLICABLE": 120,
        "NOT_APPLICABLE": 380,
        "UNKNOWN": 40,
        "BLOCKED": 6,
        "TOTAL": 546,
        "integrity_critical_unknown": 0,
    }
    base.update(overrides)
    return base


def finding(fid="SHX-F-1", status="VERIFIED", surface="api/orders.py:41", **extra):
    base = {
        "finding_id": fid,
        "title": "Order lookup omits the tenant predicate",
        "status": status,
        "severity": "HIGH",
        "resolution": "OPEN",
        "affected_surface": [surface],
    }
    base.update(extra)
    return base


def report(findings=None, **overrides):
    base = {
        "schema_version": "1.0",
        "report_id": "SHX-R-1",
        "coverage": coverage(),
        "findings": list(findings or []),
        # Deliberately favourable, and deliberately never read.
        "release_recommendation": {"decision": "PASS"},
    }
    base.update(overrides)
    return base


class MaterialityTests(unittest.TestCase):
    """A bot that comments on every pull request gets muted, and protects nothing."""

    def test_a_typo_produces_no_comment(self):
        review = review_pull_request(TYPO, report=report(), gate_decision=PASS)
        self.assertTrue(review.nothing_to_say)
        self.assertIsNone(review.comment)
        self.assertIsNone(review.as_dict()["comment"])
        self.assertIn("no NEW_RISK", review.suppressed_because)

    def test_an_empty_diff_produces_no_comment(self):
        review = review_pull_request("", report=report(), gate_decision=PASS)
        self.assertTrue(review.nothing_to_say)
        self.assertEqual(review.materiality_reasons, ())

    def test_adding_a_control_alone_is_not_material(self):
        """A risk reduction leaves the reviewer nothing to do."""
        review = review_pull_request(ADDED_HEADER, report=report(), gate_decision=PASS)
        self.assertTrue(review.nothing_to_say)
        self.assertEqual(review.security_delta["counts"]["RISK_REDUCED"], 1)

    def test_a_new_risk_is_material(self):
        review = review_pull_request(NEW_ROUTE, report=report(), gate_decision=PASS)
        self.assertTrue(review.material)
        self.assertIn("NEW_HYPOTHESIS", review.materiality_reasons)
        self.assertIsNotNone(review.comment)

    def test_a_diff_that_cannot_be_parsed_is_material(self):
        """Silence on an unreadable diff would be silence on an unanalyzed change."""
        review = review_pull_request("this is not a diff", report=report(), gate_decision=PASS)
        self.assertIn("UNREADABLE_DIFF", review.materiality_reasons)
        self.assertEqual(review.decision.outcome, INCOMPLETE)

    def test_a_newly_verified_finding_is_material(self):
        review = review_pull_request(
            TYPO,
            prior_report=report([finding(status="HYPOTHESIS")]),
            report=report([finding(status="VERIFIED")]),
            gate_decision=BLOCKED,
        )
        self.assertIn("NEW_VERIFIED_FINDING", review.materiality_reasons)

    def test_a_refuted_candidate_is_material(self):
        review = review_pull_request(
            TYPO,
            prior_report=report([finding(status="HYPOTHESIS")]),
            report=report([finding(status="FALSE_POSITIVE")]),
            gate_decision=PASS,
        )
        self.assertIn("CANDIDATE_REFUTED", review.materiality_reasons)

    def test_degraded_coverage_is_material(self):
        review = review_pull_request(
            TYPO,
            prior_report=report(),
            report=report(coverage=coverage(UNKNOWN=70, APPLICABLE=90)),
            gate_decision=PASS,
        )
        self.assertIn("COVERAGE_DEGRADED", review.materiality_reasons)
        self.assertEqual(review.coverage_change["state"], DEGRADED)

    def test_improved_coverage_alone_is_not_material(self):
        review = review_pull_request(
            TYPO,
            prior_report=report(),
            report=report(coverage=coverage(UNKNOWN=10, APPLICABLE=150)),
            gate_decision=PASS,
        )
        self.assertTrue(review.nothing_to_say)
        self.assertEqual(review.coverage_change["state"], "IMPROVED")

    def test_a_changed_decision_is_material(self):
        review = review_pull_request(TYPO, report=report(), gate_decision=BLOCKED,
                                     prior_decision=PASS)
        self.assertIn("DECISION_CHANGED", review.materiality_reasons)

    def test_an_unchanged_decision_alone_is_not_material(self):
        review = review_pull_request(TYPO, report=report(), gate_decision=PASS,
                                     prior_decision=PASS)
        self.assertTrue(review.nothing_to_say)

    def test_silence_never_upgrades_the_decision(self):
        """Nothing to say is not an approval."""
        review = review_pull_request(TYPO)
        self.assertTrue(review.nothing_to_say)
        self.assertEqual(review.decision.outcome, INCOMPLETE)
        self.assertEqual(review.evidence_basis, NO_REPORT)

    def test_every_materiality_reason_is_explained_in_the_output(self):
        review = review_pull_request(NEW_ROUTE, report=report(), gate_decision=PASS)
        for entry in review.as_dict()["materiality_reasons"]:
            self.assertTrue(entry["explanation"])


class DecisionTests(unittest.TestCase):
    """The decision may never be more favourable than the evidence behind it."""

    def test_unverified_new_risk_is_incomplete_not_pass(self):
        review = review_pull_request(NEW_ROUTE, report=report(), gate_decision=PASS)
        self.assertEqual(review.decision.outcome, INCOMPLETE)
        self.assertIn("not looking is not a pass", " ".join(review.decision.reasons))

    def test_no_gate_decision_is_incomplete(self):
        """A report's own release_recommendation is not evidence."""
        review = review_pull_request(ADDED_HEADER, report=report())
        self.assertEqual(review.decision.outcome, INCOMPLETE)
        self.assertIn("release_recommendation", " ".join(review.decision.reasons))

    def test_no_report_is_incomplete(self):
        review = review_pull_request(ADDED_HEADER, gate_decision=PASS)
        self.assertEqual(review.decision.outcome, INCOMPLETE)

    def test_a_report_about_the_base_tree_does_not_describe_this_change(self):
        review = review_pull_request(ADDED_HEADER, prior_report=report(), gate_decision=PASS)
        self.assertEqual(review.decision.outcome, INCOMPLETE)
        self.assertEqual(review.evidence_basis, BASE_REPORT)
        self.assertIn("pre-change tree", " ".join(review.decision.reasons))

    def test_a_report_bound_to_another_commit_is_incomplete(self):
        bound = report(target_revision={
            "repository": "x", "commit": "a" * 40, "working_tree": "CLEAN",
        })
        review = review_pull_request(ADDED_HEADER, report=bound, gate_decision=PASS,
                                     head_commit="b" * 40)
        self.assertEqual(review.decision.outcome, INCOMPLETE)
        self.assertIn("not bound to this change", " ".join(review.decision.reasons))

    def test_a_clean_change_with_full_evidence_passes(self):
        bound = report(target_revision={
            "repository": "x", "commit": "c" * 40, "working_tree": "CLEAN",
        })
        review = review_pull_request(ADDED_HEADER, report=bound, gate_decision=PASS,
                                     head_commit="c" * 40)
        self.assertEqual(review.decision.outcome, PASS)

    def test_the_gate_outcome_is_never_improved_on(self):
        for outcome in RELEASE_OUTCOMES:
            with self.subTest(outcome):
                review = review_pull_request(ADDED_HEADER, report=report(),
                                             gate_decision=outcome)
                self.assertLessEqual(
                    FAVOURABILITY[review.decision.outcome], FAVOURABILITY[outcome]
                )

    def test_known_risk_is_carried_through_not_rounded_up(self):
        review = review_pull_request(ADDED_HEADER, report=report(),
                                     gate_decision=PASS_WITH_KNOWN_RISK)
        self.assertEqual(review.decision.outcome, PASS_WITH_KNOWN_RISK)

    def test_a_blocked_gate_beats_an_otherwise_quiet_diff(self):
        review = review_pull_request(TYPO, report=report(), gate_decision=BLOCKED)
        self.assertEqual(review.decision.outcome, BLOCKED)

    def test_new_risk_never_reaches_pass_whatever_the_gate_says(self):
        for outcome in RELEASE_OUTCOMES:
            with self.subTest(outcome):
                review = review_pull_request(NEW_ROUTE, report=report(), gate_decision=outcome)
                self.assertNotEqual(review.decision.outcome, PASS)

    def test_the_outcome_is_the_least_favourable_constraint(self):
        review = review_pull_request(NEW_ROUTE, report=report(), gate_decision=BLOCKED)
        floor = min(FAVOURABILITY[c.outcome] for c in review.decision.constraints)
        self.assertEqual(FAVOURABILITY[review.decision.outcome], floor)

    def test_an_unknown_gate_vocabulary_is_refused(self):
        for hostile in ["APPROVED", "pass!", "OK"]:
            with self.subTest(hostile):
                with self.assertRaises(PullRequestReviewError):
                    review_pull_request(TYPO, gate_decision=hostile)

    def test_worst_defaults_to_incomplete_when_nothing_is_known(self):
        self.assertEqual(worst(), INCOMPLETE)
        self.assertEqual(worst(PASS, BLOCKED), BLOCKED)
        self.assertEqual(worst(PASS, PASS_WITH_KNOWN_RISK), PASS_WITH_KNOWN_RISK)

    def test_a_malformed_report_is_refused(self):
        with self.assertRaises(PullRequestReviewError):
            review_pull_request(TYPO, report=["not", "a", "report"])
        with self.assertRaises(PullRequestReviewError):
            review_pull_request(None)


class EvidenceAttributionTests(unittest.TestCase):
    def test_a_head_finding_citing_the_file_marks_the_delta_examined(self):
        review = review_pull_request(
            NEW_ROUTE,
            report=report([finding(status="FALSE_POSITIVE")]),
            gate_decision=PASS,
        )
        self.assertEqual(review.new_hypotheses[0]["evidence_state"],
                         "ADDRESSED_BY_REFUTATION")
        self.assertEqual(review.decision.outcome, PASS)

    def test_a_base_report_finding_never_marks_a_new_delta_examined(self):
        """The base report cannot have examined code this diff added."""
        review = review_pull_request(
            NEW_ROUTE,
            prior_report=report([finding(status="FALSE_POSITIVE")]),
            gate_decision=PASS,
        )
        self.assertEqual(review.new_hypotheses[0]["evidence_state"], UNADDRESSED)
        self.assertEqual(review.decision.outcome, INCOMPLETE)

    def test_a_finding_on_another_file_does_not_cover_this_delta(self):
        review = review_pull_request(
            NEW_ROUTE,
            report=report([finding(status="FALSE_POSITIVE", surface="billing/charge.py:9")]),
            gate_decision=PASS,
        )
        self.assertEqual(review.new_hypotheses[0]["evidence_state"], UNADDRESSED)
        self.assertEqual(review.decision.outcome, INCOMPLETE)

    def test_attribution_states_that_it_is_only_path_level(self):
        review = review_pull_request(
            NEW_ROUTE, report=report([finding()]), gate_decision=BLOCKED,
        )
        self.assertIn("path-level", review.new_hypotheses[0]["attribution"])
        self.assertEqual(review.new_hypotheses[0]["cited_findings"], ["SHX-F-1"])


class ContentTests(unittest.TestCase):
    def test_the_result_carries_every_required_section(self):
        payload = review_pull_request(
            NEW_ROUTE,
            prior_report=report(),
            report=report([finding(), finding("SHX-F-2", status="FALSE_POSITIVE")]),
            gate_decision=BLOCKED,
        ).as_dict()
        for key in ("security_delta", "new_hypotheses", "verified_findings",
                    "refuted_candidates", "coverage_change", "release_decision"):
            self.assertIn(key, payload)
        self.assertEqual([f["finding_id"] for f in payload["verified_findings"]], ["SHX-F-1"])
        self.assertEqual([f["finding_id"] for f in payload["refuted_candidates"]], ["SHX-F-2"])

    def test_the_security_delta_is_the_diff_reviewer_output(self):
        """Diff classification is not reimplemented here."""
        review = review_pull_request(NEW_ROUTE, gate_decision=PASS)
        self.assertEqual(review.security_delta, review_diff(NEW_ROUTE))
        self.assertEqual(review.security_delta["overall"], NEW_RISK)

    def test_findings_carry_their_reported_severity_without_reassigning_it(self):
        review = review_pull_request(TYPO, report=report([finding()]), gate_decision=BLOCKED)
        row = review.verified_findings[0]
        self.assertEqual(row["severity_as_reported"], "HIGH")
        self.assertEqual(row["read_from"], HEAD_REPORT)

    def test_incomparable_coverage_is_unknown_not_unchanged(self):
        review = review_pull_request(
            TYPO,
            prior_report=report(coverage=coverage(catalog_version="2.0")),
            report=report(coverage=coverage(catalog_version="2.1")),
            gate_decision=PASS,
        )
        self.assertEqual(review.coverage_change["state"], "UNKNOWN")
        self.assertIn("not comparable", review.coverage_change["reason"])

    def test_missing_coverage_names_the_uninspected_paths(self):
        review = review_pull_request(NEW_ROUTE, gate_decision=PASS)
        self.assertEqual(review.coverage_change["state"], "UNKNOWN")
        self.assertEqual(review.coverage_change["uninspected_paths"], ["api/orders.py"])

    def test_hypotheses_are_only_raised_for_questioning_directions(self):
        review = review_pull_request(ADDED_HEADER, report=report(), gate_decision=PASS)
        self.assertEqual(review.new_hypotheses, ())


class CommentTests(unittest.TestCase):
    def test_the_comment_names_every_section_a_reviewer_needs(self):
        review = review_pull_request(
            NEW_ROUTE,
            prior_report=report(),
            report=report([finding(), finding("SHX-F-2", status="FALSE_POSITIVE")]),
            gate_decision=BLOCKED,
        )
        body = review.comment
        for heading in ("Security delta", "New hypotheses", "Verified findings",
                        "Refuted candidates", "Coverage", "Release decision"):
            self.assertIn(heading, body)

    def test_the_comment_states_that_a_hypothesis_is_not_a_finding(self):
        body = review_pull_request(NEW_ROUTE, report=report(), gate_decision=PASS).comment
        self.assertIn("unverified", body)
        self.assertIn("`UNKNOWN` is not a pass", body)
        self.assertIn("never better than the evidence", body)

    def test_the_comment_marks_findings_read_from_the_base_report(self):
        review = review_pull_request(NEW_ROUTE, prior_report=report([finding()]),
                                     gate_decision=BLOCKED)
        self.assertIn("before** this change", review.comment)

    def test_a_long_list_is_truncated_rather_than_dumped(self):
        findings = [finding(f"SHX-F-{i}") for i in range(MAX_ROWS + 5)]
        review = review_pull_request(NEW_ROUTE, report=report(findings), gate_decision=BLOCKED)
        self.assertIn("and 5 more", review.comment)

    def test_rendering_is_available_even_when_the_comment_is_suppressed(self):
        review = review_pull_request(TYPO, report=report(), gate_decision=PASS)
        self.assertIsNone(review.comment)
        self.assertIn("Release decision", render_comment(review))

    def test_the_comment_is_stable_for_the_same_input(self):
        args = dict(report=report([finding()]), gate_decision=BLOCKED)
        self.assertEqual(review_pull_request(NEW_ROUTE, **args).comment,
                         review_pull_request(NEW_ROUTE, **args).comment)


if __name__ == "__main__":
    unittest.main()
