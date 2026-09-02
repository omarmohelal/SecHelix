"""A quorum must stay blind, and disagreement must never become a verdict."""

import unittest

from sechelix_core.quorum import (
    ABSTAIN,
    CONSENSUS_REFUTED,
    CONSENSUS_VERIFIED,
    DISAGREEMENT,
    INSUFFICIENT_EVIDENCE,
    REFUTED,
    VERIFIED,
    QuorumError,
    SealedQuorum,
    Vote,
    apply_to_finding,
    tally,
)


def vote(voter, conclusion, kind="REVIEWER", rationale="because"):
    return Vote(voter_id=voter, path_kind=kind, conclusion=conclusion, rationale=rationale)


class BlindnessTests(unittest.TestCase):
    """The blindness is the mechanism; without it the paths are not independent."""

    def _quorum(self):
        return SealedQuorum("SHX-F-1", ["a", "b"])

    def test_a_sealed_quorum_cannot_be_inspected(self):
        q = self._quorum()
        q.submit(vote("a", VERIFIED))
        with self.assertRaises(QuorumError):
            q.peek()

    def test_it_cannot_be_opened_while_a_voter_is_outstanding(self):
        q = self._quorum()
        q.submit(vote("a", VERIFIED))
        with self.assertRaises(QuorumError) as ctx:
            q.open()
        self.assertIn("has not voted", str(ctx.exception))

    def test_a_vote_after_opening_is_refused(self):
        q = self._quorum()
        q.submit(vote("a", VERIFIED))
        q.submit(vote("b", VERIFIED))
        q.open()
        with self.assertRaises(QuorumError) as ctx:
            q.submit(vote("a", REFUTED))
        self.assertIn("not an independent one", str(ctx.exception))

    def test_an_unexpected_voter_is_refused(self):
        q = self._quorum()
        with self.assertRaises(QuorumError):
            q.submit(vote("c", VERIFIED))

    def test_a_voter_cannot_vote_twice(self):
        q = self._quorum()
        q.submit(vote("a", VERIFIED))
        with self.assertRaises(QuorumError):
            q.submit(vote("a", REFUTED))

    def test_outstanding_names_who_is_missing(self):
        q = self._quorum()
        q.submit(vote("a", VERIFIED))
        self.assertEqual(q.outstanding, ("b",))

    def test_a_quorum_too_small_to_satisfy_its_minimum_is_refused(self):
        with self.assertRaises(QuorumError):
            SealedQuorum("SHX-F-1", ["a"], minimum_voters=2)

    def test_duplicate_expected_voters_are_refused(self):
        with self.assertRaises(QuorumError):
            SealedQuorum("SHX-F-1", ["a", "a", "b"])


class OutcomeTests(unittest.TestCase):
    def test_unanimous_verification_is_consensus_verified(self):
        result = tally("SHX-F-1", [vote("a", VERIFIED), vote("b", VERIFIED, "TOOL")])
        self.assertEqual(result.outcome, CONSENSUS_VERIFIED)
        self.assertTrue(result.verifies_the_finding)

    def test_unanimous_refutation_is_consensus_refuted(self):
        result = tally("SHX-F-1", [vote("a", REFUTED), vote("b", REFUTED, "TOOL")])
        self.assertEqual(result.outcome, CONSENSUS_REFUTED)
        self.assertFalse(result.verifies_the_finding)

    def test_opposite_conclusions_are_disagreement(self):
        result = tally("SHX-F-1", [vote("a", VERIFIED), vote("b", REFUTED)])
        self.assertEqual(result.outcome, DISAGREEMENT)

    def test_disagreement_never_verifies(self):
        """DISAGREEMENT is not a vulnerability and not a clearance."""
        result = tally("SHX-F-1", [vote("a", VERIFIED), vote("b", REFUTED)])
        self.assertFalse(result.verifies_the_finding)
        self.assertTrue(result.requires_human_review)

    def test_a_majority_does_not_overrule_a_dissent(self):
        """Two against one is still disagreement, not a verified finding."""
        result = tally("SHX-F-1", [vote("a", VERIFIED), vote("b", VERIFIED),
                                   vote("c", REFUTED)])
        self.assertEqual(result.outcome, DISAGREEMENT)
        self.assertFalse(result.verifies_the_finding)

    def test_too_few_conclusions_is_insufficient_not_refuted(self):
        """An abstention is not a vote for safety."""
        result = tally("SHX-F-1", [vote("a", VERIFIED), vote("b", ABSTAIN)])
        self.assertEqual(result.outcome, INSUFFICIENT_EVIDENCE)
        self.assertFalse(result.verifies_the_finding)
        self.assertTrue(result.requires_human_review)

    def test_all_abstaining_is_insufficient(self):
        result = tally("SHX-F-1", [vote("a", ABSTAIN), vote("b", ABSTAIN)])
        self.assertEqual(result.outcome, INSUFFICIENT_EVIDENCE)
        self.assertEqual(result.concluding, 0)
        self.assertEqual(result.abstained, 2)

    def test_only_consensus_verified_verifies(self):
        cases = [
            ([vote("a", VERIFIED), vote("b", VERIFIED)], True),
            ([vote("a", REFUTED), vote("b", REFUTED)], False),
            ([vote("a", VERIFIED), vote("b", REFUTED)], False),
            ([vote("a", VERIFIED), vote("b", ABSTAIN)], False),
        ]
        for votes, expected in cases:
            with self.subTest([v.conclusion for v in votes]):
                self.assertEqual(tally("SHX-F-1", votes).verifies_the_finding, expected)


class EvidenceQualityTests(unittest.TestCase):
    def test_agreement_among_reviewers_alone_is_flagged_as_weaker(self):
        result = tally("SHX-F-1", [vote("a", VERIFIED), vote("b", VERIFIED)])
        self.assertTrue(any("same kind" in n for n in result.notes), result.notes)

    def test_mixed_paths_are_not_flagged(self):
        result = tally("SHX-F-1", [vote("a", VERIFIED), vote("b", VERIFIED, "RUNTIME")])
        self.assertFalse(any("same kind" in n for n in result.notes), result.notes)

    def test_path_kinds_are_recorded(self):
        result = tally("SHX-F-1", [vote("a", VERIFIED, "TOOL"), vote("b", VERIFIED, "RUNTIME")])
        self.assertEqual(result.as_dict()["path_kinds"], ["RUNTIME", "TOOL"])


class VoteValidityTests(unittest.TestCase):
    def test_a_vote_without_a_rationale_is_refused(self):
        with self.assertRaises(QuorumError):
            Vote("a", "REVIEWER", VERIFIED, "   ")

    def test_an_invalid_conclusion_is_refused(self):
        with self.assertRaises(QuorumError):
            Vote("a", "REVIEWER", "PROBABLY", "because")

    def test_an_invalid_path_kind_is_refused(self):
        with self.assertRaises(QuorumError):
            Vote("a", "VIBES", VERIFIED, "because")


class ApplicationTests(unittest.TestCase):
    def _finding(self, status="HYPOTHESIS"):
        return {"finding_id": "SHX-F-1", "status": status, "resolution": "OPEN"}

    def test_a_quorum_never_promotes_an_unverified_finding(self):
        """Several paths agreeing later does not retroactively verify."""
        finding = self._finding()
        apply_to_finding(finding, tally("SHX-F-1", [vote("a", VERIFIED),
                                                    vote("b", VERIFIED, "TOOL")]))
        self.assertEqual(finding["status"], "HYPOTHESIS")

    def test_consensus_refutation_marks_it_a_false_positive(self):
        finding = self._finding("VERIFIED")
        apply_to_finding(finding, tally("SHX-F-1", [vote("a", REFUTED),
                                                    vote("b", REFUTED, "TOOL")]))
        self.assertEqual(finding["status"], "FALSE_POSITIVE")
        self.assertEqual(finding["resolution"], "FALSE_POSITIVE")

    def test_disagreement_flags_for_human_review_and_changes_nothing_else(self):
        finding = self._finding("VERIFIED")
        apply_to_finding(finding, tally("SHX-F-1", [vote("a", VERIFIED), vote("b", REFUTED)]))
        self.assertEqual(finding["status"], "VERIFIED")
        self.assertTrue(finding["requires_human_review"])

    def test_the_recorded_quorum_carries_a_checkable_digest(self):
        result = tally("SHX-F-1", [vote("a", VERIFIED), vote("b", VERIFIED, "TOOL")])
        payload = result.as_dict()
        self.assertEqual(len(payload["vote_digest"]), 32)
        self.assertEqual(payload["vote_digest"], result.digest())

    def test_the_digest_is_order_independent(self):
        a = tally("SHX-F-1", [vote("a", VERIFIED), vote("b", REFUTED)])
        b = tally("SHX-F-1", [vote("b", REFUTED), vote("a", VERIFIED)])
        self.assertEqual(a.digest(), b.digest())

    def test_the_digest_changes_when_a_conclusion_changes(self):
        a = tally("SHX-F-1", [vote("a", VERIFIED), vote("b", VERIFIED)])
        b = tally("SHX-F-1", [vote("a", VERIFIED), vote("b", REFUTED)])
        self.assertNotEqual(a.digest(), b.digest())


if __name__ == "__main__":
    unittest.main()
