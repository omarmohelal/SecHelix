import unittest

from evals.arena import (
    MEASURED,
    NOT_MEASURED,
    ArenaError,
    canonical_digest,
    comparable,
    finalize_manifest,
    prepare_manifest,
    validate_participant,
)


PACKET = {
    "cases": [
        {"case_id": "CASE-A", "family": "Authorization", "source": "opaque-a"},
        {"case_id": "CASE-B", "family": "Authorization", "source": "opaque-b"},
    ]
}

PARTICIPANT = {
    "participant_id": "demo-agent",
    "display_name": "Demo Agent",
    "category": "AGENT_WORKFLOW",
    "source_url": "https://example.test/demo-agent",
    "version": "1.2.3",
    "capability_scope": ["security_review", "verification", "regression_proof"],
}

RUN = {
    "agent_host": "isolated-eval-host",
    "provider": "NOT_APPLICABLE",
    "model": "NOT_APPLICABLE",
    "started_at": "2026-09-03T18:00:00Z",
    "finished_at": "2026-09-03T18:10:00Z",
    "input_tokens": None,
    "output_tokens": None,
    "cost": None,
}

BLINDNESS = {
    "evaluator_independent": True,
    "truth_revealed_after_predictions": True,
    "contamination": "UNCONTAMINATED",
    "ground_truth_digest": "sha256:" + "1" * 64,
    "prediction_digest": "sha256:" + "2" * 64,
}

ASSESSMENT = {
    "assessor": {"identity": "independent-evaluator-1", "independent": True},
    "observations": [
        {
            "case_id": "CASE-A",
            "applicability": True,
            "verification": True,
            "false_positive_refutation": True,
            "root_cause": False,
            "regression_proof": True,
            "release_gate": True,
        }
    ],
}


class ArenaTests(unittest.TestCase):
    def test_digest_is_canonical(self) -> None:
        self.assertEqual(canonical_digest({"a": 1, "b": 2}), canonical_digest({"b": 2, "a": 1}))

    def test_prepared_manifest_contains_no_cases_or_score(self) -> None:
        prepared = prepare_manifest(PACKET, PARTICIPANT)
        self.assertEqual(prepared["measurement_status"], NOT_MEASURED)
        self.assertFalse(prepared["publication"]["eligible"])
        rendered = str(prepared)
        self.assertNotIn("opaque-a", rendered)
        self.assertNotIn("opaque-b", rendered)
        self.assertEqual(prepared["packet"]["case_count"], 2)

    def test_placeholder_versions_are_not_comparable_versions(self) -> None:
        participant = dict(PARTICIPANT, version="PIN_REQUIRED")
        with self.assertRaises(ArenaError):
            validate_participant(participant)

    def test_contaminated_evaluator_never_measures(self) -> None:
        prepared = prepare_manifest(PACKET, PARTICIPANT)
        blindness = dict(BLINDNESS, contamination="CONTAMINATED")
        result = finalize_manifest(prepared, run=RUN, blindness=blindness, assessment=ASSESSMENT)
        self.assertEqual(result["measurement_status"], NOT_MEASURED)
        self.assertFalse(result["publication"]["eligible"])
        self.assertTrue(any("contamination" in blocker for blocker in result["publication"]["blockers"]))

    def test_complete_independent_assessment_can_measure_workflow_metrics(self) -> None:
        prepared = prepare_manifest(PACKET, PARTICIPANT)
        result = finalize_manifest(prepared, run=RUN, blindness=BLINDNESS, assessment=ASSESSMENT)
        self.assertEqual(result["measurement_status"], MEASURED)
        self.assertTrue(result["publication"]["eligible"])
        self.assertEqual(result["full_workflow"]["root_cause_accuracy"], 0.0)
        self.assertEqual(result["full_workflow"]["verification_accuracy"], 1.0)

    def test_missing_metric_observation_keeps_record_not_measured(self) -> None:
        prepared = prepare_manifest(PACKET, PARTICIPANT)
        assessment = {
            "assessor": ASSESSMENT["assessor"],
            "observations": [{"case_id": "CASE-A", "applicability": True}],
        }
        result = finalize_manifest(prepared, run=RUN, blindness=BLINDNESS, assessment=assessment)
        self.assertEqual(result["measurement_status"], NOT_MEASURED)
        self.assertIn("one or more full-workflow metrics", " ".join(result["publication"]["blockers"]))

    def test_different_scopes_cannot_be_ranked_against_each_other(self) -> None:
        left = finalize_manifest(prepare_manifest(PACKET, PARTICIPANT), run=RUN, blindness=BLINDNESS, assessment=ASSESSMENT)
        other = dict(PARTICIPANT, participant_id="narrow", capability_scope=["security_review"])
        right = finalize_manifest(prepare_manifest(PACKET, other), run=RUN, blindness=BLINDNESS, assessment=ASSESSMENT)
        ok, reason = comparable(left, right)
        self.assertFalse(ok)
        self.assertIn("capability scopes differ", reason)

    def test_same_scope_and_packet_are_comparable_after_measurement(self) -> None:
        left = finalize_manifest(prepare_manifest(PACKET, PARTICIPANT), run=RUN, blindness=BLINDNESS, assessment=ASSESSMENT)
        other = dict(PARTICIPANT, participant_id="demo-agent-2", display_name="Demo Agent 2")
        right = finalize_manifest(prepare_manifest(PACKET, other), run=RUN, blindness=BLINDNESS, assessment=ASSESSMENT)
        ok, reason = comparable(left, right)
        self.assertTrue(ok, reason)


if __name__ == "__main__":
    unittest.main()
