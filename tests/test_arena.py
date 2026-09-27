import json
import unittest

from evals.arena import (
    MEASURED,
    NOT_MEASURED,
    ArenaError,
    canonical_digest,
    comparable,
    finalize_manifest as arena_finalize_manifest,
    prepare_manifest,
    validate_participant,
)
from evals.arena_freeze import (
    BLINDNESS_SCHEMA_VERSION,
    FREEZE_SCHEMA_VERSION,
    FREEZE_STATUS,
)


PACKET = {
    "cases": [
        {"case_id": "CASE-A", "family": "Authorization", "source": "opaque-a"},
        {"case_id": "CASE-B", "family": "Authorization", "source": "opaque-b"},
    ]
}
PACKET_DIGEST = canonical_digest(PACKET)

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

def make_prediction_freeze(participant: dict = PARTICIPANT) -> dict:
    prediction_set = [
        {
            "case_id": "CASE-A",
            "run_id": "RUN-A",
            "bundle_digest": "sha256:" + "a" * 64,
        },
        {
            "case_id": "CASE-B",
            "run_id": "RUN-B",
            "bundle_digest": "sha256:" + "b" * 64,
        },
    ]
    freeze = {
        "schema_version": FREEZE_SCHEMA_VERSION,
        "status": FREEZE_STATUS,
        "measurement_status": NOT_MEASURED,
        "packet_digest": PACKET_DIGEST,
        "participant_digest": canonical_digest(participant),
        "handoff_digest": "sha256:" + "c" * 64,
        "case_count": len(prediction_set),
        "prediction_digest": canonical_digest(prediction_set),
        "frozen_at": "2026-09-03T18:11:00Z",
        "recorder": {
            "identity": "independent-eval-operator",
            "role": "prediction-custodian",
        },
        "prediction_set": prediction_set,
        "scope": {
            "reveals_ground_truth": False,
            "establishes_evaluator_independence": False,
            "scores_correctness": False,
        },
    }
    freeze["freeze_digest"] = canonical_digest(
        {key: value for key, value in freeze.items() if key != "freeze_digest"}
    )
    return freeze


def make_blindness(freeze: dict, **overrides: object) -> dict:
    blindness = {
        "schema_version": BLINDNESS_SCHEMA_VERSION,
        "evaluator_independent": True,
        "truth_revealed_after_predictions": True,
        "contamination": "UNCONTAMINATED",
        "ground_truth_digest": "sha256:" + "1" * 64,
        "prediction_digest": freeze["prediction_digest"],
        "prediction_freeze_digest": freeze["freeze_digest"],
        "frozen_at": freeze["frozen_at"],
        "truth_revealed_at": "2026-09-03T18:12:00Z",
        "scope": {
            "ordering_checked": True,
            "ordering_is_self_or_externally_attested": True,
            "establishes_evaluator_independence": False,
        },
    }
    blindness.update(overrides)
    return blindness


FREEZE = make_prediction_freeze()
BLINDNESS = make_blindness(FREEZE)


def finalize_manifest(
    prepared: dict,
    *,
    run: dict,
    blindness: dict,
    assessment: dict,
    prediction_freeze: dict = FREEZE,
) -> dict:
    return arena_finalize_manifest(
        prepared,
        run=run,
        blindness=blindness,
        assessment=assessment,
        prediction_freeze=prediction_freeze,
    )

WORKFLOW_FIELDS = (
    "applicability",
    "verification",
    "false_positive_refutation",
    "root_cause",
    "regression_proof",
    "release_gate",
)


def metric_evidence(case_id: str) -> dict[str, dict[str, object]]:
    return {
        field: {
            "basis": (
                f"Independent assessment of {field} for {case_id} against the "
                "sealed truth and participant run artifacts."
            ),
            "refs": [f"{case_id}:{field}:artifact"],
            "artifact_digest": "sha256:" + (
                "a" if case_id == "CASE-A" else "b"
            ) * 64,
        }
        for field in WORKFLOW_FIELDS
    }


ASSESSMENT = {
    "packet_digest": PACKET_DIGEST,
    "assessor": {
        "identity": "independent-evaluator-1",
        "independent": True,
        "independence_basis": "assessed by a reviewer unaffiliated with the participant",
        "attestation_url": "https://example.test/evaluator-1/attestations/demo-agent",
    },
    "observations": [
        {
            "case_id": "CASE-A",
            "applicability": True,
            "verification": True,
            "false_positive_refutation": True,
            "root_cause": False,
            "regression_proof": True,
            "release_gate": True,
            "evidence": metric_evidence("CASE-A"),
        },
        {
            "case_id": "CASE-B",
            "applicability": True,
            "verification": True,
            "false_positive_refutation": True,
            "root_cause": True,
            "regression_proof": True,
            "release_gate": True,
            "evidence": metric_evidence("CASE-B"),
        },
    ],
}


class ArenaTests(unittest.TestCase):
    def test_self_declared_independence_alone_never_measures(self) -> None:
        """A perfect score plus two flipped booleans must not be publishable."""
        assessment = json.loads(json.dumps(ASSESSMENT))
        assessment["assessor"] = {
            "identity": "the maintainer",
            "independent": True,
        }
        record = finalize_manifest(
            prepare_manifest(PACKET, PARTICIPANT),
            run=RUN,
            blindness=BLINDNESS,
            assessment=assessment,
        )
        self.assertEqual(record["measurement_status"], NOT_MEASURED)
        self.assertIn(
            "assessor.attestation_url missing", record["publication"]["blockers"]
        )

    def test_attestation_from_the_participants_own_account_never_measures(self) -> None:
        assessment = json.loads(json.dumps(ASSESSMENT))
        assessment["assessor"]["attestation_url"] = (
            "https://example.test/demo-agent/attestations/self"
        )
        record = finalize_manifest(
            prepare_manifest(PACKET, PARTICIPANT),
            run=RUN,
            blindness=BLINDNESS,
            assessment=assessment,
        )
        self.assertEqual(record["measurement_status"], NOT_MEASURED)
        self.assertTrue(
            any(
                "participant's own account" in blocker
                for blocker in record["publication"]["blockers"]
            )
        )

    def test_non_https_attestation_never_measures(self) -> None:
        assessment = json.loads(json.dumps(ASSESSMENT))
        assessment["assessor"]["attestation_url"] = "file:///tmp/attestation.txt"
        record = finalize_manifest(
            prepare_manifest(PACKET, PARTICIPANT),
            run=RUN,
            blindness=BLINDNESS,
            assessment=assessment,
        )
        self.assertEqual(record["measurement_status"], NOT_MEASURED)

    def test_assessor_independence_must_agree_with_blindness_record(self) -> None:
        blindness = dict(BLINDNESS, evaluator_independent=False)
        record = finalize_manifest(
            prepare_manifest(PACKET, PARTICIPANT),
            run=RUN,
            blindness=blindness,
            assessment=ASSESSMENT,
        )
        self.assertEqual(record["measurement_status"], NOT_MEASURED)
        self.assertIn(
            "assessor.independent contradicts blindness.evaluator_independent",
            record["publication"]["blockers"],
        )

    def test_a_declared_dependent_assessment_owes_no_attestation(self) -> None:
        """Honestly self-assessed records stay unpublishable, not malformed."""
        assessment = json.loads(json.dumps(ASSESSMENT))
        assessment["assessor"] = {"identity": "the maintainer", "independent": False}
        record = finalize_manifest(
            prepare_manifest(PACKET, PARTICIPANT),
            run=RUN,
            blindness=dict(BLINDNESS, evaluator_independent=False),
            assessment=assessment,
        )
        blockers = record["publication"]["blockers"]
        self.assertEqual(record["measurement_status"], NOT_MEASURED)
        self.assertNotIn("assessor.attestation_url missing", blockers)
        self.assertIn("assessment is not marked independent", blockers)

    def test_digest_is_canonical(self) -> None:
        self.assertEqual(canonical_digest({"a": 1, "b": 2}), canonical_digest({"b": 2, "a": 1}))

    def test_prepared_manifest_contains_no_case_source_or_score(self) -> None:
        prepared = prepare_manifest(PACKET, PARTICIPANT)
        self.assertEqual(prepared["measurement_status"], NOT_MEASURED)
        self.assertFalse(prepared["publication"]["eligible"])
        rendered = str(prepared)
        self.assertNotIn("opaque-a", rendered)
        self.assertNotIn("opaque-b", rendered)
        self.assertEqual(prepared["packet"]["case_count"], 2)
        self.assertEqual(prepared["packet"]["case_ids"], ["CASE-A", "CASE-B"])

    def test_placeholder_versions_are_not_comparable_versions(self) -> None:
        participant = dict(PARTICIPANT, version="PIN_REQUIRED")
        with self.assertRaises(ArenaError):
            validate_participant(participant)

    def test_placeholder_capability_scope_is_refused(self) -> None:
        participant = dict(PARTICIPANT, capability_scope=["REVIEW_AND_PIN_FROM_TESTED_VERSION"])
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
        self.assertEqual(result["full_workflow"]["root_cause_accuracy"], 0.5)
        self.assertEqual(result["full_workflow"]["verification_accuracy"], 1.0)

    def test_manual_blindness_without_prediction_freeze_never_measures(self) -> None:
        result = arena_finalize_manifest(
            prepare_manifest(PACKET, PARTICIPANT),
            run=RUN,
            blindness=BLINDNESS,
            assessment=ASSESSMENT,
        )
        self.assertEqual(result["measurement_status"], NOT_MEASURED)
        self.assertIn(
            "prediction freeze evidence missing",
            result["publication"]["blockers"],
        )

    def test_blindness_must_be_bound_to_exact_prediction_freeze(self) -> None:
        blindness = dict(
            BLINDNESS,
            prediction_freeze_digest="sha256:" + "9" * 64,
        )
        result = finalize_manifest(
            prepare_manifest(PACKET, PARTICIPANT),
            run=RUN,
            blindness=blindness,
            assessment=ASSESSMENT,
        )
        self.assertEqual(result["measurement_status"], NOT_MEASURED)
        self.assertTrue(
            any(
                "prediction_freeze_digest does not match" in blocker
                for blocker in result["publication"]["blockers"]
            )
        )

    def test_prediction_freeze_for_other_packet_never_measures(self) -> None:
        freeze = dict(FREEZE, packet_digest="sha256:" + "8" * 64)
        freeze["freeze_digest"] = canonical_digest(
            {key: value for key, value in freeze.items() if key != "freeze_digest"}
        )
        blindness = make_blindness(freeze)
        result = finalize_manifest(
            prepare_manifest(PACKET, PARTICIPANT),
            run=RUN,
            blindness=blindness,
            assessment=ASSESSMENT,
            prediction_freeze=freeze,
        )
        self.assertEqual(result["measurement_status"], NOT_MEASURED)
        self.assertIn(
            "prediction freeze is not bound to the prepared packet digest",
            result["publication"]["blockers"],
        )

    def test_naked_workflow_boolean_never_measures(self) -> None:
        assessment = json.loads(json.dumps(ASSESSMENT))
        assessment["observations"][0]["evidence"].pop("verification")
        result = finalize_manifest(
            prepare_manifest(PACKET, PARTICIPANT),
            run=RUN,
            blindness=BLINDNESS,
            assessment=assessment,
        )
        self.assertEqual(result["measurement_status"], NOT_MEASURED)
        self.assertIn(
            "CASE-A.verification missing evidence record",
            result["publication"]["blockers"],
        )

    def test_metric_evidence_requires_basis_reference_and_digest(self) -> None:
        assessment = json.loads(json.dumps(ASSESSMENT))
        evidence = assessment["observations"][0]["evidence"]["root_cause"]
        evidence["basis"] = "too short"
        evidence["refs"] = []
        evidence["artifact_digest"] = "not-a-digest"
        result = finalize_manifest(
            prepare_manifest(PACKET, PARTICIPANT),
            run=RUN,
            blindness=BLINDNESS,
            assessment=assessment,
        )
        blockers = result["publication"]["blockers"]
        self.assertEqual(result["measurement_status"], NOT_MEASURED)
        self.assertTrue(any("root_cause.evidence.basis" in item for item in blockers))
        self.assertTrue(any("root_cause.evidence.refs" in item for item in blockers))
        self.assertTrue(any("root_cause.evidence.artifact_digest" in item for item in blockers))

    def test_not_applicable_metric_does_not_require_fake_evidence(self) -> None:
        assessment = json.loads(json.dumps(ASSESSMENT))
        assessment["observations"][0]["regression_proof"] = "NOT_APPLICABLE"
        assessment["observations"][0]["evidence"].pop("regression_proof")
        result = finalize_manifest(
            prepare_manifest(PACKET, PARTICIPANT),
            run=RUN,
            blindness=BLINDNESS,
            assessment=assessment,
        )
        self.assertEqual(result["measurement_status"], MEASURED)
        self.assertTrue(result["publication"]["eligible"])
        self.assertEqual(result["full_workflow"]["regression_proof_accuracy"], 1.0)

    def test_missing_metric_observation_keeps_record_not_measured(self) -> None:
        prepared = prepare_manifest(PACKET, PARTICIPANT)
        assessment = {
            "packet_digest": PACKET_DIGEST,
            "assessor": ASSESSMENT["assessor"],
            "observations": [
                dict(ASSESSMENT["observations"][0]),
                {key: value for key, value in ASSESSMENT["observations"][1].items() if key != "release_gate"},
            ],
        }
        result = finalize_manifest(prepared, run=RUN, blindness=BLINDNESS, assessment=assessment)
        self.assertEqual(result["measurement_status"], NOT_MEASURED)
        self.assertTrue(any("release_gate" in blocker for blocker in result["publication"]["blockers"]))

    def test_incomplete_case_coverage_never_measures(self) -> None:
        prepared = prepare_manifest(PACKET, PARTICIPANT)
        assessment = dict(ASSESSMENT, observations=[ASSESSMENT["observations"][0]])
        result = finalize_manifest(prepared, run=RUN, blindness=BLINDNESS, assessment=assessment)
        self.assertEqual(result["measurement_status"], NOT_MEASURED)
        self.assertTrue(any("every prepared blind case" in blocker for blocker in result["publication"]["blockers"]))

    def test_assessment_for_another_packet_never_measures(self) -> None:
        prepared = prepare_manifest(PACKET, PARTICIPANT)
        assessment = dict(ASSESSMENT, packet_digest="sha256:" + "9" * 64)
        result = finalize_manifest(prepared, run=RUN, blindness=BLINDNESS, assessment=assessment)
        self.assertEqual(result["measurement_status"], NOT_MEASURED)
        self.assertTrue(any("prepared packet digest" in blocker for blocker in result["publication"]["blockers"]))

    def test_different_scopes_cannot_be_ranked_against_each_other(self) -> None:
        left = finalize_manifest(prepare_manifest(PACKET, PARTICIPANT), run=RUN, blindness=BLINDNESS, assessment=ASSESSMENT)
        other = dict(PARTICIPANT, participant_id="narrow", capability_scope=["security_review"])
        other_freeze = make_prediction_freeze(other)
        right = finalize_manifest(
            prepare_manifest(PACKET, other),
            run=RUN,
            blindness=make_blindness(other_freeze),
            assessment=ASSESSMENT,
            prediction_freeze=other_freeze,
        )
        ok, reason = comparable(left, right)
        self.assertFalse(ok)
        self.assertIn("capability scopes differ", reason)

    def test_same_scope_and_packet_are_comparable_after_measurement(self) -> None:
        left = finalize_manifest(prepare_manifest(PACKET, PARTICIPANT), run=RUN, blindness=BLINDNESS, assessment=ASSESSMENT)
        other = dict(PARTICIPANT, participant_id="demo-agent-2", display_name="Demo Agent 2")
        other_freeze = make_prediction_freeze(other)
        right = finalize_manifest(
            prepare_manifest(PACKET, other),
            run=RUN,
            blindness=make_blindness(other_freeze),
            assessment=ASSESSMENT,
            prediction_freeze=other_freeze,
        )
        ok, reason = comparable(left, right)
        self.assertTrue(ok, reason)


if __name__ == "__main__":
    unittest.main()
