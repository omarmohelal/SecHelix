from __future__ import annotations

import copy
import json
import unittest

from evals.arena import canonical_digest, prepare_manifest
from evals.arena_batch import READY_STATUS as BATCH_READY_STATUS
from evals.arena_freeze import (
    ArenaPredictionFreezeError,
    BLINDNESS_SCHEMA_VERSION,
    FREEZE_SCHEMA_VERSION,
    FREEZE_STATUS,
    build_blindness_record,
    build_prediction_freeze,
    validate_prediction_freeze,
)


PACKET = {
    "cases": [
        {"case_id": "CASE-A", "family": "Authorization", "source": "opaque-a"},
        {"case_id": "CASE-B", "family": "Business logic", "source": "opaque-b"},
    ]
}

PARTICIPANT = {
    "participant_id": "sechelix-test",
    "display_name": "SecHelix Test",
    "category": "AGENT_WORKFLOW",
    "source_url": "https://github.com/example/sechelix-test",
    "version": "abc123",
    "capability_scope": ["security_review", "verification", "regression_proof"],
}


def make_bundle(run_id: str) -> dict:
    return {
        "schema_version": "sechelix-arena-measurement-bundle/v1",
        "status": "READY_FOR_INDEPENDENT_ASSESSMENT",
        "run_identity": {"run_id": run_id},
        "bindings": {
            "workspace_artifacts": {
                "run.json": "sha256:" + "1" * 64,
                "graph.json": "sha256:" + "2" * 64,
                "replay/outcomes.json": "sha256:" + "3" * 64,
                "manifest.json": "sha256:" + "4" * 64,
            }
        },
        "assessment_targets": {
            "independent_verifier": [
                {"node_id": "verifier", "artifact_ref": "replay/outcomes.json"}
            ],
            "release_gate": [
                {"node_id": "gate", "artifact_ref": "replay/outcomes.json"}
            ],
        },
    }


def make_handoff(prepared: dict) -> dict:
    cases = []
    for case_id, run_id in (("CASE-A", "RUN-A"), ("CASE-B", "RUN-B")):
        bundle = make_bundle(run_id)
        cases.append(
            {
                "case_id": case_id,
                "run_id": run_id,
                "bundle_digest": canonical_digest(bundle),
                "bundle": bundle,
            }
        )
    handoff = {
        "schema_version": "sechelix-arena-batch-handoff/v1",
        "status": BATCH_READY_STATUS,
        "measurement_status": "NOT_MEASURED",
        "packet": {
            "digest": prepared["packet"]["digest"],
            "case_count": 2,
            "case_id_digest": prepared["packet"]["case_id_digest"],
        },
        "participant": PARTICIPANT,
        "case_count": 2,
        "cases": cases,
        "measurement_scope": {
            "scores_correctness": False,
            "establishes_evaluator_independence": False,
            "reveals_ground_truth": False,
            "requires_independent_assessor": True,
        },
    }
    handoff["handoff_digest"] = canonical_digest(handoff)
    return handoff


class ArenaPredictionFreezeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.prepared = prepare_manifest(PACKET, PARTICIPANT)
        self.handoff = make_handoff(self.prepared)

    def test_prediction_freeze_binds_complete_batch_without_truth(self) -> None:
        result = build_prediction_freeze(
            self.prepared,
            self.handoff,
            frozen_at="2026-09-26T19:00:00+00:00",
            recorder_identity="Independent Eval Operator",
            recorder_role="prediction-custodian",
        )

        self.assertEqual(result["schema_version"], FREEZE_SCHEMA_VERSION)
        self.assertEqual(result["status"], FREEZE_STATUS)
        self.assertEqual(result["measurement_status"], "NOT_MEASURED")
        self.assertEqual(result["packet_digest"], self.prepared["packet"]["digest"])
        self.assertEqual(result["handoff_digest"], self.handoff["handoff_digest"])
        self.assertEqual(result["case_count"], 2)
        self.assertEqual(
            [row["case_id"] for row in result["prediction_set"]],
            ["CASE-A", "CASE-B"],
        )
        self.assertEqual(
            result["prediction_digest"],
            canonical_digest(result["prediction_set"]),
        )
        self.assertTrue(result["freeze_digest"].startswith("sha256:"))
        self.assertFalse(result["scope"]["reveals_ground_truth"])
        self.assertFalse(result["scope"]["scores_correctness"])
        rendered = json.dumps(result).lower()
        self.assertNotIn("ground_truth_digest", rendered)
        self.assertNotIn("truth_revealed_at", rendered)
        validate_prediction_freeze(result)

    def test_prediction_freeze_is_deterministic_for_same_declared_inputs(self) -> None:
        first = build_prediction_freeze(
            self.prepared,
            self.handoff,
            frozen_at="2026-09-26T19:00:00Z",
            recorder_identity="Eval Lab",
            recorder_role="custodian",
        )
        second = build_prediction_freeze(
            self.prepared,
            self.handoff,
            frozen_at="2026-09-26T19:00:00Z",
            recorder_identity="Eval Lab",
            recorder_role="custodian",
        )
        self.assertEqual(first, second)

    def test_handoff_tamper_and_packet_mismatch_fail_closed(self) -> None:
        tampered = copy.deepcopy(self.handoff)
        tampered["case_count"] = 99
        with self.assertRaises(ArenaPredictionFreezeError) as ctx:
            build_prediction_freeze(
                self.prepared,
                tampered,
                frozen_at="2026-09-26T19:00:00Z",
                recorder_identity="Eval Lab",
                recorder_role="custodian",
            )
        self.assertIn("digest", str(ctx.exception).lower())

        other = copy.deepcopy(self.handoff)
        other.pop("handoff_digest")
        other["packet"]["digest"] = "sha256:" + "9" * 64
        other["handoff_digest"] = canonical_digest(other)
        with self.assertRaises(ArenaPredictionFreezeError) as ctx:
            build_prediction_freeze(
                self.prepared,
                other,
                frozen_at="2026-09-26T19:00:00Z",
                recorder_identity="Eval Lab",
                recorder_role="custodian",
            )
        self.assertIn("different blind packet", str(ctx.exception))

    def test_bundle_digest_drift_fails_closed(self) -> None:
        broken = copy.deepcopy(self.handoff)
        broken.pop("handoff_digest")
        broken["cases"][0]["bundle"]["status"] = "TAMPERED"
        broken["handoff_digest"] = canonical_digest(broken)
        with self.assertRaises(ArenaPredictionFreezeError) as ctx:
            build_prediction_freeze(
                self.prepared,
                broken,
                frozen_at="2026-09-26T19:00:00Z",
                recorder_identity="Eval Lab",
                recorder_role="custodian",
            )
        self.assertIn("bundle digest mismatch", str(ctx.exception))

    def test_blindness_record_requires_truth_after_freeze(self) -> None:
        freeze = build_prediction_freeze(
            self.prepared,
            self.handoff,
            frozen_at="2026-09-26T19:00:00Z",
            recorder_identity="Eval Lab",
            recorder_role="custodian",
        )

        with self.assertRaises(ArenaPredictionFreezeError):
            build_blindness_record(
                freeze,
                ground_truth_digest="sha256:" + "a" * 64,
                truth_revealed_at="2026-09-26T19:00:00Z",
                evaluator_independent=True,
                contamination="UNCONTAMINATED",
            )
        with self.assertRaises(ArenaPredictionFreezeError):
            build_blindness_record(
                freeze,
                ground_truth_digest="sha256:" + "a" * 64,
                truth_revealed_at="2026-09-26T18:59:59Z",
                evaluator_independent=True,
                contamination="UNCONTAMINATED",
            )

    def test_blindness_record_uses_frozen_prediction_digest(self) -> None:
        freeze = build_prediction_freeze(
            self.prepared,
            self.handoff,
            frozen_at="2026-09-26T19:00:00+00:00",
            recorder_identity="Independent Eval Operator",
            recorder_role="prediction-custodian",
        )
        blindness = build_blindness_record(
            freeze,
            ground_truth_digest="sha256:" + "b" * 64,
            truth_revealed_at="2026-09-26T19:01:00+00:00",
            evaluator_independent=True,
            contamination="UNCONTAMINATED",
        )

        self.assertEqual(blindness["schema_version"], BLINDNESS_SCHEMA_VERSION)
        self.assertTrue(blindness["truth_revealed_after_predictions"])
        self.assertEqual(blindness["prediction_digest"], freeze["prediction_digest"])
        self.assertEqual(blindness["prediction_freeze_digest"], freeze["freeze_digest"])
        self.assertEqual(blindness["ground_truth_digest"], "sha256:" + "b" * 64)
        self.assertTrue(blindness["scope"]["ordering_checked"])
        self.assertFalse(blindness["scope"]["establishes_evaluator_independence"])

    def test_blindness_record_rejects_bad_truth_digest_and_naive_timestamps(self) -> None:
        freeze = build_prediction_freeze(
            self.prepared,
            self.handoff,
            frozen_at="2026-09-26T19:00:00Z",
            recorder_identity="Eval Lab",
            recorder_role="custodian",
        )
        with self.assertRaises(ArenaPredictionFreezeError):
            build_blindness_record(
                freeze,
                ground_truth_digest="not-a-digest",
                truth_revealed_at="2026-09-26T19:01:00Z",
                evaluator_independent=True,
                contamination="UNCONTAMINATED",
            )

        with self.assertRaises(ArenaPredictionFreezeError):
            build_prediction_freeze(
                self.prepared,
                self.handoff,
                frozen_at="2026-09-26T19:00:00",
                recorder_identity="Eval Lab",
                recorder_role="custodian",
            )

    def test_freeze_digest_tampering_is_detected_before_blindness(self) -> None:
        freeze = build_prediction_freeze(
            self.prepared,
            self.handoff,
            frozen_at="2026-09-26T19:00:00Z",
            recorder_identity="Eval Lab",
            recorder_role="custodian",
        )
        freeze["case_count"] = 999
        with self.assertRaises(ArenaPredictionFreezeError) as ctx:
            build_blindness_record(
                freeze,
                ground_truth_digest="sha256:" + "c" * 64,
                truth_revealed_at="2026-09-26T19:01:00Z",
                evaluator_independent=False,
                contamination="UNASSESSED",
            )
        self.assertIn("digest", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
