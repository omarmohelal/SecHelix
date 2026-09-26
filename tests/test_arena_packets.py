from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from evals.arena import MEASURED, canonical_digest, finalize_manifest, prepare_manifest
from evals.arena_packets import (
    AssessmentPacketError,
    WORKFLOW_FIELDS,
    artifact_bundle_digest,
    build_assessment_packet,
)


PACKET = {
    "cases": [
        {"case_id": "CASE-A", "family": "Authorization", "source": "opaque-a"},
    ]
}

PARTICIPANT = {
    "participant_id": "demo-agent",
    "display_name": "Demo Agent",
    "category": "AGENT_WORKFLOW",
    "source_url": "https://participant.example/demo-agent",
    "version": "1.2.3",
    "capability_scope": ["security_review", "verification", "regression_proof"],
}

RUN = {
    "agent_host": "isolated-eval-host",
    "provider": "NOT_APPLICABLE",
    "model": "NOT_APPLICABLE",
    "started_at": "2026-09-26T09:00:00Z",
    "finished_at": "2026-09-26T09:05:00Z",
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

ASSESSOR = {
    "identity": "Independent Eval Lab",
    "independent": True,
    "independence_basis": (
        "The evaluator did not author participant predictions and received sealed "
        "ground truth only after the prediction digest was fixed."
    ),
    "attestation_url": "https://independent.example/attestations/run-1",
}


def make_spec(artifact_path: str = "artifacts/case-a.json") -> dict[str, object]:
    judgments: dict[str, object] = {}
    for field in WORKFLOW_FIELDS:
        judgments[field] = {
            "value": True,
            "basis": (
                f"Independent evaluator compared {field} for CASE-A with the "
                "sealed expected workflow outcome and recorded run artifact."
            ),
            "artifacts": [
                {
                    "ref": f"run:CASE-A:{field}",
                    "path": artifact_path,
                }
            ],
        }
    return {
        "packet_digest": canonical_digest(PACKET),
        "assessor": ASSESSOR,
        "observations": [
            {
                "case_id": "CASE-A",
                "judgments": judgments,
            }
        ],
    }


class ArenaAssessmentPacketTests(unittest.TestCase):
    def test_builder_hashes_artifacts_without_persisting_contents_or_local_paths(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "artifacts" / "case-a.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(
                '{"private_marker":"DO-NOT-COPY-MARKER","result":"verified"}',
                encoding="utf-8",
            )

            packet = build_assessment_packet(make_spec(), base_dir=root)
            rendered = json.dumps(packet, sort_keys=True)

            self.assertNotIn("DO-NOT-COPY-MARKER", rendered)
            self.assertNotIn(str(root), rendered)
            self.assertNotIn("artifacts/case-a.json", rendered)
            observation = packet["observations"][0]
            for field in WORKFLOW_FIELDS:
                evidence = observation["evidence"][field]
                self.assertEqual(evidence["refs"], [f"run:CASE-A:{field}"])
                self.assertTrue(evidence["artifact_digest"].startswith("sha256:"))

    def test_packet_is_compatible_with_fail_closed_arena_finalization(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "artifacts" / "case-a.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text('{"result":"independently-assessed"}', encoding="utf-8")

            assessment = build_assessment_packet(make_spec(), base_dir=root)
            result = finalize_manifest(
                prepare_manifest(PACKET, PARTICIPANT),
                run=RUN,
                blindness=BLINDNESS,
                assessment=assessment,
            )

            self.assertEqual(result["measurement_status"], MEASURED)
            self.assertTrue(result["publication"]["eligible"])
            self.assertEqual(result["full_workflow"]["verification_accuracy"], 1.0)
            self.assertEqual(result["full_workflow"]["regression_proof_accuracy"], 1.0)
            self.assertEqual(result["full_workflow"]["release_gate_accuracy"], 1.0)

    def test_not_applicable_judgment_requires_no_fake_evidence(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "artifacts" / "case-a.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("{}", encoding="utf-8")
            spec = make_spec()
            observation = spec["observations"][0]
            observation["judgments"]["regression_proof"] = {
                "value": "NOT_APPLICABLE"
            }

            assessment = build_assessment_packet(spec, base_dir=root)
            row = assessment["observations"][0]
            self.assertEqual(row["regression_proof"], "NOT_APPLICABLE")
            self.assertNotIn("regression_proof", row["evidence"])

    def test_missing_or_escaping_artifact_fails_closed(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(AssessmentPacketError):
                build_assessment_packet(make_spec("missing.json"), base_dir=root)

            outside = root.parent / "outside-arena-evidence.txt"
            outside.write_text("outside", encoding="utf-8")
            try:
                with self.assertRaises(AssessmentPacketError):
                    build_assessment_packet(make_spec("../outside-arena-evidence.txt"), base_dir=root)
            finally:
                outside.unlink(missing_ok=True)

    def test_duplicate_artifact_refs_are_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "first.json"
            second = root / "second.json"
            first.write_text("one", encoding="utf-8")
            second.write_text("two", encoding="utf-8")
            with self.assertRaises(AssessmentPacketError):
                artifact_bundle_digest(
                    [
                        {"ref": "same-ref", "path": "first.json"},
                        {"ref": "same-ref", "path": "second.json"},
                    ],
                    base_dir=root,
                )

    def test_missing_workflow_field_is_rejected_before_arena(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "artifacts" / "case-a.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("{}", encoding="utf-8")
            spec = make_spec()
            del spec["observations"][0]["judgments"]["release_gate"]
            with self.assertRaises(AssessmentPacketError):
                build_assessment_packet(spec, base_dir=root)

    def test_boolean_judgment_requires_basis_and_artifact(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "artifacts" / "case-a.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("{}", encoding="utf-8")

            spec = make_spec()
            spec["observations"][0]["judgments"]["verification"]["basis"] = "too short"
            with self.assertRaises(AssessmentPacketError):
                build_assessment_packet(spec, base_dir=root)

            spec = make_spec()
            spec["observations"][0]["judgments"]["verification"]["artifacts"] = []
            with self.assertRaises(AssessmentPacketError):
                build_assessment_packet(spec, base_dir=root)


if __name__ == "__main__":
    unittest.main()
