from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from evals.arena import MEASURED, canonical_digest, finalize_manifest, prepare_manifest
from evals.arena_batch import READY_STATUS as BATCH_READY_STATUS
from evals.arena_batch_assessor import (
    ArenaBatchAssessmentError,
    READY_STATUS,
    WORKFLOW_FIELDS,
    build_batch_assessment,
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

ASSESSOR = {
    "identity": "Independent Eval Lab",
    "independent": True,
    "independence_basis": (
        "The assessor is organizationally separate from the participant and received "
        "ground truth only after predictions were cryptographically frozen."
    ),
    "attestation_url": "https://independent.example/attestations/arena-1",
}

RUN = {
    "agent_host": "isolated-eval-host",
    "provider": "MULTI",
    "model": "MULTI",
    "started_at": "2026-09-26T10:00:00Z",
    "finished_at": "2026-09-26T10:10:00Z",
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


def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def make_handoff(root: Path) -> tuple[dict, dict[str, str]]:
    artifacts: dict[str, str] = {}
    cases = []
    for case_id in ("CASE-A", "CASE-B"):
        case_root = root / case_id
        replay = case_root / "replay" / "outcomes.json"
        run = case_root / "run.json"
        graph = case_root / "graph.json"
        manifest = case_root / "manifest.json"
        replay.parent.mkdir(parents=True)
        replay.write_text(
            json.dumps({"case": case_id, "role": "verifier", "marker": "PRIVATE-CONTENT"}),
            encoding="utf-8",
        )
        run.write_text(json.dumps({"case": case_id}), encoding="utf-8")
        graph.write_text(json.dumps({"nodes": []}), encoding="utf-8")
        manifest.write_text(json.dumps({"manifest": True}), encoding="utf-8")

        workspace_artifacts = {
            "run.json": file_digest(run),
            "graph.json": file_digest(graph),
            "replay/outcomes.json": file_digest(replay),
            "manifest.json": file_digest(manifest),
        }
        cases.append(
            {
                "case_id": case_id,
                "run_id": f"RUN-{case_id}",
                "bundle_digest": "sha256:" + ("a" if case_id == "CASE-A" else "b") * 64,
                "bundle": {
                    "schema_version": "sechelix-arena-measurement-bundle/v1",
                    "status": "READY_FOR_INDEPENDENT_ASSESSMENT",
                    "run_identity": {"run_id": f"RUN-{case_id}"},
                    "bindings": {
                        "workspace_artifacts": workspace_artifacts,
                    },
                    "assessment_targets": {
                        "independent_verifier": [
                            {
                                "node_id": "verifier",
                                "artifact_ref": "replay/outcomes.json",
                            }
                        ],
                        "release_gate": [
                            {
                                "node_id": "gate",
                                "artifact_ref": "replay/outcomes.json",
                            }
                        ],
                    },
                },
            }
        )
        artifacts[case_id] = str(replay.relative_to(root))

    prepared = prepare_manifest(PACKET, PARTICIPANT)
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
    return handoff, artifacts


def make_spec(handoff: dict, artifacts: dict[str, str]) -> dict:
    observations = []
    for case_id in ("CASE-A", "CASE-B"):
        judgments = {}
        for field in WORKFLOW_FIELDS:
            judgments[field] = {
                "value": True,
                "basis": (
                    f"Independent assessor compared {field} for {case_id} against "
                    "sealed expected workflow behavior and the manifest-verified run evidence."
                ),
                "artifacts": [
                    {
                        "artifact_ref": "replay/outcomes.json",
                        "path": artifacts[case_id],
                    }
                ],
            }
        observations.append({"case_id": case_id, "judgments": judgments})
    return {
        "handoff_digest": handoff["handoff_digest"],
        "packet_digest": handoff["packet"]["digest"],
        "assessor": ASSESSOR,
        "observations": observations,
    }


class ArenaBatchAssessmentTests(unittest.TestCase):
    def test_complete_assessment_binds_only_manifest_verified_artifacts(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            handoff, artifacts = make_handoff(root)
            assessment = build_batch_assessment(
                handoff,
                make_spec(handoff, artifacts),
                base_dir=root,
            )

            self.assertEqual(assessment["batch_binding"]["status"], READY_STATUS)
            self.assertTrue(
                assessment["batch_binding"]["manifest_verified_artifacts_only"]
            )
            self.assertFalse(assessment["batch_binding"]["scores_correctness"])
            self.assertEqual(
                [row["case_id"] for row in assessment["observations"]],
                ["CASE-A", "CASE-B"],
            )
            rendered = json.dumps(assessment, sort_keys=True)
            self.assertNotIn("PRIVATE-CONTENT", rendered)
            self.assertNotIn(str(root), rendered)
            self.assertNotIn(artifacts["CASE-A"], rendered)
            self.assertIn(
                "case:CASE-A:workspace:replay/outcomes.json",
                rendered,
            )

    def test_result_is_compatible_with_fail_closed_arena_finalize(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            handoff, artifacts = make_handoff(root)
            assessment = build_batch_assessment(
                handoff,
                make_spec(handoff, artifacts),
                base_dir=root,
            )
            result = finalize_manifest(
                prepare_manifest(PACKET, PARTICIPANT),
                run=RUN,
                blindness=BLINDNESS,
                assessment=assessment,
            )
            self.assertEqual(result["measurement_status"], MEASURED)
            self.assertTrue(result["publication"]["eligible"])
            self.assertEqual(result["full_workflow"]["verification_accuracy"], 1.0)
            self.assertEqual(result["full_workflow"]["release_gate_accuracy"], 1.0)

    def test_handoff_digest_tampering_fails_closed(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            handoff, artifacts = make_handoff(root)
            handoff["case_count"] = 999
            with self.assertRaises(ArenaBatchAssessmentError) as ctx:
                build_batch_assessment(
                    handoff,
                    make_spec(handoff, artifacts),
                    base_dir=root,
                )
            self.assertIn("digest", str(ctx.exception).lower())

    def test_assessment_must_cover_every_batch_case_exactly_once(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            handoff, artifacts = make_handoff(root)
            spec = make_spec(handoff, artifacts)
            spec["observations"].pop()
            with self.assertRaises(ArenaBatchAssessmentError) as ctx:
                build_batch_assessment(handoff, spec, base_dir=root)
            self.assertIn("every batch case", str(ctx.exception))

            spec = make_spec(handoff, artifacts)
            spec["observations"].append(copy.deepcopy(spec["observations"][0]))
            with self.assertRaises(ArenaBatchAssessmentError):
                build_batch_assessment(handoff, spec, base_dir=root)

    def test_artifact_must_be_named_in_same_case_verified_bundle(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            handoff, artifacts = make_handoff(root)
            spec = make_spec(handoff, artifacts)
            spec["observations"][0]["judgments"]["verification"]["artifacts"][0][
                "artifact_ref"
            ] = "private/unmanifested.txt"
            with self.assertRaises(ArenaBatchAssessmentError) as ctx:
                build_batch_assessment(handoff, spec, base_dir=root)
            self.assertIn("manifest-verified", str(ctx.exception))

    def test_changed_artifact_or_path_escape_fails_closed(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            handoff, artifacts = make_handoff(root)
            replay = root / artifacts["CASE-A"]
            replay.write_text('{"tampered":true}', encoding="utf-8")
            with self.assertRaises(ArenaBatchAssessmentError) as ctx:
                build_batch_assessment(
                    handoff,
                    make_spec(handoff, artifacts),
                    base_dir=root,
                )
            self.assertIn("digest mismatch", str(ctx.exception))

            handoff, artifacts = make_handoff(root)
            spec = make_spec(handoff, artifacts)
            spec["observations"][0]["judgments"]["verification"]["artifacts"][0][
                "path"
            ] = "../outside.json"
            with self.assertRaises(ArenaBatchAssessmentError) as ctx:
                build_batch_assessment(handoff, spec, base_dir=root)
            self.assertIn("escapes", str(ctx.exception))

    def test_not_applicable_requires_no_artifact_and_does_not_invent_evidence(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            handoff, artifacts = make_handoff(root)
            spec = make_spec(handoff, artifacts)
            spec["observations"][0]["judgments"]["regression_proof"] = {
                "value": "NOT_APPLICABLE"
            }
            result = build_batch_assessment(handoff, spec, base_dir=root)
            row = result["observations"][0]
            self.assertEqual(row["regression_proof"], "NOT_APPLICABLE")
            self.assertNotIn("regression_proof", row["evidence"])

    def test_wrong_batch_binding_or_packet_digest_is_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            handoff, artifacts = make_handoff(root)
            spec = make_spec(handoff, artifacts)
            spec["handoff_digest"] = "sha256:" + "9" * 64
            with self.assertRaises(ArenaBatchAssessmentError):
                build_batch_assessment(handoff, spec, base_dir=root)

            spec = make_spec(handoff, artifacts)
            spec["packet_digest"] = "sha256:" + "8" * 64
            with self.assertRaises(ArenaBatchAssessmentError):
                build_batch_assessment(handoff, spec, base_dir=root)


if __name__ == "__main__":
    unittest.main()
