#!/usr/bin/env python3
"""Bind SecHelix Arena run telemetry to a manifest-verified workspace index.

This helper does not score security correctness. It creates one fail-closed
measurement bundle that proves the operational telemetry and the workspace
evidence refer to the same SecHelix run before an independent evaluator judges
verification, regression, or release-gate correctness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from evals.arena_run import build_arena_run_record
from evals.arena_workspace import build_workspace_evidence_index


SCHEMA_VERSION = "sechelix-arena-measurement-bundle/v1"
READY = "READY_FOR_INDEPENDENT_ASSESSMENT"


class ArenaMeasurementBundleError(ValueError):
    pass


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _read_object(path: Path | str, label: str) -> Mapping[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArenaMeasurementBundleError(f"{label} cannot be read as JSON") from exc
    if not isinstance(payload, Mapping):
        raise ArenaMeasurementBundleError(f"{label} must be a JSON object")
    return payload


def _require_equal(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
    field: str,
) -> None:
    left_value = left.get(field)
    right_value = right.get(field)
    if left_value in (None, "") or right_value in (None, ""):
        raise ArenaMeasurementBundleError(f"{field} missing from bound evidence")
    if left_value != right_value:
        raise ArenaMeasurementBundleError(
            f"{field} mismatch between run telemetry and workspace evidence"
        )


def build_measurement_bundle(
    run_record: Mapping[str, Any],
    workspace_index: Mapping[str, Any],
) -> dict[str, Any]:
    if run_record.get("schema_version") != "sechelix-arena-run/v1":
        raise ArenaMeasurementBundleError("unsupported arena run telemetry schema")
    if workspace_index.get("schema_version") != "sechelix-arena-workspace-evidence/v1":
        raise ArenaMeasurementBundleError("unsupported workspace evidence schema")
    if workspace_index.get("workspace_integrity") != "VERIFIED":
        raise ArenaMeasurementBundleError("workspace integrity is not VERIFIED")

    for field in ("run_id", "target_commit", "scope_id", "graph_digest"):
        _require_equal(run_record, workspace_index, field)

    role_evidence = workspace_index.get("role_evidence")
    if not isinstance(role_evidence, Mapping):
        raise ArenaMeasurementBundleError("workspace role evidence missing")
    verifier = role_evidence.get("INDEPENDENT_VERIFIER")
    gate = role_evidence.get("RELEASE_GATE")
    if not isinstance(verifier, list) or not verifier:
        raise ArenaMeasurementBundleError(
            "manifest-verified INDEPENDENT_VERIFIER evidence is required"
        )
    if not isinstance(gate, list) or not gate:
        raise ArenaMeasurementBundleError(
            "manifest-verified RELEASE_GATE evidence is required"
        )

    operational = run_record.get("operational_metrics")
    if not isinstance(operational, Mapping):
        raise ArenaMeasurementBundleError("arena run operational metrics missing")
    verifier_runtime = operational.get("independent_verifier")
    gate_runtime = operational.get("release_gate")
    if not isinstance(verifier_runtime, Mapping) or verifier_runtime.get("present") is not True:
        raise ArenaMeasurementBundleError("run telemetry has no independent verifier node")
    if not isinstance(gate_runtime, Mapping) or gate_runtime.get("present") is not True:
        raise ArenaMeasurementBundleError("run telemetry has no release gate node")

    artifacts = workspace_index.get("artifacts")
    if not isinstance(artifacts, Mapping) or not artifacts:
        raise ArenaMeasurementBundleError("workspace artifact digests missing")

    return {
        "schema_version": SCHEMA_VERSION,
        "status": READY,
        "run_identity": {
            field: run_record[field]
            for field in ("run_id", "target_commit", "scope_id", "graph_digest")
        },
        "bindings": {
            "arena_run_digest": _canonical_digest(run_record),
            "workspace_evidence_digest": _canonical_digest(workspace_index),
            "workspace_artifacts": dict(artifacts),
        },
        "operational_telemetry": {
            "agent_host": run_record.get("agent_host"),
            "provider": run_record.get("provider"),
            "model": run_record.get("model"),
            "started_at": run_record.get("started_at"),
            "finished_at": run_record.get("finished_at"),
            "elapsed_seconds": run_record.get("elapsed_seconds"),
            "input_tokens": run_record.get("input_tokens"),
            "output_tokens": run_record.get("output_tokens"),
            "cost": run_record.get("cost"),
            "telemetry_completeness": operational.get("telemetry_completeness"),
        },
        "assessment_targets": {
            "independent_verifier": verifier,
            "release_gate": gate,
        },
        "measurement_scope": {
            "scores_correctness": False,
            "requires_independent_assessor": True,
            "next_step": (
                "Use the manifest-verified artifacts referenced by this bundle "
                "to produce an independent Arena assessment; this bundle itself "
                "does not assign workflow correctness."
            ),
        },
    }


def build_bundle_from_workspace(
    *,
    run_path: Path | str,
    workspace_root: Path | str,
    run_id: str,
    agent_host: str,
) -> dict[str, Any]:
    run = _read_object(run_path, "run artifact")
    if run.get("run_id") != run_id:
        raise ArenaMeasurementBundleError(
            "requested run_id does not match the run artifact"
        )
    run_digest = "sha256:" + hashlib.sha256(Path(run_path).read_bytes()).hexdigest()
    run_record = build_arena_run_record(
        run,
        agent_host=agent_host,
        artifact_digest=run_digest,
    )
    workspace_index = build_workspace_evidence_index(workspace_root, run_id)
    return build_measurement_bundle(run_record, workspace_index)


def _cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, help="SecHelix RunResult JSON artifact")
    parser.add_argument("--workspace-root", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--agent-host", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    bundle = build_bundle_from_workspace(
        run_path=args.run,
        workspace_root=args.workspace_root,
        run_id=args.run_id,
        agent_host=args.agent_host,
    )
    Path(args.output).write_text(
        json.dumps(bundle, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
