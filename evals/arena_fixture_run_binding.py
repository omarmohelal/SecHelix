#!/usr/bin/env python3
"""Bind a production-like LOCAL fixture result to one completed full-workflow run.

This helper is deliberately a pre-Arena integrity boundary, not a correctness
scorer. It proves that a deterministic STATEFUL_APPLICATION or
COMPOSITE_APPLICATION fixture self-test and one SecHelix full-workflow run are
both structurally valid before the normal manifest-verified Arena handoff,
prediction freeze, truth reveal, and independent assessment.

It never reads blind truth, never assigns security correctness, and never turns
fixture realism into a production-effectiveness claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA_VERSION = "sechelix-arena-fixture-run-binding/v1"
READY = "READY_FOR_ARENA_FIXTURE_HANDOFF"
NOT_MEASURED = "NOT_MEASURED"

_ALLOWED_FIXTURES = {
    "STATEFUL_APPLICATION": "sechelix-stateful-application-fixture/v1",
    "COMPOSITE_APPLICATION": "sechelix-composite-application-fixture/v1",
}

_REQUIRED_CHAIN = (
    ("INDEPENDENT_VERIFIER", None),
    ("REMEDIATOR", "INDEPENDENT_VERIFIER"),
    ("PATCH_VERIFIER", "REMEDIATOR"),
    ("RELEASE_GATE", "PATCH_VERIFIER"),
)


class ArenaFixtureRunBindingError(ValueError):
    """The fixture/run pair is not safe to hand to Arena."""


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
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArenaFixtureRunBindingError(
            f"{label} cannot be read as JSON"
        ) from exc
    if not isinstance(value, Mapping):
        raise ArenaFixtureRunBindingError(f"{label} must be a JSON object")
    return value


def _validate_fixture(
    fixture: Mapping[str, Any],
    expected_tier: str,
) -> None:
    if expected_tier not in _ALLOWED_FIXTURES:
        raise ArenaFixtureRunBindingError(
            "expected fixture tier must be STATEFUL_APPLICATION or COMPOSITE_APPLICATION"
        )
    if fixture.get("schema_version") != _ALLOWED_FIXTURES[expected_tier]:
        raise ArenaFixtureRunBindingError("fixture schema does not match expected tier")
    if fixture.get("fixture_tier") != expected_tier:
        raise ArenaFixtureRunBindingError("fixture tier mismatch")
    if fixture.get("status") != "MEASURED":
        raise ArenaFixtureRunBindingError("fixture self-test is not MEASURED")
    if fixture.get("network_scope") != "LOOPBACK_ONLY":
        raise ArenaFixtureRunBindingError("fixture network scope must be LOOPBACK_ONLY")
    if fixture.get("production_effectiveness_established") is not False:
        raise ArenaFixtureRunBindingError(
            "fixture must not claim production effectiveness"
        )
    if fixture.get("arena_full_workflow_measured") is not False:
        raise ArenaFixtureRunBindingError(
            "fixture self-test must not claim Arena full-workflow measurement"
        )

    checks = fixture.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ArenaFixtureRunBindingError("fixture checks are missing")
    if any(
        not isinstance(check, Mapping) or check.get("passed") is not True
        for check in checks
    ):
        raise ArenaFixtureRunBindingError("fixture contains a failed or malformed check")


def _record_index(run: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    records = run.get("records")
    if not isinstance(records, Mapping) or not records:
        raise ArenaFixtureRunBindingError("run.records must be a non-empty mapping")

    by_role: dict[str, Mapping[str, Any]] = {}
    for node_id, raw in records.items():
        if not isinstance(node_id, str) or not isinstance(raw, Mapping):
            raise ArenaFixtureRunBindingError("run.records contains malformed entries")
        role = raw.get("role")
        if not isinstance(role, str) or not role:
            continue
        if role in {item[0] for item in _REQUIRED_CHAIN}:
            if role in by_role:
                raise ArenaFixtureRunBindingError(
                    f"full-workflow run contains multiple {role} nodes"
                )
            row = dict(raw)
            row["_node_id"] = node_id
            by_role[role] = row
    return by_role


def _validate_full_workflow_run(run: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    run_id = run.get("run_id")
    if not isinstance(run_id, str) or not run_id.startswith("RUN-"):
        raise ArenaFixtureRunBindingError("run_id is missing or invalid")
    for field in ("target_commit", "scope_id", "graph_digest"):
        value = run.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ArenaFixtureRunBindingError(f"run.{field} is missing")

    if list(run.get("unsatisfied_mandatory") or []):
        raise ArenaFixtureRunBindingError(
            "full-workflow run has unsatisfied mandatory nodes"
        )
    if list(run.get("blocked") or []):
        raise ArenaFixtureRunBindingError("full-workflow run contains blocked nodes")
    if list(run.get("failed") or []):
        raise ArenaFixtureRunBindingError("full-workflow run contains failed nodes")

    by_role = _record_index(run)
    for role, parent_role in _REQUIRED_CHAIN:
        row = by_role.get(role)
        if row is None:
            raise ArenaFixtureRunBindingError(
                f"full-workflow run is missing {role}"
            )
        if row.get("status") != "SUCCEEDED":
            raise ArenaFixtureRunBindingError(
                f"{role} did not finish SUCCEEDED"
            )
        if parent_role is not None:
            parent = by_role[parent_role]
            parents = row.get("parent_node_ids")
            if not isinstance(parents, list) or parent.get("_node_id") not in parents:
                raise ArenaFixtureRunBindingError(
                    f"{role} is not bound to the expected {parent_role} dependency"
                )

    patch = by_role["PATCH_VERIFIER"]
    evidence_ids = patch.get("output_evidence_ids")
    if not isinstance(evidence_ids, list) or not evidence_ids:
        raise ArenaFixtureRunBindingError(
            "PATCH_VERIFIER must expose runtime verification evidence IDs"
        )

    return by_role


def build_fixture_run_binding(
    fixture: Mapping[str, Any],
    run: Mapping[str, Any],
    *,
    expected_tier: str,
) -> dict[str, Any]:
    """Return a digest-stable pre-Arena binding or fail closed."""

    _validate_fixture(fixture, expected_tier)
    roles = _validate_full_workflow_run(run)

    role_summary = {
        role: {
            "node_id": row["_node_id"],
            "status": row.get("status"),
            "output_digest": row.get("output_digest"),
            "output_evidence_ids": list(row.get("output_evidence_ids") or []),
        }
        for role, row in roles.items()
    }

    result = {
        "schema_version": SCHEMA_VERSION,
        "status": READY,
        "measurement_status": NOT_MEASURED,
        "fixture": {
            "tier": expected_tier,
            "schema_version": fixture["schema_version"],
            "result_kind": fixture.get("result_kind"),
            "network_scope": fixture["network_scope"],
            "fixture_result_digest": _canonical_digest(fixture),
        },
        "run_identity": {
            field: run[field]
            for field in ("run_id", "target_commit", "scope_id", "graph_digest")
        },
        "workflow_chain": role_summary,
        "run_artifact_digest": _canonical_digest(run),
        "measurement_scope": {
            "scores_correctness": False,
            "establishes_production_effectiveness": False,
            "reveals_ground_truth": False,
            "establishes_evaluator_independence": False,
            "requires_manifest_verified_workspace": True,
            "requires_prediction_freeze": True,
            "requires_independent_assessor": True,
            "next_step": (
                "Build the normal manifest-verified Arena measurement/batch handoff "
                "for this exact run, freeze the complete prediction packet before "
                "truth reveal, then obtain an evidence-backed independent assessment."
            ),
        },
    }
    result["binding_digest"] = _canonical_digest(
        {key: value for key, value in result.items() if key != "binding_digest"}
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-result", required=True, type=Path)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument(
        "--expected-tier",
        required=True,
        choices=sorted(_ALLOWED_FIXTURES),
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    result = build_fixture_run_binding(
        _read_object(args.fixture_result, "fixture result"),
        _read_object(args.run, "run artifact"),
        expected_tier=args.expected_tier,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
