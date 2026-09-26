#!/usr/bin/env python3
"""Build a fail-closed Arena handoff for a complete blind-packet run set.

This helper does not score SecHelix and does not establish evaluator independence.
It takes a PREPARED Arena manifest plus one manifest-verified SecHelix workspace
per opaque case ID and produces a digest-stable handoff for an independent
evaluator. Every prepared case must be covered exactly once.

The output intentionally contains operational telemetry and artifact digests
only. It never copies node output bodies, blind truth, repository source, or
credential material into the handoff.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from evals.arena import SCHEMA_VERSION as ARENA_SCHEMA_VERSION
from evals.arena_measurement_bundle import (
    READY,
    ArenaMeasurementBundleError,
    build_bundle_from_workspace,
)


SCHEMA_VERSION = "sechelix-arena-batch-handoff/v1"
READY_STATUS = "READY_FOR_INDEPENDENT_BATCH_ASSESSMENT"


class ArenaBatchHandoffError(ValueError):
    """The prepared manifest or case-run mapping is incomplete or ambiguous."""


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
        raise ArenaBatchHandoffError(f"{label} cannot be read as JSON") from exc
    if not isinstance(value, Mapping):
        raise ArenaBatchHandoffError(f"{label} must be a JSON object")
    return value


def _resolve_inside(base_dir: Path, raw: str, *, expect_dir: bool) -> Path:
    candidate = Path(raw)
    if candidate.is_absolute():
        raise ArenaBatchHandoffError("case paths must be relative to --base-dir")
    base = base_dir.resolve()
    resolved = (base / candidate).resolve()
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ArenaBatchHandoffError("case path escapes --base-dir") from exc
    if expect_dir:
        if not resolved.is_dir():
            raise ArenaBatchHandoffError(f"workspace root does not exist: {raw}")
    elif not resolved.is_file():
        raise ArenaBatchHandoffError(f"run artifact does not exist: {raw}")
    return resolved


def _prepared_case_ids(manifest: Mapping[str, Any]) -> list[str]:
    if manifest.get("schema_version") != ARENA_SCHEMA_VERSION:
        raise ArenaBatchHandoffError("unsupported Arena manifest schema")
    if manifest.get("phase") != "PREPARED":
        raise ArenaBatchHandoffError("Arena manifest must be in PREPARED phase")
    packet = manifest.get("packet")
    if not isinstance(packet, Mapping):
        raise ArenaBatchHandoffError("prepared manifest packet record missing")
    case_ids = packet.get("case_ids")
    if (
        not isinstance(case_ids, list)
        or not case_ids
        or not all(isinstance(item, str) and item.startswith("CASE-") for item in case_ids)
    ):
        raise ArenaBatchHandoffError("prepared manifest case identities are invalid")
    if len(case_ids) != len(set(case_ids)):
        raise ArenaBatchHandoffError("prepared manifest contains duplicate case IDs")
    return sorted(case_ids)


def _numeric_summary(values: list[Any]) -> dict[str, Any]:
    """Aggregate a complete numeric vector without treating missing data as zero."""

    numeric: list[float] = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return {
                "complete": False,
                "measured_count": len(numeric),
                "applicable_count": len(values),
                "total": "NOT_MEASURED",
                "mean": "NOT_MEASURED",
                "min": "NOT_MEASURED",
                "max": "NOT_MEASURED",
            }
        numeric.append(float(value))
    if not numeric:
        return {
            "complete": True,
            "measured_count": 0,
            "applicable_count": 0,
            "total": "NOT_APPLICABLE",
            "mean": "NOT_APPLICABLE",
            "min": "NOT_APPLICABLE",
            "max": "NOT_APPLICABLE",
        }
    total = round(sum(numeric), 6)
    return {
        "complete": True,
        "measured_count": len(numeric),
        "applicable_count": len(numeric),
        "total": total,
        "mean": round(total / len(numeric), 6),
        "min": round(min(numeric), 6),
        "max": round(max(numeric), 6),
    }


def _role_runtime_summary(cases: list[dict[str, Any]], role: str) -> dict[str, Any]:
    nodes: list[Mapping[str, Any]] = []
    for case in cases:
        bundle = case.get("bundle")
        if not isinstance(bundle, Mapping):
            raise ArenaBatchHandoffError("case bundle missing while summarizing runtime")
        telemetry = bundle.get("operational_telemetry")
        if not isinstance(telemetry, Mapping):
            raise ArenaBatchHandoffError("case operational telemetry missing")
        role_runtime = telemetry.get("role_runtime")
        if not isinstance(role_runtime, Mapping):
            raise ArenaBatchHandoffError("case role runtime telemetry missing")
        runtime = role_runtime.get(role)
        if not isinstance(runtime, Mapping) or runtime.get("present") is not True:
            raise ArenaBatchHandoffError(f"{role} runtime telemetry missing")
        raw_nodes = runtime.get("nodes")
        if not isinstance(raw_nodes, list) or not raw_nodes:
            raise ArenaBatchHandoffError(f"{role} runtime nodes missing")
        for node in raw_nodes:
            if not isinstance(node, Mapping):
                raise ArenaBatchHandoffError(f"{role} runtime node is malformed")
            nodes.append(node)

    statuses: dict[str, int] = {}
    for node in nodes:
        status = str(node.get("status") or "UNKNOWN")
        statuses[status] = statuses.get(status, 0) + 1

    return {
        "node_count": len(nodes),
        "status_counts": dict(sorted(statuses.items())),
        "duration_seconds": _numeric_summary(
            [node.get("duration_seconds") for node in nodes]
        ),
        "input_tokens": _numeric_summary(
            [node.get("input_tokens") for node in nodes]
        ),
        "output_tokens": _numeric_summary(
            [node.get("output_tokens") for node in nodes]
        ),
        "cost_usd": _numeric_summary(
            [node.get("cost_usd") for node in nodes]
        ),
    }


def _batch_operational_summary(cases: list[dict[str, Any]]) -> dict[str, Any]:
    telemetry_rows: list[Mapping[str, Any]] = []
    for case in cases:
        bundle = case.get("bundle")
        if not isinstance(bundle, Mapping):
            raise ArenaBatchHandoffError("case bundle missing while summarizing operations")
        telemetry = bundle.get("operational_telemetry")
        if not isinstance(telemetry, Mapping):
            raise ArenaBatchHandoffError("case operational telemetry missing")
        telemetry_rows.append(telemetry)

    elapsed = _numeric_summary(
        [row.get("elapsed_seconds") for row in telemetry_rows]
    )
    input_tokens = _numeric_summary(
        [row.get("input_tokens") for row in telemetry_rows]
    )
    output_tokens = _numeric_summary(
        [row.get("output_tokens") for row in telemetry_rows]
    )
    cost = _numeric_summary([row.get("cost") for row in telemetry_rows])

    return {
        "case_count": len(cases),
        "agent_hosts": sorted(
            {
                str(row.get("agent_host"))
                for row in telemetry_rows
                if row.get("agent_host") not in (None, "")
            }
        ),
        "providers": sorted(
            {
                str(row.get("provider"))
                for row in telemetry_rows
                if row.get("provider") not in (None, "")
            }
        ),
        "models": sorted(
            {
                str(row.get("model"))
                for row in telemetry_rows
                if row.get("model") not in (None, "")
            }
        ),
        "elapsed_seconds": elapsed,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cost_usd": cost,
        "independent_verifier": _role_runtime_summary(
            cases, "independent_verifier"
        ),
        "release_gate": _role_runtime_summary(cases, "release_gate"),
        "measurement_scope": {
            "operational_only": True,
            "scores_correctness": False,
            "note": (
                "Totals describe manifest-bound Arena run operations across the "
                "complete packet. Missing token/cost telemetry remains "
                "NOT_MEASURED and no correctness metric is inferred."
            ),
        },
    }


def build_batch_handoff(
    manifest: Mapping[str, Any],
    run_map: Mapping[str, Any],
    *,
    base_dir: Path | str = ".",
) -> dict[str, Any]:
    """Build one complete independent-assessor handoff for all prepared cases."""

    expected_ids = _prepared_case_ids(manifest)
    raw_cases = run_map.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ArenaBatchHandoffError("run map must contain a non-empty cases list")

    case_rows: dict[str, Mapping[str, Any]] = {}
    for raw in raw_cases:
        if not isinstance(raw, Mapping):
            raise ArenaBatchHandoffError("every run-map case must be an object")
        case_id = raw.get("case_id")
        if not isinstance(case_id, str) or not case_id.startswith("CASE-"):
            raise ArenaBatchHandoffError("every run-map case needs an opaque CASE- identifier")
        if case_id in case_rows:
            raise ArenaBatchHandoffError(f"duplicate run-map case: {case_id}")
        case_rows[case_id] = raw

    observed_ids = sorted(case_rows)
    if observed_ids != expected_ids:
        missing = sorted(set(expected_ids) - set(observed_ids))
        extra = sorted(set(observed_ids) - set(expected_ids))
        raise ArenaBatchHandoffError(
            f"run map must cover every prepared case exactly once; missing={missing}, extra={extra}"
        )

    root = Path(base_dir)
    cases: list[dict[str, Any]] = []
    run_ids: set[str] = set()
    for case_id in expected_ids:
        raw = case_rows[case_id]
        run_path = raw.get("run_path")
        workspace_root = raw.get("workspace_root")
        run_id = raw.get("run_id")
        agent_host = raw.get("agent_host")
        if not isinstance(run_path, str) or not run_path.strip():
            raise ArenaBatchHandoffError(f"{case_id}.run_path missing")
        if not isinstance(workspace_root, str) or not workspace_root.strip():
            raise ArenaBatchHandoffError(f"{case_id}.workspace_root missing")
        if not isinstance(run_id, str) or not run_id.startswith("RUN-"):
            raise ArenaBatchHandoffError(f"{case_id}.run_id is invalid")
        if run_id in run_ids:
            raise ArenaBatchHandoffError(f"run_id reused across cases: {run_id}")
        run_ids.add(run_id)
        if not isinstance(agent_host, str) or not agent_host.strip():
            raise ArenaBatchHandoffError(f"{case_id}.agent_host missing")

        resolved_run = _resolve_inside(root, run_path.strip(), expect_dir=False)
        resolved_workspace = _resolve_inside(root, workspace_root.strip(), expect_dir=True)

        try:
            bundle = build_bundle_from_workspace(
                run_path=resolved_run,
                workspace_root=resolved_workspace,
                run_id=run_id,
                agent_host=agent_host.strip(),
            )
        except (ArenaMeasurementBundleError, ValueError) as exc:
            raise ArenaBatchHandoffError(
                f"{case_id} failed measurement-bundle validation: {exc}"
            ) from exc

        if bundle.get("status") != READY:
            raise ArenaBatchHandoffError(f"{case_id} is not ready for independent assessment")
        identity = bundle.get("run_identity")
        if not isinstance(identity, Mapping) or identity.get("run_id") != run_id:
            raise ArenaBatchHandoffError(f"{case_id} bundle run identity mismatch")

        cases.append(
            {
                "case_id": case_id,
                "run_id": run_id,
                "bundle_digest": _canonical_digest(bundle),
                "bundle": bundle,
            }
        )

    packet = manifest["packet"]
    participant = manifest.get("participant")
    handoff = {
        "schema_version": SCHEMA_VERSION,
        "status": READY_STATUS,
        "measurement_status": "NOT_MEASURED",
        "packet": {
            "digest": packet.get("digest"),
            "case_count": len(expected_ids),
            "case_id_digest": packet.get("case_id_digest"),
        },
        "participant": dict(participant) if isinstance(participant, Mapping) else participant,
        "case_count": len(cases),
        "cases": cases,
        "operational_summary": _batch_operational_summary(cases),
        "measurement_scope": {
            "scores_correctness": False,
            "establishes_evaluator_independence": False,
            "reveals_ground_truth": False,
            "requires_independent_assessor": True,
            "note": (
                "Every prepared case is bound to manifest-verified SecHelix run evidence. "
                "The independent evaluator must still judge workflow correctness and "
                "satisfy Arena blindness/contamination requirements."
            ),
        },
    }
    handoff["handoff_digest"] = _canonical_digest(
        {key: value for key, value in handoff.items() if key != "handoff_digest"}
    )
    return handoff


def build_batch_from_files(
    *,
    manifest_path: Path | str,
    run_map_path: Path | str,
    base_dir: Path | str = ".",
) -> dict[str, Any]:
    return build_batch_handoff(
        _read_object(manifest_path, "prepared Arena manifest"),
        _read_object(run_map_path, "run map"),
        base_dir=base_dir,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--run-map", required=True, type=Path)
    parser.add_argument("--base-dir", type=Path, default=Path("."))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    result = build_batch_from_files(
        manifest_path=args.manifest,
        run_map_path=args.run_map,
        base_dir=args.base_dir,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
