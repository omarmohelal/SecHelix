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
