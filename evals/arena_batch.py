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
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from evals.arena import SCHEMA_VERSION as ARENA_SCHEMA_VERSION
from evals.arena_measurement_bundle import (
    READY,
    ArenaMeasurementBundleError,
    build_bundle_from_workspace,
)
from evals.arena_run import NOT_APPLICABLE, NOT_MEASURED


SCHEMA_VERSION = "sechelix-arena-batch-handoff/v1"
READY_STATUS = "READY_FOR_INDEPENDENT_BATCH_ASSESSMENT"
FIXTURE_BINDING_SCHEMA = "sechelix-arena-fixture-run-binding/v1"
FIXTURE_BINDING_READY = "READY_FOR_ARENA_FIXTURE_HANDOFF"


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




def _fixture_binding_for_case(
    root: Path,
    raw: Mapping[str, Any],
    *,
    case_id: str,
    bundle: Mapping[str, Any],
    run_id: str,
) -> dict[str, Any] | None:
    raw_path = raw.get("fixture_binding_path")
    if raw_path in (None, ""):
        return None
    if not isinstance(raw_path, str):
        raise ArenaBatchHandoffError(
            f"{case_id}.fixture_binding_path must be a relative path"
        )

    resolved = _resolve_inside(root, raw_path.strip(), expect_dir=False)
    binding = _read_object(resolved, f"{case_id} fixture binding")
    if binding.get("schema_version") != FIXTURE_BINDING_SCHEMA:
        raise ArenaBatchHandoffError(
            f"{case_id} fixture binding schema is unsupported"
        )
    if binding.get("status") != FIXTURE_BINDING_READY:
        raise ArenaBatchHandoffError(
            f"{case_id} fixture binding is not ready for Arena handoff"
        )
    if binding.get("measurement_status") != NOT_MEASURED:
        raise ArenaBatchHandoffError(
            f"{case_id} fixture binding must remain NOT_MEASURED"
        )

    binding_identity = binding.get("run_identity")
    bundle_identity = bundle.get("run_identity")
    if not isinstance(binding_identity, Mapping) or not isinstance(bundle_identity, Mapping):
        raise ArenaBatchHandoffError(
            f"{case_id} fixture/run identity is missing"
        )
    for field in ("run_id", "target_commit", "scope_id", "graph_digest"):
        if binding_identity.get(field) != bundle_identity.get(field):
            raise ArenaBatchHandoffError(
                f"{case_id} fixture binding {field} does not match the Arena bundle"
            )
    if binding_identity.get("run_id") != run_id:
        raise ArenaBatchHandoffError(
            f"{case_id} fixture binding run_id mismatch"
        )

    bindings = bundle.get("bindings")
    if not isinstance(bindings, Mapping):
        raise ArenaBatchHandoffError(
            f"{case_id} Arena bundle bindings are missing"
        )
    bundle_run_digest = bindings.get("run_artifact_digest")
    binding_run_digest = binding.get("run_artifact_digest")
    if (
        not isinstance(bundle_run_digest, str)
        or not bundle_run_digest.startswith("sha256:")
        or binding_run_digest != bundle_run_digest
    ):
        raise ArenaBatchHandoffError(
            f"{case_id} fixture binding is not bound to the exact run artifact"
        )

    fixture = binding.get("fixture")
    if not isinstance(fixture, Mapping):
        raise ArenaBatchHandoffError(
            f"{case_id} fixture binding metadata is missing"
        )
    tier = fixture.get("tier")
    if tier not in {"STATEFUL_APPLICATION", "COMPOSITE_APPLICATION"}:
        raise ArenaBatchHandoffError(
            f"{case_id} fixture binding tier is invalid"
        )
    binding_digest = binding.get("binding_digest")
    fixture_result_digest = fixture.get("fixture_result_digest")
    for label, value in (
        ("binding_digest", binding_digest),
        ("fixture_result_digest", fixture_result_digest),
    ):
        if not isinstance(value, str) or not value.startswith("sha256:"):
            raise ArenaBatchHandoffError(
                f"{case_id} fixture binding {label} is invalid"
            )

    return {
        "tier": tier,
        "binding_digest": binding_digest,
        "fixture_result_digest": fixture_result_digest,
    }


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


def _metric_summary(values: list[Any], *, field: str) -> dict[str, Any]:
    """Aggregate one packet-wide operational metric without inventing zeroes."""

    numeric: list[float] = []
    applicable = 0
    for value in values:
        if value == NOT_APPLICABLE:
            continue
        applicable += 1
        if value == NOT_MEASURED:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ArenaBatchHandoffError(
                f"case operational telemetry field {field} is malformed"
            )
        numeric.append(float(value))

    complete = len(numeric) == applicable
    if applicable == 0:
        total: int | float | str = NOT_APPLICABLE
        mean: int | float | str = NOT_APPLICABLE
        minimum: int | float | str = NOT_APPLICABLE
        maximum: int | float | str = NOT_APPLICABLE
    elif not complete:
        total = mean = minimum = maximum = NOT_MEASURED
    else:
        raw_total = sum(numeric)
        if field in {"input_tokens", "output_tokens"}:
            total = int(raw_total)
            mean = round(raw_total / applicable, 6)
            minimum = int(min(numeric))
            maximum = int(max(numeric))
        elif field == "cost":
            total = round(raw_total, 8)
            mean = round(raw_total / applicable, 8)
            minimum = round(min(numeric), 8)
            maximum = round(max(numeric), 8)
        else:
            total = round(raw_total, 6)
            mean = round(raw_total / applicable, 6)
            minimum = round(min(numeric), 6)
            maximum = round(max(numeric), 6)

    return {
        "complete": complete,
        "measured_cases": len(numeric),
        "applicable_cases": applicable,
        "total": total,
        "mean": mean,
        "min": minimum,
        "max": maximum,
    }


def _parse_iso_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _observed_packet_span_seconds(rows: list[Mapping[str, Any]]) -> int | float | str:
    """Return earliest-start to latest-finish span when timestamps are comparable."""

    starts = [_parse_iso_timestamp(row.get("started_at")) for row in rows]
    finishes = [_parse_iso_timestamp(row.get("finished_at")) for row in rows]
    if any(item is None for item in [*starts, *finishes]):
        return NOT_MEASURED

    concrete_starts = [item for item in starts if item is not None]
    concrete_finishes = [item for item in finishes if item is not None]
    try:
        span = (max(concrete_finishes) - min(concrete_starts)).total_seconds()
    except (TypeError, ValueError):
        return NOT_MEASURED
    if span < 0:
        return NOT_MEASURED
    return round(span, 6)


def _batch_operational_summary(cases: list[dict[str, Any]]) -> dict[str, Any]:
    rows: list[Mapping[str, Any]] = []
    for case in cases:
        bundle = case.get("bundle")
        if not isinstance(bundle, Mapping):
            raise ArenaBatchHandoffError("case bundle missing while summarizing operations")
        telemetry = bundle.get("operational_telemetry")
        if not isinstance(telemetry, Mapping):
            raise ArenaBatchHandoffError("case operational telemetry missing")
        rows.append(telemetry)

    return {
        "case_count": len(cases),
        "agent_hosts": sorted(
            {
                str(row.get("agent_host")).strip()
                for row in rows
                if isinstance(row.get("agent_host"), str)
                and str(row.get("agent_host")).strip()
            }
        ),
        "providers": sorted(
            {
                str(row.get("provider")).strip()
                for row in rows
                if isinstance(row.get("provider"), str)
                and str(row.get("provider")).strip()
                and row.get("provider") != NOT_APPLICABLE
            }
        ),
        "models": sorted(
            {
                str(row.get("model")).strip()
                for row in rows
                if isinstance(row.get("model"), str)
                and str(row.get("model")).strip()
                and row.get("model") != NOT_APPLICABLE
            }
        ),
        "case_elapsed_seconds": _metric_summary(
            [row.get("elapsed_seconds") for row in rows],
            field="elapsed_seconds",
        ),
        "observed_packet_span_seconds": _observed_packet_span_seconds(rows),
        "input_tokens": _metric_summary(
            [row.get("input_tokens") for row in rows],
            field="input_tokens",
        ),
        "output_tokens": _metric_summary(
            [row.get("output_tokens") for row in rows],
            field="output_tokens",
        ),
        "cost_usd": _metric_summary(
            [row.get("cost") for row in rows],
            field="cost",
        ),
        "measurement_scope": {
            "operational_only": True,
            "scores_correctness": False,
            "sum_case_elapsed_is_not_packet_wall_clock": True,
            "note": (
                "Case elapsed totals sum per-run wall time and may double-count "
                "concurrent runs. observed_packet_span_seconds is earliest start "
                "to latest finish. Missing token/cost telemetry remains "
                "NOT_MEASURED rather than being coerced to zero."
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

        case_entry = {
            "case_id": case_id,
            "run_id": run_id,
            "bundle_digest": _canonical_digest(bundle),
            "bundle": bundle,
        }
        fixture_binding = _fixture_binding_for_case(
            root,
            raw,
            case_id=case_id,
            bundle=bundle,
            run_id=run_id,
        )
        if fixture_binding is not None:
            case_entry["fixture_binding"] = fixture_binding
        cases.append(case_entry)

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
            "fixture_bound_case_count": sum(
                1 for case in cases if "fixture_binding" in case
            ),
            "note": (
                "Every prepared case is bound to manifest-verified SecHelix run evidence. "
                "Cases with fixture_binding are additionally bound to an exact LOCAL "
                "stateful/composite fixture-run integrity record. The independent "
                "evaluator must still judge workflow correctness and satisfy Arena "
                "blindness/contamination requirements."
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
