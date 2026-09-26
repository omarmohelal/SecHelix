#!/usr/bin/env python3
"""Build Arena run telemetry from a SecHelix run artifact.

This helper does not score security correctness. It reduces one completed
SecHelix run into operational metadata that can be supplied to
`evals/arena.py finalize` without turning missing telemetry into zero.

The input is expected to be the JSON form of `RunResult.to_dict()`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

NOT_MEASURED = "NOT_MEASURED"
NOT_APPLICABLE = "NOT_APPLICABLE"
SCHEMA_VERSION = "sechelix-arena-run/v1"


class ArenaRunTelemetryError(ValueError):
    pass


def _read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ArenaRunTelemetryError(f"{field} missing")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise ArenaRunTelemetryError(f"{field} is not ISO-8601") from exc


def _records(run: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    records = run.get("records")
    if not isinstance(records, Mapping) or not records:
        raise ArenaRunTelemetryError("run.records must be a non-empty mapping")
    output: dict[str, Mapping[str, Any]] = {}
    for node_id, raw in records.items():
        if not isinstance(node_id, str) or not node_id.strip():
            raise ArenaRunTelemetryError("run.records contains an invalid node id")
        if not isinstance(raw, Mapping):
            raise ArenaRunTelemetryError(f"run.records.{node_id} must be an object")
        output[node_id] = raw
    return output


def _aggregate_optional_numeric(
    records: Mapping[str, Mapping[str, Any]],
    field: str,
) -> tuple[int | float | str, bool, int, int]:
    """Return total, completeness, measured count and applicable count.

    SKIPPED/BLOCKED nodes did not execute provider work and therefore do not
    make token/cost telemetry incomplete. Every other node that ran or failed is
    applicable to operational telemetry. A missing value on any applicable node
    makes the aggregate NOT_MEASURED rather than silently summing the rest.
    """

    applicable = [
        item
        for item in records.values()
        if str(item.get("status") or "") not in {"SKIPPED", "BLOCKED", "PENDING"}
    ]
    values: list[int | float] = []
    for item in applicable:
        value = item.get(field)
        if isinstance(value, bool):
            value = None
        if isinstance(value, (int, float)):
            values.append(value)
    complete = len(values) == len(applicable)
    if not applicable:
        return NOT_APPLICABLE, True, 0, 0
    if not complete:
        return NOT_MEASURED, False, len(values), len(applicable)
    total: int | float = sum(values)
    if field == "cost_usd":
        total = round(float(total), 8)
    else:
        total = int(total)
    return total, True, len(values), len(applicable)


def _identity_summary(
    records: Mapping[str, Mapping[str, Any]],
    field: str,
) -> tuple[str, list[str]]:
    values = sorted(
        {
            str(item.get(field)).strip()
            for item in records.values()
            if isinstance(item.get(field), str) and str(item.get(field)).strip()
        }
    )
    if not values:
        return NOT_APPLICABLE, []
    if len(values) == 1:
        return values[0], values
    return "MULTI", values


def _role_rows(
    records: Mapping[str, Mapping[str, Any]],
    role: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for node_id, item in sorted(records.items()):
        if item.get("role") != role:
            continue
        rows.append(
            {
                "node_id": node_id,
                "status": item.get("status"),
                "duration_seconds": item.get("duration_seconds"),
                "provider": item.get("provider"),
                "model": item.get("model"),
                "input_tokens": item.get("input_tokens"),
                "output_tokens": item.get("output_tokens"),
                "cost_usd": item.get("cost_usd"),
                "output_evidence_ids": list(item.get("output_evidence_ids") or []),
                "blocker": item.get("blocker"),
                "error": item.get("error"),
            }
        )
    return rows


def build_arena_run_record(
    run: Mapping[str, Any],
    *,
    agent_host: str,
    artifact_digest: str | None = None,
) -> dict[str, Any]:
    if not isinstance(agent_host, str) or not agent_host.strip():
        raise ArenaRunTelemetryError("agent_host must be a non-empty label")

    records = _records(run)
    started = _parse_timestamp(run.get("started_at"), "run.started_at")
    finished = _parse_timestamp(run.get("finished_at"), "run.finished_at")
    elapsed = (finished - started).total_seconds()
    if elapsed < 0:
        raise ArenaRunTelemetryError("run.finished_at is earlier than run.started_at")

    input_tokens, input_complete, input_measured, input_applicable = _aggregate_optional_numeric(
        records, "input_tokens"
    )
    output_tokens, output_complete, output_measured, output_applicable = _aggregate_optional_numeric(
        records, "output_tokens"
    )
    cost, cost_complete, cost_measured, cost_applicable = _aggregate_optional_numeric(
        records, "cost_usd"
    )
    provider, providers = _identity_summary(records, "provider")
    model, models = _identity_summary(records, "model")

    statuses: dict[str, int] = {}
    for item in records.values():
        status = str(item.get("status") or "UNKNOWN")
        statuses[status] = statuses.get(status, 0) + 1

    verifier_rows = _role_rows(records, "INDEPENDENT_VERIFIER")
    gate_rows = _role_rows(records, "RELEASE_GATE")

    return {
        "schema_version": SCHEMA_VERSION,
        "agent_host": agent_host.strip(),
        "provider": provider,
        "model": model,
        "started_at": run["started_at"],
        "finished_at": run["finished_at"],
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cost": cost,
        "elapsed_seconds": round(elapsed, 6),
        "run_id": run.get("run_id"),
        "runner_version": run.get("runner_version"),
        "target_commit": run.get("target_commit"),
        "scope_id": run.get("scope_id"),
        "graph_digest": run.get("graph_digest"),
        "executor": run.get("executor"),
        "run_artifact_digest": artifact_digest,
        "operational_metrics": {
            "node_count": len(records),
            "status_counts": dict(sorted(statuses.items())),
            "unsatisfied_mandatory": list(run.get("unsatisfied_mandatory") or []),
            "blocked": list(run.get("blocked") or []),
            "failed": list(run.get("failed") or []),
            "providers": providers,
            "models": models,
            "telemetry_completeness": {
                "input_tokens": {
                    "complete": input_complete,
                    "measured_nodes": input_measured,
                    "applicable_nodes": input_applicable,
                },
                "output_tokens": {
                    "complete": output_complete,
                    "measured_nodes": output_measured,
                    "applicable_nodes": output_applicable,
                },
                "cost_usd": {
                    "complete": cost_complete,
                    "measured_nodes": cost_measured,
                    "applicable_nodes": cost_applicable,
                },
            },
            "independent_verifier": {
                "present": bool(verifier_rows),
                "nodes": verifier_rows,
            },
            "release_gate": {
                "present": bool(gate_rows),
                "nodes": gate_rows,
            },
        },
    }


def _cli() -> int:
    parser = argparse.ArgumentParser(
        description="Build Arena-compatible operational telemetry from a SecHelix run.json"
    )
    parser.add_argument("--run", required=True, help="SecHelix RunResult JSON artifact")
    parser.add_argument("--agent-host", required=True, help="stable evaluator/host label")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    path = Path(args.run)
    payload = _read_json(path)
    if not isinstance(payload, Mapping):
        raise ArenaRunTelemetryError("run artifact must be a JSON object")
    record = build_arena_run_record(
        payload,
        agent_host=args.agent_host,
        artifact_digest=_sha256_file(path),
    )
    Path(args.output).write_text(
        json.dumps(record, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
