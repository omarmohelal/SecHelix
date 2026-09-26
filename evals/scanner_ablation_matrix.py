#!/usr/bin/env python3
"""Build isolated single-scanner ablation matrices from matched blind runs.

A scanner bundle can show that something in the bundle changed the result, but
it cannot attribute that change to one tool. This helper permits per-scanner
attribution only when each treatment arm enables exactly one unique scanner and
all arms are compared against the same scanner-disabled control under the same
blind-evaluation conditions.

It never runs scanners or models and never emits per-case ground truth. It only
composes complete prediction packets through the canonical
`build_scanner_ablation` comparator.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from evals.scanner_ablation import (
    MEASURED,
    NOT_MEASURED,
    ScannerAblationError,
    build_scanner_ablation,
)


SCHEMA_VERSION = "sechelix-scanner-ablation-matrix/v1"


class ScannerAblationMatrixError(ValueError):
    """An isolated scanner matrix is confounded, incomplete, or ambiguous."""


def _read_object(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScannerAblationMatrixError(f"cannot read JSON packet: {path}") from exc
    if not isinstance(value, Mapping):
        raise ScannerAblationMatrixError(f"packet must be a JSON object: {path}")
    return value


def _treatment_source(packet: Mapping[str, Any]) -> str:
    raw = packet.get("scanner_ablation")
    if not isinstance(raw, Mapping):
        raise ScannerAblationMatrixError(
            "treatment scanner_ablation metadata must be an object"
        )
    if raw.get("enabled") is not True:
        raise ScannerAblationMatrixError(
            "every matrix treatment must enable exactly one scanner"
        )
    sources = raw.get("sources")
    if not isinstance(sources, list) or len(sources) != 1:
        raise ScannerAblationMatrixError(
            "every matrix treatment must declare exactly one scanner source"
        )
    source = sources[0]
    if not isinstance(source, str) or not source.strip():
        raise ScannerAblationMatrixError(
            "matrix treatment scanner source must be a non-empty string"
        )
    return source.strip()


def _numeric_summary(values: list[Any]) -> dict[str, Any]:
    """Sum only complete operational deltas; never coerce missing data to zero."""

    measured = [
        float(value)
        for value in values
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    ]
    if len(measured) != len(values) or not measured:
        return {
            "complete": False,
            "value": NOT_MEASURED,
            "measured_arms": len(measured),
            "applicable_arms": len(values),
        }
    return {
        "complete": True,
        "value": round(sum(measured), 6),
        "measured_arms": len(measured),
        "applicable_arms": len(values),
    }


def build_scanner_ablation_matrix(
    control: Mapping[str, Any],
    treatments: Sequence[Mapping[str, Any]],
    *,
    fixtures: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compare isolated scanners against one matched scanner-off control.

    Each treatment must contain exactly one unique scanner source. The pair
    comparator independently enforces matched model/provider/host/prompt/run-id,
    identical blind cases, declared scanner provenance and canonical scoring.
    """

    if not treatments:
        raise ScannerAblationMatrixError(
            "scanner matrix needs at least one treatment arm"
        )

    seen_sources: set[str] = set()
    rows: list[dict[str, Any]] = []
    for index, treatment in enumerate(treatments):
        source = _treatment_source(treatment)
        if source in seen_sources:
            raise ScannerAblationMatrixError(
                f"duplicate isolated scanner treatment: {source}"
            )
        seen_sources.add(source)

        try:
            result = build_scanner_ablation(
                control,
                treatment,
                fixtures=fixtures,
            )
        except ScannerAblationError as exc:
            raise ScannerAblationMatrixError(
                f"treatment[{index}] {source!r} is not a controlled ablation: {exc}"
            ) from exc

        bundle = result.get("scanner_bundle")
        if (
            not isinstance(bundle, Mapping)
            or bundle.get("individual_scanner_credit") is not True
        ):
            raise ScannerAblationMatrixError(
                f"treatment[{index}] did not produce single-scanner attribution"
            )

        rows.append(
            {
                "scanner_source": source,
                "measurement_status": result["measurement_status"],
                "delta": dict(result["delta"]),
                "changed_cases": dict(result["changed_cases"]),
                "control_metrics": dict(result["control"]["metrics"]),
                "treatment_metrics": dict(result["treatment"]["metrics"]),
            }
        )

    rows.sort(key=lambda row: row["scanner_source"].casefold())

    operational = {
        name: _numeric_summary([row["delta"][name] for row in rows])
        for name in ("time_seconds", "input_tokens", "output_tokens", "cost")
    }
    aggregate_changes = {
        name: sum(int(row["changed_cases"][name]) for row in rows)
        for name in (
            "vulnerable_detections_gained",
            "vulnerable_detections_lost",
            "clean_false_positives_removed",
            "clean_false_positives_introduced",
            "label_unchanged",
        )
    }

    measured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": SCHEMA_VERSION,
        "measurement_status": MEASURED,
        "result_kind": "CONTROLLED_ISOLATED_SCANNER_ABLATION_MATRIX",
        "measured_at": measured_at,
        "ablation_run_id": control.get("ablation_run_id"),
        "matched_conditions": {
            key: control.get(key)
            for key in (
                "model",
                "provider",
                "agent_host",
                "execution_mode",
                "prompt_reference",
                "cases_sha256",
                "fixture_suite_version",
            )
        },
        "scanner_count": len(rows),
        "scanners": rows,
        "operational_delta_totals": operational,
        "aggregate_changed_case_counts": aggregate_changes,
        "attribution_rule": (
            "Each scanner row comes from a treatment arm where that scanner was "
            "the only enabled scanner. No causal credit is inferred from a bundle."
        ),
        "claim_boundary": (
            "This matrix compares isolated scanner treatments under one matched "
            "blind label-suite setup. Aggregate changed-case counts sum separate "
            "counterfactual arms and are not unique production findings. It does "
            "not establish production effectiveness or full-workflow Arena accuracy."
        ),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", required=True, type=Path)
    parser.add_argument(
        "--treatment",
        required=True,
        action="append",
        type=Path,
        help="repeat once per isolated single-scanner treatment packet",
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        result = build_scanner_ablation_matrix(
            _read_object(args.control),
            [_read_object(path) for path in args.treatment],
        )
    except ScannerAblationMatrixError as exc:
        parser.error(str(exc))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
