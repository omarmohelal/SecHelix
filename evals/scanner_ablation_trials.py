#!/usr/bin/env python3
"""Aggregate repeated isolated-scanner ablation matrices without confounding them.

Each input must be a measured isolated-scanner matrix produced by
`scanner_ablation_matrix.py`. Repeated trials may have different
`ablation_run_id` values, but all other comparison conditions and the isolated
scanner set must match exactly.

The output reports spread across trials; it does not run scanners/models, reveal
per-case truth, compute significance, or claim production effectiveness.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "sechelix-scanner-ablation-trials/v1"
MATRIX_SCHEMA_VERSION = "sechelix-scanner-ablation-matrix/v1"
MEASURED = "MEASURED"
NOT_MEASURED = "NOT_MEASURED"

_DELTA_FIELDS = (
    "precision",
    "detection_recall",
    "verified_precision",
    "false_positive_rate",
    "false_positive_rejection_rate",
    "time_seconds",
    "input_tokens",
    "output_tokens",
    "cost",
)
_CHANGE_FIELDS = (
    "vulnerable_detections_gained",
    "vulnerable_detections_lost",
    "clean_false_positives_removed",
    "clean_false_positives_introduced",
    "label_unchanged",
)


class ScannerAblationTrialsError(ValueError):
    """Repeated isolated-scanner trials are malformed or confounded."""


def _read_object(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScannerAblationTrialsError(f"cannot read scanner matrix: {path}") from exc
    if not isinstance(value, Mapping):
        raise ScannerAblationTrialsError(f"scanner matrix must be a JSON object: {path}")
    return value


def _require_matrix(matrix: Mapping[str, Any], index: int) -> None:
    if matrix.get("schema_version") != MATRIX_SCHEMA_VERSION:
        raise ScannerAblationTrialsError(
            f"matrix[{index}] has unsupported schema_version"
        )
    if matrix.get("result_kind") != "CONTROLLED_ISOLATED_SCANNER_ABLATION_MATRIX":
        raise ScannerAblationTrialsError(
            f"matrix[{index}] is not an isolated scanner ablation matrix"
        )
    if matrix.get("measurement_status") != MEASURED:
        raise ScannerAblationTrialsError(
            f"matrix[{index}] is not MEASURED"
        )
    run_id = matrix.get("ablation_run_id")
    if not isinstance(run_id, str) or not run_id.strip():
        raise ScannerAblationTrialsError(
            f"matrix[{index}] ablation_run_id must be a non-empty string"
        )
    conditions = matrix.get("matched_conditions")
    if not isinstance(conditions, Mapping) or not conditions:
        raise ScannerAblationTrialsError(
            f"matrix[{index}] matched_conditions missing"
        )
    scanners = matrix.get("scanners")
    if not isinstance(scanners, list) or not scanners:
        raise ScannerAblationTrialsError(
            f"matrix[{index}] scanners must be a non-empty array"
        )


def _scanner_map(matrix: Mapping[str, Any], index: int) -> dict[str, Mapping[str, Any]]:
    rows = matrix["scanners"]
    output: dict[str, Mapping[str, Any]] = {}
    for row_index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise ScannerAblationTrialsError(
                f"matrix[{index}].scanners[{row_index}] must be an object"
            )
        source = row.get("scanner_source")
        if not isinstance(source, str) or not source.strip():
            raise ScannerAblationTrialsError(
                f"matrix[{index}].scanners[{row_index}] scanner_source missing"
            )
        source = source.strip()
        if source in output:
            raise ScannerAblationTrialsError(
                f"matrix[{index}] contains duplicate scanner source {source}"
            )
        if row.get("measurement_status") != MEASURED:
            raise ScannerAblationTrialsError(
                f"matrix[{index}] scanner {source} is not MEASURED"
            )
        if not isinstance(row.get("delta"), Mapping):
            raise ScannerAblationTrialsError(
                f"matrix[{index}] scanner {source} delta missing"
            )
        if not isinstance(row.get("changed_cases"), Mapping):
            raise ScannerAblationTrialsError(
                f"matrix[{index}] scanner {source} changed_cases missing"
            )
        output[source] = row
    return output


def _numeric(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _spread(values: list[Any]) -> dict[str, Any]:
    measured = [_numeric(value) for value in values]
    numeric = [value for value in measured if value is not None]
    if len(numeric) != len(values) or not numeric:
        return {
            "complete": False,
            "mean": NOT_MEASURED,
            "min": NOT_MEASURED,
            "max": NOT_MEASURED,
            "measured_trials": len(numeric),
            "applicable_trials": len(values),
        }
    return {
        "complete": True,
        "mean": round(sum(numeric) / len(numeric), 6),
        "min": round(min(numeric), 6),
        "max": round(max(numeric), 6),
        "measured_trials": len(numeric),
        "applicable_trials": len(values),
    }


def build_scanner_ablation_trials(
    matrices: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Aggregate repeated matched isolated-scanner matrices."""

    if len(matrices) < 2:
        raise ScannerAblationTrialsError(
            "repeated scanner trials require at least two matrices"
        )

    run_ids: list[str] = []
    maps: list[dict[str, Mapping[str, Any]]] = []
    expected_conditions: dict[str, Any] | None = None
    expected_sources: tuple[str, ...] | None = None

    for index, matrix in enumerate(matrices):
        _require_matrix(matrix, index)
        run_id = str(matrix["ablation_run_id"]).strip()
        if run_id in run_ids:
            raise ScannerAblationTrialsError(
                f"duplicate ablation_run_id across trials: {run_id}"
            )
        run_ids.append(run_id)

        conditions = dict(matrix["matched_conditions"])
        if expected_conditions is None:
            expected_conditions = conditions
        elif conditions != expected_conditions:
            raise ScannerAblationTrialsError(
                "repeated trials require identical matched_conditions"
            )

        scanner_map = _scanner_map(matrix, index)
        sources = tuple(sorted(scanner_map, key=str.casefold))
        if expected_sources is None:
            expected_sources = sources
        elif sources != expected_sources:
            raise ScannerAblationTrialsError(
                "repeated trials require the exact same isolated scanner set"
            )
        maps.append(scanner_map)

    assert expected_conditions is not None
    assert expected_sources is not None

    scanner_summaries: list[dict[str, Any]] = []
    for source in expected_sources:
        rows = [mapping[source] for mapping in maps]
        delta_spread = {
            field: _spread([row["delta"].get(field) for row in rows])
            for field in _DELTA_FIELDS
        }
        changed_case_totals = {
            field: sum(int(row["changed_cases"].get(field, 0)) for row in rows)
            for field in _CHANGE_FIELDS
        }
        changed_case_means = {
            field: round(changed_case_totals[field] / len(rows), 6)
            for field in _CHANGE_FIELDS
        }
        scanner_summaries.append(
            {
                "scanner_source": source,
                "trial_count": len(rows),
                "delta_spread": delta_spread,
                "changed_case_totals": changed_case_totals,
                "changed_case_means": changed_case_means,
            }
        )

    measured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": SCHEMA_VERSION,
        "measurement_status": MEASURED,
        "result_kind": "REPEATED_ISOLATED_SCANNER_ABLATION_TRIALS",
        "measured_at": measured_at,
        "trial_count": len(matrices),
        "run_ids": sorted(run_ids),
        "matched_conditions": expected_conditions,
        "scanner_count": len(expected_sources),
        "scanners": scanner_summaries,
        "interpretation": (
            "Mean/min/max describe repeated matched blind-label trials. No "
            "statistical significance or production generalization is inferred."
        ),
        "claim_boundary": (
            "Repeated trials reduce dependence on one run, but they remain the "
            "same authored blind fixture suite under matched conditions. Changed-"
            "case totals sum counterfactual trials and are not unique findings."
        ),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--matrix",
        required=True,
        action="append",
        type=Path,
        help="repeat for each matched isolated-scanner matrix",
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        result = build_scanner_ablation_trials(
            [_read_object(path) for path in args.matrix]
        )
    except ScannerAblationTrialsError as exc:
        parser.error(str(exc))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
