#!/usr/bin/env python3
"""Measure scanner-bundle contribution with a controlled paired ablation.

This compares two complete blind prediction packets over the same SecHelix
fixture suite. The control arm must have scanners disabled; the treatment arm
must enable one declared scanner bundle. Model/provider/host/prompt/case packet
metadata must match exactly so the reported delta is not confused with a changed
evaluation setup.

When multiple scanners are enabled the result is bundle-level only. SecHelix
never invents per-tool causal credit from one combined treatment arm.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from evals.run_evals import EvalInputError, blind_case_id, load_fixtures, score


SCHEMA_VERSION = "sechelix-scanner-ablation/v1"
MEASURED = "MEASURED"
NOT_MEASURED = "NOT_MEASURED"

_MATCH_FIELDS = (
    "ablation_run_id",
    "model",
    "provider",
    "agent_host",
    "execution_mode",
    "prompt_reference",
    "cases_sha256",
    "fixture_suite_version",
)


class ScannerAblationError(ValueError):
    """A scanner ablation is confounded, incomplete, or malformed."""


def _require_string(packet: Mapping[str, Any], field: str) -> str:
    value = packet.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ScannerAblationError(f"{field} must be a non-empty string")
    return value.strip()


def _scanner_config(packet: Mapping[str, Any], *, enabled: bool) -> tuple[str, ...]:
    raw = packet.get("scanner_ablation")
    if not isinstance(raw, Mapping):
        raise ScannerAblationError("scanner_ablation metadata must be an object")
    if raw.get("enabled") is not enabled:
        raise ScannerAblationError(
            f"scanner_ablation.enabled must be {str(enabled).lower()}"
        )
    sources = raw.get("sources")
    if not isinstance(sources, list) or not all(
        isinstance(item, str) and item.strip() for item in sources
    ):
        raise ScannerAblationError("scanner_ablation.sources must be a string list")
    normalized = tuple(dict.fromkeys(item.strip() for item in sources))
    if enabled and not normalized:
        raise ScannerAblationError(
            "treatment arm must declare at least one scanner source"
        )
    if not enabled and normalized:
        raise ScannerAblationError("control arm must not declare scanner sources")
    return normalized


def _validate_pair(
    control: Mapping[str, Any],
    treatment: Mapping[str, Any],
) -> tuple[str, ...]:
    for field in _MATCH_FIELDS:
        left = _require_string(control, field)
        right = _require_string(treatment, field)
        if left != right:
            raise ScannerAblationError(
                f"controlled scanner ablation requires matching {field}: "
                f"{left!r} != {right!r}"
            )
    _scanner_config(control, enabled=False)
    return _scanner_config(treatment, enabled=True)


def _prediction_map(packet: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    rows = packet.get("predictions")
    if not isinstance(rows, list):
        raise ScannerAblationError("predictions must be an array")
    output: dict[str, Mapping[str, Any]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise ScannerAblationError(f"predictions[{index}] must be an object")
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise ScannerAblationError(f"predictions[{index}].case_id missing")
        if case_id in output:
            raise ScannerAblationError(f"duplicate prediction case_id: {case_id}")
        output[case_id] = row
    return output


def _numeric_delta(left: Any, right: Any) -> float | int | str:
    if isinstance(left, bool) or isinstance(right, bool):
        return NOT_MEASURED
    if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
        return NOT_MEASURED
    value = right - left
    return round(value, 6) if isinstance(value, float) else value


def _metric_delta(
    control_result: Mapping[str, Any],
    treatment_result: Mapping[str, Any],
    key: str,
) -> float | str:
    left = control_result["metrics"].get(key)
    right = treatment_result["metrics"].get(key)
    if not isinstance(left, (int, float)) or isinstance(left, bool):
        return NOT_MEASURED
    if not isinstance(right, (int, float)) or isinstance(right, bool):
        return NOT_MEASURED
    return round(float(right) - float(left), 6)


def build_scanner_ablation(
    control: Mapping[str, Any],
    treatment: Mapping[str, Any],
    *,
    fixtures: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a controlled scanner-bundle delta from two complete packets."""

    scanner_sources = _validate_pair(control, treatment)
    fixture_rows = fixtures if fixtures is not None else load_fixtures()

    declared_sources = set(scanner_sources)
    for arm_name, packet, scanners_allowed in (
        ("control", control, set()),
        ("treatment", treatment, declared_sources),
    ):
        rows = packet.get("predictions")
        if not isinstance(rows, list):
            raise ScannerAblationError(f"{arm_name} predictions must be an array")
        for index, row in enumerate(rows):
            if not isinstance(row, Mapping):
                continue
            raw_sources = row.get("scanner_sources", [])
            if not isinstance(raw_sources, list) or not all(
                isinstance(item, str) and item.strip() for item in raw_sources
            ):
                raise ScannerAblationError(
                    f"{arm_name} predictions[{index}].scanner_sources must be a string list"
                )
            normalized = {item.strip() for item in raw_sources}
            undeclared = sorted(normalized - scanners_allowed)
            if undeclared:
                raise ScannerAblationError(
                    f"{arm_name} prediction references undeclared scanner sources: "
                    + ", ".join(undeclared)
                )

    try:
        control_result = score(control, fixture_rows)
        treatment_result = score(treatment, fixture_rows)
    except EvalInputError as exc:
        raise ScannerAblationError(str(exc)) from exc

    control_predictions = _prediction_map(control)
    treatment_predictions = _prediction_map(treatment)
    if set(control_predictions) != set(treatment_predictions):
        raise ScannerAblationError(
            "control and treatment case sets must match exactly"
        )

    expected_by_case: dict[str, str] = {}
    for fixture in fixture_rows:
        expected_by_case[blind_case_id(fixture["id"], "vulnerable")] = "VULNERABLE"
        expected_by_case[blind_case_id(fixture["id"], "clean")] = "CLEAN"
        expected_by_case[f"{fixture['id']}::vulnerable"] = "VULNERABLE"
        expected_by_case[f"{fixture['id']}::clean"] = "CLEAN"

    changed = {
        "vulnerable_detections_gained": 0,
        "vulnerable_detections_lost": 0,
        "clean_false_positives_removed": 0,
        "clean_false_positives_introduced": 0,
        "label_unchanged": 0,
    }
    for case_id in sorted(control_predictions):
        before = str(
            control_predictions[case_id].get("predicted_label", "")
        ).upper()
        after = str(
            treatment_predictions[case_id].get("predicted_label", "")
        ).upper()
        if before == after:
            changed["label_unchanged"] += 1
            continue
        truth = expected_by_case.get(case_id)
        if truth is None:
            raise ScannerAblationError(
                f"unknown case_id after scoring: {case_id}"
            )
        if truth == "VULNERABLE":
            if before == "CLEAN" and after == "VULNERABLE":
                changed["vulnerable_detections_gained"] += 1
            elif before == "VULNERABLE" and after == "CLEAN":
                changed["vulnerable_detections_lost"] += 1
        else:
            if before == "VULNERABLE" and after == "CLEAN":
                changed["clean_false_positives_removed"] += 1
            elif before == "CLEAN" and after == "VULNERABLE":
                changed["clean_false_positives_introduced"] += 1

    measured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": SCHEMA_VERSION,
        "measurement_status": MEASURED,
        "result_kind": "CONTROLLED_SCANNER_BUNDLE_ABLATION",
        "measured_at": measured_at,
        "ablation_run_id": control["ablation_run_id"],
        "scanner_bundle": {
            "sources": list(scanner_sources),
            "attribution_scope": (
                "bundle-level only"
                if len(scanner_sources) > 1
                else "single declared scanner"
            ),
            "individual_scanner_credit": len(scanner_sources) == 1,
        },
        "matched_conditions": {field: control[field] for field in _MATCH_FIELDS},
        "control": {
            "metrics": control_result["metrics"],
            "counts": control_result["counts"],
        },
        "treatment": {
            "metrics": treatment_result["metrics"],
            "counts": treatment_result["counts"],
        },
        "delta": {
            "precision": _metric_delta(
                control_result, treatment_result, "precision"
            ),
            "detection_recall": _metric_delta(
                control_result, treatment_result, "detection_recall"
            ),
            "verified_precision": _metric_delta(
                control_result, treatment_result, "verified_precision"
            ),
            "false_positive_rate": _metric_delta(
                control_result, treatment_result, "false_positive_rate"
            ),
            "false_positive_rejection_rate": _metric_delta(
                control_result,
                treatment_result,
                "false_positive_rejection_rate",
            ),
            "time_seconds": _numeric_delta(
                control_result["run"].get("time_seconds"),
                treatment_result["run"].get("time_seconds"),
            ),
            "input_tokens": _numeric_delta(
                control_result["run"].get("input_tokens"),
                treatment_result["run"].get("input_tokens"),
            ),
            "output_tokens": _numeric_delta(
                control_result["run"].get("output_tokens"),
                treatment_result["run"].get("output_tokens"),
            ),
            "cost": _numeric_delta(
                control_result["run"].get("cost"),
                treatment_result["run"].get("cost"),
            ),
        },
        "changed_cases": changed,
        "claim_boundary": (
            "This measures the delta of the declared scanner bundle under the "
            "matched blind evaluation conditions above. It does not establish "
            "individual-tool causal credit, production effectiveness, or "
            "full-workflow Arena accuracy."
        ),
    }


def _read_object(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScannerAblationError(f"cannot read JSON packet: {path}") from exc
    if not isinstance(value, Mapping):
        raise ScannerAblationError(f"packet must be a JSON object: {path}")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", required=True, type=Path)
    parser.add_argument("--treatment", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        result = build_scanner_ablation(
            _read_object(args.control),
            _read_object(args.treatment),
        )
    except ScannerAblationError as exc:
        parser.error(str(exc))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
