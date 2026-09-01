#!/usr/bin/env python3
"""Score externally produced predictions against SecHelix paired fixtures.

This runner does not call models or scanners. It exports blind cases and scores
results supplied by an authorized evaluator, keeping expected truth out of the
model packet until scoring time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
POSITIVE = "VULNERABLE"
NEGATIVE = "CLEAN"


class EvalInputError(ValueError):
    pass


def load_fixtures(fixtures_dir: Path = FIXTURES) -> list[dict[str, Any]]:
    fixtures = []
    for path in sorted(fixtures_dir.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not data.get("id"):
            raise EvalInputError(f"invalid fixture: {path}")
        variants = data.get("variants")
        if not isinstance(variants, dict) or set(variants) != {"vulnerable", "clean"}:
            raise EvalInputError(f"fixture {data.get('id', path.name)} must have vulnerable and clean variants")
        if variants["vulnerable"].get("expected") != POSITIVE or variants["clean"].get("expected") != NEGATIVE:
            raise EvalInputError(f"fixture {data['id']} has invalid paired truth labels")
        fixtures.append(data)
    if not fixtures:
        raise EvalInputError("no fixtures found")
    return fixtures


def blind_case_id(fixture_id: str, variant_name: str) -> str:
    """Derive an opaque, deterministic case identifier.

    The legacy identifier was ``FIXTURE::vulnerable``, which disclosed the answer
    in the identifier itself. The digest keeps scoring reproducible without a
    state file while withholding ground truth from the evaluated model.
    """
    digest = hashlib.sha256(f"{fixture_id}::{variant_name}".encode("utf-8")).hexdigest()
    return f"CASE-{digest[:16].upper()}"


def _case_index(fixtures: list[dict[str, Any]]) -> dict[str, tuple[str, str, str]]:
    """Map every case identifier to (fixture_id, variant_name, expected_label)."""
    index: dict[str, tuple[str, str, str]] = {}
    for fixture in fixtures:
        for variant_name, variant in fixture["variants"].items():
            entry = (fixture["id"], variant_name, variant["expected"])
            index[blind_case_id(fixture["id"], variant_name)] = entry
            # Legacy identifiers stay scoreable so older packets remain valid.
            index[f"{fixture['id']}::{variant_name}"] = entry
    return index


def export_blind_cases(fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    cases = []
    for fixture in fixtures:
        for variant_name, variant in fixture["variants"].items():
            # Deliberately omits `expected`, `rationale`, `variant`, and the
            # fixture id: each of those discloses or narrows the ground truth.
            cases.append({
                "case_id": blind_case_id(fixture["id"], variant_name),
                "family": fixture["family"],
                "language": variant["language"],
                "filename": variant["filename"],
                "source": variant["source"],
                "task": fixture["task"],
            })
    # Deterministic order that does not group each vulnerable/clean pair together.
    cases.sort(key=lambda case: case["case_id"])
    return {"schema_version": "1.1.0", "cases": cases}


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def score(predictions: Mapping[str, Any], fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    rows = predictions.get("predictions")
    if not isinstance(rows, list):
        raise EvalInputError("predictions must be an array")
    index = _case_index(fixtures)
    families = {
        fixture["id"]: fixture["family"] for fixture in fixtures
    }
    # Canonical key is (fixture_id, variant); either identifier form resolves to it.
    expected: dict[tuple[str, str], str] = {}
    for fixture in fixtures:
        for variant_name, variant in fixture["variants"].items():
            expected[(fixture["id"], variant_name)] = variant["expected"]

    supplied: dict[tuple[str, str], Mapping[str, Any]] = {}
    for position, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise EvalInputError(f"predictions[{position}] must be an object")
        case_id = str(row.get("case_id", ""))
        if case_id not in index:
            raise EvalInputError(f"unknown case_id: {case_id or '<missing>'}")
        fixture_id, variant_name, _ = index[case_id]
        key = (fixture_id, variant_name)
        if key in supplied:
            raise EvalInputError(f"duplicate prediction for {case_id}")
        label = str(row.get("predicted_label", "")).upper()
        if label not in {POSITIVE, NEGATIVE}:
            raise EvalInputError(f"{case_id} predicted_label must be VULNERABLE or CLEAN")
        supplied[key] = row
    missing = sorted(f"{fid}::{variant}" for fid, variant in set(expected) - set(supplied))
    if missing:
        raise EvalInputError(f"missing predictions for {len(missing)} case(s): {', '.join(missing)}")

    tp = fp = tn = fn = verified_tp = verified_fp = duplicate = 0
    rejected_false_candidates = 0
    scanner_counts: dict[str, int] = {}
    per_family: dict[str, dict[str, int]] = {}
    for key, truth in expected.items():
        fixture_id, _variant = key
        row = supplied[key]
        predicted = str(row["predicted_label"]).upper()
        bucket = per_family.setdefault(
            families[fixture_id], {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        )
        if truth == POSITIVE and predicted == POSITIVE:
            tp += 1
            bucket["tp"] += 1
        elif truth == NEGATIVE and predicted == POSITIVE:
            fp += 1
            bucket["fp"] += 1
        elif truth == NEGATIVE:
            tn += 1
            bucket["tn"] += 1
        else:
            fn += 1
            bucket["fn"] += 1
        verification = str(row.get("verification_status", "NOT_RUN")).upper()
        if verification == "VERIFIED" and predicted == POSITIVE:
            if truth == POSITIVE:
                verified_tp += 1
            else:
                verified_fp += 1
        # A clean case that the workflow declined to promote is a correctly
        # rejected false candidate, whether it was never raised or was refuted.
        if truth == NEGATIVE and (predicted == NEGATIVE or verification == "FALSE_POSITIVE"):
            rejected_false_candidates += 1
        if verification == "DUPLICATE_ROOT_CAUSE":
            duplicate += 1
        for source in row.get("scanner_sources", []):
            source_key = str(source)
            scanner_counts[source_key] = scanner_counts.get(source_key, 0) + 1

    positives = tp + fn
    negatives = fp + tn
    predicted_positive = tp + fp
    verified_positive = verified_tp + verified_fp
    measured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": "1.0.0",
        "measurement_status": "MEASURED",
        "measured_at": measured_at,
        "run": {
            "model": predictions.get("model", "UNSPECIFIED"),
            "provider": predictions.get("provider", "UNSPECIFIED"),
            "runner": predictions.get("runner", "external"),
            "sechelix_commit": predictions.get("sechelix_commit", "NOT_MEASURED"),
            "fixture_suite_version": predictions.get("fixture_suite_version", "NOT_MEASURED"),
            "agent_host": predictions.get("agent_host", "NOT_MEASURED"),
            "execution_mode": predictions.get("execution_mode", "NOT_MEASURED"),
            "tools": predictions.get("tools", "NOT_MEASURED"),
            "prompt_reference": predictions.get("prompt_reference", "NOT_MEASURED"),
            "fixture_count": len(fixtures),
            "case_count": len(expected),
            "time_seconds": predictions.get("time_seconds", "NOT_MEASURED"),
            "input_tokens": predictions.get("input_tokens", "NOT_MEASURED"),
            "output_tokens": predictions.get("output_tokens", "NOT_MEASURED"),
            "cost": predictions.get("cost", "NOT_MEASURED"),
        },
        "counts": {
            "true_positive": tp,
            "false_positive": fp,
            "true_negative": tn,
            "false_negative": fn,
            "rejected_false_candidates": rejected_false_candidates,
        },
        "metrics": {
            "precision": _ratio(tp, predicted_positive),
            "detection_recall": _ratio(tp, positives),
            "recall": _ratio(tp, positives),
            "verified_precision": _ratio(verified_tp, verified_positive),
            "false_positive_rate": _ratio(fp, negatives),
            "false_positive_rejection_rate": _ratio(rejected_false_candidates, negatives),
            "duplicate_root_cause_rate": _ratio(duplicate, len(expected)),
            # These belong to a full audit run, not a label-only fixture scoring.
            # They stay NOT_MEASURED here rather than being silently reported as 0.
            "applicability_accuracy": "NOT_MEASURED",
            "regression_proof_rate": "NOT_MEASURED",
            "release_gate_accuracy": "NOT_MEASURED",
        },
        "per_family": {
            family: {
                **counts,
                "detection_recall": _ratio(counts["tp"], counts["tp"] + counts["fn"]),
                "false_positive_rate": _ratio(counts["fp"], counts["fp"] + counts["tn"]),
            }
            for family, counts in sorted(per_family.items())
        },
        "scanner_contribution": scanner_counts,
        "limitations": predictions.get("limitations", []),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", type=Path, help="complete prediction packet to score")
    parser.add_argument("--export-cases", type=Path, help="write blind cases without expected labels")
    parser.add_argument("--output", type=Path, help="write measured result; stdout when omitted")
    args = parser.parse_args(argv)
    if bool(args.predictions) == bool(args.export_cases):
        parser.error("choose exactly one of --predictions or --export-cases")
    try:
        fixtures = load_fixtures()
        if args.export_cases:
            value = export_blind_cases(fixtures)
            args.export_cases.parent.mkdir(parents=True, exist_ok=True)
            args.export_cases.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"exported {len(value['cases'])} blind cases to {args.export_cases}")
            return 0
        predictions = json.loads(args.predictions.read_text(encoding="utf-8"))
        result = score(predictions, fixtures)
    except (OSError, json.JSONDecodeError, EvalInputError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
