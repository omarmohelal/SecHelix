#!/usr/bin/env python3
"""SecHelix Arena: neutral, fail-closed full-workflow measurement records.

The Arena never installs or executes a participant. It prepares a blind run
manifest and finalizes independently assessed workflow observations. Label-only
precision/recall stays in ``evals/run_evals.py``; this module exists for the
workflow properties that label scoring cannot establish.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

MEASURED = "MEASURED"
NOT_MEASURED = "NOT_MEASURED"
NA = "NOT_APPLICABLE"
SCHEMA_VERSION = "sechelix-arena/v1"

PARTICIPANT_CATEGORIES = {
    "AGENT_WORKFLOW",
    "SAST_ENGINE",
    "RESEARCH_AGENT",
    "OTHER",
}

WORKFLOW_METRICS = (
    "applicability_accuracy",
    "verification_accuracy",
    "false_positive_refutation_accuracy",
    "root_cause_accuracy",
    "regression_proof_accuracy",
    "release_gate_accuracy",
)

REQUIRED_PARTICIPANT_FIELDS = (
    "participant_id",
    "display_name",
    "category",
    "source_url",
    "version",
    "capability_scope",
)

REQUIRED_RUN_FIELDS = (
    "agent_host",
    "provider",
    "model",
    "started_at",
    "finished_at",
)


class ArenaError(ValueError):
    pass


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _is_digest(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def _read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _packet_cases(packet: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    cases = packet.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ArenaError("blind packet must contain a non-empty cases list")
    ids: set[str] = set()
    result: list[Mapping[str, Any]] = []
    for item in cases:
        if not isinstance(item, Mapping):
            raise ArenaError("every blind case must be an object")
        case_id = item.get("case_id")
        if not isinstance(case_id, str) or not case_id.startswith("CASE-"):
            raise ArenaError("every blind case needs an opaque CASE- identifier")
        if case_id in ids:
            raise ArenaError(f"duplicate blind case id: {case_id}")
        ids.add(case_id)
        result.append(item)
    return result


def validate_participant(participant: Mapping[str, Any]) -> dict[str, Any]:
    missing = [key for key in REQUIRED_PARTICIPANT_FIELDS if key not in participant]
    if missing:
        raise ArenaError(f"participant metadata missing: {', '.join(missing)}")
    category = participant["category"]
    if category not in PARTICIPANT_CATEGORIES:
        raise ArenaError(f"unknown participant category: {category!r}")
    source_url = participant["source_url"]
    if not isinstance(source_url, str) or not source_url.startswith("https://"):
        raise ArenaError("participant source_url must be an explicit HTTPS source")
    scope = participant["capability_scope"]
    if not isinstance(scope, list) or not scope or not all(isinstance(item, str) and item.strip() for item in scope):
        raise ArenaError("capability_scope must be a non-empty list of explicit capabilities")
    if "REVIEW_AND_PIN_FROM_TESTED_VERSION" in scope:
        raise ArenaError("placeholder capability scope must be replaced before a run")
    version = participant["version"]
    if (
        not isinstance(version, str)
        or not version.strip()
        or version in {"latest", "HEAD", "UNKNOWN", "PIN_REQUIRED"}
    ):
        raise ArenaError("participant version must be pinned; placeholders/latest/HEAD are not comparable")
    return dict(participant)


def prepare_manifest(packet: Mapping[str, Any], participant: Mapping[str, Any]) -> dict[str, Any]:
    cases = _packet_cases(packet)
    clean_participant = validate_participant(participant)
    case_ids = sorted(str(item["case_id"]) for item in cases)
    return {
        "schema_version": SCHEMA_VERSION,
        "phase": "PREPARED",
        "measurement_status": NOT_MEASURED,
        "packet": {
            "digest": canonical_digest(packet),
            "case_count": len(case_ids),
            "case_ids": case_ids,
            "case_id_digest": canonical_digest(case_ids),
        },
        "participant": clean_participant,
        "run": {
            "agent_host": None,
            "provider": None,
            "model": None,
            "started_at": None,
            "finished_at": None,
            "input_tokens": None,
            "output_tokens": None,
            "cost": None,
        },
        "blindness": {
            "evaluator_independent": False,
            "truth_revealed_after_predictions": False,
            "contamination": "UNASSESSED",
            "ground_truth_digest": None,
            "prediction_digest": None,
        },
        "full_workflow": {metric: NOT_MEASURED for metric in WORKFLOW_METRICS},
        "publication": {
            "eligible": False,
            "blockers": ["run not finalized"],
            "note": "Prepared manifests contain no score and are not leaderboard results.",
        },
    }


def _rate(assessment: Mapping[str, Any], metric: str) -> float | str:
    observations = assessment.get("observations")
    if not isinstance(observations, list) or not observations:
        return NOT_MEASURED
    field = metric.removesuffix("_accuracy")
    values: list[bool] = []
    for observation in observations:
        if not isinstance(observation, Mapping) or field not in observation:
            return NOT_MEASURED
        value = observation[field]
        if value == NA:
            continue
        if not isinstance(value, bool):
            return NOT_MEASURED
        values.append(value)
    if not values:
        return NOT_MEASURED
    return round(sum(values) / len(values), 6)


def _assessment_blockers(manifest: Mapping[str, Any], assessment: Mapping[str, Any]) -> list[str]:
    blockers: list[str] = []
    packet = manifest.get("packet")
    if not isinstance(packet, Mapping):
        return ["packet record missing"]
    expected_ids = packet.get("case_ids")
    if not isinstance(expected_ids, list) or not all(isinstance(item, str) for item in expected_ids):
        return ["prepared packet case identities missing"]
    if assessment.get("packet_digest") != packet.get("digest"):
        blockers.append("assessment is not bound to the prepared packet digest")
    observations = assessment.get("observations")
    if not isinstance(observations, list):
        blockers.append("assessment observations missing")
        return blockers
    observed_ids: list[str] = []
    for observation in observations:
        if not isinstance(observation, Mapping):
            blockers.append("assessment contains a non-object observation")
            continue
        case_id = observation.get("case_id")
        if not isinstance(case_id, str):
            blockers.append("assessment observation missing case_id")
            continue
        observed_ids.append(case_id)
        for metric in WORKFLOW_METRICS:
            field = metric.removesuffix("_accuracy")
            if field not in observation:
                blockers.append(f"{case_id} missing workflow field {field}")
                continue
            value = observation[field]
            if value != NA and not isinstance(value, bool):
                blockers.append(f"{case_id}.{field} must be boolean or {NA}")
    if len(observed_ids) != len(set(observed_ids)):
        blockers.append("assessment contains duplicate case IDs")
    if sorted(observed_ids) != sorted(expected_ids):
        blockers.append("assessment does not cover every prepared blind case exactly once")
    return blockers


def _publication_blockers(manifest: Mapping[str, Any], assessment: Mapping[str, Any]) -> list[str]:
    blockers = _assessment_blockers(manifest, assessment)
    run = manifest.get("run")
    if not isinstance(run, Mapping):
        return sorted(set(blockers + ["run metadata missing"]))
    for key in REQUIRED_RUN_FIELDS:
        if not isinstance(run.get(key), str) or not str(run.get(key)).strip():
            blockers.append(f"run.{key} missing")

    blindness = manifest.get("blindness")
    if not isinstance(blindness, Mapping):
        blockers.append("blindness record missing")
    else:
        if blindness.get("contamination") != "UNCONTAMINATED":
            blockers.append("evaluator contamination is not UNCONTAMINATED")
        if blindness.get("evaluator_independent") is not True:
            blockers.append("independent evaluator not established")
        if blindness.get("truth_revealed_after_predictions") is not True:
            blockers.append("truth was not established as sealed until predictions were fixed")
        for key in ("ground_truth_digest", "prediction_digest"):
            if not _is_digest(blindness.get(key)):
                blockers.append(f"blindness.{key} missing or malformed")

    assessor = assessment.get("assessor")
    if not isinstance(assessor, Mapping):
        blockers.append("independent assessment metadata missing")
    else:
        if assessor.get("independent") is not True:
            blockers.append("assessment is not marked independent")
        if not isinstance(assessor.get("identity"), str) or not assessor.get("identity", "").strip():
            blockers.append("assessor identity missing")

    measured = [_rate(assessment, metric) for metric in WORKFLOW_METRICS]
    if any(value == NOT_MEASURED for value in measured):
        blockers.append("one or more full-workflow metrics lack applicable assessed observations")
    return sorted(set(blockers))


def finalize_manifest(
    prepared: Mapping[str, Any],
    *,
    run: Mapping[str, Any],
    blindness: Mapping[str, Any],
    assessment: Mapping[str, Any],
) -> dict[str, Any]:
    if prepared.get("schema_version") != SCHEMA_VERSION or prepared.get("phase") != "PREPARED":
        raise ArenaError("finalize requires a PREPARED sechelix-arena/v1 manifest")
    participant = validate_participant(prepared.get("participant", {}))
    result = json.loads(json.dumps(prepared))
    result["phase"] = "FINALIZED"
    result["participant"] = participant
    result["run"] = dict(run)
    result["blindness"] = dict(blindness)
    result["assessment_digest"] = canonical_digest(assessment)
    result["full_workflow"] = {metric: _rate(assessment, metric) for metric in WORKFLOW_METRICS}
    blockers = _publication_blockers(result, assessment)
    result["measurement_status"] = MEASURED if not blockers else NOT_MEASURED
    result["publication"] = {
        "eligible": not blockers,
        "blockers": blockers,
        "note": (
            "Comparable full-workflow measurement; label precision/recall is scored separately by run_evals.py."
            if not blockers
            else "Do not publish this record as a measured Arena result until every blocker is resolved."
        ),
    }
    return result


def comparable(left: Mapping[str, Any], right: Mapping[str, Any]) -> tuple[bool, str]:
    """Decide whether two finalized records are eligible for an apples-to-apples comparison."""
    if left.get("measurement_status") != MEASURED or right.get("measurement_status") != MEASURED:
        return False, "both records must be MEASURED"
    lp = left.get("participant", {})
    rp = right.get("participant", {})
    if lp.get("category") != rp.get("category"):
        return False, "participant categories differ"
    if sorted(lp.get("capability_scope", [])) != sorted(rp.get("capability_scope", [])):
        return False, "capability scopes differ"
    if left.get("packet", {}).get("digest") != right.get("packet", {}).get("digest"):
        return False, "blind packets differ"
    return True, "same category, capability scope, and blind packet"


def _cli() -> int:
    parser = argparse.ArgumentParser(description="Prepare or finalize a SecHelix Arena measurement record")
    sub = parser.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare")
    prepare.add_argument("--packet", required=True)
    prepare.add_argument("--participant", required=True)
    prepare.add_argument("--output", required=True)

    final = sub.add_parser("finalize")
    final.add_argument("--manifest", required=True)
    final.add_argument("--run", required=True)
    final.add_argument("--blindness", required=True)
    final.add_argument("--assessment", required=True)
    final.add_argument("--output", required=True)

    args = parser.parse_args()
    if args.command == "prepare":
        record = prepare_manifest(_read_json(args.packet), _read_json(args.participant))
    else:
        record = finalize_manifest(
            _read_json(args.manifest),
            run=_read_json(args.run),
            blindness=_read_json(args.blindness),
            assessment=_read_json(args.assessment),
        )
    Path(args.output).write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
