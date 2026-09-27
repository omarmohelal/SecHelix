#!/usr/bin/env python3
"""Create attributable Arena prediction-freeze and blindness records.

This helper closes one protocol gap without pretending to establish evaluator
independence. A prediction freeze binds the exact prepared blind packet, pinned
participant metadata and complete manifest-verified batch handoff before truth is
revealed. A later blindness record can only be built when its declared truth
reveal time is strictly after the freeze time.

Timestamps and evaluator-independence claims remain externally attributable
facts; this module cannot prove them. It only makes contradictory or malformed
records fail closed and gives Arena a deterministic prediction digest derived
from the sealed batch evidence.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from evals.arena import (
    SCHEMA_VERSION as ARENA_SCHEMA_VERSION,
    canonical_digest,
)
from evals.arena_batch import (
    READY_STATUS as BATCH_READY_STATUS,
    SCHEMA_VERSION as BATCH_SCHEMA_VERSION,
)


FREEZE_SCHEMA_VERSION = "sechelix-arena-prediction-freeze/v1"
FREEZE_STATUS = "PREDICTIONS_FROZEN"
BLINDNESS_SCHEMA_VERSION = "sechelix-arena-blindness/v1"
_ALLOWED_CONTAMINATION = {"UNCONTAMINATED", "CONTAMINATED", "UNASSESSED"}


class ArenaPredictionFreezeError(ValueError):
    """The supplied Arena run state cannot be frozen consistently."""


def _is_digest(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    raw = value.removeprefix("sha256:")
    return len(raw) == 64 and all(ch in "0123456789abcdef" for ch in raw)


def _parse_timestamp(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ArenaPredictionFreezeError(f"{field} must be a non-empty ISO-8601 timestamp")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ArenaPredictionFreezeError(f"{field} is not a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ArenaPredictionFreezeError(f"{field} must include an explicit timezone")
    return parsed


def _validate_prepared(manifest: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    if manifest.get("schema_version") != ARENA_SCHEMA_VERSION:
        raise ArenaPredictionFreezeError("unsupported Arena manifest schema")
    if manifest.get("phase") != "PREPARED":
        raise ArenaPredictionFreezeError("prediction freeze requires a PREPARED Arena manifest")
    packet = manifest.get("packet")
    participant = manifest.get("participant")
    if not isinstance(packet, Mapping):
        raise ArenaPredictionFreezeError("prepared packet record missing")
    if not _is_digest(packet.get("digest")):
        raise ArenaPredictionFreezeError("prepared packet digest missing or malformed")
    case_ids = packet.get("case_ids")
    if (
        not isinstance(case_ids, list)
        or not case_ids
        or len(case_ids) != len(set(case_ids))
        or not all(isinstance(item, str) and item.startswith("CASE-") for item in case_ids)
    ):
        raise ArenaPredictionFreezeError("prepared packet case identities are invalid")
    if not isinstance(participant, Mapping):
        raise ArenaPredictionFreezeError("prepared participant record missing")
    return packet, participant


def _validate_handoff(handoff: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if handoff.get("schema_version") != BATCH_SCHEMA_VERSION:
        raise ArenaPredictionFreezeError("unsupported Arena batch handoff schema")
    if handoff.get("status") != BATCH_READY_STATUS:
        raise ArenaPredictionFreezeError("batch handoff is not ready for independent assessment")
    supplied = handoff.get("handoff_digest")
    if not _is_digest(supplied):
        raise ArenaPredictionFreezeError("batch handoff digest missing or malformed")
    recalculated = canonical_digest(
        {key: value for key, value in handoff.items() if key != "handoff_digest"}
    )
    if supplied != recalculated:
        raise ArenaPredictionFreezeError("batch handoff digest does not match handoff contents")

    raw_cases = handoff.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ArenaPredictionFreezeError("batch handoff has no cases")
    seen: set[str] = set()
    cases: list[Mapping[str, Any]] = []
    for row in raw_cases:
        if not isinstance(row, Mapping):
            raise ArenaPredictionFreezeError("batch handoff contains a non-object case")
        case_id = row.get("case_id")
        run_id = row.get("run_id")
        bundle_digest = row.get("bundle_digest")
        bundle = row.get("bundle")
        if not isinstance(case_id, str) or not case_id.startswith("CASE-"):
            raise ArenaPredictionFreezeError("batch case id is invalid")
        if case_id in seen:
            raise ArenaPredictionFreezeError(f"duplicate batch case id: {case_id}")
        seen.add(case_id)
        if not isinstance(run_id, str) or not run_id.startswith("RUN-"):
            raise ArenaPredictionFreezeError(f"{case_id} run id is invalid")
        if not _is_digest(bundle_digest):
            raise ArenaPredictionFreezeError(f"{case_id} bundle digest missing or malformed")
        if not isinstance(bundle, Mapping) or canonical_digest(bundle) != bundle_digest:
            raise ArenaPredictionFreezeError(f"{case_id} bundle digest mismatch")
        cases.append(row)
    if handoff.get("case_count") != len(cases):
        raise ArenaPredictionFreezeError("batch case_count does not match batch cases")
    return cases


def build_prediction_freeze(
    prepared: Mapping[str, Any],
    handoff: Mapping[str, Any],
    *,
    frozen_at: str,
    recorder_identity: str,
    recorder_role: str,
) -> dict[str, Any]:
    """Bind one complete prepared Arena packet to sealed SecHelix run evidence."""

    packet, participant = _validate_prepared(prepared)
    cases = _validate_handoff(handoff)

    handoff_packet = handoff.get("packet")
    if not isinstance(handoff_packet, Mapping):
        raise ArenaPredictionFreezeError("batch handoff packet record missing")
    if handoff_packet.get("digest") != packet.get("digest"):
        raise ArenaPredictionFreezeError("batch handoff is bound to a different blind packet")
    expected_case_ids = sorted(str(item) for item in packet["case_ids"])
    observed_case_ids = sorted(str(item["case_id"]) for item in cases)
    if observed_case_ids != expected_case_ids:
        raise ArenaPredictionFreezeError("batch handoff does not cover the prepared case set")
    if handoff.get("participant") != participant:
        raise ArenaPredictionFreezeError("batch participant does not match prepared participant")

    _parse_timestamp(frozen_at, field="frozen_at")
    if not isinstance(recorder_identity, str) or not recorder_identity.strip():
        raise ArenaPredictionFreezeError("recorder_identity must be a non-empty string")
    if not isinstance(recorder_role, str) or not recorder_role.strip():
        raise ArenaPredictionFreezeError("recorder_role must be a non-empty string")

    prediction_set = [
        {
            "case_id": str(row["case_id"]),
            "run_id": str(row["run_id"]),
            "bundle_digest": str(row["bundle_digest"]),
        }
        for row in sorted(cases, key=lambda item: str(item["case_id"]))
    ]
    prediction_digest = canonical_digest(prediction_set)

    freeze: dict[str, Any] = {
        "schema_version": FREEZE_SCHEMA_VERSION,
        "status": FREEZE_STATUS,
        "measurement_status": "NOT_MEASURED",
        "packet_digest": packet["digest"],
        "participant_digest": canonical_digest(participant),
        "handoff_digest": handoff["handoff_digest"],
        "case_count": len(prediction_set),
        "prediction_digest": prediction_digest,
        "frozen_at": frozen_at,
        "recorder": {
            "identity": recorder_identity.strip(),
            "role": recorder_role.strip(),
        },
        "prediction_set": prediction_set,
        "scope": {
            "reveals_ground_truth": False,
            "establishes_evaluator_independence": False,
            "scores_correctness": False,
            "note": (
                "This record proves which manifest-verified prediction bundles were "
                "declared frozen. Timestamp truth and evaluator independence remain "
                "externally attributable protocol facts."
            ),
        },
    }
    freeze["freeze_digest"] = canonical_digest(
        {key: value for key, value in freeze.items() if key != "freeze_digest"}
    )
    return freeze


def validate_prediction_freeze(freeze: Mapping[str, Any]) -> None:
    if freeze.get("schema_version") != FREEZE_SCHEMA_VERSION:
        raise ArenaPredictionFreezeError("unsupported prediction freeze schema")
    if freeze.get("status") != FREEZE_STATUS:
        raise ArenaPredictionFreezeError("prediction freeze status is invalid")
    for key in (
        "packet_digest",
        "participant_digest",
        "handoff_digest",
        "prediction_digest",
        "freeze_digest",
    ):
        if not _is_digest(freeze.get(key)):
            raise ArenaPredictionFreezeError(f"{key} missing or malformed")
    expected = canonical_digest(
        {key: value for key, value in freeze.items() if key != "freeze_digest"}
    )
    if expected != freeze.get("freeze_digest"):
        raise ArenaPredictionFreezeError("prediction freeze digest does not match contents")
    _parse_timestamp(freeze.get("frozen_at"), field="frozen_at")
    prediction_set = freeze.get("prediction_set")
    if not isinstance(prediction_set, list) or not prediction_set:
        raise ArenaPredictionFreezeError("prediction set missing")
    if freeze.get("case_count") != len(prediction_set):
        raise ArenaPredictionFreezeError("freeze case_count does not match prediction set")
    if canonical_digest(prediction_set) != freeze.get("prediction_digest"):
        raise ArenaPredictionFreezeError("prediction digest does not match prediction set")


def build_blindness_record(
    freeze: Mapping[str, Any],
    *,
    ground_truth_digest: str,
    truth_revealed_at: str,
    evaluator_independent: bool,
    contamination: str,
) -> dict[str, Any]:
    """Create Arena blindness metadata only after a valid prediction freeze."""

    validate_prediction_freeze(freeze)
    if not _is_digest(ground_truth_digest):
        raise ArenaPredictionFreezeError("ground_truth_digest missing or malformed")
    if not isinstance(evaluator_independent, bool):
        raise ArenaPredictionFreezeError("evaluator_independent must be boolean")
    if contamination not in _ALLOWED_CONTAMINATION:
        raise ArenaPredictionFreezeError(
            "contamination must be UNCONTAMINATED, CONTAMINATED, or UNASSESSED"
        )
    frozen_at = _parse_timestamp(freeze["frozen_at"], field="frozen_at")
    revealed_at = _parse_timestamp(truth_revealed_at, field="truth_revealed_at")
    if revealed_at <= frozen_at:
        raise ArenaPredictionFreezeError(
            "truth_revealed_at must be strictly after the prediction freeze"
        )

    return {
        "schema_version": BLINDNESS_SCHEMA_VERSION,
        "evaluator_independent": evaluator_independent,
        "truth_revealed_after_predictions": True,
        "contamination": contamination,
        "ground_truth_digest": ground_truth_digest,
        "prediction_digest": freeze["prediction_digest"],
        "prediction_freeze_digest": freeze["freeze_digest"],
        "frozen_at": freeze["frozen_at"],
        "truth_revealed_at": truth_revealed_at,
        "scope": {
            "ordering_checked": True,
            "ordering_is_self_or_externally_attested": True,
            "establishes_evaluator_independence": False,
            "note": (
                "Timestamp ordering is validated, but SecHelix cannot independently "
                "prove the timestamps, contamination state, or evaluator independence."
            ),
        },
    }


def validate_blindness_record(
    freeze: Mapping[str, Any],
    blindness: Mapping[str, Any],
) -> None:
    """Validate that a blindness record is bound to one valid prediction freeze.

    This is intentionally stricter than checking a handful of booleans during
    Arena finalization. A publishable record must preserve the exact prediction
    digest and freeze digest, carry the freeze timestamp unchanged, and declare
    a truth-reveal timestamp that is strictly later.
    """

    validate_prediction_freeze(freeze)
    if blindness.get("schema_version") != BLINDNESS_SCHEMA_VERSION:
        raise ArenaPredictionFreezeError("unsupported Arena blindness schema")
    if not isinstance(blindness.get("evaluator_independent"), bool):
        raise ArenaPredictionFreezeError(
            "blindness evaluator_independent must be boolean"
        )
    if blindness.get("truth_revealed_after_predictions") is not True:
        raise ArenaPredictionFreezeError(
            "blindness must establish truth reveal after predictions"
        )
    if blindness.get("contamination") not in _ALLOWED_CONTAMINATION:
        raise ArenaPredictionFreezeError("blindness contamination state is invalid")
    if not _is_digest(blindness.get("ground_truth_digest")):
        raise ArenaPredictionFreezeError(
            "blindness ground_truth_digest missing or malformed"
        )
    if blindness.get("prediction_digest") != freeze.get("prediction_digest"):
        raise ArenaPredictionFreezeError(
            "blindness prediction_digest does not match the prediction freeze"
        )
    if blindness.get("prediction_freeze_digest") != freeze.get("freeze_digest"):
        raise ArenaPredictionFreezeError(
            "blindness prediction_freeze_digest does not match the prediction freeze"
        )
    if blindness.get("frozen_at") != freeze.get("frozen_at"):
        raise ArenaPredictionFreezeError(
            "blindness frozen_at does not match the prediction freeze"
        )

    frozen_at = _parse_timestamp(freeze.get("frozen_at"), field="frozen_at")
    revealed_at = _parse_timestamp(
        blindness.get("truth_revealed_at"),
        field="truth_revealed_at",
    )
    if revealed_at <= frozen_at:
        raise ArenaPredictionFreezeError(
            "truth_revealed_at must be strictly after the prediction freeze"
        )

    scope = blindness.get("scope")
    if not isinstance(scope, Mapping) or scope.get("ordering_checked") is not True:
        raise ArenaPredictionFreezeError(
            "blindness scope must record that freeze/reveal ordering was checked"
        )


def _read_object(path: Path | str, label: str) -> Mapping[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArenaPredictionFreezeError(f"{label} cannot be read as JSON") from exc
    if not isinstance(payload, Mapping):
        raise ArenaPredictionFreezeError(f"{label} must be a JSON object")
    return payload


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    freeze = sub.add_parser("freeze")
    freeze.add_argument("--manifest", required=True, type=Path)
    freeze.add_argument("--handoff", required=True, type=Path)
    freeze.add_argument("--frozen-at", required=True)
    freeze.add_argument("--recorder-identity", required=True)
    freeze.add_argument("--recorder-role", required=True)
    freeze.add_argument("--output", required=True, type=Path)

    blind = sub.add_parser("blindness")
    blind.add_argument("--freeze", required=True, type=Path)
    blind.add_argument("--ground-truth-digest", required=True)
    blind.add_argument("--truth-revealed-at", required=True)
    blind.add_argument("--evaluator-independent", choices=("true", "false"), required=True)
    blind.add_argument(
        "--contamination",
        choices=tuple(sorted(_ALLOWED_CONTAMINATION)),
        required=True,
    )
    blind.add_argument("--output", required=True, type=Path)

    args = parser.parse_args(argv)
    if args.command == "freeze":
        result = build_prediction_freeze(
            _read_object(args.manifest, "prepared manifest"),
            _read_object(args.handoff, "batch handoff"),
            frozen_at=args.frozen_at,
            recorder_identity=args.recorder_identity,
            recorder_role=args.recorder_role,
        )
    else:
        result = build_blindness_record(
            _read_object(args.freeze, "prediction freeze"),
            ground_truth_digest=args.ground_truth_digest,
            truth_revealed_at=args.truth_revealed_at,
            evaluator_independent=args.evaluator_independent == "true",
            contamination=args.contamination,
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
