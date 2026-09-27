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
from urllib.parse import urlparse
from typing import Any, Mapping

MEASURED = "MEASURED"
NOT_MEASURED = "NOT_MEASURED"
NA = "NOT_APPLICABLE"
SCHEMA_VERSION = "sechelix-arena/v1"
_BATCH_ASSESSMENT_SCHEMA_VERSION = "sechelix-arena-batch-assessment/v1"
_BATCH_ASSESSMENT_READY_STATUS = "READY_FOR_ARENA_FINALIZE"
_PROTOCOL_BINDING_SCHEMA_VERSION = "sechelix-arena-assessment-protocol-binding/v1"
_PROTOCOL_BINDING_STATUS = "SEALED_FOR_ARENA_FINALIZE"

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

_MIN_BASIS_CHARS = 24
_MIN_METRIC_BASIS_CHARS = 24
_ATTESTATION_SCHEMES = frozenset({"https"})

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


def _metric_evidence_blockers(
    case_id: str,
    observation: Mapping[str, Any],
    field: str,
) -> list[str]:
    """Require every scored workflow judgment to point at attributable evidence.

    Arena cannot independently inspect arbitrary external artifacts here, but a
    naked boolean is too weak for a publishable workflow measurement. Every
    boolean therefore needs a short rationale, one or more stable evidence
    references, and a digest binding the cited evidence bundle.
    """

    value = observation.get(field)
    if value == NA:
        return []
    if not isinstance(value, bool):
        return []

    evidence = observation.get("evidence")
    if not isinstance(evidence, Mapping):
        return [f"{case_id}.{field} missing evidence mapping"]
    item = evidence.get(field)
    if not isinstance(item, Mapping):
        return [f"{case_id}.{field} missing evidence record"]

    blockers: list[str] = []
    basis = item.get("basis")
    if not isinstance(basis, str) or len(basis.strip()) < _MIN_METRIC_BASIS_CHARS:
        blockers.append(
            f"{case_id}.{field}.evidence.basis must explain the scored judgment"
        )

    refs = item.get("refs")
    if (
        not isinstance(refs, list)
        or not refs
        or not all(isinstance(ref, str) and ref.strip() for ref in refs)
    ):
        blockers.append(
            f"{case_id}.{field}.evidence.refs must contain at least one stable reference"
        )

    digest = item.get("artifact_digest")
    if not _is_digest(digest):
        blockers.append(
            f"{case_id}.{field}.evidence.artifact_digest missing or malformed"
        )
    return blockers


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
                continue
            blockers.extend(_metric_evidence_blockers(case_id, observation, field))
    if len(observed_ids) != len(set(observed_ids)):
        blockers.append("assessment contains duplicate case IDs")
    if sorted(observed_ids) != sorted(expected_ids):
        blockers.append("assessment does not cover every prepared blind case exactly once")
    return blockers


def _origin(url: str) -> str:
    """Scheme-and-host of a URL, lowercased, for same-origin comparison."""
    parsed = urlparse(url.strip())
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path.rstrip('/').lower()}"


def _owner_namespace(url: str) -> str:
    """The account or organisation a source URL belongs to, or "" if undecidable."""
    parsed = urlparse(url.strip())
    parts = [segment for segment in parsed.path.split("/") if segment]
    if not parsed.netloc or not parts:
        return ""
    return f"{parsed.netloc.lower()}/{parts[0].lower()}"


def _independence_blockers(
    manifest: Mapping[str, Any],
    assessor: Mapping[str, Any],
    blindness: Any,
) -> list[str]:
    """Independence cannot be verified here, so require it to be attributable.

    A bare ``independent: true`` is a claim about a fact this harness has no way
    to check. Flipping it costs one keystroke and, before this gate existed,
    promoted a self-authored perfect score straight to publishable. So the claim
    must instead be attributable: it has to name how independence was
    established and point at an artifact a reader can open, and it must not come
    from the account that publishes the participant.
    """
    blockers: list[str] = []
    if assessor.get("independent") is not True:
        return blockers

    basis = assessor.get("independence_basis")
    if not isinstance(basis, str) or len(basis.strip()) < _MIN_BASIS_CHARS:
        blockers.append(
            "assessor.independence_basis must state how independence was established"
        )

    attestation = assessor.get("attestation_url")
    if not isinstance(attestation, str) or not attestation.strip():
        blockers.append("assessor.attestation_url missing")
    elif urlparse(attestation.strip()).scheme not in _ATTESTATION_SCHEMES:
        blockers.append("assessor.attestation_url must be a resolvable https URL")
    else:
        participant = manifest.get("participant")
        source = participant.get("source_url") if isinstance(participant, Mapping) else None
        if isinstance(source, str) and source.strip():
            owner = _owner_namespace(source)
            if owner and _owner_namespace(attestation) == owner:
                blockers.append(
                    "assessor.attestation_url is published by the participant's own "
                    "account, which cannot attest to its independence"
                )
            if _origin(attestation) == _origin(source):
                blockers.append(
                    "assessor.attestation_url points at the participant itself"
                )

    if isinstance(blindness, Mapping) and blindness.get("evaluator_independent") is not True:
        blockers.append(
            "assessor.independent contradicts blindness.evaluator_independent"
        )
    return blockers


def _prediction_freeze_blockers(
    manifest: Mapping[str, Any],
    prediction_freeze: Mapping[str, Any] | None,
) -> list[str]:
    """Require publishable Arena results to bind the real prediction freeze.

    arena_freeze.py intentionally owns freeze/blindness validation. Import it
    lazily here to avoid a module-import cycle because that helper imports
    Arena's canonical digest implementation.
    """

    if not isinstance(prediction_freeze, Mapping):
        return ["prediction freeze evidence missing"]

    blindness = manifest.get("blindness")
    if not isinstance(blindness, Mapping):
        return ["blindness record missing"]

    blockers: list[str] = []
    try:
        from evals.arena_freeze import (
            ArenaPredictionFreezeError,
            validate_blindness_record,
        )

        run = manifest.get("run")
        not_before = run.get("finished_at") if isinstance(run, Mapping) else None
        validate_blindness_record(
            prediction_freeze,
            blindness,
            not_before=not_before if isinstance(not_before, str) else None,
        )
    except (ArenaPredictionFreezeError, TypeError, ValueError) as exc:
        blockers.append(f"prediction freeze/blindness validation failed: {exc}")

    packet = manifest.get("packet")
    if not isinstance(packet, Mapping) or prediction_freeze.get("packet_digest") != packet.get("digest"):
        blockers.append("prediction freeze is not bound to the prepared packet digest")
    elif isinstance(packet.get("case_ids"), list):
        prediction_set = prediction_freeze.get("prediction_set")
        frozen_case_ids = (
            sorted(str(row.get("case_id")) for row in prediction_set)
            if isinstance(prediction_set, list)
            and all(isinstance(row, Mapping) for row in prediction_set)
            else []
        )
        if frozen_case_ids != sorted(str(case_id) for case_id in packet["case_ids"]):
            blockers.append(
                "prediction freeze does not cover every prepared blind case exactly once"
            )

    participant = manifest.get("participant")
    if (
        not isinstance(participant, Mapping)
        or prediction_freeze.get("participant_digest") != canonical_digest(participant)
    ):
        blockers.append("prediction freeze is not bound to the prepared participant")

    return blockers


def _assessment_core_digest(assessment: Mapping[str, Any]) -> str:
    return canonical_digest(
        {
            "packet_digest": assessment.get("packet_digest"),
            "assessor": assessment.get("assessor"),
            "observations": assessment.get("observations"),
        }
    )


def _batch_protocol_blockers(
    manifest: Mapping[str, Any],
    assessment: Mapping[str, Any],
    prediction_freeze: Mapping[str, Any] | None,
) -> list[str]:
    """Require batch assessments to be sealed to one exact protocol chain.

    Generic Arena assessment packets remain supported. Once an assessment carries
    batch_binding metadata, publication requires the stronger binding emitted by
    arena_batch_assessor.py so the same judgments cannot be replayed against a
    different handoff, freeze, or post-freeze blindness record.
    """

    batch_binding = assessment.get("batch_binding")
    if batch_binding is None:
        return []
    if not isinstance(batch_binding, Mapping):
        return ["assessment batch_binding is malformed"]

    blockers: list[str] = []
    if batch_binding.get("schema_version") != _BATCH_ASSESSMENT_SCHEMA_VERSION:
        blockers.append("assessment batch_binding schema is unsupported")
    if batch_binding.get("status") != _BATCH_ASSESSMENT_READY_STATUS:
        blockers.append("assessment batch_binding is not ready for Arena finalize")

    core_digest = _assessment_core_digest(assessment)
    if batch_binding.get("assessment_digest") != core_digest:
        blockers.append("assessment payload digest does not match batch_binding")

    packet = manifest.get("packet")
    observations = assessment.get("observations")
    if not isinstance(packet, Mapping):
        blockers.append("prepared packet record missing for batch assessment")
    else:
        if batch_binding.get("case_id_digest") != packet.get("case_id_digest"):
            blockers.append("assessment batch_binding case identity digest mismatch")
    if not isinstance(observations, list):
        blockers.append("assessment observations missing for batch binding")
    elif batch_binding.get("case_count") != len(observations):
        blockers.append("assessment batch_binding case_count mismatch")

    handoff_digest = batch_binding.get("handoff_digest")
    if not _is_digest(handoff_digest):
        blockers.append("assessment batch_binding handoff_digest missing or malformed")

    protocol = assessment.get("protocol_binding")
    if not isinstance(protocol, Mapping):
        blockers.append("batch assessment protocol binding missing")
        return blockers

    if protocol.get("schema_version") != _PROTOCOL_BINDING_SCHEMA_VERSION:
        blockers.append("assessment protocol binding schema is unsupported")
    if protocol.get("status") != _PROTOCOL_BINDING_STATUS:
        blockers.append("assessment protocol binding is not sealed for finalize")

    binding_digest = protocol.get("binding_digest")
    if not _is_digest(binding_digest):
        blockers.append("assessment protocol binding digest missing or malformed")
    else:
        expected_binding_digest = canonical_digest(
            {key: value for key, value in protocol.items() if key != "binding_digest"}
        )
        if binding_digest != expected_binding_digest:
            blockers.append("assessment protocol binding digest does not match contents")

    if isinstance(packet, Mapping):
        if protocol.get("packet_digest") != packet.get("digest"):
            blockers.append("assessment protocol binding packet digest mismatch")
        if protocol.get("case_id_digest") != packet.get("case_id_digest"):
            blockers.append("assessment protocol binding case identity digest mismatch")

    if protocol.get("handoff_digest") != handoff_digest:
        blockers.append("assessment protocol binding handoff digest mismatch")
    if protocol.get("assessment_digest") != core_digest:
        blockers.append("assessment protocol binding assessment digest mismatch")
    if protocol.get("case_count") != batch_binding.get("case_count"):
        blockers.append("assessment protocol binding case_count mismatch")

    blindness = manifest.get("blindness")
    if not isinstance(blindness, Mapping):
        blockers.append("blindness record missing for assessment protocol binding")
    else:
        if protocol.get("blindness_digest") != canonical_digest(blindness):
            blockers.append("assessment protocol binding blindness digest mismatch")
        if protocol.get("ground_truth_digest") != blindness.get("ground_truth_digest"):
            blockers.append("assessment protocol binding ground-truth digest mismatch")
        if protocol.get("truth_revealed_at") != blindness.get("truth_revealed_at"):
            blockers.append("assessment protocol binding truth-reveal timestamp mismatch")

    if not isinstance(prediction_freeze, Mapping):
        blockers.append("prediction freeze missing for assessment protocol binding")
    else:
        if protocol.get("prediction_freeze_digest") != prediction_freeze.get("freeze_digest"):
            blockers.append("assessment protocol binding prediction-freeze digest mismatch")
        if protocol.get("prediction_digest") != prediction_freeze.get("prediction_digest"):
            blockers.append("assessment protocol binding prediction digest mismatch")
        if protocol.get("participant_digest") != prediction_freeze.get("participant_digest"):
            blockers.append("assessment protocol binding participant digest mismatch")
        if prediction_freeze.get("handoff_digest") != handoff_digest:
            blockers.append("prediction freeze and assessment batch handoff digest mismatch")

    return blockers


def _publication_blockers(
    manifest: Mapping[str, Any],
    assessment: Mapping[str, Any],
    prediction_freeze: Mapping[str, Any] | None = None,
) -> list[str]:
    blockers = _assessment_blockers(manifest, assessment)
    blockers.extend(_prediction_freeze_blockers(manifest, prediction_freeze))
    blockers.extend(_batch_protocol_blockers(manifest, assessment, prediction_freeze))
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
        identity = assessor.get("identity")
        if not isinstance(identity, str) or not identity.strip():
            blockers.append("assessor identity missing")
        blockers.extend(_independence_blockers(manifest, assessor, blindness))

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
    prediction_freeze: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if prepared.get("schema_version") != SCHEMA_VERSION or prepared.get("phase") != "PREPARED":
        raise ArenaError("finalize requires a PREPARED sechelix-arena/v1 manifest")
    participant = validate_participant(prepared.get("participant", {}))
    result = json.loads(json.dumps(prepared))
    result["phase"] = "FINALIZED"
    result["participant"] = participant
    result["run"] = dict(run)
    result["blindness"] = dict(blindness)
    result["prediction_freeze_digest"] = (
        prediction_freeze.get("freeze_digest")
        if isinstance(prediction_freeze, Mapping)
        else None
    )
    result["assessment_digest"] = canonical_digest(assessment)
    protocol_binding = assessment.get("protocol_binding")
    result["assessment_protocol_binding_digest"] = (
        protocol_binding.get("binding_digest")
        if isinstance(protocol_binding, Mapping)
        else None
    )
    result["full_workflow"] = {metric: _rate(assessment, metric) for metric in WORKFLOW_METRICS}
    blockers = _publication_blockers(result, assessment, prediction_freeze)
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
    final.add_argument("--prediction-freeze", required=True)
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
            prediction_freeze=_read_json(args.prediction_freeze),
        )
    Path(args.output).write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
