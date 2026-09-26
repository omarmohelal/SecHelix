#!/usr/bin/env python3
"""Bind an independent Arena assessment to a complete manifest-verified batch handoff.

This helper is the fail-closed bridge between arena_batch.py and arena.py
finalize. It still does not decide correctness: an independent assessor supplies
the boolean / NOT_APPLICABLE judgments and human-readable basis. The helper
proves that every scored judgment cites only artifacts from the manifest-verified
workspace bundle for the same opaque case.

No artifact body, repository source, credential material, local absolute path,
or blind ground truth is copied into the assessment output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from evals.arena import NA, WORKFLOW_METRICS, canonical_digest
from evals.arena_batch import (
    READY_STATUS as BATCH_READY_STATUS,
    SCHEMA_VERSION as BATCH_SCHEMA_VERSION,
)


SCHEMA_VERSION = "sechelix-arena-batch-assessment/v1"
READY_STATUS = "READY_FOR_ARENA_FINALIZE"
WORKFLOW_FIELDS = tuple(metric.removesuffix("_accuracy") for metric in WORKFLOW_METRICS)
_MIN_BASIS_CHARS = 24


class ArenaBatchAssessmentError(ValueError):
    """The assessor spec is not bound to the manifest-verified batch."""


def _is_digest(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    raw = value.removeprefix("sha256:")
    return len(raw) == 64 and all(char in "0123456789abcdef" for char in raw)


def _canonical_without_digest(handoff: Mapping[str, Any]) -> str:
    return canonical_digest(
        {key: value for key, value in handoff.items() if key != "handoff_digest"}
    )


def _validate_handoff(handoff: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    if handoff.get("schema_version") != BATCH_SCHEMA_VERSION:
        raise ArenaBatchAssessmentError("unsupported Arena batch handoff schema")
    if handoff.get("status") != BATCH_READY_STATUS:
        raise ArenaBatchAssessmentError("batch handoff is not ready for independent assessment")
    supplied_digest = handoff.get("handoff_digest")
    if not _is_digest(supplied_digest):
        raise ArenaBatchAssessmentError("batch handoff digest is missing or malformed")
    if supplied_digest != _canonical_without_digest(handoff):
        raise ArenaBatchAssessmentError("batch handoff digest does not match handoff contents")

    packet = handoff.get("packet")
    if not isinstance(packet, Mapping) or not _is_digest(packet.get("digest")):
        raise ArenaBatchAssessmentError("batch packet digest is missing or malformed")

    raw_cases = handoff.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ArenaBatchAssessmentError("batch handoff has no cases")
    cases: dict[str, Mapping[str, Any]] = {}
    for row in raw_cases:
        if not isinstance(row, Mapping):
            raise ArenaBatchAssessmentError("batch handoff contains a non-object case")
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id.startswith("CASE-"):
            raise ArenaBatchAssessmentError("batch handoff case id is invalid")
        if case_id in cases:
            raise ArenaBatchAssessmentError(f"duplicate batch case id: {case_id}")
        bundle = row.get("bundle")
        if not isinstance(bundle, Mapping):
            raise ArenaBatchAssessmentError(f"{case_id} measurement bundle missing")
        bundle_digest = row.get("bundle_digest")
        if not _is_digest(bundle_digest):
            raise ArenaBatchAssessmentError(f"{case_id} measurement bundle digest missing")
        if bundle_digest != canonical_digest(bundle):
            raise ArenaBatchAssessmentError(f"{case_id} measurement bundle digest mismatch")
        cases[case_id] = row

    if handoff.get("case_count") != len(cases):
        raise ArenaBatchAssessmentError("batch case_count does not match batch cases")
    return cases


def _resolve_inside(base_dir: Path, raw: str) -> Path:
    candidate = Path(raw)
    if candidate.is_absolute():
        raise ArenaBatchAssessmentError("artifact paths must be relative to --base-dir")
    base = base_dir.resolve()
    resolved = (base / candidate).resolve()
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ArenaBatchAssessmentError("artifact path escapes --base-dir") from exc
    if not resolved.is_file():
        raise ArenaBatchAssessmentError(f"artifact file does not exist: {raw}")
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _allowed_artifacts(case_row: Mapping[str, Any]) -> dict[str, str]:
    bundle = case_row.get("bundle")
    if not isinstance(bundle, Mapping):
        raise ArenaBatchAssessmentError("measurement bundle missing")
    bindings = bundle.get("bindings")
    if not isinstance(bindings, Mapping):
        raise ArenaBatchAssessmentError("measurement bundle bindings missing")
    raw = bindings.get("workspace_artifacts")
    if not isinstance(raw, Mapping) or not raw:
        raise ArenaBatchAssessmentError("measurement bundle workspace artifacts missing")

    allowed: dict[str, str] = {}
    for ref, digest in raw.items():
        if not isinstance(ref, str) or not ref.strip() or not _is_digest(digest):
            raise ArenaBatchAssessmentError("measurement bundle artifact map is malformed")
        allowed[ref] = str(digest)
    return allowed


def _bind_judgment_artifacts(
    *,
    case_id: str,
    case_row: Mapping[str, Any],
    artifacts: Any,
    base_dir: Path,
) -> tuple[list[str], str]:
    if not isinstance(artifacts, list) or not artifacts:
        raise ArenaBatchAssessmentError(
            f"{case_id} scored judgment requires at least one manifest-verified artifact"
        )
    allowed = _allowed_artifacts(case_row)
    manifest: list[dict[str, Any]] = []
    stable_refs: list[str] = []
    seen: set[str] = set()

    for item in artifacts:
        if not isinstance(item, Mapping):
            raise ArenaBatchAssessmentError(f"{case_id} artifact entry must be an object")
        artifact_ref = item.get("artifact_ref")
        path = item.get("path")
        if not isinstance(artifact_ref, str) or artifact_ref not in allowed:
            raise ArenaBatchAssessmentError(
                f"{case_id} artifact_ref is not in the manifest-verified workspace bundle"
            )
        if artifact_ref in seen:
            raise ArenaBatchAssessmentError(
                f"{case_id} duplicate artifact_ref in one judgment: {artifact_ref}"
            )
        seen.add(artifact_ref)
        if not isinstance(path, str) or not path.strip():
            raise ArenaBatchAssessmentError(f"{case_id} artifact path missing")

        resolved = _resolve_inside(base_dir, path.strip())
        observed = _sha256(resolved)
        expected = allowed[artifact_ref]
        if observed != expected:
            raise ArenaBatchAssessmentError(
                f"{case_id} artifact digest mismatch for {artifact_ref}"
            )

        stable_ref = f"case:{case_id}:workspace:{artifact_ref}"
        stable_refs.append(stable_ref)
        manifest.append(
            {
                "ref": stable_ref,
                "sha256": observed,
                "size_bytes": resolved.stat().st_size,
            }
        )

    manifest.sort(key=lambda row: str(row["ref"]))
    stable_refs.sort()
    return stable_refs, canonical_digest(manifest)


def build_batch_assessment(
    handoff: Mapping[str, Any],
    spec: Mapping[str, Any],
    *,
    base_dir: Path | str = ".",
) -> dict[str, Any]:
    """Build an Arena-compatible assessment bound to one verified batch."""

    cases = _validate_handoff(handoff)
    handoff_digest = handoff["handoff_digest"]
    if spec.get("handoff_digest") != handoff_digest:
        raise ArenaBatchAssessmentError("assessment spec is not bound to this batch handoff")

    packet_digest = handoff["packet"]["digest"]
    if spec.get("packet_digest") != packet_digest:
        raise ArenaBatchAssessmentError("assessment spec packet digest does not match batch")

    assessor = spec.get("assessor")
    if not isinstance(assessor, Mapping):
        raise ArenaBatchAssessmentError("assessor metadata must be an object")

    raw_observations = spec.get("observations")
    if not isinstance(raw_observations, list) or not raw_observations:
        raise ArenaBatchAssessmentError("assessment observations must be a non-empty list")

    observed: dict[str, Mapping[str, Any]] = {}
    for row in raw_observations:
        if not isinstance(row, Mapping):
            raise ArenaBatchAssessmentError("assessment contains a non-object observation")
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or case_id not in cases:
            raise ArenaBatchAssessmentError("assessment references a case outside the batch")
        if case_id in observed:
            raise ArenaBatchAssessmentError(f"duplicate assessment case: {case_id}")
        observed[case_id] = row

    if sorted(observed) != sorted(cases):
        missing = sorted(set(cases) - set(observed))
        extra = sorted(set(observed) - set(cases))
        raise ArenaBatchAssessmentError(
            f"assessment must cover every batch case exactly once; missing={missing}, extra={extra}"
        )

    root = Path(base_dir)
    output: list[dict[str, Any]] = []
    for case_id in sorted(cases):
        row = observed[case_id]
        judgments = row.get("judgments")
        if not isinstance(judgments, Mapping):
            raise ArenaBatchAssessmentError(f"{case_id} judgments missing")
        unknown = sorted(set(judgments) - set(WORKFLOW_FIELDS))
        missing = sorted(set(WORKFLOW_FIELDS) - set(judgments))
        if unknown or missing:
            raise ArenaBatchAssessmentError(
                f"{case_id} workflow fields invalid; missing={missing}, unknown={unknown}"
            )

        out: dict[str, Any] = {"case_id": case_id, "evidence": {}}
        for field in WORKFLOW_FIELDS:
            judgment = judgments[field]
            if not isinstance(judgment, Mapping):
                raise ArenaBatchAssessmentError(f"{case_id}.{field} judgment must be an object")
            value = judgment.get("value")
            if value == NA:
                out[field] = NA
                continue
            if not isinstance(value, bool):
                raise ArenaBatchAssessmentError(
                    f"{case_id}.{field}.value must be boolean or {NA}"
                )
            basis = judgment.get("basis")
            if not isinstance(basis, str) or len(basis.strip()) < _MIN_BASIS_CHARS:
                raise ArenaBatchAssessmentError(
                    f"{case_id}.{field}.basis must explain the independent judgment"
                )
            refs, digest = _bind_judgment_artifacts(
                case_id=case_id,
                case_row=cases[case_id],
                artifacts=judgment.get("artifacts"),
                base_dir=root,
            )
            out[field] = value
            out["evidence"][field] = {
                "basis": basis.strip(),
                "refs": refs,
                "artifact_digest": digest,
            }
        output.append(out)

    assessment = {
        "packet_digest": packet_digest,
        "assessor": dict(assessor),
        "observations": output,
        "batch_binding": {
            "schema_version": SCHEMA_VERSION,
            "status": READY_STATUS,
            "handoff_digest": handoff_digest,
            "case_count": len(output),
            "case_id_digest": handoff["packet"].get("case_id_digest"),
            "manifest_verified_artifacts_only": True,
            "scores_correctness": False,
            "note": (
                "This builder binds assessor-supplied judgments to manifest-verified "
                "workspace bytes. It does not decide correctness or establish assessor "
                "independence."
            ),
        },
    }
    assessment["batch_binding"]["assessment_digest"] = canonical_digest(
        {
            "packet_digest": assessment["packet_digest"],
            "assessor": assessment["assessor"],
            "observations": assessment["observations"],
        }
    )
    return assessment


def _read_object(path: Path | str, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArenaBatchAssessmentError(f"{label} cannot be read as JSON") from exc
    if not isinstance(value, Mapping):
        raise ArenaBatchAssessmentError(f"{label} must be a JSON object")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", required=True, type=Path)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--base-dir", type=Path, default=Path("."))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    result = build_batch_assessment(
        _read_object(args.handoff, "batch handoff"),
        _read_object(args.spec, "assessment spec"),
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
