#!/usr/bin/env python3
"""Build evidence-backed SecHelix Arena assessment packets.

This helper does not decide whether a participant was correct and does not
establish assessor independence. An independent evaluator supplies each workflow
judgment and its human-readable basis. The builder only binds those judgments to
stable artifact references and SHA-256 digests while keeping artifact contents
out of the assessment JSON.

Input schema (JSON):

{
  "packet_digest": "sha256:...",
  "assessor": {...},
  "observations": [
    {
      "case_id": "CASE-...",
      "judgments": {
        "verification": {
          "value": true,
          "basis": "...",
          "artifacts": [
            {"ref": "run:CASE-...:verifier", "path": "artifacts/verifier.json"}
          ]
        },
        ...
      }
    }
  ]
}

Every Arena workflow field must be present. A judgment may instead use
"value": "NOT_APPLICABLE", in which case evidence is intentionally omitted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from evals.arena import NA, WORKFLOW_METRICS, canonical_digest


class AssessmentPacketError(ValueError):
    """The evaluator packet spec is incomplete, unsafe, or ambiguous."""


WORKFLOW_FIELDS = tuple(metric.removesuffix("_accuracy") for metric in WORKFLOW_METRICS)
_MIN_BASIS_CHARS = 24


def _is_digest(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def _resolve_artifact(base_dir: Path, relative_path: str) -> Path:
    raw = Path(relative_path)
    if raw.is_absolute():
        raise AssessmentPacketError("artifact paths must be relative to --base-dir")
    base = base_dir.resolve()
    resolved = (base / raw).resolve()
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise AssessmentPacketError("artifact path escapes --base-dir") from exc
    if not resolved.is_file():
        raise AssessmentPacketError(f"artifact file does not exist: {relative_path}")
    return resolved


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def artifact_bundle_digest(
    artifacts: Sequence[Mapping[str, Any]],
    *,
    base_dir: Path | str,
) -> tuple[list[str], str]:
    """Return stable refs and a digest binding their exact file bytes.

    Absolute/local filesystem paths and artifact contents are deliberately not
    returned. The bundle digest is over a canonical list of
    {ref, sha256, size_bytes} records sorted by ref.
    """

    if not artifacts:
        raise AssessmentPacketError("scored judgment requires at least one artifact")

    root = Path(base_dir)
    manifest: list[dict[str, Any]] = []
    refs: list[str] = []
    seen: set[str] = set()
    for item in artifacts:
        if not isinstance(item, Mapping):
            raise AssessmentPacketError("artifact entries must be objects")
        ref = item.get("ref")
        path = item.get("path")
        if not isinstance(ref, str) or not ref.strip():
            raise AssessmentPacketError("artifact ref must be a non-empty stable reference")
        ref = ref.strip()
        if ref in seen:
            raise AssessmentPacketError(f"duplicate artifact ref: {ref}")
        seen.add(ref)
        if not isinstance(path, str) or not path.strip():
            raise AssessmentPacketError(f"artifact {ref!r} is missing a relative path")
        resolved = _resolve_artifact(root, path.strip())
        refs.append(ref)
        manifest.append(
            {
                "ref": ref,
                "sha256": _file_sha256(resolved),
                "size_bytes": resolved.stat().st_size,
            }
        )

    manifest.sort(key=lambda item: str(item["ref"]))
    refs.sort()
    return refs, canonical_digest(manifest)


def build_assessment_packet(
    spec: Mapping[str, Any],
    *,
    base_dir: Path | str = ".",
) -> dict[str, Any]:
    """Build an Arena-compatible assessment object from explicit judgments."""

    packet_digest = spec.get("packet_digest")
    if not _is_digest(packet_digest):
        raise AssessmentPacketError("packet_digest must be a sha256 digest")

    assessor = spec.get("assessor")
    if not isinstance(assessor, Mapping):
        raise AssessmentPacketError("assessor metadata must be an object")

    raw_observations = spec.get("observations")
    if not isinstance(raw_observations, list) or not raw_observations:
        raise AssessmentPacketError("observations must be a non-empty list")

    output: list[dict[str, Any]] = []
    seen_cases: set[str] = set()
    for raw in raw_observations:
        if not isinstance(raw, Mapping):
            raise AssessmentPacketError("every observation must be an object")
        case_id = raw.get("case_id")
        if not isinstance(case_id, str) or not case_id.startswith("CASE-"):
            raise AssessmentPacketError("every observation needs an opaque CASE- identifier")
        if case_id in seen_cases:
            raise AssessmentPacketError(f"duplicate case id: {case_id}")
        seen_cases.add(case_id)

        judgments = raw.get("judgments")
        if not isinstance(judgments, Mapping):
            raise AssessmentPacketError(f"{case_id} is missing judgments")

        unknown = sorted(set(judgments) - set(WORKFLOW_FIELDS))
        missing = sorted(set(WORKFLOW_FIELDS) - set(judgments))
        if unknown:
            raise AssessmentPacketError(
                f"{case_id} has unknown workflow judgments: {', '.join(unknown)}"
            )
        if missing:
            raise AssessmentPacketError(
                f"{case_id} is missing workflow judgments: {', '.join(missing)}"
            )

        observation: dict[str, Any] = {"case_id": case_id, "evidence": {}}
        for field in WORKFLOW_FIELDS:
            judgment = judgments[field]
            if not isinstance(judgment, Mapping):
                raise AssessmentPacketError(f"{case_id}.{field} judgment must be an object")
            value = judgment.get("value")
            if value == NA:
                observation[field] = NA
                continue
            if not isinstance(value, bool):
                raise AssessmentPacketError(
                    f"{case_id}.{field}.value must be boolean or {NA}"
                )
            basis = judgment.get("basis")
            if not isinstance(basis, str) or len(basis.strip()) < _MIN_BASIS_CHARS:
                raise AssessmentPacketError(
                    f"{case_id}.{field}.basis must explain the judgment"
                )
            artifacts = judgment.get("artifacts")
            if not isinstance(artifacts, list):
                raise AssessmentPacketError(
                    f"{case_id}.{field}.artifacts must be a list"
                )
            refs, bundle_digest = artifact_bundle_digest(
                artifacts,
                base_dir=base_dir,
            )
            observation[field] = value
            observation["evidence"][field] = {
                "basis": basis.strip(),
                "refs": refs,
                "artifact_digest": bundle_digest,
            }
        output.append(observation)

    return {
        "packet_digest": packet_digest,
        "assessor": dict(assessor),
        "observations": output,
    }


def _read_json(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise AssessmentPacketError("assessment packet spec must be a JSON object")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--base-dir", type=Path, default=Path("."))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    packet = build_assessment_packet(
        _read_json(args.spec),
        base_dir=args.base_dir,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(packet, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
