#!/usr/bin/env python3
"""Offline, provenance-preserving evaluation corpus importer.

This module intentionally has no network client. Operators acquire a corpus under
its own terms, then point this importer at the local copy. The importer verifies
pinned identity when possible and emits a deterministic metadata index; it does
not vendor third-party source into SecHelix.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = ROOT / "evals" / "corpora" / "manifest.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_head(path: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip().lower()


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != "1.0" or not isinstance(data.get("corpora"), list):
        raise ValueError("unsupported corpus manifest")
    ids = [item.get("id") for item in data["corpora"]]
    if any(not isinstance(item, str) or not item for item in ids) or len(ids) != len(set(ids)):
        raise ValueError("corpus ids must be unique non-empty strings")
    return data


def verify_identity(entry: dict[str, Any], source: Path) -> dict[str, str]:
    identity = entry["identity"]
    algorithm = identity["algorithm"]
    expected = identity["value"].lower()
    if algorithm == "sha256":
        if not source.is_file():
            raise ValueError("sha256-pinned corpus must be supplied as the original archive file")
        actual = _sha256(source)
    elif algorithm == "git-commit":
        if not source.is_dir():
            raise ValueError("git-pinned corpus must be supplied as a repository directory")
        actual = _git_head(source)
    else:
        raise ValueError(f"unsupported identity algorithm: {algorithm}")
    if actual != expected:
        raise ValueError(f"corpus identity mismatch: expected {expected}, got {actual}")
    return {"algorithm": algorithm, "expected": expected, "actual": actual, "verified": "true"}


def build_index(entry: dict[str, Any], source: Path) -> dict[str, Any]:
    verification = verify_identity(entry, source)
    return {
        "schema_version": "1.0",
        "corpus_id": entry["id"],
        "source_id": entry["source_id"],
        "publisher": entry["publisher"],
        "origin": entry["origin"],
        "version": entry["version"],
        "identity": verification,
        "license": entry["license"],
        "allowed_use": entry["allowed_use"],
        "vendored": False,
        "source_path_recorded": False,
        "note": "The local filesystem path and third-party source contents are deliberately omitted from the portable index.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus_id")
    parser.add_argument("source", type=Path)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    entry = next((item for item in manifest["corpora"] if item["id"] == args.corpus_id), None)
    if entry is None:
        raise SystemExit(f"unknown corpus id: {args.corpus_id}")
    record = build_index(entry, args.source.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
