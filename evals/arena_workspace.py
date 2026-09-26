#!/usr/bin/env python3
"""Build a digest-stable evidence index for one persisted SecHelix run workspace.

This helper verifies the workspace manifest first, then emits only metadata and
content digests for the artifacts an independent Arena evaluator is likely to
need. It does not score correctness and does not copy node output bodies into the
index.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from sechelix_runner.storage import RunWorkspace


class ArenaWorkspaceEvidenceError(ValueError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _load_object(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArenaWorkspaceEvidenceError(f"{label} cannot be read as JSON") from exc
    if not isinstance(value, Mapping):
        raise ArenaWorkspaceEvidenceError(f"{label} must be a JSON object")
    return value


def build_workspace_evidence_index(root: Path | str, run_id: str) -> dict[str, Any]:
    workspace = RunWorkspace(root, run_id)
    if not workspace.exists:
        raise ArenaWorkspaceEvidenceError(f"run workspace {run_id!r} does not exist")
    drift = workspace.verify()
    if drift:
        raise ArenaWorkspaceEvidenceError(
            "workspace manifest verification failed: " + "; ".join(drift)
        )

    run_path = workspace.path / "run.json"
    graph_path = workspace.path / "graph.json"
    replay_path = workspace.path / "replay" / "outcomes.json"
    manifest_path = workspace.path / "manifest.json"
    for path, label in (
        (run_path, "run.json"),
        (graph_path, "graph.json"),
        (replay_path, "replay/outcomes.json"),
        (manifest_path, "manifest.json"),
    ):
        if not path.is_file():
            raise ArenaWorkspaceEvidenceError(f"{label} missing")

    run = _load_object(run_path, "run.json")
    graph = _load_object(graph_path, "graph.json")
    replay = _load_object(replay_path, "replay/outcomes.json")

    graph_nodes = graph.get("nodes")
    if not isinstance(graph_nodes, list):
        raise ArenaWorkspaceEvidenceError("graph.json nodes missing")
    roles: dict[str, str] = {}
    for raw in graph_nodes:
        if not isinstance(raw, Mapping):
            continue
        node_id = raw.get("node_id")
        role = raw.get("role")
        if isinstance(node_id, str) and isinstance(role, str):
            roles[node_id] = role

    role_evidence: dict[str, list[dict[str, Any]]] = {
        "INDEPENDENT_VERIFIER": [],
        "RELEASE_GATE": [],
        "PATCH_VERIFIER": [],
        "REMEDIATOR": [],
    }
    for node_id, raw in replay.items():
        if not isinstance(node_id, str) or not isinstance(raw, Mapping):
            continue
        role = roles.get(node_id)
        if role not in role_evidence:
            continue
        output = raw.get("output")
        output_digest = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(
                    output,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
        )
        role_evidence[role].append(
            {
                "node_id": node_id,
                "status": raw.get("status"),
                "output_digest": output_digest,
                "output_evidence_ids": list(raw.get("output_evidence_ids") or []),
                "provider": raw.get("provider"),
                "model": raw.get("model"),
                "input_tokens": raw.get("input_tokens"),
                "output_tokens": raw.get("output_tokens"),
                "cost_usd": raw.get("cost_usd"),
                "artifact_ref": "replay/outcomes.json",
            }
        )

    return {
        "schema_version": "sechelix-arena-workspace-evidence/v1",
        "run_id": run.get("run_id"),
        "target_commit": run.get("target_commit"),
        "scope_id": run.get("scope_id"),
        "graph_digest": run.get("graph_digest"),
        "workspace_integrity": "VERIFIED",
        "artifacts": {
            "run.json": _sha256(run_path),
            "graph.json": _sha256(graph_path),
            "replay/outcomes.json": _sha256(replay_path),
            "manifest.json": _sha256(manifest_path),
        },
        "role_evidence": {
            role: rows
            for role, rows in role_evidence.items()
            if rows
        },
        "limitations": [
            "This index proves artifact identity and workspace integrity, not security correctness.",
            "Node output bodies are intentionally not copied into this index.",
            "Independent Arena assessment is still required for workflow scoring.",
        ],
    }


def _cli() -> int:
    parser = argparse.ArgumentParser(
        description="Build a digest-stable Arena evidence index for a SecHelix run workspace"
    )
    parser.add_argument("--root", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    result = build_workspace_evidence_index(args.root, args.run_id)
    Path(args.output).write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
