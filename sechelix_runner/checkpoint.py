"""Durable node-boundary checkpoints for resumable SecHelix runs.

A checkpoint is not a finding and cannot make a release decision. It is a
self-sealed record of work that had already completed at a node boundary so an
operator can resume remaining graph work after an infrastructure interruption
without replaying completed model/tool work.

Resume is fail-closed: target commit, scope, graph and caller-owned world input
must still match. Any changed byte in the checkpoint payload is rejected.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping

from .digests import canonical_json, digest


CHECKPOINT_VERSION = "runner-checkpoint-v1"


class CheckpointError(ValueError):
    """A checkpoint is malformed, tampered, or incompatible with this run."""


@dataclass(frozen=True)
class RunnerCheckpoint:
    run_id: str
    target_commit: str
    scope_id: str
    graph_digest: str
    world_digest: str
    started_at: str
    completed_node_ids: tuple[str, ...]
    records: dict[str, dict[str, Any]]
    outputs: dict[str, dict[str, Any]]
    routing: tuple[dict[str, Any], ...]
    context_views: dict[str, dict[str, Any]]
    budget: dict[str, Any]

    def to_payload(self) -> dict[str, Any]:
        return {
            "version": CHECKPOINT_VERSION,
            "run_id": self.run_id,
            "target_commit": self.target_commit,
            "scope_id": self.scope_id,
            "graph_digest": self.graph_digest,
            "world_digest": self.world_digest,
            "started_at": self.started_at,
            "completed_node_ids": list(self.completed_node_ids),
            "records": self.records,
            "outputs": self.outputs,
            "routing": list(self.routing),
            "context_views": self.context_views,
            "budget": self.budget,
        }


def write_checkpoint(path: str | Path, checkpoint: RunnerCheckpoint) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = checkpoint.to_payload()
    envelope = {
        "payload": payload,
        "payload_digest": digest(payload),
    }
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(canonical_json(envelope) + "\n", encoding="utf-8")
    temporary.replace(target)
    return target


def load_checkpoint(path: str | Path) -> RunnerCheckpoint:
    source = Path(path)
    try:
        envelope = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CheckpointError(f"checkpoint is unreadable: {exc}") from exc
    if not isinstance(envelope, Mapping):
        raise CheckpointError("checkpoint envelope must be a JSON object")
    payload = envelope.get("payload")
    claimed = envelope.get("payload_digest")
    if not isinstance(payload, Mapping) or not isinstance(claimed, str):
        raise CheckpointError("checkpoint envelope is missing payload or payload_digest")
    payload_dict = dict(payload)
    if digest(payload_dict) != claimed:
        raise CheckpointError("checkpoint payload digest mismatch")
    if payload_dict.get("version") != CHECKPOINT_VERSION:
        raise CheckpointError(
            f"unsupported checkpoint version: {payload_dict.get('version')!r}"
        )

    required_strings = (
        "run_id",
        "target_commit",
        "scope_id",
        "graph_digest",
        "world_digest",
        "started_at",
    )
    for key in required_strings:
        if not isinstance(payload_dict.get(key), str) or not payload_dict[key]:
            raise CheckpointError(f"checkpoint {key} must be a non-empty string")

    completed = payload_dict.get("completed_node_ids")
    records = payload_dict.get("records")
    outputs = payload_dict.get("outputs")
    routing = payload_dict.get("routing")
    context_views = payload_dict.get("context_views")
    budget = payload_dict.get("budget")
    if not isinstance(completed, list) or not all(isinstance(x, str) for x in completed):
        raise CheckpointError("checkpoint completed_node_ids must be a string array")
    if not isinstance(records, dict) or not isinstance(outputs, dict):
        raise CheckpointError("checkpoint records and outputs must be objects")
    if not isinstance(routing, list) or not all(isinstance(x, dict) for x in routing):
        raise CheckpointError("checkpoint routing must be an object array")
    if not isinstance(context_views, dict) or not isinstance(budget, dict):
        raise CheckpointError("checkpoint context_views and budget must be objects")

    missing = set(completed) - set(records)
    if missing:
        raise CheckpointError(
            "checkpoint completed nodes missing records: " + ", ".join(sorted(missing))
        )
    extras = set(records) - set(completed)
    if extras:
        raise CheckpointError(
            "checkpoint records contain non-completed nodes: " + ", ".join(sorted(extras))
        )

    return RunnerCheckpoint(
        run_id=payload_dict["run_id"],
        target_commit=payload_dict["target_commit"],
        scope_id=payload_dict["scope_id"],
        graph_digest=payload_dict["graph_digest"],
        world_digest=payload_dict["world_digest"],
        started_at=payload_dict["started_at"],
        completed_node_ids=tuple(completed),
        records={str(k): dict(v) for k, v in records.items() if isinstance(v, dict)},
        outputs={str(k): dict(v) for k, v in outputs.items() if isinstance(v, dict)},
        routing=tuple(dict(x) for x in routing),
        context_views={
            str(k): dict(v) for k, v in context_views.items() if isinstance(v, dict)
        },
        budget=dict(budget),
    )


__all__ = [
    "CHECKPOINT_VERSION",
    "CheckpointError",
    "RunnerCheckpoint",
    "load_checkpoint",
    "write_checkpoint",
]
