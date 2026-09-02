"""Deterministic replay.

Replay does **not** mean pretending a model is deterministic. It means the
orchestration history is reconstructible from the recorded artifacts: which
nodes ran, why they ran, what they consumed, what they produced, and why the
release gate reached the state it did.

So a replay re-executes the graph with a :class:`ReplayExecutor` fed from
``replay/outcomes.json``. The routing, the budget arithmetic, the context
projections and the blocking logic all run again for real. Only the node outputs
are played back, because those are the part no rerun can reproduce.

Two refusals keep this honest.

**A tampered workspace does not replay.** ``manifest.json`` digests every file
at close time. If a byte moved, :func:`replay_run` raises instead of producing a
plausible answer over altered evidence.

**A recording that does not cover the graph does not replay.** The executor
raises on an unrecorded node rather than inventing an outcome, so a partial
recording surfaces as an error rather than as a shorter, cleaner-looking run.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .budget import BudgetGovernor, BudgetLimits
from .executor import ReplayExecutor
from .graph import GraphNode, ReasonerGraph
from .roles import NodeRole
from .runner import RunResult, Runner
from .storage import RunWorkspace


class ReplayError(RuntimeError):
    """The run cannot be faithfully replayed."""


@dataclass
class ReplayComparison:
    """How a replay compares to the run it came from."""

    run_id: str
    statuses_match: bool
    routing_matches: bool
    graph_digest_matches: bool
    unsatisfied_matches: bool
    differences: list[str]

    @property
    def faithful(self) -> bool:
        return not self.differences

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "faithful": self.faithful,
            "statuses_match": self.statuses_match,
            "routing_matches": self.routing_matches,
            "graph_digest_matches": self.graph_digest_matches,
            "unsatisfied_matches": self.unsatisfied_matches,
            "differences": self.differences,
        }


def load_graph(workspace: RunWorkspace) -> ReasonerGraph:
    """Rebuild the executed graph from ``graph.json``."""
    data = workspace.read_json("graph.json")
    return ReasonerGraph(
        [
            GraphNode(
                node_id=node["node_id"],
                role=NodeRole(node["role"]),
                depends_on=tuple(node["depends_on"]),
                mandatory=node["mandatory"],
                node_version=node["node_version"],
                reason=node.get("reason", ""),
            )
            for node in data["nodes"]
        ]
    )


def replay_run(
    root: Path | str,
    run_id: str,
    world: dict[str, Any],
    *,
    verify_integrity: bool = True,
) -> tuple[RunResult, ReplayComparison]:
    """Re-execute a recorded run and report whether it reproduced.

    ``world`` is supplied by the caller rather than read from the workspace: run
    artifacts are redacted on write, so replaying from them would compare a
    redacted projection against an unredacted original and report a spurious
    difference. Replay checks that the *orchestration* is reproducible, and the
    context digests in the comparison are what prove the same projections were
    built.
    """
    workspace = RunWorkspace(root, run_id)
    if not workspace.exists:
        raise ReplayError(f"no run workspace for {run_id!r}")

    if verify_integrity:
        problems = workspace.verify()
        if problems:
            raise ReplayError(
                "workspace integrity check failed; refusing to replay:\n  "
                + "\n  ".join(problems)
            )

    original = workspace.read_json("run.json")
    graph = load_graph(workspace)
    outcomes = workspace.read_json("replay/outcomes.json")

    limits = original.get("budget", {}).get("limits", {})
    governor = BudgetGovernor(
        BudgetLimits(**{k: v for k, v in limits.items() if v is not None})
    )

    replayed = Runner(
        executor=ReplayExecutor(outcomes),
        budget=governor,
        target_commit=original["target_commit"],
        scope_id=original["scope_id"],
    ).run(graph, world, run_id=run_id)

    return replayed, _compare(original, replayed)


def _compare(original: dict[str, Any], replayed: RunResult) -> ReplayComparison:
    differences: list[str] = []

    original_statuses = {
        node_id: record["status"] for node_id, record in original["records"].items()
    }
    replay_statuses = {
        node_id: record.status.value for node_id, record in replayed.records.items()
    }
    statuses_match = original_statuses == replay_statuses
    if not statuses_match:
        for node_id in sorted(set(original_statuses) | set(replay_statuses)):
            was = original_statuses.get(node_id, "<absent>")
            now = replay_statuses.get(node_id, "<absent>")
            if was != now:
                differences.append(f"node {node_id}: recorded {was}, replayed {now}")

    original_routing = [(d["node_id"], d["included"]) for d in original["routing"]]
    replay_routing = [(d.node_id, d.included) for d in replayed.routing]
    routing_matches = original_routing == replay_routing
    if not routing_matches:
        differences.append("routing decisions differ")

    graph_digest_matches = original["graph_digest"] == replayed.graph_digest
    if not graph_digest_matches:
        differences.append("graph digest differs")

    unsatisfied_matches = sorted(original["unsatisfied_mandatory"]) == sorted(
        replayed.unsatisfied_mandatory
    )
    if not unsatisfied_matches:
        differences.append(
            f"unsatisfied mandatory differs: recorded "
            f"{original['unsatisfied_mandatory']}, replayed {replayed.unsatisfied_mandatory}"
        )

    return ReplayComparison(
        run_id=replayed.run_id,
        statuses_match=statuses_match,
        routing_matches=routing_matches,
        graph_digest_matches=graph_digest_matches,
        unsatisfied_matches=unsatisfied_matches,
        differences=differences,
    )
