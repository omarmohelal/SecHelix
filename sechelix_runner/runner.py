"""The orchestrator.

Walks a :class:`~sechelix_runner.graph.ReasonerGraph` in deterministic order,
gives each node only its context view, admits it against the budget, runs it
through an executor, and records everything.

Three behaviours here are load-bearing, and all three are about what a run is
allowed to claim when something goes wrong.

**A node that did not deliver blocks its dependents, transitively.** If the
authorization lane fails, the verifier that needed its candidates does not run
on nothing and report success -- it is recorded ``BLOCKED`` naming the
dependency, and so is everything downstream of it.

**Nothing disappears.** Every node in the graph ends with a record, including
the ones that never ran. A report that lists only what succeeded describes a
different run than the one that happened.

**Budget refusal is not node failure.** A node the governor would not admit is
``BLOCKED`` with the limit named, never ``SKIPPED`` and never silently absent.
The distinction is the whole reason the release decision can be trusted: an
inapplicable lane owes nothing, but an unaffordable verifier leaves a real
question unanswered.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .budget import BudgetExceeded, BudgetGovernor, BudgetLimits
from .context import ContextBuilder
from .digests import digest
from .executor import Executor, ExecutorError, NodeOutcome
from .graph import ReasonerGraph
from .roles import NodeRole, NodeStatus
from .telemetry import NodeRecord
from . import RUNNER_VERSION


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def new_run_id() -> str:
    return f"RUN-{uuid.uuid4().hex[:16].upper()}"


@dataclass
class RoutingDecision:
    """Why a node is, or is not, in this run."""

    node_id: str
    role: str
    included: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "role": self.role,
            "included": self.included,
            "reason": self.reason,
        }


@dataclass
class RunResult:
    """Everything a completed run produced."""

    run_id: str
    target_commit: str
    scope_id: str
    graph_digest: str
    records: dict[str, NodeRecord] = field(default_factory=dict)
    routing: list[RoutingDecision] = field(default_factory=list)
    budget_snapshot: dict[str, Any] = field(default_factory=dict)
    context_views: dict[str, dict[str, Any]] = field(default_factory=dict)
    outputs: dict[str, dict[str, Any]] = field(default_factory=dict)
    started_at: str = ""
    finished_at: str = ""
    executor_name: str = ""

    # -- the questions the release gate asks --------------------------------

    @property
    def unsatisfied_mandatory(self) -> list[str]:
        """Mandatory nodes that did not deliver. Non-empty means no clean PASS."""
        return sorted(
            node_id
            for node_id, record in self.records.items()
            if record.status is not NodeStatus.SKIPPED
            and not record.satisfied
            and self._mandatory.get(node_id, False)
        )

    @property
    def blocked(self) -> list[str]:
        return sorted(
            n for n, r in self.records.items() if r.status is NodeStatus.BLOCKED
        )

    @property
    def failed(self) -> list[str]:
        return sorted(
            n for n, r in self.records.items() if r.status is NodeStatus.FAILED
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "runner_version": RUNNER_VERSION,
            "target_commit": self.target_commit,
            "scope_id": self.scope_id,
            "graph_digest": self.graph_digest,
            "executor": self.executor_name,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "records": {n: r.to_dict() for n, r in sorted(self.records.items())},
            "routing": [d.to_dict() for d in self.routing],
            "budget": self.budget_snapshot,
            "context_views": self.context_views,
            "unsatisfied_mandatory": self.unsatisfied_mandatory,
            "blocked": self.blocked,
            "failed": self.failed,
        }

    #: Populated by the runner so the properties above can see it without the
    #: result needing a reference back to the graph.
    _mandatory: dict[str, bool] = field(default_factory=dict)


#: What one node is assumed to cost when the caller gives no estimate. Small and
#: deliberately not tuned to any provider -- a real estimate comes from the
#: planner, and this only exists so an unconfigured run still reserves something
#: rather than treating every node as free.
DEFAULT_NODE_COST_USD = 0.0


class Runner:
    """Executes a graph and returns a :class:`RunResult`."""

    def __init__(
        self,
        *,
        executor: Executor,
        budget: BudgetGovernor | None = None,
        target_commit: str = "UNKNOWN",
        scope_id: str = "UNKNOWN",
        node_cost_estimates: dict[str, float] | None = None,
    ) -> None:
        self.executor = executor
        self.budget = budget or BudgetGovernor(BudgetLimits())
        self.target_commit = target_commit
        self.scope_id = scope_id
        self._estimates = dict(node_cost_estimates or {})

    def run(
        self,
        graph: ReasonerGraph,
        world: dict[str, Any],
        *,
        run_id: str | None = None,
    ) -> RunResult:
        run_id = run_id or new_run_id()
        builder = ContextBuilder(world)
        result = RunResult(
            run_id=run_id,
            target_commit=self.target_commit,
            scope_id=self.scope_id,
            graph_digest=digest(
                [
                    {
                        "node_id": n.node_id,
                        "role": n.role.value,
                        "depends_on": sorted(n.depends_on),
                        "mandatory": n.mandatory,
                        "node_version": n.node_version,
                    }
                    for n in graph.nodes
                ]
            ),
            executor_name=getattr(self.executor, "name", type(self.executor).__name__),
            started_at=_now(),
        )
        result._mandatory = {n.node_id: n.mandatory for n in graph.nodes}

        satisfied: set[str] = set()
        done: set[str] = set()

        for node_id in graph.topological_order():
            node = graph[node_id]

            # A dependency that never delivered blocks this node. Recorded, not
            # skipped: the question this node exists to answer is still open.
            unmet = graph.blocked_by(node_id, satisfied)
            if unmet:
                self._record_blocked(
                    result, node_id, node.role, node.node_version,
                    f"dependency not satisfied: {', '.join(unmet)}",
                )
                done.add(node_id)
                result.routing.append(
                    RoutingDecision(node_id, node.role.value, False,
                                    f"blocked by {', '.join(unmet)}")
                )
                continue

            view = builder.build(node_id, node.role)

            # An under-informed specialist is not an answer. Missing required
            # context blocks rather than producing output nobody can trust.
            if not view.complete:
                self._record_blocked(
                    result, node_id, node.role, node.node_version,
                    f"missing required context: {', '.join(sorted(view.missing_required))}",
                    context_view=view,
                )
                done.add(node_id)
                result.context_views[node_id] = view.to_dict()
                result.routing.append(
                    RoutingDecision(node_id, node.role.value, False, "incomplete context")
                )
                continue

            result.context_views[node_id] = view.to_dict()

            # Budget admission. A refusal blocks the node with the limit named.
            estimate = self._estimates.get(node_id, DEFAULT_NODE_COST_USD)
            try:
                self.budget.reserve("max_nodes", 1, node_id)
            except BudgetExceeded as exc:
                self._record_blocked(result, node_id, node.role, node.node_version,
                                     str(exc), context_view=view)
                done.add(node_id)
                result.routing.append(
                    RoutingDecision(node_id, node.role.value, False, "budget: max_nodes")
                )
                continue

            reserved_cost = 0.0
            if estimate:
                try:
                    self.budget.reserve("max_cost_usd", estimate, node_id)
                    reserved_cost = estimate
                except BudgetExceeded as exc:
                    self.budget.release("max_nodes", 1)
                    self._record_blocked(result, node_id, node.role, node.node_version,
                                         str(exc), context_view=view)
                    done.add(node_id)
                    result.routing.append(
                        RoutingDecision(node_id, node.role.value, False,
                                        "budget: max_cost_usd")
                    )
                    continue

            record = self._execute(result, node_id, node, view, reserved_cost)
            done.add(node_id)
            if record.satisfied:
                satisfied.add(node_id)
            result.routing.append(
                RoutingDecision(node_id, node.role.value, True, node.reason or "applicable")
            )

        result.finished_at = _now()
        result.budget_snapshot = self.budget.snapshot()
        return result

    # -- internals -----------------------------------------------------------

    def _execute(self, result, node_id, node, view, reserved_cost) -> NodeRecord:
        record = NodeRecord(
            run_id=result.run_id,
            node_id=node_id,
            role=node.role,
            node_version=node.node_version,
            target_commit=self.target_commit,
            scope_id=self.scope_id,
            parent_node_ids=sorted(node.depends_on),
            context_digest=view.digest,
            context_source_ids=sorted(view.source_ids),
            context_approx_tokens=view.approx_tokens,
            input_digest=view.digest,
            started_at=_now(),
            status=NodeStatus.RUNNING,
        )
        clock = time.monotonic()
        try:
            outcome: NodeOutcome = self.executor.execute(node, view.payload)
        except ExecutorError as exc:
            outcome = NodeOutcome(status=NodeStatus.FAILED, error=str(exc))
        except Exception as exc:  # a provider adapter must not take the run down
            outcome = NodeOutcome(
                status=NodeStatus.FAILED, error=f"{type(exc).__name__}: {exc}"
            )

        record.duration_seconds = time.monotonic() - clock
        record.finished_at = _now()
        record.status = outcome.status
        record.output_digest = outcome.output_digest
        record.output_evidence_ids = list(outcome.output_evidence_ids)
        record.model = outcome.model
        record.provider = outcome.provider
        record.input_tokens = outcome.input_tokens
        record.output_tokens = outcome.output_tokens
        record.cost_usd = outcome.cost_usd
        record.error = outcome.error
        record.blocker = outcome.blocker

        self.budget.settle("max_cost_usd", reserved_cost, outcome.cost_usd or 0.0)
        if outcome.input_tokens:
            self.budget.spend("max_input_tokens", outcome.input_tokens)
            self.budget.spend("max_total_tokens", outcome.input_tokens)
        if outcome.output_tokens:
            self.budget.spend("max_output_tokens", outcome.output_tokens)
            self.budget.spend("max_total_tokens", outcome.output_tokens)

        result.records[node_id] = record
        result.outputs[node_id] = outcome.output
        return record

    def _record_blocked(
        self, result, node_id, role: NodeRole, node_version: str, blocker: str, *,
        context_view=None,
    ) -> None:
        record = NodeRecord(
            run_id=result.run_id,
            node_id=node_id,
            role=role,
            node_version=node_version,
            target_commit=self.target_commit,
            scope_id=self.scope_id,
            status=NodeStatus.BLOCKED,
            blocker=blocker,
            started_at=_now(),
            finished_at=_now(),
            duration_seconds=0.0,
        )
        if context_view is not None:
            record.context_digest = context_view.digest
            record.context_source_ids = sorted(context_view.source_ids)
            record.context_approx_tokens = context_view.approx_tokens
        result.records[node_id] = record
