"""How a node actually runs.

The orchestration layer must not know whether a node was answered by a model, a
scanner, a fixture or a recording. Everything below implements one small
protocol, so the graph, the budget governor and the release gate behave
identically no matter what produced the output.

Two executors ship here and neither needs a network:

``MockExecutor``    scripted outcomes. This is what the test suite runs on, and
                    it is why the suite costs nothing and cannot flake on a
                    provider outage.
``ReplayExecutor``  returns what a previous run recorded, refusing to invent
                    anything for a node the recording does not cover.

A provider-backed executor is an optional integration that lives outside this
module. Nothing in the evidence contracts mentions a vendor, and nothing here
imports one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .digests import digest
from .graph import GraphNode
from .roles import NodeStatus


class ExecutorError(RuntimeError):
    """The executor could not answer for this node."""


@dataclass
class NodeOutcome:
    """What a node produced.

    ``tokens``/``cost`` are ``None`` when the executor genuinely does not know.
    A mock run has no token count, and writing ``0`` would understate a later
    budget report -- "not measured" and "measured as zero" are different claims
    and the governor treats them differently.
    """

    status: NodeStatus
    output: dict[str, Any] = field(default_factory=dict)
    output_evidence_ids: list[str] = field(default_factory=list)
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None
    model: str | None = None
    provider: str | None = None
    error: str | None = None
    blocker: str | None = None

    @property
    def output_digest(self) -> str:
        return digest(self.output)


class Executor(Protocol):
    """The one method the orchestrator calls."""

    name: str

    def execute(self, node: GraphNode, view: dict[str, Any]) -> NodeOutcome:
        """Answer for ``node`` given its context ``view``."""
        ...


class MockExecutor:
    """Deterministic scripted outcomes, for tests and dry runs.

    Outcomes are keyed by ``node_id``. A node with no script entry SUCCEEDS with
    empty output, which keeps a test that only cares about one node from having
    to describe the whole graph.
    """

    name = "mock"

    def __init__(
        self,
        outcomes: dict[str, NodeOutcome] | None = None,
        *,
        default_status: NodeStatus = NodeStatus.SUCCEEDED,
    ) -> None:
        self._outcomes = dict(outcomes or {})
        self._default_status = default_status
        #: Every (node_id, context digest) pair this executor was asked for, in
        #: order. Tests assert against it to prove context isolation.
        self.calls: list[tuple[str, str]] = []

    def execute(self, node: GraphNode, view: dict[str, Any]) -> NodeOutcome:
        self.calls.append((node.node_id, digest(view)))
        scripted = self._outcomes.get(node.node_id)
        if scripted is not None:
            return scripted
        return NodeOutcome(status=self._default_status)


class ReplayExecutor:
    """Returns outputs recorded by an earlier run.

    Replay is about the orchestration being reproducible, not about pretending a
    model is deterministic. This executor therefore never generates: if the
    recording has no entry for a node, that is a defect in the recording and it
    raises rather than substituting a plausible answer. A replay that quietly
    fills gaps is not evidence of anything.
    """

    name = "replay"

    def __init__(self, recorded: dict[str, dict[str, Any]]) -> None:
        self._recorded = dict(recorded)
        self.calls: list[str] = []

    def execute(self, node: GraphNode, view: dict[str, Any]) -> NodeOutcome:
        self.calls.append(node.node_id)
        entry = self._recorded.get(node.node_id)
        if entry is None:
            raise ExecutorError(
                f"replay has no recorded outcome for node {node.node_id!r}; "
                "the recording does not cover this graph"
            )
        return NodeOutcome(
            status=NodeStatus(entry.get("status", NodeStatus.SUCCEEDED.value)),
            output=entry.get("output", {}),
            output_evidence_ids=list(entry.get("output_evidence_ids", [])),
            input_tokens=entry.get("input_tokens"),
            output_tokens=entry.get("output_tokens"),
            cost_usd=entry.get("cost_usd"),
            model=entry.get("model"),
            provider=entry.get("provider"),
            error=entry.get("error"),
            blocker=entry.get("blocker"),
        )
