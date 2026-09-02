"""Adaptive orchestration.

The competitive audit found that **no reference project implements this.**
sec-af selects hunter strategies once, from recon output, by boolean gating;
cloudflare adapts across runs rather than within one. So this is net-new
engineering with no prior art to copy, which is exactly why it ships the way it
does below.

**It is off by default.** ``AdaptivePolicy.enabled`` starts false and the static
graph stays the default path. An orchestration feature with no reference
implementation is the wrong thing to make mandatory on day one.

**Every adaptation is a durable record, never a silent reroute.** A run that
quietly deepened one lane and skipped another is a run whose results cannot be
compared to any other run. :class:`AdaptationDecision` captures the signal, the
value, the threshold it crossed, what changed in the graph, and why.

**The thresholds are ours and they are conservative.** The audit explicitly
refused to import sec-af's or sam-cre's numbers -- theirs are unvalidated here,
and a threshold nobody has measured is a guess wearing a constant's clothes.
These defaults are set to fire rarely; they are meant to be tuned against the
eval suite, and until that measurement exists they stay timid on purpose.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .graph import GraphNode, ReasonerGraph
from .roles import NodeRole


class Signal(str, Enum):
    """What the orchestrator is allowed to react to."""

    ARCHITECTURE_SIGNAL = "ARCHITECTURE_SIGNAL"
    FINDING_DENSITY = "FINDING_DENSITY"
    REFUTATION_RATE = "REFUTATION_RATE"
    COVERAGE_GAP = "COVERAGE_GAP"
    BUDGET_PRESSURE = "BUDGET_PRESSURE"
    UNKNOWN_APPLICABILITY = "UNKNOWN_APPLICABILITY"
    RUNTIME_CONTRADICTION = "RUNTIME_CONTRADICTION"
    REPEATED_ROOT_CAUSE = "REPEATED_ROOT_CAUSE"
    DEPENDENCY_REACHABILITY = "DEPENDENCY_REACHABILITY"
    TOOL_FAILURE = "TOOL_FAILURE"


class Action(str, Enum):
    ADD_NODE = "ADD_NODE"
    DEEPEN_LANE = "DEEPEN_LANE"
    TIGHTEN_LANE = "TIGHTEN_LANE"
    PRIORITISE = "PRIORITISE"
    NO_CHANGE = "NO_CHANGE"


@dataclass
class AdaptationDecision:
    """One routing change, with everything needed to argue about it later."""

    signal: Signal
    value: float
    threshold: float
    action: Action
    target: str
    reason: str
    nodes_added: list[str] = field(default_factory=list)
    nodes_before: int = 0
    nodes_after: int = 0
    estimated_cost_delta_usd: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal": self.signal.value,
            "value": self.value,
            "threshold": self.threshold,
            "action": self.action.value,
            "target": self.target,
            "reason": self.reason,
            "nodes_added": sorted(self.nodes_added),
            "nodes_before": self.nodes_before,
            "nodes_after": self.nodes_after,
            "estimated_cost_delta_usd": self.estimated_cost_delta_usd,
        }


@dataclass
class AdaptivePolicy:
    """Thresholds. Conservative, ours, and unvalidated until the eval says so.

    Each default is chosen to fire only on an unambiguous signal:

    ``refutation_rate``   0.70 -- a lane whose findings are refuted more often
                          than not is already suspect at 0.5; 0.7 waits for the
                          pattern to be clear rather than reacting to noise.
    ``coverage_gap``      0.50 -- half the observed surface never examined.
    ``budget_pressure``   0.80 -- four fifths spent, so remaining work is
                          prioritised rather than started and abandoned.
    ``min_lane_findings`` 4 -- no rate is computed from fewer, because a lane
                          with two findings and one refutation is not a 50%
                          refutation rate in any useful sense.
    """

    enabled: bool = False
    refutation_rate: float = 0.70
    coverage_gap: float = 0.50
    budget_pressure: float = 0.80
    finding_density: float = 0.25
    min_lane_findings: int = 4
    #: Cost assumed for each node an adaptation adds, used only to report the
    #: delta. It is not a measurement and is labelled as an estimate everywhere.
    estimated_node_cost_usd: float = 0.0


@dataclass
class Observation:
    """What the orchestrator knows part-way through a run."""

    architecture_signals: list[str] = field(default_factory=list)
    lane_findings: dict[str, int] = field(default_factory=dict)
    lane_refutations: dict[str, int] = field(default_factory=dict)
    coverage_never_covered: int = 0
    coverage_total: int = 0
    budget_fraction_used: float = 0.0
    unknown_applicability: list[str] = field(default_factory=list)
    repeated_root_causes: dict[str, int] = field(default_factory=dict)
    tool_failures: list[str] = field(default_factory=list)

    def refutation_rate(self, lane: str) -> float | None:
        """Refuted / total for one lane, or ``None`` when too few to mean anything."""
        total = self.lane_findings.get(lane, 0)
        if total < 1:
            return None
        return self.lane_refutations.get(lane, 0) / total

    @property
    def coverage_gap_fraction(self) -> float:
        if self.coverage_total <= 0:
            return 0.0
        return self.coverage_never_covered / self.coverage_total


#: Architecture signals that justify deepening a specific lane, and which role
#: they justify. Kept explicit rather than inferred: "we saw the word payment"
#: is not a reason to spend budget unless it maps to a lane that can use it.
_ARCHITECTURE_DEEPENING: dict[str, NodeRole] = {
    "payment_state_machine": NodeRole.BUSINESS_LOGIC,
    "money_movement": NodeRole.BUSINESS_LOGIC,
    "multi_tenant": NodeRole.AUTHORIZATION,
    "webhook_ingress": NodeRole.API_PROTOCOL,
    "file_upload": NodeRole.FILES_PARSERS,
    "mcp_server": NodeRole.AI_MCP,
}


class AdaptiveOrchestrator:
    """Proposes graph changes from observations, and records every one."""

    def __init__(self, policy: AdaptivePolicy | None = None) -> None:
        self.policy = policy or AdaptivePolicy()
        self.decisions: list[AdaptationDecision] = []

    def adapt(
        self, graph: ReasonerGraph, observation: Observation
    ) -> tuple[ReasonerGraph, list[AdaptationDecision]]:
        """Return a possibly-extended graph plus the decisions that changed it.

        When the policy is disabled this returns the graph unchanged and records
        nothing, so a disabled adaptive path is genuinely identical to the
        static path rather than a differently-shaped no-op.
        """
        if not self.policy.enabled:
            return graph, []

        decisions: list[AdaptationDecision] = []
        nodes = list(graph.nodes)
        before = len(nodes)
        existing_roles = {node.role for node in nodes}

        # 1. Architecture signal -> deepen the lane it actually maps to.
        for signal_name in sorted(observation.architecture_signals):
            role = _ARCHITECTURE_DEEPENING.get(signal_name)
            if role is None or role in existing_roles:
                continue
            node_id = f"deep_{role.value.lower()}"
            nodes.append(
                GraphNode(
                    node_id, role, ("map",) if "map" in graph else (),
                    reason=f"architecture signal: {signal_name}",
                )
            )
            existing_roles.add(role)
            decisions.append(
                AdaptationDecision(
                    signal=Signal.ARCHITECTURE_SIGNAL, value=1.0, threshold=1.0,
                    action=Action.DEEPEN_LANE, target=role.value,
                    reason=f"{signal_name} observed; {role.value} lane deepened",
                    nodes_added=[node_id],
                    estimated_cost_delta_usd=self.policy.estimated_node_cost_usd,
                )
            )

        # 2. A lane refuting most of its own findings gets tightened, not trusted.
        for lane in sorted(observation.lane_findings):
            total = observation.lane_findings.get(lane, 0)
            if total < self.policy.min_lane_findings:
                continue
            rate = observation.refutation_rate(lane)
            if rate is not None and rate >= self.policy.refutation_rate:
                decisions.append(
                    AdaptationDecision(
                        signal=Signal.REFUTATION_RATE, value=round(rate, 3),
                        threshold=self.policy.refutation_rate,
                        action=Action.TIGHTEN_LANE, target=lane,
                        reason=(
                            f"{observation.lane_refutations.get(lane, 0)} of {total} "
                            f"findings refuted; lane tightened rather than trusted"
                        ),
                    )
                )

        # 3. Large unexamined surface -> schedule a variant hunter.
        gap = observation.coverage_gap_fraction
        if gap >= self.policy.coverage_gap and NodeRole.VARIANT_HUNTER not in existing_roles:
            node_id = "variant_hunter"
            nodes.append(
                GraphNode(
                    node_id, NodeRole.VARIANT_HUNTER,
                    ("map",) if "map" in graph else (),
                    reason="coverage gap above threshold",
                )
            )
            existing_roles.add(NodeRole.VARIANT_HUNTER)
            decisions.append(
                AdaptationDecision(
                    signal=Signal.COVERAGE_GAP, value=round(gap, 3),
                    threshold=self.policy.coverage_gap,
                    action=Action.ADD_NODE, target="variant_hunter",
                    reason=(
                        f"{observation.coverage_never_covered} of "
                        f"{observation.coverage_total} items never covered"
                    ),
                    nodes_added=[node_id],
                    estimated_cost_delta_usd=self.policy.estimated_node_cost_usd,
                )
            )

        # 4. Budget pressure prioritises; it never adds work.
        if observation.budget_fraction_used >= self.policy.budget_pressure:
            decisions.append(
                AdaptationDecision(
                    signal=Signal.BUDGET_PRESSURE,
                    value=round(observation.budget_fraction_used, 3),
                    threshold=self.policy.budget_pressure,
                    action=Action.PRIORITISE, target="unresolved_high_risk",
                    reason=(
                        "budget mostly consumed; remaining effort prioritised toward "
                        "unresolved high-risk evidence rather than new lanes"
                    ),
                )
            )

        # 5. Tool failures are surfaced, never silently absorbed.
        for tool in sorted(observation.tool_failures):
            decisions.append(
                AdaptationDecision(
                    signal=Signal.TOOL_FAILURE, value=1.0, threshold=1.0,
                    action=Action.NO_CHANGE, target=tool,
                    reason=(
                        f"{tool} failed; its evidence is absent and the affected "
                        "hypotheses stay UNKNOWN rather than being treated as clear"
                    ),
                )
            )

        adapted = ReasonerGraph(nodes) if len(nodes) != before else graph
        for decision in decisions:
            decision.nodes_before = before
            decision.nodes_after = len(nodes)
        self.decisions.extend(decisions)
        return adapted, decisions
