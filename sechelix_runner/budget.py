"""The budget governor.

Limits exist so a run stops rather than spending without bound. The dangerous
part is not the stopping -- it is what a stopped run is allowed to claim.

**The invariant this module exists to protect:** running out of budget before a
required verification must never produce a PASS. Budget exhaustion turns the
affected evidence into a recorded ``BLOCKED`` state, and a gate that needs that
evidence fails closed. A governor that lets the caller skip a verifier and then
report success has converted a cost limit into a correctness bug, which is worse
than having no limit at all.

Four quantities are tracked per limit, and they are not the same thing:

``estimated``  what the planner expects the whole run to need.
``reserved``   held for work that is admitted but not finished.
``actual``     what has genuinely been consumed.
``remaining``  the limit minus reserved minus actual.

Reservation is what makes the governor safe under concurrency: admitting two
nodes that each fit in the remainder, but not both, is exactly the overspend a
naive "check then run" governor allows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class BudgetExceeded(RuntimeError):
    """A limit would be broken by the requested work.

    Callers catch this and mark the node BLOCKED. It is deliberately not a
    subclass of anything the runner treats as a node error: the node did not
    fail, it was never allowed to start, and the report must say so.
    """

    def __init__(self, limit_name: str, requested: float, remaining: float) -> None:
        super().__init__(
            f"{limit_name} budget exhausted: requested {requested}, {remaining} remaining"
        )
        self.limit_name = limit_name
        self.requested = requested
        self.remaining = remaining


#: Every governed quantity. Absent from a ``BudgetLimits`` means "no limit",
#: which is different from a limit of zero.
LIMIT_NAMES = (
    "max_cost_usd",
    "max_duration_seconds",
    "max_total_tokens",
    "max_input_tokens",
    "max_output_tokens",
    "max_nodes",
    "max_concurrency",
    "max_hunters",
    "max_verifiers",
    "max_runtime_requests",
    "max_browser_actions",
)


@dataclass
class BudgetLimits:
    """Caller-supplied ceilings. ``None`` means unlimited."""

    max_cost_usd: float | None = None
    max_duration_seconds: float | None = None
    max_total_tokens: int | None = None
    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    max_nodes: int | None = None
    max_concurrency: int | None = None
    max_hunters: int | None = None
    max_verifiers: int | None = None
    max_runtime_requests: int | None = None
    max_browser_actions: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in LIMIT_NAMES}


@dataclass
class BudgetDecision:
    """One admission decision, kept for the run record.

    Every refusal is durable. "The verifier did not run" is not a fact anyone
    should have to reconstruct from a cost total.
    """

    limit_name: str
    node_id: str
    requested: float
    remaining: float
    admitted: bool
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "limit_name": self.limit_name,
            "node_id": self.node_id,
            "requested": self.requested,
            "remaining": self.remaining,
            "admitted": self.admitted,
            "reason": self.reason,
        }


class BudgetGovernor:
    """Tracks spend against :class:`BudgetLimits` and admits or refuses work."""

    def __init__(self, limits: BudgetLimits | None = None) -> None:
        self.limits = limits or BudgetLimits()
        self._actual: dict[str, float] = {name: 0.0 for name in LIMIT_NAMES}
        self._reserved: dict[str, float] = {name: 0.0 for name in LIMIT_NAMES}
        self._estimated: dict[str, float] = {name: 0.0 for name in LIMIT_NAMES}
        self.decisions: list[BudgetDecision] = []
        #: Set once any limit has refused work, so the report can say the run
        #: was shaped by its budget rather than by the target.
        self.exhausted: bool = False

    # -- reading -------------------------------------------------------------

    def limit(self, name: str) -> float | None:
        return getattr(self.limits, name)

    def actual(self, name: str) -> float:
        return self._actual[name]

    def reserved(self, name: str) -> float:
        return self._reserved[name]

    def estimated(self, name: str) -> float:
        return self._estimated[name]

    def remaining(self, name: str) -> float:
        """What is still available. ``inf`` when the limit is unset."""
        limit = self.limit(name)
        if limit is None:
            return float("inf")
        return float(limit) - self._actual[name] - self._reserved[name]

    def estimate(self, name: str, amount: float) -> None:
        """Record a planner expectation. Never gates anything by itself."""
        self._estimated[name] += float(amount)

    # -- admission -----------------------------------------------------------

    def can_afford(self, name: str, amount: float) -> bool:
        return self.remaining(name) >= float(amount)

    def reserve(self, name: str, amount: float, node_id: str) -> None:
        """Hold ``amount`` for ``node_id`` or raise :class:`BudgetExceeded`.

        Reserving before running is what closes the concurrency hole: two nodes
        cannot both pass a check against the same remainder.
        """
        amount = float(amount)
        remaining = self.remaining(name)
        if amount > remaining:
            self.exhausted = True
            self.decisions.append(
                BudgetDecision(name, node_id, amount, remaining, admitted=False,
                               reason="insufficient remaining budget")
            )
            raise BudgetExceeded(name, amount, remaining)
        self._reserved[name] += amount
        self.decisions.append(
            BudgetDecision(name, node_id, amount, remaining, admitted=True)
        )

    def release(self, name: str, amount: float) -> None:
        """Give back an unused reservation, never below zero."""
        self._reserved[name] = max(0.0, self._reserved[name] - float(amount))

    def settle(self, name: str, reserved_amount: float, actual_amount: float) -> None:
        """Convert a reservation into real spend."""
        self.release(name, reserved_amount)
        self._actual[name] += float(actual_amount)

    def spend(self, name: str, amount: float) -> None:
        """Record consumption that was not reserved (already-incurred cost)."""
        self._actual[name] += float(amount)

    # -- reporting -----------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """The full budget state, for the run record and the report."""
        return {
            "exhausted": self.exhausted,
            "limits": self.limits.to_dict(),
            "usage": {
                name: {
                    "estimated": self._estimated[name],
                    "reserved": self._reserved[name],
                    "actual": self._actual[name],
                    "remaining": (
                        None if self.limit(name) is None else self.remaining(name)
                    ),
                }
                for name in LIMIT_NAMES
            },
            "decisions": [d.to_dict() for d in self.decisions],
        }

    @property
    def refusals(self) -> list[BudgetDecision]:
        return [d for d in self.decisions if not d.admitted]
