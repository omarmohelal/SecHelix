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


class BudgetUnenforceable(BudgetExceeded):
    """A limit can no longer be checked, so further work under it is refused.

    Raised once spend the governor could not measure has happened with nothing
    reserved to charge for it. The true remainder is then unknown; admitting
    more work would turn the ceiling back into a suggestion.
    """

    def __init__(self, limit_name: str, requested: float, reason: str) -> None:
        RuntimeError.__init__(self, f"{limit_name} budget unenforceable: {reason}")
        self.limit_name = limit_name
        self.requested = requested
        self.remaining = float("inf")
        self.reason = reason


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
        # An unset limit leaves `remaining` infinite, and infinity is not JSON.
        # `None` is the same "unlimited" spelling `snapshot()` already uses, so
        # a reader never has to learn two encodings for the same idea.
        remaining = None if self.remaining == float("inf") else self.remaining
        return {
            "limit_name": self.limit_name,
            "node_id": self.node_id,
            "requested": self.requested,
            "remaining": remaining,
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
        #: Limits whose remainder became unknowable, with the reason why.
        self._unenforceable: dict[str, str] = {}

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

    def unenforceable(self, name: str) -> str | None:
        """Why ``name`` can no longer be enforced, or ``None`` if it still can."""
        return self._unenforceable.get(name)

    def reserve(
        self, name: str, amount: float, node_id: str, *, require_headroom: bool = False
    ) -> None:
        """Hold ``amount`` for ``node_id`` or raise :class:`BudgetExceeded`.

        Reserving before running is what closes the concurrency hole: two nodes
        cannot both pass a check against the same remainder.

        ``require_headroom`` is for work whose cost is not known in advance: the
        amount held is only a guess, so the node is also refused once nothing at
        all remains. Without it, a zero estimate would be admitted forever.
        """
        amount = float(amount)
        reason = self._unenforceable.get(name)
        if reason is not None:
            self.exhausted = True
            self.decisions.append(
                BudgetDecision(name, node_id, amount, float("inf"), admitted=False,
                               reason=f"unenforceable: {reason}")
            )
            raise BudgetUnenforceable(name, amount, reason)
        remaining = self.remaining(name)
        out_of_headroom = (
            require_headroom and self.limit(name) is not None and remaining <= 0
        )
        if amount > remaining or out_of_headroom:
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

    def settle_unmeasured(self, name: str, reserved_amount: float, node_id: str) -> None:
        """Settle work that may have spent but reported no amount.

        The reservation is the only bound available, so it is charged in full and
        the substitution is recorded. With nothing reserved there is nothing to
        charge: the remainder becomes unknown and the limit is marked
        unenforceable, so every later reservation under it is refused.
        """
        reserved_amount = float(reserved_amount)
        if reserved_amount > 0:
            self.settle(name, reserved_amount, reserved_amount)
            self.decisions.append(
                BudgetDecision(name, node_id, reserved_amount, self.remaining(name),
                               admitted=True,
                               reason="usage unmeasured; charged the reserved estimate")
            )
            return
        self.release(name, reserved_amount)
        reason = (f"node {node_id} spent an unmeasured amount with nothing reserved; "
                  "supply per-node estimates or use a provider that reports usage")
        self._unenforceable[name] = reason
        self.decisions.append(
            BudgetDecision(name, node_id, 0.0, float("inf"), admitted=True,
                           reason=f"usage unmeasured; {reason}")
        )

    def spend(self, name: str, amount: float) -> None:
        """Record consumption that was not reserved (already-incurred cost).

        A non-numeric amount is a corrupt record -- a redacted field, a provider
        returning a string -- and is refused loudly. Coercing it to zero would
        make a budget report that silently understates spend, which is the one
        failure mode this whole module exists to prevent.
        """
        try:
            self._actual[name] += float(amount)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"{name}: refusing to record non-numeric usage {amount!r}"
            ) from exc

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
            "unenforceable": dict(self._unenforceable),
        }

    def restore(self, snapshot: dict[str, Any]) -> None:
        """Restore a previously recorded budget state for checkpoint resume.

        Limits must match the governor the caller supplied for the resumed run.
        Resume may not silently increase a budget or erase prior consumption.
        Active reservations are refused because checkpoints are written only at
        completed node boundaries.
        """

        if not isinstance(snapshot, dict):
            raise ValueError("budget checkpoint must be an object")
        limits = snapshot.get("limits")
        usage = snapshot.get("usage")
        decisions = snapshot.get("decisions")
        if limits != self.limits.to_dict():
            raise ValueError("checkpoint budget limits do not match resumed run")
        if not isinstance(usage, dict) or not isinstance(decisions, list):
            raise ValueError("checkpoint budget usage/decisions are malformed")

        restored_actual: dict[str, float] = {}
        restored_reserved: dict[str, float] = {}
        restored_estimated: dict[str, float] = {}
        for name in LIMIT_NAMES:
            row = usage.get(name)
            if not isinstance(row, dict):
                raise ValueError(f"checkpoint budget is missing {name}")
            try:
                actual = float(row.get("actual", 0.0))
                reserved = float(row.get("reserved", 0.0))
                estimated = float(row.get("estimated", 0.0))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"checkpoint budget {name} is not numeric") from exc
            if actual < 0 or estimated < 0 or reserved < 0:
                raise ValueError(f"checkpoint budget {name} has negative usage")
            # max_nodes is deliberately accounted as a cumulative reservation:
            # each admitted node consumes one slot and Runner does not release
            # it. Other reservations represent in-flight work and therefore
            # cannot exist at a node-boundary checkpoint.
            if name != "max_nodes" and reserved != 0:
                raise ValueError(
                    f"checkpoint budget {name} contains in-flight reservation state"
                )
            restored_actual[name] = actual
            restored_reserved[name] = reserved
            restored_estimated[name] = estimated

        restored_decisions: list[BudgetDecision] = []
        for row in decisions:
            if not isinstance(row, dict):
                raise ValueError("checkpoint budget decision must be an object")
            name = row.get("limit_name")
            if name not in LIMIT_NAMES:
                raise ValueError(f"checkpoint budget decision has unknown limit {name!r}")
            remaining = row.get("remaining")
            restored_decisions.append(
                BudgetDecision(
                    limit_name=str(name),
                    node_id=str(row.get("node_id", "")),
                    requested=float(row.get("requested", 0.0)),
                    remaining=(
                        float("inf") if remaining is None else float(remaining)
                    ),
                    admitted=bool(row.get("admitted")),
                    reason=str(row.get("reason", "")),
                )
            )

        # A resume must not lift an unenforceable limit: the spend that made it
        # unknowable still happened. Older checkpoints predate the key.
        unenforceable = snapshot.get("unenforceable", {})
        if not isinstance(unenforceable, dict) or any(
            name not in LIMIT_NAMES or not isinstance(reason, str)
            for name, reason in unenforceable.items()
        ):
            raise ValueError("checkpoint budget unenforceable state is malformed")

        self._actual = restored_actual
        self._reserved = restored_reserved
        self._estimated = restored_estimated
        self.decisions = restored_decisions
        self.exhausted = bool(snapshot.get("exhausted", False))
        self._unenforceable = dict(unenforceable)

    @property
    def refusals(self) -> list[BudgetDecision]:
        return [d for d in self.decisions if not d.admitted]
