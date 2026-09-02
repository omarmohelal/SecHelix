"""What a node records about itself.

Every executed node leaves one :class:`NodeRecord`. The fields are not
negotiable per-role: an authorization lane and a release gate record the same
shape, because the coverage ledger, the budget governor and replay all read
these records generically and none of them should need to know what a node does.

Two design choices worth stating.

**Cost and tokens are optional, and their absence is recorded rather than
guessed.** A node executed by ``MockExecutor`` has no token count. Writing ``0``
there would make a budget report that silently understates spend. ``None`` means
"not available", which is a different claim from "zero", and the budget governor
treats them differently.

**A failed node keeps its record.** Nothing removes a node from the graph
because it errored. A report that omits its failures describes a run that did
not happen.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from .digests import digest
from .roles import NodeRole, NodeStatus


@dataclass
class NodeRecord:
    """The durable trace of one node execution."""

    run_id: str
    node_id: str
    role: NodeRole
    node_version: str
    target_commit: str
    scope_id: str

    parent_node_ids: list[str] = field(default_factory=list)
    input_evidence_ids: list[str] = field(default_factory=list)
    output_evidence_ids: list[str] = field(default_factory=list)

    input_digest: str | None = None
    output_digest: str | None = None

    started_at: str | None = None
    finished_at: str | None = None
    duration_seconds: float | None = None

    model: str | None = None
    provider: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None

    status: NodeStatus = NodeStatus.PENDING
    error: str | None = None
    blocker: str | None = None
    retry_count: int = 0

    #: Digest of the context view actually handed to this node, so a later
    #: reader can prove which projection produced the output without the
    #: projection itself being retained.
    context_digest: str | None = None
    context_source_ids: list[str] = field(default_factory=list)
    context_approx_tokens: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Plain-JSON form, with enums flattened to their string values."""
        data = asdict(self)
        data["role"] = self.role.value
        data["status"] = self.status.value
        return data

    def record_digest(self) -> str:
        """Digest over everything except wall-clock and the digest fields.

        Timing is excluded because two honest replays of the same orchestration
        differ in duration, and a tamper check that fires on that is a tamper
        check nobody will keep enabled.
        """
        data = self.to_dict()
        for volatile in ("started_at", "finished_at", "duration_seconds"):
            data.pop(volatile, None)
        return digest(data)

    @property
    def satisfied(self) -> bool:
        """Whether this node delivered what it exists to deliver.

        ``SKIPPED`` counts as satisfied: an inapplicable lane owes no evidence.
        Every other non-success state does not.
        """
        return self.status in (NodeStatus.SUCCEEDED, NodeStatus.SKIPPED)
