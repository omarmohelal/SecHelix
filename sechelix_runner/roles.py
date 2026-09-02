"""Node roles and lifecycle states for the reasoner graph.

Roles are a closed set on purpose. A graph that can name an arbitrary role is a
graph whose report cannot be compared across runs, and the coverage ledger needs
to answer "was the authorization lane ever run against this commit" without
string-matching whatever a caller invented.
"""

from __future__ import annotations

from enum import Enum


class NodeRole(str, Enum):
    """What a node is for. One role, one job, one evidence contribution."""

    MAPPER = "MAPPER"
    ARCHITECTURE = "ARCHITECTURE"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    BUSINESS_LOGIC = "BUSINESS_LOGIC"
    INJECTION_DATAFLOW = "INJECTION_DATAFLOW"
    API_PROTOCOL = "API_PROTOCOL"
    BROWSER = "BROWSER"
    FILES_PARSERS = "FILES_PARSERS"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    CLOUD_CONFIGURATION = "CLOUD_CONFIGURATION"
    AI_MCP = "AI_MCP"
    RUNTIME_VERIFICATION = "RUNTIME_VERIFICATION"
    VARIANT_HUNTER = "VARIANT_HUNTER"
    INDEPENDENT_VERIFIER = "INDEPENDENT_VERIFIER"
    REMEDIATOR = "REMEDIATOR"
    PATCH_VERIFIER = "PATCH_VERIFIER"
    RELEASE_GATE = "RELEASE_GATE"


class NodeStatus(str, Enum):
    """Where a node got to.

    The three non-success terminal states are not interchangeable and the
    release gate reads them differently:

    ``FAILED``     the node ran and errored. Something is wrong with the run.
    ``BLOCKED``    the node could not run -- missing authority, budget, or a
                   dependency that never produced its evidence. The *question*
                   is unanswered, which is not the same as answered "no".
    ``SKIPPED``    applicability said this lane does not apply to this target.
                   That is a real answer and does not weaken the gate.
    ``INCOMPLETE`` the node started and could not finish. Partial output may
                   exist; it is never treated as a whole answer.
    """

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"
    INCOMPLETE = "INCOMPLETE"


#: Statuses after which a node will not run again in this run.
TERMINAL_STATUSES = frozenset(
    {
        NodeStatus.SUCCEEDED,
        NodeStatus.FAILED,
        NodeStatus.BLOCKED,
        NodeStatus.SKIPPED,
        NodeStatus.INCOMPLETE,
    }
)

#: Statuses that mean the node did not deliver the evidence it exists to produce.
#: ``SKIPPED`` is absent deliberately -- an inapplicable lane owes nothing.
UNSATISFIED_STATUSES = frozenset(
    {
        NodeStatus.PENDING,
        NodeStatus.RUNNING,
        NodeStatus.FAILED,
        NodeStatus.BLOCKED,
        NodeStatus.INCOMPLETE,
    }
)
