"""The active proof builder.

Turns an eligible candidate into the **smallest safe verification plan** that
would distinguish a real finding from a plausible one. It produces plans; it
does not execute them, and nothing in this module opens a socket or starts a
process.

The rule that constrains every plan, inherited from the contract work in
`sechelix_core`: **a runtime observation cannot manufacture attacker control.**
Watching a request succeed proves the request succeeded. It does not prove an
attacker could have made it. So every plan names the authority it needs, and a
plan whose authority is unavailable yields ``BLOCKED`` -- not a weaker proof.

Plans are deliberately boring. Two identities and one object settles an IDOR;
a deterministic concurrent fixture settles a race. Nothing escalates: no
destructive payloads, no persistence, no credential capture, no denial of
service, and no traffic to any host the network policy has not granted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProofClass(str, Enum):
    """Vulnerability classes with a deterministic safe proof."""

    AUTHORIZATION_IDOR = "AUTHORIZATION_IDOR"
    RACE_IDEMPOTENCY = "RACE_IDEMPOTENCY"
    WEBHOOK_SIGNATURE = "WEBHOOK_SIGNATURE"
    XSS_EXECUTION = "XSS_EXECUTION"
    SSRF_CALLBACK = "SSRF_CALLBACK"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"


class PlanState(str, Enum):
    READY = "READY"
    BLOCKED = "BLOCKED"


#: Actions no plan may contain, at any severity, for any class. Asserted by a
#: test over every generated plan rather than left to review.
FORBIDDEN_ACTIONS = (
    "delete",
    "drop",
    "truncate",
    "shutdown",
    "encrypt",
    "ransom",
    "exfiltrate",
    "persist",
    "backdoor",
    "flood",
    "denial of service",
    "brute force",
)


@dataclass
class ProofPlan:
    """A verification plan and the conditions under which it may run."""

    proof_class: ProofClass
    finding_id: str
    preconditions: list[str] = field(default_factory=list)
    required_authority: list[str] = field(default_factory=list)
    environment: str = "LOCAL"
    actions: list[str] = field(default_factory=list)
    expected_secure_behavior: str = ""
    expected_vulnerable_behavior: str = ""
    stop_conditions: list[str] = field(default_factory=list)
    forbidden_actions: list[str] = field(default_factory=lambda: list(FORBIDDEN_ACTIONS))
    state: PlanState = PlanState.READY
    blocker: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "proof_class": self.proof_class.value,
            "finding_id": self.finding_id,
            "state": self.state.value,
            "blocker": self.blocker,
            "environment": self.environment,
            "preconditions": self.preconditions,
            "required_authority": self.required_authority,
            "actions": self.actions,
            "expected_secure_behavior": self.expected_secure_behavior,
            "expected_vulnerable_behavior": self.expected_vulnerable_behavior,
            "stop_conditions": self.stop_conditions,
            "forbidden_actions": self.forbidden_actions,
        }


_COMMON_STOPS = [
    "any unexpected write outside the fixture workspace",
    "any request to a host not covered by an active network grant",
    "any response indicating the target is not the intended fixture",
    "budget exhausted before the plan completes",
]


def _plan(proof_class: ProofClass, finding_id: str, **kwargs: Any) -> ProofPlan:
    kwargs.setdefault("stop_conditions", list(_COMMON_STOPS))
    return ProofPlan(proof_class=proof_class, finding_id=finding_id, **kwargs)


def build_plan(
    proof_class: ProofClass,
    finding_id: str,
    *,
    available_authority: set[str] | None = None,
    environment: str = "LOCAL",
) -> ProofPlan:
    """Build the smallest safe plan for ``proof_class``.

    ``available_authority`` is what the operator has actually granted. A plan
    whose required authority is missing comes back ``BLOCKED`` with the gap
    named -- never downgraded into a weaker proof that would read as evidence.
    """
    available = available_authority or set()
    plan = _BUILDERS[proof_class](finding_id)
    plan.environment = environment

    missing = [a for a in plan.required_authority if a not in available]
    if missing:
        plan.state = PlanState.BLOCKED
        plan.blocker = (
            f"required authority not available: {', '.join(missing)}. "
            "Observation without this authority would not establish attacker control."
        )
    if environment == "PRODUCTION":
        plan.state = PlanState.BLOCKED
        plan.blocker = "active proof is not performed against production"
    return plan


def _idor(finding_id: str) -> ProofPlan:
    return _plan(
        ProofClass.AUTHORIZATION_IDOR,
        finding_id,
        preconditions=[
            "two distinct identities exist in the fixture",
            "one object is owned by identity A and not shared with identity B",
            "the object identifier is known and stable",
        ],
        required_authority=["identity_a_credentials", "identity_b_credentials"],
        actions=[
            "authenticate as identity A and read the owned object; record the response",
            "authenticate as identity B and request the same object identifier",
            "compare the two responses for the object body and status",
        ],
        expected_secure_behavior=(
            "identity B receives 403 or 404 and no field of the object body"
        ),
        expected_vulnerable_behavior=(
            "identity B receives the object body belonging to identity A"
        ),
    )


def _race(finding_id: str) -> ProofPlan:
    return _plan(
        ProofClass.RACE_IDEMPOTENCY,
        finding_id,
        preconditions=[
            "the operation is repeatable against a fixture with a known starting state",
            "a bounded concurrency level is fixed in advance",
        ],
        required_authority=["fixture_write_access"],
        actions=[
            "record the starting state of the affected resource",
            "issue N identical requests concurrently, with N fixed and small",
            "record the ending state and compare against the single-request outcome",
        ],
        expected_secure_behavior="the ending state matches exactly one applied operation",
        expected_vulnerable_behavior=(
            "the ending state reflects more applied operations than the invariant allows"
        ),
    )


def _webhook(finding_id: str) -> ProofPlan:
    return _plan(
        ProofClass.WEBHOOK_SIGNATURE,
        finding_id,
        preconditions=["a webhook endpoint and its documented signature scheme are known"],
        required_authority=["fixture_endpoint_access"],
        actions=[
            "send a correctly signed payload and record acceptance",
            "send the same payload with the signature removed",
            "send the same payload with a signature from a different key",
            "replay the original correctly signed payload a second time",
        ],
        expected_secure_behavior=(
            "unsigned and wrongly signed payloads are rejected, and the replay is "
            "rejected or is idempotent"
        ),
        expected_vulnerable_behavior=(
            "an unsigned, wrongly signed, or replayed payload is accepted and applied"
        ),
    )


def _xss(finding_id: str) -> ProofPlan:
    return _plan(
        ProofClass.XSS_EXECUTION,
        finding_id,
        preconditions=["the sink renders into a page reachable in the local fixture"],
        required_authority=["local_browser_runtime"],
        actions=[
            "load the page with a benign marker payload that sets a known variable",
            "read the variable back from the page context",
            "capture the rendered markup around the injection point",
        ],
        expected_secure_behavior="the marker appears as inert text and the variable is unset",
        expected_vulnerable_behavior="the variable is set, proving script execution",
    )


def _ssrf(finding_id: str) -> ProofPlan:
    return _plan(
        ProofClass.SSRF_CALLBACK,
        finding_id,
        preconditions=[
            "a listener is bound on loopback and its address is known",
            "the loopback listener is covered by an active network grant",
        ],
        # Local only. The audit found the competitor uses a public OOB service
        # for this; routing a target's traffic to a third party is not a proof
        # method this project uses, and sandbox.FORBIDDEN_HOSTS enforces it.
        required_authority=["local_callback_listener"],
        actions=[
            "start a listener bound to 127.0.0.1 on an unused port",
            "submit the loopback URL through the suspected parameter",
            "record whether the listener observed a connection, and from where",
        ],
        expected_secure_behavior="the request is rejected and the listener sees nothing",
        expected_vulnerable_behavior=(
            "the listener observes a connection originating from the target process"
        ),
    )


def _traversal(finding_id: str) -> ProofPlan:
    return _plan(
        ProofClass.PATH_TRAVERSAL,
        finding_id,
        preconditions=[
            "a sentinel file exists outside the intended directory but inside the fixture",
        ],
        required_authority=["fixture_filesystem"],
        actions=[
            "request a path inside the intended directory and record the result",
            "request a traversal path pointing at the sentinel file",
            "compare the two results",
        ],
        expected_secure_behavior="the traversal request is rejected and the sentinel is not read",
        expected_vulnerable_behavior="the sentinel file contents are returned",
    )


_BUILDERS = {
    ProofClass.AUTHORIZATION_IDOR: _idor,
    ProofClass.RACE_IDEMPOTENCY: _race,
    ProofClass.WEBHOOK_SIGNATURE: _webhook,
    ProofClass.XSS_EXECUTION: _xss,
    ProofClass.SSRF_CALLBACK: _ssrf,
    ProofClass.PATH_TRAVERSAL: _traversal,
}
