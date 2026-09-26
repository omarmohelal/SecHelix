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
    CSRF_REQUEST = "CSRF_REQUEST"
    SESSION_REVOCATION = "SESSION_REVOCATION"
    STATE_TRANSITION = "STATE_TRANSITION"
    PAYMENT_INVARIANT = "PAYMENT_INVARIANT"
    WORKFLOW_SEQUENCE = "WORKFLOW_SEQUENCE"
    MONEY_FLOW_INVARIANT = "MONEY_FLOW_INVARIANT"


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



def _csrf(finding_id: str) -> ProofPlan:
    return _plan(
        ProofClass.CSRF_REQUEST,
        finding_id,
        preconditions=[
            "the fixture endpoint performs one harmless state-changing action",
            "an authenticated fixture session is available",
            "the endpoint is browser-reachable and cookies would normally accompany the request",
        ],
        required_authority=["fixture_authenticated_session", "fixture_write_access"],
        actions=[
            "send the harmless action with the expected same-origin Origin header as a control",
            "send the same harmless action with the same authenticated session but a fixed foreign Origin",
            "compare whether the foreign-origin request is rejected before the action is applied",
        ],
        expected_secure_behavior=(
            "the same-origin control succeeds and the foreign-origin authenticated request is denied"
        ),
        expected_vulnerable_behavior=(
            "the foreign-origin authenticated request is accepted like the same-origin control"
        ),
    )


def _session_revocation(finding_id: str) -> ProofPlan:
    return _plan(
        ProofClass.SESSION_REVOCATION,
        finding_id,
        preconditions=[
            "an authenticated fixture session reaches one harmless protected read",
            "the fixture exposes a deterministic operator-controlled revocation hook",
            "the exact same session can be replayed after revocation",
        ],
        required_authority=["fixture_authenticated_session", "fixture_session_revocation"],
        actions=[
            "request the protected fixture resource with the authenticated session and record the control",
            "revoke that exact fixture session through the operator-supplied local revocation hook",
            "replay the same session against the same protected resource",
        ],
        expected_secure_behavior=(
            "the pre-revocation control succeeds and the exact same session is denied after revocation"
        ),
        expected_vulnerable_behavior=(
            "the exact same revoked session continues to reach the protected resource"
        ),
    )

def _state_transition(finding_id: str) -> ProofPlan:
    return _plan(
        ProofClass.STATE_TRANSITION,
        finding_id,
        preconditions=[
            "the fixture has a deterministic readable starting state",
            "one harmless transition request represents an operator-declared forbidden state edge",
            "the post-request state can be read without exposing credential material",
        ],
        required_authority=["fixture_write_access", "fixture_state_readback"],
        actions=[
            "read and verify the fixture starting state",
            "issue exactly one bounded forbidden-transition request",
            "read the resulting fixture state and compare it with the declared safe and forbidden outcomes",
        ],
        expected_secure_behavior=(
            "the declared forbidden target state is not reached and the fixture remains in the supplied safe state"
        ),
        expected_vulnerable_behavior=(
            "the request moves the fixture into the operator-declared forbidden target state"
        ),
    )

def _payment_invariant(finding_id: str) -> ProofPlan:
    return _plan(
        ProofClass.PAYMENT_INVARIANT,
        finding_id,
        preconditions=[
            "the fixture exposes a deterministic balance or liability readback in integer minor units",
            "one harmless charge or refund request has an operator-declared expected single-operation delta",
            "replaying the exact same request is safe in the local fixture",
        ],
        required_authority=["fixture_write_access", "fixture_financial_readback"],
        actions=[
            "read the starting financial state",
            "issue one bounded payment mutation and verify the exact declared delta",
            "replay the exact same request once and verify it does not apply the financial delta twice",
        ],
        expected_secure_behavior=(
            "the first request applies exactly the declared delta and replay leaves the financial state unchanged"
        ),
        expected_vulnerable_behavior=(
            "the first request applies the declared delta and replay applies that same financial effect again"
        ),
    )


def _workflow_sequence(finding_id: str) -> ProofPlan:
    return _plan(
        ProofClass.WORKFLOW_SEQUENCE,
        finding_id,
        preconditions=[
            "the local fixture has a deterministic start, intermediate, and final state",
            "two harmless ordered mutations form one operator-declared legitimate workflow",
            "an operator-controlled local reset hook can restore the exact starting state",
        ],
        required_authority=[
            "fixture_write_access",
            "fixture_state_readback",
            "fixture_reset",
        ],
        actions=[
            "verify the fixture starts in the declared starting state",
            "execute step one and require the declared intermediate state",
            "execute step two and require the declared final state",
            "reset the local fixture and verify the starting state is restored",
            "attempt step two directly from the starting state and compare the resulting state",
        ],
        expected_secure_behavior=(
            "the ordered control reaches the final state, while direct step two from the start "
            "is denied or leaves the fixture in the declared safe bypass state"
        ),
        expected_vulnerable_behavior=(
            "the ordered control is valid and direct step two from the start reaches the final state "
            "without the required intermediate step"
        ),
    )


def _money_flow_invariant(finding_id: str) -> ProofPlan:
    return _plan(
        ProofClass.MONEY_FLOW_INVARIANT,
        finding_id,
        preconditions=[
            "the local fixture exposes a deterministic readback for every declared financial entity",
            "one harmless money-moving request has an operator-declared expected delta vector",
            "any forbidden partial or misrouted delta vector is declared explicitly",
        ],
        required_authority=["fixture_write_access", "fixture_financial_readback"],
        actions=[
            "read the starting balances for the declared financial entities",
            "issue one bounded money-flow mutation and compare the exact observed delta vector",
            "if the expected vector was established, replay the exact same request once",
            "compare replay deltas for duplicate movement or preserved idempotency",
        ],
        expected_secure_behavior=(
            "the first mutation matches the declared cross-entity delta vector and replay produces no additional movement"
        ),
        expected_vulnerable_behavior=(
            "the first mutation reaches an explicitly forbidden delta vector or replay applies the expected money-flow vector again"
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
    ProofClass.CSRF_REQUEST: _csrf,
    ProofClass.SESSION_REVOCATION: _session_revocation,
    ProofClass.STATE_TRANSITION: _state_transition,
    ProofClass.PAYMENT_INVARIANT: _payment_invariant,
    ProofClass.WORKFLOW_SEQUENCE: _workflow_sequence,
    ProofClass.MONEY_FLOW_INVARIANT: _money_flow_invariant,
}
