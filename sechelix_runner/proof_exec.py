"""Bounded LOCAL execution for SecHelix proof plans.

The builder in :mod:`sechelix_runner.proof` decides *what would distinguish* a
real finding from a plausible one.  This module performs a deliberately small
subset of those plans against operator-supplied LOCAL fixtures.

It is intentionally not a generic HTTP fuzzer.  Each executor has a fixed
request shape and a hard request bound.  Every outbound request is checked by
:class:`~sechelix_runner.sandbox.NetworkPolicy`, production plans are refused,
and credentials/signatures are accepted only as ephemeral request inputs: they
are never returned in the result artifact.

A proof result also does not promote a finding by itself.  It records
``VULNERABLE_BEHAVIOR`` or ``SECURE_BEHAVIOR``; the independent verifier still
has to establish attacker control, reachability and the boundary failure before
a finding can become VERIFIED.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import StrEnum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping

from .proof import PlanState, ProofClass, ProofPlan
from .sandbox import ExecutionMode, NetworkPolicy


class ProofExecutionError(RuntimeError):
    """The execution spec is unsafe, malformed, or inconsistent with the plan."""


def _default_browser_factory(*args: Any, **kwargs: Any) -> Any:
    from .pentest.safe_browser import SafeAuthorizedBrowser

    return SafeAuthorizedBrowser(*args, **kwargs)


class ProofBehavior(StrEnum):
    VULNERABLE_BEHAVIOR = "VULNERABLE_BEHAVIOR"
    SECURE_BEHAVIOR = "SECURE_BEHAVIOR"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True, slots=True)
class HttpObservation:
    label: str
    status: int | None
    body_sha256: str
    body_length: int
    elapsed_ms: int
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "status": self.status,
            "body_sha256": self.body_sha256,
            "body_length": self.body_length,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
        }


@dataclass(slots=True)
class ProofExecutionResult:
    finding_id: str
    proof_class: ProofClass
    behavior: ProofBehavior
    observations: list[dict[str, Any]] = field(default_factory=list)
    request_count: int = 0
    blocker: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "sechelix-proof-execution/v1",
            "finding_id": self.finding_id,
            "proof_class": self.proof_class.value,
            "behavior": self.behavior.value,
            "request_count": self.request_count,
            "blocker": self.blocker,
            "observations": self.observations,
            "notes": self.notes,
            "promotes_finding": False,
        }


@dataclass(frozen=True, slots=True)
class IdorHttpSpec:
    url_template: str
    object_id: str
    identity_a_headers: Mapping[str, str]
    identity_b_headers: Mapping[str, str]
    foreign_denial_statuses: tuple[int, ...] = (403, 404)


@dataclass(frozen=True, slots=True)
class TraversalHttpSpec:
    url_template: str
    safe_path: str
    traversal_path: str
    sentinel_marker: bytes


@dataclass(frozen=True, slots=True)
class RaceHttpSpec:
    url: str
    method: str = "POST"
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)
    concurrency: int = 2
    success_statuses: tuple[int, ...] = (200, 201, 202, 204)
    # A caller-supplied local readback converts "N HTTP successes" into a state
    # invariant. It receives no credentials from the executor.
    read_state: Callable[[], Any] | None = None
    expected_single_state: Any = None


@dataclass(frozen=True, slots=True)
class WebhookHttpSpec:
    url: str
    body: bytes
    signature_header: str
    valid_signature: str
    invalid_signature: str = "sechelix-invalid-signature"
    accepted_statuses: tuple[int, ...] = (200, 201, 202, 204)
    # Optional local readback turns webhook status observations into a
    # deterministic side-effect invariant. The value never enters the artifact
    # in the clear; only digests are recorded in notes.
    read_state: Callable[[], Any] | None = None
    expected_single_state: Any = None


@dataclass(frozen=True, slots=True)
class CsrfHttpSpec:
    """One harmless, authenticated state-changing request against a LOCAL fixture.

    The foreign origin is fixed by default and never contacted. Session headers
    are ephemeral request inputs and never enter the result artifact.
    """

    url: str
    body: bytes = b"sechelix_fixture=1"
    authenticated_headers: Mapping[str, str] = field(default_factory=dict)
    same_origin: str = ""
    foreign_origin: str = "https://csrf-attacker.invalid"
    accepted_statuses: tuple[int, ...] = (200, 201, 202, 204)
    denial_statuses: tuple[int, ...] = (400, 401, 403, 409, 422)


@dataclass(frozen=True, slots=True)
class SessionRevocationHttpSpec:
    """Replay one operator-supplied LOCAL fixture session across revocation.

    The revocation hook is a fixture callback, not an arbitrary network action.
    Session headers are ephemeral and never appear in the result artifact.
    """

    url: str
    authenticated_headers: Mapping[str, str] = field(default_factory=dict)
    revoke_session: Callable[[], Any] | None = None
    accepted_statuses: tuple[int, ...] = (200, 201, 202, 204)
    denial_statuses: tuple[int, ...] = (401, 403, 404)


@dataclass(frozen=True, slots=True)
class StateTransitionHttpSpec:
    """One operator-declared forbidden LOCAL state transition.

    The executor issues exactly one POST request and compares local readback
    against explicit start, safe and forbidden state invariants. Raw state
    values and request headers never enter the proof artifact.
    """

    url: str
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)
    read_state: Callable[[], Any] | None = None
    expected_start_state: Any = None
    expected_secure_state: Any = None
    forbidden_state: Any = None
    accepted_statuses: tuple[int, ...] = (200, 201, 202, 204)
    denial_statuses: tuple[int, ...] = (400, 401, 403, 409, 422)


@dataclass(frozen=True, slots=True)
class PaymentInvariantHttpSpec:
    """Replay one harmless LOCAL charge/refund against an integer financial invariant.

    The operator supplies a local balance/liability readback in integer minor
    units plus the exact expected delta of one legitimate operation. Raw
    balances, request headers and request bodies never enter the artifact.
    """

    url: str
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)
    read_balance_minor: Callable[[], int] | None = None
    expected_single_delta_minor: int = 0
    accepted_statuses: tuple[int, ...] = (200, 201, 202, 204)


@dataclass(frozen=True, slots=True)
class MoneyFlowInvariantHttpSpec:
    """Validate one bounded multi-entity money movement in a LOCAL fixture.

    Balances are integer minor units keyed by operator-declared entity labels.
    Expected and forbidden delta vectors are explicit fixture invariants. Raw
    balances, headers and bodies never enter the serialized proof artifact.
    """

    url: str
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)
    read_balances_minor: Callable[[], Mapping[str, int]] | None = None
    expected_deltas_minor: Mapping[str, int] = field(default_factory=dict)
    forbidden_delta_vectors: tuple[Mapping[str, int], ...] = ()
    accepted_statuses: tuple[int, ...] = (200, 201, 202, 204)


@dataclass(frozen=True, slots=True)
class WorkflowSequenceHttpSpec:
    """Prove one declared prerequisite edge in a LOCAL multi-step workflow.

    The ordered control runs step one then step two, after which an
    operator-supplied local reset hook restores the fixture. The bypass attempt
    executes step two directly from the declared start state. Raw workflow
    states, headers and request bodies never enter the proof artifact.
    """

    step_one_url: str
    step_two_url: str
    step_one_body: bytes = b""
    step_two_body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)
    read_state: Callable[[], Any] | None = None
    reset_fixture: Callable[[], Any] | None = None
    expected_start_state: Any = None
    expected_intermediate_state: Any = None
    expected_final_state: Any = None
    expected_safe_bypass_state: Any = None
    accepted_statuses: tuple[int, ...] = (200, 201, 202, 204)
    denial_statuses: tuple[int, ...] = (400, 401, 403, 409, 422)


@dataclass(frozen=True, slots=True)
class XssBrowserSpec:
    """One reflected LOCAL browser sink with a fixed benign marker payload.

    ``url_template`` must contain ``{payload}``. The executor URL-encodes a
    SecHelix-owned script marker; callers cannot provide arbitrary JavaScript.
    ``injection_selector`` identifies where inert text should appear in a
    compensated fixture so absence of execution is not mistaken for proof.
    """

    url_template: str
    injection_selector: str
    marker_name: str = "__SECHELIX_XSS_MARKER"
    marker_value: str = "SECHELIX_XSS_MARKER_1"
    timeout_ms: int = 10_000


@dataclass(frozen=True, slots=True)
class SsrfHttpSpec:
    """Submit a loopback callback URL through one bounded target request.

    ``submit_url_template`` must contain ``{callback}``; the callback value is
    percent-encoded before insertion.  This supports owned local fixtures
    without inventing a universal SSRF parameter format.
    """

    submit_url_template: str
    callback_timeout_seconds: float = 1.5


class _CallbackHandler(BaseHTTPRequestHandler):
    event: threading.Event

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        self.__class__.event.set()
        self.send_response(204)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        self.__class__.event.set()
        self.send_response(204)
        self.end_headers()

    def log_message(self, _format: str, *args: Any) -> None:
        return


class LocalProofExecutor:
    """Execute fixed-shape proof plans against explicitly granted LOCAL targets."""

    def __init__(
        self,
        policy: NetworkPolicy,
        *,
        timeout_seconds: float = 5.0,
        max_requests: int = 8,
        browser_factory: Callable[..., Any] | None = _default_browser_factory,
    ) -> None:
        if policy.mode is not ExecutionMode.LOCAL:
            raise ProofExecutionError("active proof executor requires LOCAL network policy")
        if not 0.1 <= timeout_seconds <= 30:
            raise ProofExecutionError("timeout_seconds must be between 0.1 and 30")
        if not 1 <= max_requests <= 16:
            raise ProofExecutionError("max_requests must be between 1 and 16")
        self.policy = policy
        self.timeout_seconds = timeout_seconds
        self.max_requests = max_requests
        self.browser_factory = browser_factory
        self._requests = 0

    def execute(self, plan: ProofPlan, spec: Any) -> ProofExecutionResult:
        if plan.state is not PlanState.READY:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.BLOCKED,
                blocker=plan.blocker or "proof plan is not READY",
            )
        if plan.environment != "LOCAL":
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.BLOCKED,
                blocker="bounded proof execution is implemented for LOCAL fixtures only",
            )
        self._requests = 0
        dispatch = {
            ProofClass.AUTHORIZATION_IDOR: self._idor,
            ProofClass.PATH_TRAVERSAL: self._traversal,
            ProofClass.RACE_IDEMPOTENCY: self._race,
            ProofClass.WEBHOOK_SIGNATURE: self._webhook,
            ProofClass.SSRF_CALLBACK: self._ssrf,
            ProofClass.CSRF_REQUEST: self._csrf,
            ProofClass.SESSION_REVOCATION: self._session_revocation,
            ProofClass.STATE_TRANSITION: self._state_transition,
            ProofClass.PAYMENT_INVARIANT: self._payment_invariant,
            ProofClass.WORKFLOW_SEQUENCE: self._workflow_sequence,
            ProofClass.MONEY_FLOW_INVARIANT: self._money_flow_invariant,
        }
        if plan.proof_class is ProofClass.XSS_EXECUTION:
            return self._xss(plan, spec)
        handler = dispatch.get(plan.proof_class)
        if handler is None:
            raise ProofExecutionError(f"no executor for {plan.proof_class.value}")
        result = handler(plan, spec)
        result.request_count = self._requests
        return result

    # -- fixed proof shapes -------------------------------------------------

    def _idor(self, plan: ProofPlan, spec: Any) -> ProofExecutionResult:
        if not isinstance(spec, IdorHttpSpec):
            raise ProofExecutionError("IDOR plan requires IdorHttpSpec")
        if "{object_id}" not in spec.url_template:
            raise ProofExecutionError("IDOR url_template must contain {object_id}")
        url = spec.url_template.format(object_id=urllib.parse.quote(spec.object_id, safe=""))
        owned = self._request("owned-control", url, headers=spec.identity_a_headers)
        foreign = self._request("foreign-object", url, headers=spec.identity_b_headers)
        observations = [owned.to_dict(), foreign.to_dict()]
        if owned.status is None:
            behavior = ProofBehavior.INCONCLUSIVE
            notes = ["owned-object control did not succeed; authorization conclusion would be ambiguous"]
        elif foreign.status in spec.foreign_denial_statuses:
            behavior = ProofBehavior.SECURE_BEHAVIOR
            notes = ["foreign identity was denied while the owned control reached the endpoint"]
        elif foreign.status is not None and owned.status is not None and foreign.body_sha256 == owned.body_sha256:
            behavior = ProofBehavior.VULNERABLE_BEHAVIOR
            notes = ["foreign identity received the same response body as the owning identity"]
        else:
            behavior = ProofBehavior.INCONCLUSIVE
            notes = ["foreign response was neither an expected denial nor identical to the owned response"]
        return ProofExecutionResult(plan.finding_id, plan.proof_class, behavior, observations, notes=notes)

    def _traversal(self, plan: ProofPlan, spec: Any) -> ProofExecutionResult:
        if not isinstance(spec, TraversalHttpSpec):
            raise ProofExecutionError("path traversal plan requires TraversalHttpSpec")
        if "{path}" not in spec.url_template:
            raise ProofExecutionError("traversal url_template must contain {path}")
        if not spec.sentinel_marker:
            raise ProofExecutionError("sentinel_marker must not be empty")
        safe_url = spec.url_template.format(path=urllib.parse.quote(spec.safe_path, safe="/"))
        traversal_url = spec.url_template.format(path=urllib.parse.quote(spec.traversal_path, safe="/"))
        safe = self._request("safe-path-control", safe_url)
        escaped = self._request("traversal-path", traversal_url)
        observations = [safe.to_dict(), escaped.to_dict()]
        marker_digest = hashlib.sha256(spec.sentinel_marker).hexdigest()
        marker_seen = escaped.body_sha256 == marker_digest
        notes = [f"sentinel_sha256={marker_digest}"]
        behavior = ProofBehavior.VULNERABLE_BEHAVIOR if marker_seen else ProofBehavior.SECURE_BEHAVIOR
        notes.append("sentinel returned by traversal path" if marker_seen else "sentinel not returned")
        return ProofExecutionResult(plan.finding_id, plan.proof_class, behavior, observations, notes=notes)

    def _race(self, plan: ProofPlan, spec: Any) -> ProofExecutionResult:
        if not isinstance(spec, RaceHttpSpec):
            raise ProofExecutionError("race plan requires RaceHttpSpec")
        if not 2 <= spec.concurrency <= min(8, self.max_requests):
            raise ProofExecutionError("race concurrency must be between 2 and the bounded request limit (max 8)")
        before = spec.read_state() if spec.read_state else None
        with ThreadPoolExecutor(max_workers=spec.concurrency) as pool:
            futures = [
                pool.submit(self._request, f"race-{index + 1}", spec.url, spec.method, spec.headers, spec.body)
                for index in range(spec.concurrency)
            ]
            responses = [future.result() for future in as_completed(futures)]
        after = spec.read_state() if spec.read_state else None
        observations = [item.to_dict() for item in sorted(responses, key=lambda item: item.label)]
        if spec.read_state is None:
            successes = sum(item.status in spec.success_statuses for item in responses)
            behavior = ProofBehavior.INCONCLUSIVE
            notes = [
                f"{successes}/{spec.concurrency} requests returned success; no state readback was supplied, "
                "so HTTP success count alone cannot prove duplicate application"
            ]
        elif after == spec.expected_single_state:
            behavior = ProofBehavior.SECURE_BEHAVIOR
            notes = ["bounded concurrent execution ended in the expected single-application state"]
        else:
            behavior = ProofBehavior.VULNERABLE_BEHAVIOR
            notes = [
                "bounded concurrent execution ended in a state different from the supplied single-application invariant",
                f"before_sha256={_value_digest(before)}",
                f"after_sha256={_value_digest(after)}",
            ]
        return ProofExecutionResult(plan.finding_id, plan.proof_class, behavior, observations, notes=notes)

    def _webhook(self, plan: ProofPlan, spec: Any) -> ProofExecutionResult:
        if not isinstance(spec, WebhookHttpSpec):
            raise ProofExecutionError("webhook plan requires WebhookHttpSpec")
        if not spec.signature_header.strip():
            raise ProofExecutionError("signature_header must not be empty")

        before = spec.read_state() if spec.read_state else None
        valid = self._request(
            "valid-signature-control",
            spec.url,
            "POST",
            {spec.signature_header: spec.valid_signature},
            spec.body,
        )
        after_valid = spec.read_state() if spec.read_state else None

        unsigned = self._request("unsigned", spec.url, "POST", {}, spec.body)
        after_unsigned = spec.read_state() if spec.read_state else None

        invalid = self._request(
            "invalid-signature",
            spec.url,
            "POST",
            {spec.signature_header: spec.invalid_signature},
            spec.body,
        )
        after_invalid = spec.read_state() if spec.read_state else None

        replay = self._request(
            "valid-signature-replay",
            spec.url,
            "POST",
            {spec.signature_header: spec.valid_signature},
            spec.body,
        )
        after_replay = spec.read_state() if spec.read_state else None

        observations = [item.to_dict() for item in (valid, unsigned, invalid, replay)]
        bad_accept = unsigned.status in spec.accepted_statuses or invalid.status in spec.accepted_statuses
        replay_accept = replay.status in spec.accepted_statuses and valid.status in spec.accepted_statuses

        if valid.status not in spec.accepted_statuses:
            behavior = ProofBehavior.INCONCLUSIVE
            notes = ["valid signed control was not accepted"]
        elif spec.read_state is not None:
            if after_valid != spec.expected_single_state or before == after_valid:
                behavior = ProofBehavior.INCONCLUSIVE
                notes = [
                    "valid signed control did not establish the supplied single-application state invariant",
                    f"before_sha256={_value_digest(before)}",
                    f"after_valid_sha256={_value_digest(after_valid)}",
                ]
            else:
                unauthorized_mutation = (
                    after_unsigned != after_valid
                    or after_invalid != after_unsigned
                )
                replay_mutation = after_replay != after_invalid
                if unauthorized_mutation or replay_mutation:
                    behavior = ProofBehavior.VULNERABLE_BEHAVIOR
                    notes = [
                        "fixture state changed after an unauthorized delivery or replay",
                        f"after_valid_sha256={_value_digest(after_valid)}",
                        f"after_unsigned_sha256={_value_digest(after_unsigned)}",
                        f"after_invalid_sha256={_value_digest(after_invalid)}",
                        f"after_replay_sha256={_value_digest(after_replay)}",
                    ]
                elif bad_accept:
                    behavior = ProofBehavior.INCONCLUSIVE
                    notes = [
                        "unsigned or invalid-signature delivery returned an accepted status but produced no observed state change; signature enforcement remains ambiguous",
                        f"after_valid_sha256={_value_digest(after_valid)}",
                    ]
                else:
                    behavior = ProofBehavior.SECURE_BEHAVIOR
                    notes = [
                        "only the valid signed control changed fixture state; rejected unauthorized deliveries and accepted/rejected replay produced no additional side effect",
                        f"after_valid_sha256={_value_digest(after_valid)}",
                    ]
        elif bad_accept:
            behavior = ProofBehavior.VULNERABLE_BEHAVIOR
            notes = ["unsigned or incorrectly signed payload was accepted"]
        elif replay_accept:
            behavior = ProofBehavior.INCONCLUSIVE
            notes = [
                "replay returned an accepted status; status alone cannot distinguish idempotent acceptance from duplicate application"
            ]
        else:
            behavior = ProofBehavior.SECURE_BEHAVIOR
            notes = ["unsigned and incorrectly signed payloads were rejected; replay was not accepted"]
        return ProofExecutionResult(plan.finding_id, plan.proof_class, behavior, observations, notes=notes)

    def _csrf(self, plan: ProofPlan, spec: Any) -> ProofExecutionResult:
        if not isinstance(spec, CsrfHttpSpec):
            raise ProofExecutionError("CSRF plan requires CsrfHttpSpec")
        if not spec.authenticated_headers:
            raise ProofExecutionError("CSRF proof requires an authenticated fixture session")
        parsed = urllib.parse.urlsplit(spec.url)
        expected_origin = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port is not None:
            expected_origin += f":{parsed.port}"
        same_origin = spec.same_origin or expected_origin
        if urllib.parse.urlsplit(same_origin).scheme not in {"http", "https"}:
            raise ProofExecutionError("same_origin must be absolute HTTP(S)")
        foreign = urllib.parse.urlsplit(spec.foreign_origin)
        if foreign.scheme != "https" or not foreign.hostname:
            raise ProofExecutionError("foreign_origin must be an absolute HTTPS origin")
        if foreign.hostname in {parsed.hostname, "127.0.0.1", "::1", "localhost"}:
            raise ProofExecutionError("foreign_origin must be distinct from the LOCAL target")

        base_headers = dict(spec.authenticated_headers)
        # The controlled payload is form-like on purpose: a browser can submit
        # this class cross-site without requiring a CORS preflight.
        base_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

        same_headers = {**base_headers, "Origin": same_origin}
        foreign_headers = {**base_headers, "Origin": spec.foreign_origin}

        control = self._request(
            "same-origin-control",
            spec.url,
            "POST",
            same_headers,
            spec.body,
        )
        cross_site = self._request(
            "foreign-origin-request",
            spec.url,
            "POST",
            foreign_headers,
            spec.body,
        )
        observations = [control.to_dict(), cross_site.to_dict()]

        if control.status not in spec.accepted_statuses:
            behavior = ProofBehavior.INCONCLUSIVE
            notes = [
                "same-origin authenticated control was not accepted; CSRF conclusion would be ambiguous"
            ]
        elif cross_site.status in spec.denial_statuses:
            behavior = ProofBehavior.SECURE_BEHAVIOR
            notes = [
                "foreign-origin authenticated request was denied while the same-origin control succeeded"
            ]
        elif cross_site.status in spec.accepted_statuses:
            behavior = ProofBehavior.VULNERABLE_BEHAVIOR
            notes = [
                "foreign-origin form-compatible request was accepted with the authenticated fixture session"
            ]
        else:
            behavior = ProofBehavior.INCONCLUSIVE
            notes = [
                "foreign-origin response was neither an expected denial nor a normal accepted outcome"
            ]
        return ProofExecutionResult(
            plan.finding_id,
            plan.proof_class,
            behavior,
            observations,
            notes=notes,
        )

    def _session_revocation(self, plan: ProofPlan, spec: Any) -> ProofExecutionResult:
        if not isinstance(spec, SessionRevocationHttpSpec):
            raise ProofExecutionError("session revocation plan requires SessionRevocationHttpSpec")
        if not spec.authenticated_headers:
            raise ProofExecutionError("session revocation proof requires an authenticated fixture session")
        if spec.revoke_session is None or not callable(spec.revoke_session):
            raise ProofExecutionError("session revocation proof requires an operator-supplied revocation hook")

        control = self._request(
            "pre-revocation-control",
            spec.url,
            headers=spec.authenticated_headers,
        )
        if control.status not in spec.accepted_statuses:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.INCONCLUSIVE,
                [control.to_dict()],
                notes=[
                    "pre-revocation authenticated control was not accepted; revocation conclusion would be ambiguous"
                ],
            )

        try:
            spec.revoke_session()
        except Exception as exc:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.INCONCLUSIVE,
                [control.to_dict()],
                notes=[f"fixture revocation hook failed: {type(exc).__name__}"],
            )

        replay = self._request(
            "post-revocation-replay",
            spec.url,
            headers=spec.authenticated_headers,
        )
        observations = [control.to_dict(), replay.to_dict()]
        if replay.status in spec.denial_statuses:
            behavior = ProofBehavior.SECURE_BEHAVIOR
            notes = ["the exact same fixture session was denied after revocation"]
        elif replay.status in spec.accepted_statuses:
            behavior = ProofBehavior.VULNERABLE_BEHAVIOR
            notes = ["the exact same revoked fixture session still reached the protected resource"]
        else:
            behavior = ProofBehavior.INCONCLUSIVE
            notes = ["post-revocation response was neither an expected denial nor a normal accepted outcome"]
        return ProofExecutionResult(
            plan.finding_id,
            plan.proof_class,
            behavior,
            observations,
            notes=notes,
        )

    def _state_transition(self, plan: ProofPlan, spec: Any) -> ProofExecutionResult:
        if not isinstance(spec, StateTransitionHttpSpec):
            raise ProofExecutionError("state transition plan requires StateTransitionHttpSpec")
        if spec.read_state is None or not callable(spec.read_state):
            raise ProofExecutionError("state transition proof requires a fixture state readback")
        if spec.expected_secure_state == spec.forbidden_state:
            raise ProofExecutionError("secure and forbidden state invariants must differ")

        before = spec.read_state()
        if before != spec.expected_start_state:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.INCONCLUSIVE,
                notes=[
                    "fixture did not begin in the declared starting state",
                    f"observed_start_sha256={_value_digest(before)}",
                    f"expected_start_sha256={_value_digest(spec.expected_start_state)}",
                ],
            )

        attempt = self._request(
            "forbidden-state-transition",
            spec.url,
            "POST",
            spec.headers,
            spec.body,
        )
        after = spec.read_state()
        observations = [attempt.to_dict()]
        notes = [
            f"before_sha256={_value_digest(before)}",
            f"after_sha256={_value_digest(after)}",
            f"secure_state_sha256={_value_digest(spec.expected_secure_state)}",
            f"forbidden_state_sha256={_value_digest(spec.forbidden_state)}",
        ]

        if attempt.status is None:
            behavior = ProofBehavior.INCONCLUSIVE
            notes.insert(0, "transition request did not produce an HTTP response")
        elif after == spec.forbidden_state:
            behavior = ProofBehavior.VULNERABLE_BEHAVIOR
            notes.insert(0, "operator-declared forbidden target state was reached")
        elif after == spec.expected_secure_state and (
            attempt.status in spec.denial_statuses
            or attempt.status in spec.accepted_statuses
        ):
            behavior = ProofBehavior.SECURE_BEHAVIOR
            notes.insert(0, "forbidden target state was not reached; supplied safe state invariant held")
        else:
            behavior = ProofBehavior.INCONCLUSIVE
            notes.insert(
                0,
                "post-request state matched neither the declared safe nor forbidden invariant",
            )
        return ProofExecutionResult(
            plan.finding_id,
            plan.proof_class,
            behavior,
            observations,
            notes=notes,
        )

    def _payment_invariant(self, plan: ProofPlan, spec: Any) -> ProofExecutionResult:
        if not isinstance(spec, PaymentInvariantHttpSpec):
            raise ProofExecutionError("payment invariant plan requires PaymentInvariantHttpSpec")
        if spec.read_balance_minor is None or not callable(spec.read_balance_minor):
            raise ProofExecutionError("payment invariant proof requires a financial readback")
        if (
            isinstance(spec.expected_single_delta_minor, bool)
            or not isinstance(spec.expected_single_delta_minor, int)
            or spec.expected_single_delta_minor == 0
        ):
            raise ProofExecutionError("expected_single_delta_minor must be a non-zero integer")
        if abs(spec.expected_single_delta_minor) > 100_000_000:
            raise ProofExecutionError("expected_single_delta_minor exceeds the bounded fixture limit")

        before = spec.read_balance_minor()
        if isinstance(before, bool) or not isinstance(before, int):
            raise ProofExecutionError("financial readback must return integer minor units")

        first = self._request(
            "payment-control",
            spec.url,
            "POST",
            spec.headers,
            spec.body,
        )
        after_first = spec.read_balance_minor()
        if isinstance(after_first, bool) or not isinstance(after_first, int):
            raise ProofExecutionError("financial readback must return integer minor units")

        first_delta = after_first - before
        observations = [first.to_dict()]
        notes = [
            f"before_sha256={_value_digest(before)}",
            f"after_first_sha256={_value_digest(after_first)}",
            f"expected_delta_sha256={_value_digest(spec.expected_single_delta_minor)}",
        ]

        if first.status not in spec.accepted_statuses:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.INCONCLUSIVE,
                observations,
                notes=[
                    "legitimate payment control was not accepted; duplicate-effect conclusion would be ambiguous",
                    *notes,
                ],
            )
        if first_delta != spec.expected_single_delta_minor:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.INCONCLUSIVE,
                observations,
                notes=[
                    "first payment mutation did not match the operator-declared single-operation delta",
                    f"observed_first_delta_sha256={_value_digest(first_delta)}",
                    *notes,
                ],
            )

        replay = self._request(
            "payment-replay",
            spec.url,
            "POST",
            spec.headers,
            spec.body,
        )
        after_replay = spec.read_balance_minor()
        if isinstance(after_replay, bool) or not isinstance(after_replay, int):
            raise ProofExecutionError("financial readback must return integer minor units")
        observations.append(replay.to_dict())
        replay_delta = after_replay - after_first
        notes.extend([
            f"after_replay_sha256={_value_digest(after_replay)}",
            f"replay_delta_sha256={_value_digest(replay_delta)}",
        ])

        if after_replay == after_first:
            behavior = ProofBehavior.SECURE_BEHAVIOR
            notes.insert(0, "exact replay produced no additional financial effect")
        elif replay_delta == spec.expected_single_delta_minor:
            behavior = ProofBehavior.VULNERABLE_BEHAVIOR
            notes.insert(0, "exact replay applied the same charge/refund delta a second time")
        else:
            behavior = ProofBehavior.INCONCLUSIVE
            notes.insert(
                0,
                "replay changed financial state, but not by the declared single-operation delta",
            )

        return ProofExecutionResult(
            plan.finding_id,
            plan.proof_class,
            behavior,
            observations,
            notes=notes,
        )

    def _money_flow_invariant(self, plan: ProofPlan, spec: Any) -> ProofExecutionResult:
        if not isinstance(spec, MoneyFlowInvariantHttpSpec):
            raise ProofExecutionError("money flow invariant plan requires MoneyFlowInvariantHttpSpec")
        if spec.read_balances_minor is None or not callable(spec.read_balances_minor):
            raise ProofExecutionError("money flow invariant proof requires a financial readback")

        def normalize_vector(value: Mapping[str, int], label: str) -> dict[str, int]:
            if not isinstance(value, Mapping):
                raise ProofExecutionError(f"{label} must be a mapping of entity labels to integer minor units")
            normalized: dict[str, int] = {}
            for raw_key, raw_amount in value.items():
                key = str(raw_key).strip()
                if not key or len(key) > 80:
                    raise ProofExecutionError(f"{label} contains an invalid entity label")
                if isinstance(raw_amount, bool) or not isinstance(raw_amount, int):
                    raise ProofExecutionError(f"{label} values must be integer minor units")
                if abs(raw_amount) > 100_000_000_000:
                    raise ProofExecutionError(f"{label} contains an amount outside the bounded fixture limit")
                normalized[key] = raw_amount
            if not 2 <= len(normalized) <= 8:
                raise ProofExecutionError(f"{label} must declare between 2 and 8 financial entities")
            return normalized

        expected = normalize_vector(spec.expected_deltas_minor, "expected_deltas_minor")
        if not any(expected.values()):
            raise ProofExecutionError("expected_deltas_minor must include at least one non-zero movement")

        forbidden = tuple(
            normalize_vector(item, f"forbidden_delta_vectors[{index}]")
            for index, item in enumerate(spec.forbidden_delta_vectors)
        )
        for item in forbidden:
            if set(item) != set(expected):
                raise ProofExecutionError("forbidden delta vectors must use the same entity labels as expected_deltas_minor")
            if item == expected:
                raise ProofExecutionError("a forbidden delta vector cannot equal the expected delta vector")

        before = normalize_vector(spec.read_balances_minor(), "financial readback")
        if set(before) != set(expected):
            raise ProofExecutionError("financial readback labels must exactly match expected_deltas_minor")

        first = self._request(
            "money-flow-control",
            spec.url,
            "POST",
            spec.headers,
            spec.body,
        )
        after_first = normalize_vector(spec.read_balances_minor(), "financial readback")
        if set(after_first) != set(before):
            raise ProofExecutionError("financial readback entity labels changed during proof")

        observed_first = {
            key: after_first[key] - before[key]
            for key in sorted(before)
        }
        observations = [first.to_dict()]
        notes = [
            f"before_sha256={_value_digest(before)}",
            f"after_first_sha256={_value_digest(after_first)}",
            f"expected_vector_sha256={_value_digest(expected)}",
            f"observed_first_vector_sha256={_value_digest(observed_first)}",
        ]

        if first.status not in spec.accepted_statuses:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.INCONCLUSIVE,
                observations,
                notes=[
                    "legitimate money-flow control was not accepted; invariant conclusion would be ambiguous",
                    *notes,
                ],
            )

        if any(observed_first == item for item in forbidden):
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.VULNERABLE_BEHAVIOR,
                observations,
                notes=[
                    "first money-flow mutation matched an operator-declared forbidden delta vector",
                    *notes,
                ],
            )

        if observed_first != expected:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.INCONCLUSIVE,
                observations,
                notes=[
                    "first money-flow mutation matched neither the expected nor any declared forbidden delta vector",
                    *notes,
                ],
            )

        replay = self._request(
            "money-flow-replay",
            spec.url,
            "POST",
            spec.headers,
            spec.body,
        )
        after_replay = normalize_vector(spec.read_balances_minor(), "financial readback")
        if set(after_replay) != set(before):
            raise ProofExecutionError("financial readback entity labels changed during replay")

        replay_delta = {
            key: after_replay[key] - after_first[key]
            for key in sorted(before)
        }
        observations.append(replay.to_dict())
        notes.extend([
            f"after_replay_sha256={_value_digest(after_replay)}",
            f"replay_vector_sha256={_value_digest(replay_delta)}",
        ])

        zero_vector = {key: 0 for key in expected}
        if replay_delta == zero_vector:
            behavior = ProofBehavior.SECURE_BEHAVIOR
            notes.insert(0, "exact replay produced no additional cross-entity money movement")
        elif replay_delta == expected or any(replay_delta == item for item in forbidden):
            behavior = ProofBehavior.VULNERABLE_BEHAVIOR
            notes.insert(0, "exact replay produced a duplicate or explicitly forbidden money-flow vector")
        else:
            behavior = ProofBehavior.INCONCLUSIVE
            notes.insert(
                0,
                "replay changed financial state by a vector outside the declared secure and vulnerable outcomes",
            )

        return ProofExecutionResult(
            plan.finding_id,
            plan.proof_class,
            behavior,
            observations,
            notes=notes,
        )

    def _workflow_sequence(self, plan: ProofPlan, spec: Any) -> ProofExecutionResult:
        if not isinstance(spec, WorkflowSequenceHttpSpec):
            raise ProofExecutionError("workflow sequence plan requires WorkflowSequenceHttpSpec")
        if spec.read_state is None or not callable(spec.read_state):
            raise ProofExecutionError("workflow sequence proof requires a fixture state readback")
        if spec.reset_fixture is None or not callable(spec.reset_fixture):
            raise ProofExecutionError("workflow sequence proof requires a fixture reset hook")
        if spec.expected_intermediate_state == spec.expected_start_state:
            raise ProofExecutionError("intermediate state must differ from starting state")
        if (
            spec.expected_final_state == spec.expected_start_state
            or spec.expected_final_state == spec.expected_intermediate_state
        ):
            raise ProofExecutionError("final state must differ from start and intermediate states")
        if spec.expected_safe_bypass_state == spec.expected_final_state:
            raise ProofExecutionError("safe bypass state must differ from final state")

        before = spec.read_state()
        if before != spec.expected_start_state:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.INCONCLUSIVE,
                notes=[
                    "fixture did not begin in the declared workflow start state",
                    f"observed_start_sha256={_value_digest(before)}",
                    f"expected_start_sha256={_value_digest(spec.expected_start_state)}",
                ],
            )

        step_one = self._request(
            "workflow-control-step-one",
            spec.step_one_url,
            "POST",
            spec.headers,
            spec.step_one_body,
        )
        after_step_one = spec.read_state()
        control_observations = [step_one.to_dict()]
        if step_one.status not in spec.accepted_statuses or after_step_one != spec.expected_intermediate_state:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.INCONCLUSIVE,
                control_observations,
                notes=[
                    "ordered control step one did not establish the declared intermediate state",
                    f"after_step_one_sha256={_value_digest(after_step_one)}",
                    f"expected_intermediate_sha256={_value_digest(spec.expected_intermediate_state)}",
                ],
            )

        step_two = self._request(
            "workflow-control-step-two",
            spec.step_two_url,
            "POST",
            spec.headers,
            spec.step_two_body,
        )
        after_step_two = spec.read_state()
        control_observations.append(step_two.to_dict())
        if step_two.status not in spec.accepted_statuses or after_step_two != spec.expected_final_state:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.INCONCLUSIVE,
                control_observations,
                notes=[
                    "ordered control step two did not establish the declared final state",
                    f"after_step_two_sha256={_value_digest(after_step_two)}",
                    f"expected_final_sha256={_value_digest(spec.expected_final_state)}",
                ],
            )

        try:
            reset_result = spec.reset_fixture()
        except Exception as exc:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.INCONCLUSIVE,
                control_observations,
                notes=[f"fixture reset hook failed: {type(exc).__name__}"],
            )
        if reset_result is False:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.INCONCLUSIVE,
                control_observations,
                notes=["fixture reset hook reported failure"],
            )

        after_reset = spec.read_state()
        if after_reset != spec.expected_start_state:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.INCONCLUSIVE,
                control_observations,
                notes=[
                    "fixture reset did not restore the declared starting state",
                    f"after_reset_sha256={_value_digest(after_reset)}",
                    f"expected_start_sha256={_value_digest(spec.expected_start_state)}",
                ],
            )

        bypass = self._request(
            "workflow-bypass-step-two",
            spec.step_two_url,
            "POST",
            spec.headers,
            spec.step_two_body,
        )
        after_bypass = spec.read_state()
        observations = [*control_observations, bypass.to_dict()]
        notes = [
            f"start_sha256={_value_digest(before)}",
            f"intermediate_sha256={_value_digest(after_step_one)}",
            f"final_sha256={_value_digest(after_step_two)}",
            f"after_reset_sha256={_value_digest(after_reset)}",
            f"after_bypass_sha256={_value_digest(after_bypass)}",
            f"safe_bypass_sha256={_value_digest(spec.expected_safe_bypass_state)}",
        ]

        if after_bypass == spec.expected_final_state:
            behavior = ProofBehavior.VULNERABLE_BEHAVIOR
            notes.insert(0, "direct step two bypassed the declared prerequisite and reached the final state")
        elif (
            after_bypass == spec.expected_safe_bypass_state
            and (
                bypass.status in spec.denial_statuses
                or bypass.status in spec.accepted_statuses
            )
        ):
            behavior = ProofBehavior.SECURE_BEHAVIOR
            notes.insert(0, "direct step two did not bypass the declared prerequisite")
        else:
            behavior = ProofBehavior.INCONCLUSIVE
            notes.insert(
                0,
                "bypass attempt produced a state outside the declared safe and vulnerable outcomes",
            )

        return ProofExecutionResult(
            plan.finding_id,
            plan.proof_class,
            behavior,
            observations,
            notes=notes,
        )

    def _xss(self, plan: ProofPlan, spec: Any) -> ProofExecutionResult:
        if not isinstance(spec, XssBrowserSpec):
            raise ProofExecutionError("XSS plan requires XssBrowserSpec")
        if "{payload}" not in spec.url_template:
            raise ProofExecutionError("XSS url_template must contain {payload}")
        if not spec.injection_selector.strip():
            raise ProofExecutionError("XSS proof requires an injection_selector control")
        if not 1_000 <= spec.timeout_ms <= 30_000:
            raise ProofExecutionError("XSS timeout_ms must be between 1000 and 30000")
        if spec.marker_name != "__SECHELIX_XSS_MARKER" or spec.marker_value != "SECHELIX_XSS_MARKER_1":
            raise ProofExecutionError("XSS proof marker is fixed by SecHelix and cannot be caller-defined")
        if self.browser_factory is None:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.BLOCKED,
                blocker="XSS execution requires an explicit browser backend",
            )

        payload = (
            '"><script>window.'
            + spec.marker_name
            + "="
            + json.dumps(spec.marker_value)
            + "</script>"
        )
        url = spec.url_template.format(payload=urllib.parse.quote(payload, safe=""))
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ProofExecutionError("XSS proof URL must be absolute HTTP(S)")
        if parsed.hostname not in {"127.0.0.1", "::1"}:
            raise ProofExecutionError("XSS LOCAL proof requires literal loopback target")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.policy.require(parsed.hostname, port, protocol=parsed.scheme)

        from .pentest.browser import BrowserUnavailable
        from .pentest.gateway import PolicyToolGateway
        from .pentest.request_policy import InteractionPolicy
        from .pentest.scope import ScopeEndpoint, TargetScope

        scope = TargetScope(
            primary_url=url,
            mode=ExecutionMode.LOCAL,
            endpoints=(
                ScopeEndpoint(
                    host=parsed.hostname,
                    schemes=(parsed.scheme,),
                    ports=(port,),
                ),
            ),
        )
        gateway = PolicyToolGateway(scope=scope)

        try:
            with self.browser_factory(
                scope,
                interaction_policy=InteractionPolicy(),
                gateway=gateway,
            ) as browser:
                observation = browser.navigate(url, timeout_ms=spec.timeout_ms)
                if observation.challenge.value != "NONE":
                    return ProofExecutionResult(
                        plan.finding_id,
                        plan.proof_class,
                        ProofBehavior.INCONCLUSIVE,
                        [{
                            "label": "browser-navigation",
                            "status": observation.status,
                            "url": observation.url,
                            "challenge": observation.challenge.value,
                            "blocked_requests": observation.blocked_requests,
                        }],
                        request_count=1,
                        notes=["browser challenge prevented a deterministic XSS conclusion"],
                    )
                executed = browser.window_marker_matches(spec.marker_name, spec.marker_value)
                rendered_text = browser.text(spec.injection_selector, timeout_ms=spec.timeout_ms)
        except BrowserUnavailable as exc:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.BLOCKED,
                blocker=str(exc),
            )

        text_digest = (
            hashlib.sha256(rendered_text.encode("utf-8")).hexdigest()
            if rendered_text is not None
            else ""
        )
        marker_present_as_text = bool(rendered_text and spec.marker_value in rendered_text)
        observations = [
            {
                "label": "browser-navigation",
                "status": observation.status,
                "url": observation.url,
                "challenge": observation.challenge.value,
                "blocked_requests": observation.blocked_requests,
            },
            {
                "label": "xss-marker",
                "executed": executed,
                "inert_text_observed": marker_present_as_text,
                "rendered_text_sha256": text_digest,
            },
        ]
        if executed:
            behavior = ProofBehavior.VULNERABLE_BEHAVIOR
            notes = ["fixed benign browser marker executed in the LOCAL fixture"]
        elif marker_present_as_text:
            behavior = ProofBehavior.SECURE_BEHAVIOR
            notes = ["marker reached the declared sink only as inert text"]
        else:
            behavior = ProofBehavior.INCONCLUSIVE
            notes = [
                "marker did not execute, but the declared sink did not expose the marker as inert text either"
            ]
        return ProofExecutionResult(
            plan.finding_id,
            plan.proof_class,
            behavior,
            observations,
            request_count=1,
            notes=notes,
        )

    def _ssrf(self, plan: ProofPlan, spec: Any) -> ProofExecutionResult:
        if not isinstance(spec, SsrfHttpSpec):
            raise ProofExecutionError("SSRF plan requires SsrfHttpSpec")
        if "{callback}" not in spec.submit_url_template:
            raise ProofExecutionError("SSRF submit_url_template must contain {callback}")
        if not 0.1 <= spec.callback_timeout_seconds <= 5:
            raise ProofExecutionError("callback timeout must be between 0.1 and 5 seconds")

        event = threading.Event()
        handler = type("SecHelixCallbackHandler", (_CallbackHandler,), {"event": event})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            callback = f"http://127.0.0.1:{port}/sechelix-proof"
            encoded = urllib.parse.quote(callback, safe="")
            submit_url = spec.submit_url_template.format(callback=encoded)
            submitted = self._request("ssrf-submit", submit_url)
            observed = event.wait(spec.callback_timeout_seconds)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)
        behavior = ProofBehavior.VULNERABLE_BEHAVIOR if observed else ProofBehavior.SECURE_BEHAVIOR
        notes = [
            "loopback callback observed" if observed else "loopback callback not observed",
            "callback was local; no public OOB service was used",
        ]
        return ProofExecutionResult(
            plan.finding_id,
            plan.proof_class,
            behavior,
            [submitted.to_dict(), {"label": "local-callback", "observed": observed, "port": port}],
            notes=notes,
        )

    # -- transport ----------------------------------------------------------

    def _request(
        self,
        label: str,
        url: str,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        body: bytes = b"",
        *,
        capture_body: bool = False,
    ) -> HttpObservation:
        if self._requests >= self.max_requests:
            raise ProofExecutionError("bounded proof request limit exhausted")
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ProofExecutionError(f"proof URL must be absolute HTTP(S): {url!r}")
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.username is not None or parsed.password is not None:
            raise ProofExecutionError("proof URL must not contain user-info credentials")

        # LOCAL proof execution has no reason to cross a DNS trust boundary.
        # Select a constant connect host so DNS rebinding, ambient proxies and
        # redirect-following cannot turn a bounded proof into arbitrary egress.
        if host == "127.0.0.1":
            connect_host = "127.0.0.1"
        elif host == "::1":
            connect_host = "::1"
        else:
            raise ProofExecutionError(
                f"LOCAL proof target must use literal loopback 127.0.0.1 or ::1, got {host!r}"
            )
        self.policy.require(connect_host, port, protocol=parsed.scheme)
        self._requests += 1

        request_target = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        connection = connection_type(connect_host, port, timeout=self.timeout_seconds)
        started = time.monotonic()
        status: int | None = None
        response_body = b""
        error = ""
        try:
            connection.request(
                method.upper(),
                request_target,
                body=body if method.upper() not in ("GET", "HEAD") else None,
                headers=dict(headers or {}),
            )
            response = connection.getresponse()
            status = int(response.status)
            response_body = response.read(262_144)
        except (http.client.HTTPException, TimeoutError, OSError) as exc:
            error = type(exc).__name__
        finally:
            connection.close()
        elapsed = int((time.monotonic() - started) * 1000)
        observation = HttpObservation(
            label=label,
            status=status,
            body_sha256=hashlib.sha256(response_body).hexdigest(),
            body_length=len(response_body),
            elapsed_ms=elapsed,
            error=error,
        )
        # Body bytes are intentionally non-serializable private state, available
        # only to the traversal comparison and never returned in artifacts.
        if capture_body:
            object.__setattr__(observation, "_body", response_body)
        return observation


def _value_digest(value: Any) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    except (TypeError, ValueError):
        encoded = repr(value).encode("utf-8", errors="replace")
    return hashlib.sha256(encoded).hexdigest()
