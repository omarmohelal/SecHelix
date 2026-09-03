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
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import StrEnum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping

from .proof import PlanState, ProofClass, ProofPlan
from .sandbox import ExecutionMode, NetworkPolicy, is_loopback


class ProofExecutionError(RuntimeError):
    """The execution spec is unsafe, malformed, or inconsistent with the plan."""


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


@dataclass(frozen=True, slots=True)
class SsrfHttpSpec:
    """Submit a loopback callback URL through one bounded target request.

    ``submit_url_template`` must contain ``{callback}``; the callback value is
    percent-encoded before insertion.  This supports owned local fixtures
    without inventing a universal SSRF parameter format.
    """

    submit_url_template: str
    callback_timeout_seconds: float = 1.5


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return redirect responses to the proof engine instead of following them.

    The original URL has passed NetworkPolicy, but a redirect target has not.
    Automatic redirect following would therefore turn a bounded LOCAL request
    into an authority bypass. Callers may record the 3xx response; they must
    build a new explicitly-authorized request to follow it.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


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
        }
        if plan.proof_class is ProofClass.XSS_EXECUTION:
            return ProofExecutionResult(
                plan.finding_id,
                plan.proof_class,
                ProofBehavior.BLOCKED,
                blocker=(
                    "XSS execution requires an explicit browser backend; the stdlib runner "
                    "does not silently install or drive a browser"
                ),
            )
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
        valid = self._request(
            "valid-signature-control",
            spec.url,
            "POST",
            {spec.signature_header: spec.valid_signature},
            spec.body,
        )
        unsigned = self._request("unsigned", spec.url, "POST", {}, spec.body)
        invalid = self._request(
            "invalid-signature",
            spec.url,
            "POST",
            {spec.signature_header: spec.invalid_signature},
            spec.body,
        )
        replay = self._request(
            "valid-signature-replay",
            spec.url,
            "POST",
            {spec.signature_header: spec.valid_signature},
            spec.body,
        )
        observations = [item.to_dict() for item in (valid, unsigned, invalid, replay)]
        bad_accept = unsigned.status in spec.accepted_statuses or invalid.status in spec.accepted_statuses
        replay_accept = replay.status in spec.accepted_statuses and valid.status in spec.accepted_statuses
        if valid.status not in spec.accepted_statuses:
            behavior = ProofBehavior.INCONCLUSIVE
            notes = ["valid signed control was not accepted"]
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
        if self.policy.mode is ExecutionMode.LOCAL and not is_loopback(host):
            raise ProofExecutionError(f"LOCAL proof target must be loopback, got {host!r}")
        self.policy.require(host, port, protocol=parsed.scheme)
        self._requests += 1

        request = urllib.request.Request(
            url,
            data=body if method.upper() not in ("GET", "HEAD") else None,
            headers=dict(headers or {}),
            method=method.upper(),
        )
        started = time.monotonic()
        status: int | None = None
        response_body = b""
        error = ""
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
            with opener.open(request, timeout=self.timeout_seconds) as response:
                status = int(response.status)
                response_body = response.read(262_144)
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            response_body = exc.read(262_144)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            error = type(exc).__name__
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
