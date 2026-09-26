import json
import threading
from types import SimpleNamespace
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sechelix_runner.proof import ProofClass, build_plan
from sechelix_runner.proof_exec import (
    CsrfHttpSpec,
    IdorHttpSpec,
    LocalProofExecutor,
    MoneyFlowInvariantHttpSpec,
    PaymentInvariantHttpSpec,
    ProofBehavior,
    ProofExecutionError,
    RaceHttpSpec,
    SessionRevocationHttpSpec,
    SsrfHttpSpec,
    StateTransitionHttpSpec,
    TraversalHttpSpec,
    WebhookHttpSpec,
    WorkflowSequenceHttpSpec,
    XssBrowserSpec,
)
from sechelix_runner.sandbox import ExecutionMode, NetworkPolicy


class _FixtureHandler(BaseHTTPRequestHandler):
    redeem_count = 0
    csrf_vulnerable_count = 0
    csrf_secure_count = 0
    webhook_vulnerable_count = 0
    webhook_idempotent_count = 0
    webhook_ambiguous_count = 0
    session_secure_active = True
    session_vulnerable_active = True
    workflow_secure_state = "cancelled"
    workflow_vulnerable_state = "cancelled"
    workflow_ambiguous_state = "cancelled"
    payment_vulnerable_balance = 10_000
    payment_idempotent_balance = 10_000
    payment_wrong_delta_balance = 10_000
    refund_idempotent_balance = 5_000
    workflow_sequence_vulnerable_state = "created"
    workflow_sequence_secure_state = "created"
    workflow_sequence_broken_state = "created"
    money_flow_duplicate = {"buyer": 10_000, "seller": 2_000, "platform": 500}
    money_flow_idempotent = {"buyer": 10_000, "seller": 2_000, "platform": 500}
    money_flow_misroute = {"buyer": 10_000, "seller": 2_000, "platform": 500}
    sentinel = b"SECHELIX_SENTINEL_93B1"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/orders/1":
            # Intentionally vulnerable demo: both identities get the same object.
            body = json.dumps({"id": 1, "owner": "A", "amount": 10}).encode()
            self._send(200, body)
            return
        if parsed.path == "/files":
            requested = urllib.parse.parse_qs(parsed.query).get("path", [""])[0]
            if "sentinel" in requested:
                self._send(200, self.sentinel)
            else:
                self._send(200, b"safe file")
            return
        if parsed.path == "/fetch":
            callback = urllib.parse.parse_qs(parsed.query).get("url", [""])[0]
            try:
                with urllib.request.urlopen(callback, timeout=1) as response:
                    response.read()
                self._send(200, b"fetched")
            except Exception:
                self._send(502, b"failed")
            return
        if parsed.path == "/session-secure":
            if self.headers.get("Cookie") != "session=fixture-auth":
                self._send(401, b"no session")
                return
            if not type(self).session_secure_active:
                self._send(401, b"revoked")
                return
            self._send(200, b"protected")
            return
        if parsed.path == "/session-vulnerable":
            if self.headers.get("Cookie") != "session=fixture-auth":
                self._send(401, b"no session")
                return
            # Intentionally vulnerable local fixture: the resolved principal was
            # cached before revocation and the protected read never re-checks
            # the authoritative session record.
            self._send(200, b"protected")
            return
        self._send(404, b"missing")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        if self.path == "/redeem":
            type(self).redeem_count += 1
            self._send(200, b"ok")
            return
        if self.path == "/webhook":
            signature = self.headers.get("X-Demo-Signature")
            self._send(200 if signature == "valid" else 401, b"ok" if signature == "valid" else b"no")
            return
        if self.path == "/webhook-state-vulnerable":
            signature = self.headers.get("X-Demo-Signature")
            if signature != "fixture-valid-secret":
                self._send(401, b"no")
                return
            type(self).webhook_vulnerable_count += 1
            self._send(200, b"applied")
            return
        if self.path == "/webhook-state-idempotent":
            signature = self.headers.get("X-Demo-Signature")
            if signature != "fixture-valid-secret":
                self._send(401, b"no")
                return
            if type(self).webhook_idempotent_count == 0:
                type(self).webhook_idempotent_count = 1
            self._send(200, b"accepted")
            return
        if self.path == "/webhook-state-ambiguous":
            signature = self.headers.get("X-Demo-Signature")
            if signature == "fixture-valid-secret" and type(self).webhook_ambiguous_count == 0:
                type(self).webhook_ambiguous_count = 1
            # Deliberately ambiguous fixture: bad signatures receive 2xx but
            # do not change the measured state. SecHelix must not call this
            # secure merely because the side-effect readback is unchanged.
            self._send(200, b"accepted")
            return
        if self.path == "/state-transition-vulnerable":
            type(self).workflow_vulnerable_state = "completed"
            self._send(200, b"transitioned")
            return
        if self.path == "/state-transition-secure":
            self._send(409, b"forbidden transition")
            return
        if self.path == "/state-transition-ambiguous":
            type(self).workflow_ambiguous_state = "manual_review"
            self._send(202, b"queued")
            return
        if self.path == "/payment-vulnerable":
            type(self).payment_vulnerable_balance -= 250
            self._send(200, b"charged")
            return
        if self.path == "/payment-idempotent":
            key = self.headers.get("Idempotency-Key")
            if key == "fixture-payment-1" and type(self).payment_idempotent_balance == 10_000:
                type(self).payment_idempotent_balance -= 250
            self._send(200, b"accepted")
            return
        if self.path == "/payment-wrong-delta":
            type(self).payment_wrong_delta_balance -= 100
            self._send(200, b"charged")
            return
        if self.path == "/refund-idempotent":
            key = self.headers.get("Idempotency-Key")
            if key == "fixture-refund-1" and type(self).refund_idempotent_balance == 5_000:
                type(self).refund_idempotent_balance += 300
            self._send(200, b"accepted")
            return
        if self.path == "/workflow-sequence-vulnerable-step1":
            if type(self).workflow_sequence_vulnerable_state != "created":
                self._send(409, b"wrong start")
                return
            type(self).workflow_sequence_vulnerable_state = "approved"
            self._send(200, b"approved")
            return
        if self.path == "/workflow-sequence-vulnerable-step2":
            # Intentionally vulnerable: step two does not require "approved".
            type(self).workflow_sequence_vulnerable_state = "completed"
            self._send(200, b"completed")
            return
        if self.path == "/workflow-sequence-secure-step1":
            if type(self).workflow_sequence_secure_state != "created":
                self._send(409, b"wrong start")
                return
            type(self).workflow_sequence_secure_state = "approved"
            self._send(200, b"approved")
            return
        if self.path == "/workflow-sequence-secure-step2":
            if type(self).workflow_sequence_secure_state != "approved":
                self._send(409, b"missing prerequisite")
                return
            type(self).workflow_sequence_secure_state = "completed"
            self._send(200, b"completed")
            return
        if self.path == "/workflow-sequence-broken-step1":
            # Deliberately broken control: never reaches the declared intermediate state.
            self._send(202, b"queued")
            return
        if self.path == "/workflow-sequence-broken-step2":
            type(self).workflow_sequence_broken_state = "completed"
            self._send(200, b"completed")
            return
        if self.path == "/money-flow-duplicate":
            state = type(self).money_flow_duplicate
            state["buyer"] -= 1000
            state["seller"] += 900
            state["platform"] += 100
            self._send(200, b"settled")
            return
        if self.path == "/money-flow-idempotent":
            state = type(self).money_flow_idempotent
            if state["buyer"] == 10_000:
                state["buyer"] -= 1000
                state["seller"] += 900
                state["platform"] += 100
            self._send(200, b"accepted")
            return
        if self.path == "/money-flow-misroute":
            state = type(self).money_flow_misroute
            state["buyer"] -= 1000
            state["seller"] += 1000
            self._send(200, b"misrouted")
            return
        if self.path == "/csrf-vulnerable":
            if self.headers.get("Cookie") != "session=fixture-auth":
                self._send(401, b"no session")
                return
            type(self).csrf_vulnerable_count += 1
            self._send(200, b"changed")
            return
        if self.path == "/csrf-secure":
            if self.headers.get("Cookie") != "session=fixture-auth":
                self._send(401, b"no session")
                return
            expected_origin = f"http://127.0.0.1:{self.server.server_port}"
            if self.headers.get("Origin") != expected_origin:
                self._send(403, b"csrf denied")
                return
            type(self).csrf_secure_count += 1
            self._send(200, b"changed")
            return
        self._send(404, b"missing")

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args) -> None:
        return


class _FakeXssBrowser:
    def __init__(self, scope, *, interaction_policy, gateway, execute_marker=False, inert_text=False):
        self.scope = scope
        self.interaction_policy = interaction_policy
        self.gateway = gateway
        self.execute_marker = execute_marker
        self.inert_text = inert_text

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def navigate(self, url, *, timeout_ms):
        self.gateway.authorize(
            __import__("sechelix_runner.pentest.gateway", fromlist=["ToolOperation"]).ToolOperation(
                tool="browser",
                target=url,
                network=True,
                risk="LOW",
                evidence_output="browser-network-events",
                purpose="authorized browser request",
                metadata={"method": "GET"},
            )
        )
        return SimpleNamespace(
            status=200,
            url=url.split("?", 1)[0] + "?q=[REDACTED]",
            challenge=SimpleNamespace(value="NONE"),
            blocked_requests=0,
        )

    def window_marker_matches(self, name, expected):
        return self.execute_marker

    def text(self, selector, *, timeout_ms):
        return "SECHELIX_XSS_MARKER_1" if self.inert_text else "no marker"


class LocalProofExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        cls.port = int(cls.server.server_address[1])
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self) -> None:
        _FixtureHandler.redeem_count = 0
        _FixtureHandler.csrf_vulnerable_count = 0
        _FixtureHandler.csrf_secure_count = 0
        _FixtureHandler.webhook_vulnerable_count = 0
        _FixtureHandler.webhook_idempotent_count = 0
        _FixtureHandler.webhook_ambiguous_count = 0
        _FixtureHandler.session_secure_active = True
        _FixtureHandler.session_vulnerable_active = True
        _FixtureHandler.workflow_secure_state = "cancelled"
        _FixtureHandler.workflow_vulnerable_state = "cancelled"
        _FixtureHandler.workflow_ambiguous_state = "cancelled"
        _FixtureHandler.payment_vulnerable_balance = 10_000
        _FixtureHandler.payment_idempotent_balance = 10_000
        _FixtureHandler.payment_wrong_delta_balance = 10_000
        _FixtureHandler.refund_idempotent_balance = 5_000
        _FixtureHandler.workflow_sequence_vulnerable_state = "created"
        _FixtureHandler.workflow_sequence_secure_state = "created"
        _FixtureHandler.workflow_sequence_broken_state = "created"
        _FixtureHandler.money_flow_duplicate = {"buyer": 10_000, "seller": 2_000, "platform": 500}
        _FixtureHandler.money_flow_idempotent = {"buyer": 10_000, "seller": 2_000, "platform": 500}
        _FixtureHandler.money_flow_misroute = {"buyer": 10_000, "seller": 2_000, "platform": 500}
        self.policy = NetworkPolicy(ExecutionMode.LOCAL)
        self.policy.grant(
            "127.0.0.1",
            self.port,
            protocol="http",
            purpose="owned SecHelix proof fixture",
            scope_id="SCOPE-DEMO",
        )
        self.executor = LocalProofExecutor(self.policy, timeout_seconds=2, max_requests=8)
        self.base = f"http://127.0.0.1:{self.port}"

    def test_idor_executes_two_identity_control_and_records_vulnerable_behavior(self) -> None:
        plan = build_plan(
            ProofClass.AUTHORIZATION_IDOR,
            "F-IDOR",
            available_authority={"identity_a_credentials", "identity_b_credentials"},
        )
        result = self.executor.execute(
            plan,
            IdorHttpSpec(
                url_template=self.base + "/orders/{object_id}",
                object_id="1",
                identity_a_headers={"Authorization": "Bearer SECRET-A"},
                identity_b_headers={"Authorization": "Bearer SECRET-B"},
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.VULNERABLE_BEHAVIOR)
        self.assertEqual(result.request_count, 2)
        rendered = json.dumps(result.to_dict())
        self.assertNotIn("SECRET-A", rendered)
        self.assertNotIn("SECRET-B", rendered)
        self.assertFalse(result.to_dict()["promotes_finding"])

    def test_path_traversal_detects_only_fixture_sentinel_without_returning_body(self) -> None:
        plan = build_plan(
            ProofClass.PATH_TRAVERSAL,
            "F-PATH",
            available_authority={"fixture_filesystem"},
        )
        result = self.executor.execute(
            plan,
            TraversalHttpSpec(
                url_template=self.base + "/files?path={path}",
                safe_path="public/readme.txt",
                traversal_path="../sentinel.txt",
                sentinel_marker=_FixtureHandler.sentinel,
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.VULNERABLE_BEHAVIOR)
        self.assertNotIn(_FixtureHandler.sentinel.decode(), json.dumps(result.to_dict()))
        self.assertIn("sentinel_sha256=", result.notes[0])

    def test_bounded_race_uses_state_readback_not_http_success_count(self) -> None:
        plan = build_plan(
            ProofClass.RACE_IDEMPOTENCY,
            "F-RACE",
            available_authority={"fixture_write_access"},
        )
        result = self.executor.execute(
            plan,
            RaceHttpSpec(
                url=self.base + "/redeem",
                concurrency=2,
                read_state=lambda: _FixtureHandler.redeem_count,
                expected_single_state=1,
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.VULNERABLE_BEHAVIOR)
        self.assertEqual(result.request_count, 2)
        self.assertEqual(_FixtureHandler.redeem_count, 2)

    def test_webhook_does_not_call_replay_vulnerable_from_status_alone(self) -> None:
        plan = build_plan(
            ProofClass.WEBHOOK_SIGNATURE,
            "F-WEBHOOK",
            available_authority={"fixture_endpoint_access"},
        )
        result = self.executor.execute(
            plan,
            WebhookHttpSpec(
                url=self.base + "/webhook",
                body=b'{"event":"demo"}',
                signature_header="X-Demo-Signature",
                valid_signature="valid",
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.INCONCLUSIVE)
        self.assertEqual(result.request_count, 4)
        self.assertNotIn("valid_signature", json.dumps(result.to_dict()))

    def test_webhook_state_readback_proves_duplicate_replay_effect(self) -> None:
        plan = build_plan(
            ProofClass.WEBHOOK_SIGNATURE,
            "F-WEBHOOK-STATE-VULN",
            available_authority={"fixture_endpoint_access"},
        )
        result = self.executor.execute(
            plan,
            WebhookHttpSpec(
                url=self.base + "/webhook-state-vulnerable",
                body=b'{"event":"demo"}',
                signature_header="X-Demo-Signature",
                valid_signature="fixture-valid-secret",
                read_state=lambda: _FixtureHandler.webhook_vulnerable_count,
                expected_single_state=1,
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.VULNERABLE_BEHAVIOR)
        self.assertEqual(result.request_count, 4)
        self.assertEqual(_FixtureHandler.webhook_vulnerable_count, 2)
        rendered = json.dumps(result.to_dict())
        self.assertNotIn("fixture-valid-secret", rendered)
        self.assertIn("after_replay_sha256=", " ".join(result.notes))

    def test_webhook_state_readback_proves_idempotent_replay(self) -> None:
        plan = build_plan(
            ProofClass.WEBHOOK_SIGNATURE,
            "F-WEBHOOK-STATE-SAFE",
            available_authority={"fixture_endpoint_access"},
        )
        result = self.executor.execute(
            plan,
            WebhookHttpSpec(
                url=self.base + "/webhook-state-idempotent",
                body=b'{"event":"demo"}',
                signature_header="X-Demo-Signature",
                valid_signature="fixture-valid-secret",
                read_state=lambda: _FixtureHandler.webhook_idempotent_count,
                expected_single_state=1,
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.SECURE_BEHAVIOR)
        self.assertEqual(result.request_count, 4)
        self.assertEqual(_FixtureHandler.webhook_idempotent_count, 1)
        self.assertIn("no additional side effect", " ".join(result.notes))

    def test_webhook_accepted_bad_signature_without_effect_stays_inconclusive(self) -> None:
        plan = build_plan(
            ProofClass.WEBHOOK_SIGNATURE,
            "F-WEBHOOK-STATE-AMBIGUOUS",
            available_authority={"fixture_endpoint_access"},
        )
        result = self.executor.execute(
            plan,
            WebhookHttpSpec(
                url=self.base + "/webhook-state-ambiguous",
                body=b'{"event":"demo"}',
                signature_header="X-Demo-Signature",
                valid_signature="fixture-valid-secret",
                read_state=lambda: _FixtureHandler.webhook_ambiguous_count,
                expected_single_state=1,
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.INCONCLUSIVE)
        self.assertEqual(_FixtureHandler.webhook_ambiguous_count, 1)
        self.assertIn("signature enforcement remains ambiguous", " ".join(result.notes))

    def test_csrf_local_fixture_distinguishes_foreign_origin_acceptance(self) -> None:
        plan = build_plan(
            ProofClass.CSRF_REQUEST,
            "F-CSRF",
            available_authority={"fixture_authenticated_session", "fixture_write_access"},
        )
        result = self.executor.execute(
            plan,
            CsrfHttpSpec(
                url=self.base + "/csrf-vulnerable",
                authenticated_headers={"Cookie": "session=fixture-auth"},
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.VULNERABLE_BEHAVIOR)
        self.assertEqual(result.request_count, 2)
        self.assertEqual(_FixtureHandler.csrf_vulnerable_count, 2)
        rendered = json.dumps(result.to_dict())
        self.assertNotIn("fixture-auth", rendered)
        self.assertNotIn("Cookie", rendered)

    def test_csrf_local_fixture_recognizes_origin_enforcement(self) -> None:
        plan = build_plan(
            ProofClass.CSRF_REQUEST,
            "F-CSRF-SAFE",
            available_authority={"fixture_authenticated_session", "fixture_write_access"},
        )
        result = self.executor.execute(
            plan,
            CsrfHttpSpec(
                url=self.base + "/csrf-secure",
                authenticated_headers={"Cookie": "session=fixture-auth"},
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.SECURE_BEHAVIOR)
        self.assertEqual(result.request_count, 2)
        self.assertEqual(_FixtureHandler.csrf_secure_count, 1)

    def test_csrf_requires_explicit_fixture_session_and_local_authority(self) -> None:
        plan = build_plan(
            ProofClass.CSRF_REQUEST,
            "F-CSRF-NOAUTH",
            available_authority={"fixture_authenticated_session", "fixture_write_access"},
        )
        with self.assertRaises(ProofExecutionError):
            self.executor.execute(
                plan,
                CsrfHttpSpec(url=self.base + "/csrf-vulnerable"),
            )

        blocked = build_plan(
            ProofClass.CSRF_REQUEST,
            "F-CSRF-BLOCKED",
            available_authority={"fixture_write_access"},
        )
        result = self.executor.execute(
            blocked,
            CsrfHttpSpec(
                url=self.base + "/csrf-vulnerable",
                authenticated_headers={"Cookie": "session=fixture-auth"},
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.BLOCKED)
        self.assertIn("fixture_authenticated_session", result.blocker)

    def test_session_revocation_rejects_same_session_after_revoke(self) -> None:
        plan = build_plan(
            ProofClass.SESSION_REVOCATION,
            "F-SESSION-REVOKE-SAFE",
            available_authority={"fixture_authenticated_session", "fixture_session_revocation"},
        )
        result = self.executor.execute(
            plan,
            SessionRevocationHttpSpec(
                url=self.base + "/session-secure",
                authenticated_headers={"Cookie": "session=fixture-auth"},
                revoke_session=lambda: setattr(_FixtureHandler, "session_secure_active", False),
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.SECURE_BEHAVIOR)
        self.assertEqual(result.request_count, 2)
        rendered = json.dumps(result.to_dict())
        self.assertNotIn("fixture-auth", rendered)
        self.assertNotIn("Cookie", rendered)

    def test_session_revocation_detects_stale_cached_authority(self) -> None:
        plan = build_plan(
            ProofClass.SESSION_REVOCATION,
            "F-SESSION-REVOKE-VULN",
            available_authority={"fixture_authenticated_session", "fixture_session_revocation"},
        )
        result = self.executor.execute(
            plan,
            SessionRevocationHttpSpec(
                url=self.base + "/session-vulnerable",
                authenticated_headers={"Cookie": "session=fixture-auth"},
                revoke_session=lambda: setattr(_FixtureHandler, "session_vulnerable_active", False),
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.VULNERABLE_BEHAVIOR)
        self.assertEqual(result.request_count, 2)
        self.assertIn("revoked fixture session", " ".join(result.notes))

    def test_session_revocation_requires_fresh_session_and_revoke_authority(self) -> None:
        plan = build_plan(
            ProofClass.SESSION_REVOCATION,
            "F-SESSION-REVOKE-NOSESSION",
            available_authority={"fixture_authenticated_session", "fixture_session_revocation"},
        )
        with self.assertRaises(ProofExecutionError):
            self.executor.execute(
                plan,
                SessionRevocationHttpSpec(
                    url=self.base + "/session-secure",
                    revoke_session=lambda: None,
                ),
            )

        blocked = build_plan(
            ProofClass.SESSION_REVOCATION,
            "F-SESSION-REVOKE-BLOCKED",
            available_authority={"fixture_authenticated_session"},
        )
        result = self.executor.execute(
            blocked,
            SessionRevocationHttpSpec(
                url=self.base + "/session-secure",
                authenticated_headers={"Cookie": "session=fixture-auth"},
                revoke_session=lambda: None,
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.BLOCKED)
        self.assertIn("fixture_session_revocation", result.blocker)

    def test_state_transition_detects_forbidden_business_state(self) -> None:
        plan = build_plan(
            ProofClass.STATE_TRANSITION,
            "F-STATE-VULN",
            available_authority={"fixture_write_access", "fixture_state_readback"},
        )
        result = self.executor.execute(
            plan,
            StateTransitionHttpSpec(
                url=self.base + "/state-transition-vulnerable",
                body=b'{"status":"completed"}',
                headers={"Authorization": "Bearer workflow-secret"},
                read_state=lambda: _FixtureHandler.workflow_vulnerable_state,
                expected_start_state="cancelled",
                expected_secure_state="cancelled",
                forbidden_state="completed",
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.VULNERABLE_BEHAVIOR)
        self.assertEqual(result.request_count, 1)
        self.assertEqual(_FixtureHandler.workflow_vulnerable_state, "completed")
        rendered = json.dumps(result.to_dict())
        self.assertNotIn("workflow-secret", rendered)
        self.assertNotIn('"completed"', rendered)
        self.assertIn("forbidden_state_sha256=", " ".join(result.notes))

    def test_state_transition_accepts_explicit_rejection_as_secure_behavior(self) -> None:
        plan = build_plan(
            ProofClass.STATE_TRANSITION,
            "F-STATE-SAFE",
            available_authority={"fixture_write_access", "fixture_state_readback"},
        )
        result = self.executor.execute(
            plan,
            StateTransitionHttpSpec(
                url=self.base + "/state-transition-secure",
                body=b'{"status":"completed"}',
                read_state=lambda: _FixtureHandler.workflow_secure_state,
                expected_start_state="cancelled",
                expected_secure_state="cancelled",
                forbidden_state="completed",
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.SECURE_BEHAVIOR)
        self.assertEqual(result.request_count, 1)
        self.assertEqual(_FixtureHandler.workflow_secure_state, "cancelled")

    def test_state_transition_unknown_intermediate_state_is_inconclusive(self) -> None:
        plan = build_plan(
            ProofClass.STATE_TRANSITION,
            "F-STATE-AMBIGUOUS",
            available_authority={"fixture_write_access", "fixture_state_readback"},
        )
        result = self.executor.execute(
            plan,
            StateTransitionHttpSpec(
                url=self.base + "/state-transition-ambiguous",
                read_state=lambda: _FixtureHandler.workflow_ambiguous_state,
                expected_start_state="cancelled",
                expected_secure_state="cancelled",
                forbidden_state="completed",
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.INCONCLUSIVE)
        self.assertEqual(_FixtureHandler.workflow_ambiguous_state, "manual_review")

    def test_state_transition_wrong_start_is_inconclusive_without_request(self) -> None:
        plan = build_plan(
            ProofClass.STATE_TRANSITION,
            "F-STATE-WRONG-START",
            available_authority={"fixture_write_access", "fixture_state_readback"},
        )
        result = self.executor.execute(
            plan,
            StateTransitionHttpSpec(
                url=self.base + "/state-transition-vulnerable",
                read_state=lambda: "already-completed",
                expected_start_state="cancelled",
                expected_secure_state="cancelled",
                forbidden_state="completed",
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.INCONCLUSIVE)
        self.assertEqual(result.request_count, 0)
        self.assertIn("did not begin", " ".join(result.notes))

    def test_state_transition_rejects_same_secure_and_forbidden_invariant(self) -> None:
        plan = build_plan(
            ProofClass.STATE_TRANSITION,
            "F-STATE-BAD-INVARIANT",
            available_authority={"fixture_write_access", "fixture_state_readback"},
        )
        with self.assertRaises(ProofExecutionError):
            self.executor.execute(
                plan,
                StateTransitionHttpSpec(
                    url=self.base + "/state-transition-secure",
                    read_state=lambda: "cancelled",
                    expected_start_state="cancelled",
                    expected_secure_state="cancelled",
                    forbidden_state="cancelled",
                ),
            )

    def test_state_transition_requires_declared_readback_authority(self) -> None:
        blocked = build_plan(
            ProofClass.STATE_TRANSITION,
            "F-STATE-BLOCKED",
            available_authority={"fixture_write_access"},
        )
        result = self.executor.execute(
            blocked,
            StateTransitionHttpSpec(
                url=self.base + "/state-transition-secure",
                read_state=lambda: _FixtureHandler.workflow_secure_state,
                expected_start_state="cancelled",
                expected_secure_state="cancelled",
                forbidden_state="completed",
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.BLOCKED)
        self.assertIn("fixture_state_readback", result.blocker)
        self.assertEqual(result.request_count, 0)

    def test_payment_invariant_detects_duplicate_charge_effect(self) -> None:
        plan = build_plan(
            ProofClass.PAYMENT_INVARIANT,
            "F-PAYMENT-DUPLICATE",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        result = self.executor.execute(
            plan,
            PaymentInvariantHttpSpec(
                url=self.base + "/payment-vulnerable",
                body=b'{"amount_minor":250}',
                headers={"Authorization": "Bearer payment-secret"},
                read_balance_minor=lambda: _FixtureHandler.payment_vulnerable_balance,
                expected_single_delta_minor=-250,
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.VULNERABLE_BEHAVIOR)
        self.assertEqual(result.request_count, 2)
        self.assertEqual(_FixtureHandler.payment_vulnerable_balance, 9_500)
        rendered = json.dumps(result.to_dict())
        self.assertNotIn("payment-secret", rendered)
        self.assertNotIn("10000", rendered)
        self.assertNotIn("9500", rendered)
        self.assertIn("same charge/refund delta a second time", " ".join(result.notes))

    def test_payment_invariant_accepts_idempotent_replay(self) -> None:
        plan = build_plan(
            ProofClass.PAYMENT_INVARIANT,
            "F-PAYMENT-IDEMPOTENT",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        result = self.executor.execute(
            plan,
            PaymentInvariantHttpSpec(
                url=self.base + "/payment-idempotent",
                headers={"Idempotency-Key": "fixture-payment-1"},
                read_balance_minor=lambda: _FixtureHandler.payment_idempotent_balance,
                expected_single_delta_minor=-250,
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.SECURE_BEHAVIOR)
        self.assertEqual(result.request_count, 2)
        self.assertEqual(_FixtureHandler.payment_idempotent_balance, 9_750)
        self.assertIn("no additional financial effect", " ".join(result.notes))

    def test_payment_invariant_refuses_to_replay_when_control_delta_is_wrong(self) -> None:
        plan = build_plan(
            ProofClass.PAYMENT_INVARIANT,
            "F-PAYMENT-WRONG-DELTA",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        result = self.executor.execute(
            plan,
            PaymentInvariantHttpSpec(
                url=self.base + "/payment-wrong-delta",
                read_balance_minor=lambda: _FixtureHandler.payment_wrong_delta_balance,
                expected_single_delta_minor=-250,
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.INCONCLUSIVE)
        self.assertEqual(result.request_count, 1)
        self.assertEqual(_FixtureHandler.payment_wrong_delta_balance, 9_900)
        self.assertIn("did not match", " ".join(result.notes))

    def test_payment_invariant_supports_refund_delta_and_replay_protection(self) -> None:
        plan = build_plan(
            ProofClass.PAYMENT_INVARIANT,
            "F-PAYMENT-REFUND",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        result = self.executor.execute(
            plan,
            PaymentInvariantHttpSpec(
                url=self.base + "/refund-idempotent",
                headers={"Idempotency-Key": "fixture-refund-1"},
                read_balance_minor=lambda: _FixtureHandler.refund_idempotent_balance,
                expected_single_delta_minor=300,
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.SECURE_BEHAVIOR)
        self.assertEqual(result.request_count, 2)
        self.assertEqual(_FixtureHandler.refund_idempotent_balance, 5_300)

    def test_payment_invariant_requires_integer_minor_units_and_authority(self) -> None:
        plan = build_plan(
            ProofClass.PAYMENT_INVARIANT,
            "F-PAYMENT-INVALID",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        with self.assertRaises(ProofExecutionError):
            self.executor.execute(
                plan,
                PaymentInvariantHttpSpec(
                    url=self.base + "/payment-vulnerable",
                    read_balance_minor=lambda: 10_000,
                    expected_single_delta_minor=0,
                ),
            )
        with self.assertRaises(ProofExecutionError):
            self.executor.execute(
                plan,
                PaymentInvariantHttpSpec(
                    url=self.base + "/payment-vulnerable",
                    read_balance_minor=lambda: 100.5,  # type: ignore[return-value]
                    expected_single_delta_minor=-250,
                ),
            )

        blocked = build_plan(
            ProofClass.PAYMENT_INVARIANT,
            "F-PAYMENT-BLOCKED",
            available_authority={"fixture_write_access"},
        )
        result = self.executor.execute(
            blocked,
            PaymentInvariantHttpSpec(
                url=self.base + "/payment-idempotent",
                read_balance_minor=lambda: _FixtureHandler.payment_idempotent_balance,
                expected_single_delta_minor=-250,
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.BLOCKED)
        self.assertIn("fixture_financial_readback", result.blocker)
        self.assertEqual(result.request_count, 0)

    def test_money_flow_invariant_detects_duplicate_cross_entity_movement(self) -> None:
        plan = build_plan(
            ProofClass.MONEY_FLOW_INVARIANT,
            "F-MONEY-FLOW-DUPLICATE",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        expected = {"buyer": -1000, "seller": 900, "platform": 100}
        result = self.executor.execute(
            plan,
            MoneyFlowInvariantHttpSpec(
                url=self.base + "/money-flow-duplicate",
                headers={"Authorization": "Bearer money-flow-secret"},
                read_balances_minor=lambda: dict(_FixtureHandler.money_flow_duplicate),
                expected_deltas_minor=expected,
                forbidden_delta_vectors=(
                    {"buyer": -1000, "seller": 1000, "platform": 0},
                ),
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.VULNERABLE_BEHAVIOR)
        self.assertEqual(result.request_count, 2)
        self.assertEqual(
            _FixtureHandler.money_flow_duplicate,
            {"buyer": 8_000, "seller": 3_800, "platform": 700},
        )
        rendered = json.dumps(result.to_dict())
        self.assertNotIn("money-flow-secret", rendered)
        self.assertNotIn('"buyer": 10000', rendered)
        self.assertNotIn('"seller": 2000', rendered)
        self.assertIn("duplicate", " ".join(result.notes))

    def test_money_flow_invariant_accepts_idempotent_multi_entity_replay(self) -> None:
        plan = build_plan(
            ProofClass.MONEY_FLOW_INVARIANT,
            "F-MONEY-FLOW-IDEMPOTENT",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        result = self.executor.execute(
            plan,
            MoneyFlowInvariantHttpSpec(
                url=self.base + "/money-flow-idempotent",
                read_balances_minor=lambda: dict(_FixtureHandler.money_flow_idempotent),
                expected_deltas_minor={"buyer": -1000, "seller": 900, "platform": 100},
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.SECURE_BEHAVIOR)
        self.assertEqual(result.request_count, 2)
        self.assertEqual(
            _FixtureHandler.money_flow_idempotent,
            {"buyer": 9_000, "seller": 2_900, "platform": 600},
        )
        self.assertIn("no additional", " ".join(result.notes))

    def test_money_flow_invariant_matches_explicit_forbidden_misroute(self) -> None:
        plan = build_plan(
            ProofClass.MONEY_FLOW_INVARIANT,
            "F-MONEY-FLOW-MISROUTE",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        result = self.executor.execute(
            plan,
            MoneyFlowInvariantHttpSpec(
                url=self.base + "/money-flow-misroute",
                read_balances_minor=lambda: dict(_FixtureHandler.money_flow_misroute),
                expected_deltas_minor={"buyer": -1000, "seller": 900, "platform": 100},
                forbidden_delta_vectors=(
                    {"buyer": -1000, "seller": 1000, "platform": 0},
                ),
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.VULNERABLE_BEHAVIOR)
        self.assertEqual(result.request_count, 1)
        self.assertIn("forbidden delta vector", " ".join(result.notes))

    def test_money_flow_invariant_unexpected_vector_is_inconclusive_without_replay(self) -> None:
        balances = {"buyer": 10_000, "seller": 2_000, "platform": 500}

        class UnexpectedHandler:
            pass

        original_request = self.executor._request

        def wrapped_request(label, url, method="GET", headers=None, body=b"", **kwargs):
            observation = original_request(label, url, method, headers, body, **kwargs)
            balances["buyer"] -= 1000
            balances["seller"] += 850
            balances["platform"] += 150
            return observation

        self.executor._request = wrapped_request  # type: ignore[method-assign]
        plan = build_plan(
            ProofClass.MONEY_FLOW_INVARIANT,
            "F-MONEY-FLOW-UNKNOWN",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        result = self.executor.execute(
            plan,
            MoneyFlowInvariantHttpSpec(
                url=self.base + "/money-flow-idempotent",
                read_balances_minor=lambda: dict(balances),
                expected_deltas_minor={"buyer": -1000, "seller": 900, "platform": 100},
                forbidden_delta_vectors=(
                    {"buyer": -1000, "seller": 1000, "platform": 0},
                ),
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.INCONCLUSIVE)
        self.assertEqual(result.request_count, 1)
        self.assertIn("neither", " ".join(result.notes))

    def test_money_flow_invariant_rejects_bad_vectors_and_missing_authority(self) -> None:
        plan = build_plan(
            ProofClass.MONEY_FLOW_INVARIANT,
            "F-MONEY-FLOW-INVALID",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        with self.assertRaises(ProofExecutionError):
            self.executor.execute(
                plan,
                MoneyFlowInvariantHttpSpec(
                    url=self.base + "/money-flow-idempotent",
                    read_balances_minor=lambda: {"buyer": 10_000, "seller": 2_000},
                    expected_deltas_minor={"buyer": -1000},
                ),
            )
        with self.assertRaises(ProofExecutionError):
            self.executor.execute(
                plan,
                MoneyFlowInvariantHttpSpec(
                    url=self.base + "/money-flow-idempotent",
                    read_balances_minor=lambda: {"buyer": 10_000, "seller": 2_000},
                    expected_deltas_minor={"buyer": -1000, "seller": 1000},
                    forbidden_delta_vectors=({"buyer": -1000, "seller": 1000},),
                ),
            )

        blocked = build_plan(
            ProofClass.MONEY_FLOW_INVARIANT,
            "F-MONEY-FLOW-BLOCKED",
            available_authority={"fixture_write_access"},
        )
        result = self.executor.execute(
            blocked,
            MoneyFlowInvariantHttpSpec(
                url=self.base + "/money-flow-idempotent",
                read_balances_minor=lambda: dict(_FixtureHandler.money_flow_idempotent),
                expected_deltas_minor={"buyer": -1000, "seller": 900, "platform": 100},
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.BLOCKED)
        self.assertIn("fixture_financial_readback", result.blocker)
        self.assertEqual(result.request_count, 0)

    def test_workflow_sequence_detects_prerequisite_bypass(self) -> None:
        plan = build_plan(
            ProofClass.WORKFLOW_SEQUENCE,
            "F-WORKFLOW-BYPASS",
            available_authority={
                "fixture_write_access",
                "fixture_state_readback",
                "fixture_reset",
            },
        )

        def reset_fixture() -> bool:
            _FixtureHandler.workflow_sequence_vulnerable_state = "created"
            return True

        result = self.executor.execute(
            plan,
            WorkflowSequenceHttpSpec(
                step_one_url=self.base + "/workflow-sequence-vulnerable-step1",
                step_two_url=self.base + "/workflow-sequence-vulnerable-step2",
                headers={"Authorization": "Bearer workflow-sequence-secret"},
                read_state=lambda: _FixtureHandler.workflow_sequence_vulnerable_state,
                reset_fixture=reset_fixture,
                expected_start_state="created",
                expected_intermediate_state="approved",
                expected_final_state="completed",
                expected_safe_bypass_state="created",
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.VULNERABLE_BEHAVIOR)
        self.assertEqual(result.request_count, 3)
        self.assertEqual(_FixtureHandler.workflow_sequence_vulnerable_state, "completed")
        rendered = json.dumps(result.to_dict())
        self.assertNotIn("workflow-sequence-secret", rendered)
        self.assertNotIn('"approved"', rendered)
        self.assertNotIn('"completed"', rendered)
        self.assertIn("bypassed", " ".join(result.notes))

    def test_workflow_sequence_recognizes_enforced_prerequisite(self) -> None:
        plan = build_plan(
            ProofClass.WORKFLOW_SEQUENCE,
            "F-WORKFLOW-SAFE",
            available_authority={
                "fixture_write_access",
                "fixture_state_readback",
                "fixture_reset",
            },
        )

        def reset_fixture() -> bool:
            _FixtureHandler.workflow_sequence_secure_state = "created"
            return True

        result = self.executor.execute(
            plan,
            WorkflowSequenceHttpSpec(
                step_one_url=self.base + "/workflow-sequence-secure-step1",
                step_two_url=self.base + "/workflow-sequence-secure-step2",
                read_state=lambda: _FixtureHandler.workflow_sequence_secure_state,
                reset_fixture=reset_fixture,
                expected_start_state="created",
                expected_intermediate_state="approved",
                expected_final_state="completed",
                expected_safe_bypass_state="created",
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.SECURE_BEHAVIOR)
        self.assertEqual(result.request_count, 3)
        self.assertEqual(_FixtureHandler.workflow_sequence_secure_state, "created")
        self.assertIn("did not bypass", " ".join(result.notes))

    def test_workflow_sequence_stops_when_legitimate_control_is_broken(self) -> None:
        plan = build_plan(
            ProofClass.WORKFLOW_SEQUENCE,
            "F-WORKFLOW-BROKEN-CONTROL",
            available_authority={
                "fixture_write_access",
                "fixture_state_readback",
                "fixture_reset",
            },
        )
        result = self.executor.execute(
            plan,
            WorkflowSequenceHttpSpec(
                step_one_url=self.base + "/workflow-sequence-broken-step1",
                step_two_url=self.base + "/workflow-sequence-broken-step2",
                read_state=lambda: _FixtureHandler.workflow_sequence_broken_state,
                reset_fixture=lambda: True,
                expected_start_state="created",
                expected_intermediate_state="approved",
                expected_final_state="completed",
                expected_safe_bypass_state="created",
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.INCONCLUSIVE)
        self.assertEqual(result.request_count, 1)
        self.assertEqual(_FixtureHandler.workflow_sequence_broken_state, "created")
        self.assertIn("step one", " ".join(result.notes))

    def test_workflow_sequence_reset_failure_is_inconclusive_without_bypass_attempt(self) -> None:
        plan = build_plan(
            ProofClass.WORKFLOW_SEQUENCE,
            "F-WORKFLOW-RESET",
            available_authority={
                "fixture_write_access",
                "fixture_state_readback",
                "fixture_reset",
            },
        )
        _FixtureHandler.workflow_sequence_secure_state = "created"
        result = self.executor.execute(
            plan,
            WorkflowSequenceHttpSpec(
                step_one_url=self.base + "/workflow-sequence-secure-step1",
                step_two_url=self.base + "/workflow-sequence-secure-step2",
                read_state=lambda: _FixtureHandler.workflow_sequence_secure_state,
                reset_fixture=lambda: False,
                expected_start_state="created",
                expected_intermediate_state="approved",
                expected_final_state="completed",
                expected_safe_bypass_state="created",
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.INCONCLUSIVE)
        self.assertEqual(result.request_count, 2)
        self.assertIn("reset", " ".join(result.notes))

    def test_workflow_sequence_wrong_start_and_missing_authority_fail_closed(self) -> None:
        plan = build_plan(
            ProofClass.WORKFLOW_SEQUENCE,
            "F-WORKFLOW-WRONG-START",
            available_authority={
                "fixture_write_access",
                "fixture_state_readback",
                "fixture_reset",
            },
        )
        result = self.executor.execute(
            plan,
            WorkflowSequenceHttpSpec(
                step_one_url=self.base + "/workflow-sequence-secure-step1",
                step_two_url=self.base + "/workflow-sequence-secure-step2",
                read_state=lambda: "already-approved",
                reset_fixture=lambda: True,
                expected_start_state="created",
                expected_intermediate_state="approved",
                expected_final_state="completed",
                expected_safe_bypass_state="created",
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.INCONCLUSIVE)
        self.assertEqual(result.request_count, 0)

        blocked = build_plan(
            ProofClass.WORKFLOW_SEQUENCE,
            "F-WORKFLOW-BLOCKED",
            available_authority={"fixture_write_access", "fixture_state_readback"},
        )
        result = self.executor.execute(
            blocked,
            WorkflowSequenceHttpSpec(
                step_one_url=self.base + "/workflow-sequence-secure-step1",
                step_two_url=self.base + "/workflow-sequence-secure-step2",
                read_state=lambda: _FixtureHandler.workflow_sequence_secure_state,
                reset_fixture=lambda: True,
                expected_start_state="created",
                expected_intermediate_state="approved",
                expected_final_state="completed",
                expected_safe_bypass_state="created",
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.BLOCKED)
        self.assertIn("fixture_reset", result.blocker)
        self.assertEqual(result.request_count, 0)

    def test_workflow_sequence_rejects_contradictory_invariants(self) -> None:
        plan = build_plan(
            ProofClass.WORKFLOW_SEQUENCE,
            "F-WORKFLOW-INVARIANT",
            available_authority={
                "fixture_write_access",
                "fixture_state_readback",
                "fixture_reset",
            },
        )
        with self.assertRaises(ProofExecutionError):
            self.executor.execute(
                plan,
                WorkflowSequenceHttpSpec(
                    step_one_url=self.base + "/workflow-sequence-secure-step1",
                    step_two_url=self.base + "/workflow-sequence-secure-step2",
                    read_state=lambda: "created",
                    reset_fixture=lambda: True,
                    expected_start_state="created",
                    expected_intermediate_state="created",
                    expected_final_state="completed",
                    expected_safe_bypass_state="created",
                ),
            )

    def test_ssrf_proof_uses_loopback_callback_not_public_oob(self) -> None:
        plan = build_plan(
            ProofClass.SSRF_CALLBACK,
            "F-SSRF",
            available_authority={"local_callback_listener"},
        )
        result = self.executor.execute(
            plan,
            SsrfHttpSpec(self.base + "/fetch?url={callback}", callback_timeout_seconds=1),
        )
        self.assertEqual(result.behavior, ProofBehavior.VULNERABLE_BEHAVIOR)
        self.assertEqual(result.request_count, 1)
        self.assertIn("callback was local", " ".join(result.notes))

    def test_xss_blocks_without_explicit_browser_backend(self) -> None:
        plan = build_plan(
            ProofClass.XSS_EXECUTION,
            "F-XSS",
            available_authority={"local_browser_runtime"},
        )
        executor = LocalProofExecutor(
            self.policy,
            timeout_seconds=2,
            max_requests=8,
            browser_factory=None,
        )
        result = executor.execute(
            plan,
            XssBrowserSpec(
                url_template=self.base + "/xss?q={payload}",
                injection_selector="#sink",
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.BLOCKED)
        self.assertIn("browser backend", result.blocker)

    def test_xss_fixed_marker_execution_is_vulnerable_behavior(self) -> None:
        plan = build_plan(
            ProofClass.XSS_EXECUTION,
            "F-XSS-VULN",
            available_authority={"local_browser_runtime"},
        )

        def factory(scope, **kwargs):
            return _FakeXssBrowser(scope, execute_marker=True, **kwargs)

        executor = LocalProofExecutor(
            self.policy,
            timeout_seconds=2,
            max_requests=8,
            browser_factory=factory,
        )
        result = executor.execute(
            plan,
            XssBrowserSpec(
                url_template=self.base + "/xss?q={payload}",
                injection_selector="#sink",
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.VULNERABLE_BEHAVIOR)
        self.assertEqual(result.request_count, 1)
        self.assertTrue(result.observations[1]["executed"])
        self.assertNotIn("<script>", json.dumps(result.to_dict()))

    def test_xss_inert_marker_is_secure_behavior(self) -> None:
        plan = build_plan(
            ProofClass.XSS_EXECUTION,
            "F-XSS-SAFE",
            available_authority={"local_browser_runtime"},
        )

        def factory(scope, **kwargs):
            return _FakeXssBrowser(scope, inert_text=True, **kwargs)

        executor = LocalProofExecutor(
            self.policy,
            timeout_seconds=2,
            max_requests=8,
            browser_factory=factory,
        )
        result = executor.execute(
            plan,
            XssBrowserSpec(
                url_template=self.base + "/xss?q={payload}",
                injection_selector="#sink",
            ),
        )
        self.assertEqual(result.behavior, ProofBehavior.SECURE_BEHAVIOR)
        self.assertTrue(result.observations[1]["inert_text_observed"])

    def test_xss_rejects_caller_defined_script_marker(self) -> None:
        plan = build_plan(
            ProofClass.XSS_EXECUTION,
            "F-XSS-MARKER",
            available_authority={"local_browser_runtime"},
        )
        with self.assertRaises(ProofExecutionError):
            self.executor.execute(
                plan,
                XssBrowserSpec(
                    url_template=self.base + "/xss?q={payload}",
                    injection_selector="#sink",
                    marker_name="x;alert(1)//",
                ),
            )

    def test_xss_refuses_non_loopback_even_with_browser_backend(self) -> None:
        plan = build_plan(
            ProofClass.XSS_EXECUTION,
            "F-XSS-REMOTE",
            available_authority={"local_browser_runtime"},
        )
        with self.assertRaises(ProofExecutionError):
            self.executor.execute(
                plan,
                XssBrowserSpec(
                    url_template="https://example.com/xss?q={payload}",
                    injection_selector="#sink",
                ),
            )

    def test_executor_rejects_ungranted_or_non_loopback_targets(self) -> None:
        plan = build_plan(
            ProofClass.PATH_TRAVERSAL,
            "F-PATH",
            available_authority={"fixture_filesystem"},
        )
        denied_policy = NetworkPolicy(ExecutionMode.LOCAL)
        denied = LocalProofExecutor(denied_policy)
        with self.assertRaises(PermissionError):
            denied.execute(
                plan,
                TraversalHttpSpec(
                    url_template=self.base + "/files?path={path}",
                    safe_path="safe",
                    traversal_path="../sentinel",
                    sentinel_marker=b"x",
                ),
            )
        with self.assertRaises(ProofExecutionError):
            self.executor.execute(
                plan,
                TraversalHttpSpec(
                    url_template="https://example.com/files?path={path}",
                    safe_path="safe",
                    traversal_path="../sentinel",
                    sentinel_marker=b"x",
                ),
            )


    def test_local_executor_refuses_dns_names_even_when_they_resolve_to_loopback(self) -> None:
        plan = build_plan(
            ProofClass.PATH_TRAVERSAL,
            "F-LOCALHOST",
            available_authority={"fixture_filesystem"},
        )
        with self.assertRaises(ProofExecutionError):
            self.executor.execute(
                plan,
                TraversalHttpSpec(
                    url_template=f"http://localhost:{self.port}/files?path={{path}}",
                    safe_path="safe",
                    traversal_path="../sentinel",
                    sentinel_marker=b"x",
                ),
            )


if __name__ == "__main__":
    unittest.main()
