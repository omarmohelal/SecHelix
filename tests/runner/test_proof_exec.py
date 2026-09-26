import json
import threading
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sechelix_runner.proof import ProofClass, build_plan
from sechelix_runner.proof_exec import (
    CsrfHttpSpec,
    IdorHttpSpec,
    LocalProofExecutor,
    ProofBehavior,
    ProofExecutionError,
    RaceHttpSpec,
    SessionRevocationHttpSpec,
    SsrfHttpSpec,
    TraversalHttpSpec,
    WebhookHttpSpec,
)
from sechelix_runner.sandbox import ExecutionMode, NetworkPolicy


class _FixtureHandler(BaseHTTPRequestHandler):
    redeem_count = 0
    csrf_vulnerable_count = 0
    csrf_secure_count = 0
    session_secure_active = True
    session_vulnerable_active = True
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
        _FixtureHandler.session_secure_active = True
        _FixtureHandler.session_vulnerable_active = True
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
        result = self.executor.execute(plan, object())
        self.assertEqual(result.behavior, ProofBehavior.BLOCKED)
        self.assertIn("browser backend", result.blocker)

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
