import json
import threading
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sechelix_runner.proof import ProofClass, build_plan
from sechelix_runner.proof_exec import (
    IdorHttpSpec,
    LocalProofExecutor,
    ProofBehavior,
    ProofExecutionError,
    RaceHttpSpec,
    SsrfHttpSpec,
    TraversalHttpSpec,
    WebhookHttpSpec,
)
from sechelix_runner.sandbox import ExecutionMode, NetworkPolicy


class _FixtureHandler(BaseHTTPRequestHandler):
    redeem_count = 0
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


if __name__ == "__main__":
    unittest.main()
