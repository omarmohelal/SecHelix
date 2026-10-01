from __future__ import annotations

import json
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sechelix_runner.proof import ProofClass, build_plan
from sechelix_runner.proof_exec import (
    CorsHttpSpec,
    KnownDefaultCredentialHttpSpec,
    LocalProofExecutor,
    ProofBehavior,
    ProofExecutionError,
    RateLimitHttpSpec,
)
from sechelix_runner.sandbox import ExecutionMode, NetworkPolicy


class _LaunchGapHandler(BaseHTTPRequestHandler):
    secure_rate_count = 0
    vulnerable_rate_count = 0
    default_body = b"username=admin&password=admin"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/cors/secure":
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            if origin == "https://app.example":
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
            self.end_headers()
            self.wfile.write(b"fixture")
            return
        if parsed.path == "/cors/vulnerable":
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
            self.end_headers()
            self.wfile.write(b"fixture")
            return
        if parsed.path == "/rate/secure":
            type(self).secure_rate_count += 1
            if type(self).secure_rate_count > 2:
                self._send(429, b"limited")
            else:
                self._send(200, b"ok")
            return
        if parsed.path == "/rate/vulnerable":
            type(self).vulnerable_rate_count += 1
            self._send(200, b"ok")
            return
        self._send(404, b"missing")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if self.path == "/default/secure":
            self._send(401, b"disabled")
            return
        if self.path == "/default/vulnerable":
            self._send(200 if body == self.default_body else 401, b"result")
            return
        self._send(404, b"missing")

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args) -> None:
        return


class LaunchProofGapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _LaunchGapHandler)
        cls.port = int(cls.server.server_address[1])
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self) -> None:
        _LaunchGapHandler.secure_rate_count = 0
        _LaunchGapHandler.vulnerable_rate_count = 0
        policy = NetworkPolicy(ExecutionMode.LOCAL)
        policy.grant(
            "127.0.0.1",
            self.port,
            protocol="http",
            purpose="owned launch proof fixture",
            scope_id="SCOPE-LAUNCH-GAPS",
        )
        self.executor = LocalProofExecutor(policy, timeout_seconds=2, max_requests=8)
        self.base = f"http://127.0.0.1:{self.port}"

    def test_cors_secure_and_reflective_foreign_origin(self) -> None:
        plan = build_plan(
            ProofClass.CORS_POLICY,
            "F-CORS",
            available_authority={"fixture_cors_probe"},
        )
        secure = self.executor.execute(
            plan,
            CorsHttpSpec(
                url=self.base + "/cors/secure",
                allowed_origin="https://app.example",
            ),
        )
        self.assertEqual(secure.behavior, ProofBehavior.SECURE_BEHAVIOR)
        self.assertEqual(secure.request_count, 2)

        vulnerable = self.executor.execute(
            plan,
            CorsHttpSpec(
                url=self.base + "/cors/vulnerable",
                allowed_origin="https://app.example",
            ),
        )
        self.assertEqual(vulnerable.behavior, ProofBehavior.VULNERABLE_BEHAVIOR)
        rendered = json.dumps(vulnerable.to_dict())
        self.assertIn("Access-Control-Allow-Origin", rendered)
        self.assertNotIn("Authorization", rendered)

    def test_rate_limit_uses_exactly_one_request_above_declared_allowance(self) -> None:
        plan = build_plan(
            ProofClass.RATE_LIMIT_INVARIANT,
            "F-RATE",
            available_authority={"fixture_rate_limit_probe"},
        )
        secure = self.executor.execute(
            plan,
            RateLimitHttpSpec(
                url=self.base + "/rate/secure",
                allowed_requests=2,
            ),
        )
        self.assertEqual(secure.behavior, ProofBehavior.SECURE_BEHAVIOR)
        self.assertEqual(secure.request_count, 3)

        _LaunchGapHandler.vulnerable_rate_count = 0
        vulnerable = self.executor.execute(
            plan,
            RateLimitHttpSpec(
                url=self.base + "/rate/vulnerable",
                allowed_requests=2,
            ),
        )
        self.assertEqual(vulnerable.behavior, ProofBehavior.VULNERABLE_BEHAVIOR)
        self.assertEqual(vulnerable.request_count, 3)

    def test_rate_limit_refuses_load_test_sized_probe(self) -> None:
        plan = build_plan(
            ProofClass.RATE_LIMIT_INVARIANT,
            "F-RATE-BOUND",
            available_authority={"fixture_rate_limit_probe"},
        )
        with self.assertRaisesRegex(ProofExecutionError, "between 1 and 5"):
            self.executor.execute(
                plan,
                RateLimitHttpSpec(
                    url=self.base + "/rate/secure",
                    allowed_requests=100,
                ),
            )

    def test_known_default_credential_is_exactly_one_ephemeral_attempt(self) -> None:
        plan = build_plan(
            ProofClass.KNOWN_DEFAULT_CREDENTIAL,
            "F-DEFAULT",
            available_authority={"fixture_default_credential_test"},
        )
        secret = _LaunchGapHandler.default_body
        secure = self.executor.execute(
            plan,
            KnownDefaultCredentialHttpSpec(
                url=self.base + "/default/secure",
                body=secret,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ),
        )
        self.assertEqual(secure.behavior, ProofBehavior.SECURE_BEHAVIOR)
        self.assertEqual(secure.request_count, 1)

        vulnerable = self.executor.execute(
            plan,
            KnownDefaultCredentialHttpSpec(
                url=self.base + "/default/vulnerable",
                body=secret,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ),
        )
        self.assertEqual(vulnerable.behavior, ProofBehavior.VULNERABLE_BEHAVIOR)
        self.assertEqual(vulnerable.request_count, 1)
        rendered = json.dumps(vulnerable.to_dict())
        self.assertNotIn("username=admin", rendered)
        self.assertNotIn("password=admin", rendered)

    def test_new_proofs_fail_closed_without_explicit_authority(self) -> None:
        for proof_class in (
            ProofClass.CORS_POLICY,
            ProofClass.RATE_LIMIT_INVARIANT,
            ProofClass.KNOWN_DEFAULT_CREDENTIAL,
        ):
            with self.subTest(proof_class=proof_class.value):
                plan = build_plan(proof_class, "F-BLOCKED", available_authority=set())
                self.assertEqual(plan.state.value, "BLOCKED")


if __name__ == "__main__":
    unittest.main()
