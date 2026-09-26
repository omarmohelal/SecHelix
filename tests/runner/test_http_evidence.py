from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sechelix_runner.pentest.api_client import AuthorizedApiClient
from sechelix_runner.pentest.gateway import PolicyToolGateway
from sechelix_runner.pentest.http_evidence import HttpEvidenceRecorder
from sechelix_runner.pentest.scope import ScopeEndpoint, TargetScope
from sechelix_runner.sandbox import ExecutionMode


def scope() -> TargetScope:
    return TargetScope(
        primary_url="https://app.example.test",
        mode=ExecutionMode.STAGING,
        endpoints=(ScopeEndpoint("app.example.test"),),
        ownership_verified=True,
        verification_method="operator-fixture",
    )


class _Headers(dict):
    def get(self, key, default=None):
        return super().get(key, default)

    def get_all(self, key):
        value = super().get(key)
        if value is None:
            return None
        if isinstance(value, (list, tuple)):
            return list(value)
        return [value]

    def items(self):
        return super().items()


class _Response:
    status = 200

    def __init__(self) -> None:
        self.headers = _Headers({
            "Content-Type": "application/json",
            "Set-Cookie": "__Host-session=super-secret; Path=/; Secure; HttpOnly; SameSite=Lax",
            "X-Trace": "trace-secret",
        })

    def geturl(self) -> str:
        return "https://app.example.test/api/me?token=should-not-persist"

    def read(self, _limit: int) -> bytes:
        return b'{"secret":"response-secret","ok":true}'


class _Opener:
    def open(self, _request, timeout=20):
        return _Response()


class HttpEvidenceRecorderTests(unittest.TestCase):
    def test_persisted_evidence_redacts_values_and_bodies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "http.jsonl"
            recorder = HttpEvidenceRecorder(path)
            record = recorder.record_exchange(
                method="POST",
                url="https://app.example.test/api/orders?api_key=top-secret&item=42",
                status=201,
                content_type="application/json",
                request_headers={
                    "Authorization": "Bearer request-secret",
                    "X-Trace": "trace-value",
                },
                response_headers={
                    "Set-Cookie": "__Host-session=response-secret; Path=/; Secure; HttpOnly; SameSite=Lax",
                    "X-Request-Id": "abc",
                },
                request_body_bytes=123,
                response_body_bytes=456,
                authentication_context="persona:buyer",
            )

            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("top-secret", raw)
            self.assertNotIn("Bearer request-secret", raw)
            self.assertNotIn("trace-value", raw)
            self.assertNotIn("response-secret", raw)
            self.assertNotIn("__Host-session", raw)
            self.assertIn("api_key=[REDACTED]", raw)
            self.assertIn("item=[REDACTED]", raw)
            self.assertFalse(record.replayable)
            self.assertIn("method-is-not-read-only", record.replay_blockers)
            self.assertIn("request-body-not-persisted", record.replay_blockers)
            self.assertIn("query-values-redacted", record.replay_blockers)
            self.assertIn("sensitive-request-headers-not-persisted", record.replay_blockers)
            self.assertEqual(len(record.set_cookie_security), 1)
            cookie = record.set_cookie_security[0]
            self.assertTrue(cookie.secure)
            self.assertTrue(cookie.http_only)
            self.assertEqual(cookie.same_site, "lax")
            self.assertTrue(cookie.path_is_root)
            self.assertTrue(cookie.host_prefix)
            self.assertFalse(cookie.domain_scoped)

    def test_cookie_security_metadata_never_persists_cookie_names_or_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "http.jsonl"
            recorder = HttpEvidenceRecorder(path)
            record = recorder.record_exchange(
                method="GET",
                url="https://app.example.test/session",
                status=200,
                content_type="text/html",
                request_headers={"Accept": "text/html"},
                response_headers={"Content-Type": "text/html", "Set-Cookie": "redacted-placeholder"},
                request_body_bytes=0,
                response_body_bytes=32,
                authentication_context=None,
                set_cookie_headers=[
                    "__Host-session=VERY-SECRET; Path=/; Secure; HttpOnly; SameSite=Strict",
                    "preferences=blue; Domain=.example.test; SameSite=None; Max-Age=0; Partitioned",
                ],
            )

            self.assertEqual(len(record.set_cookie_security), 2)
            secure_session, preference = record.set_cookie_security
            self.assertEqual(
                (
                    secure_session.secure,
                    secure_session.http_only,
                    secure_session.same_site,
                    secure_session.host_prefix,
                    secure_session.path_is_root,
                ),
                (True, True, "strict", True, True),
            )
            self.assertEqual(preference.same_site, "none")
            self.assertTrue(preference.partitioned)
            self.assertTrue(preference.domain_scoped)
            self.assertTrue(preference.max_age_zero)

            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("VERY-SECRET", raw)
            self.assertNotIn("__Host-session", raw)
            self.assertNotIn("preferences", raw)
            self.assertNotIn("blue", raw)
            parsed = json.loads(raw)
            self.assertEqual(len(parsed["set_cookie_security"]), 2)

    def test_response_security_projection_is_rich_but_value_free(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "http.jsonl"
            recorder = HttpEvidenceRecorder(path)
            record = recorder.record_exchange(
                method="GET",
                url="https://app.example.test/account",
                status=200,
                content_type="text/html",
                request_headers={
                    "Origin": "https://portal.example.test",
                    "Accept": "text/html",
                },
                response_headers={
                    "Access-Control-Allow-Origin": "https://portal.example.test",
                    "Access-Control-Allow-Credentials": "true",
                    "Vary": "Accept-Encoding, Origin",
                    "Cache-Control": "private, no-store, s-maxage=30",
                    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                    "X-Frame-Options": "DENY",
                    "X-Content-Type-Options": "nosniff",
                    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
                    "Referrer-Policy": "strict-origin-when-cross-origin",
                    "Permissions-Policy": "camera=(), microphone=()",
                    "Cross-Origin-Opener-Policy": "same-origin",
                    "Cross-Origin-Embedder-Policy": "require-corp",
                    "Cross-Origin-Resource-Policy": "same-origin",
                },
                request_body_bytes=0,
                response_body_bytes=128,
                authentication_context="persona:buyer",
                elapsed_ms=17,
                redirect_count=2,
                response_sample_sha256="a" * 64,
            )

            security = record.response_security
            self.assertEqual(security.cors_allow_origin, "same-request-origin")
            self.assertTrue(security.cors_allow_credentials)
            self.assertTrue(security.vary_origin)
            self.assertTrue(security.cache_control_present)
            self.assertTrue(security.cache_private)
            self.assertTrue(security.cache_no_store)
            self.assertTrue(security.shared_max_age_present)
            self.assertTrue(security.content_security_policy)
            self.assertTrue(security.csp_frame_ancestors)
            self.assertTrue(security.x_frame_options)
            self.assertTrue(security.nosniff)
            self.assertTrue(security.strict_transport_security)
            self.assertTrue(security.referrer_policy)
            self.assertTrue(security.permissions_policy)
            self.assertTrue(security.cross_origin_opener_policy)
            self.assertTrue(security.cross_origin_embedder_policy)
            self.assertTrue(security.cross_origin_resource_policy)
            self.assertEqual(record.elapsed_ms, 17)
            self.assertEqual(record.redirect_count, 2)
            self.assertEqual(record.response_sample_sha256, "a" * 64)

            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("https://portal.example.test", raw)
            self.assertNotIn("max-age=63072000", raw)
            self.assertNotIn("camera=()", raw)
            self.assertNotIn("frame-ancestors 'none'", raw)
            parsed = json.loads(raw)
            self.assertEqual(
                parsed["response_security"]["cors_allow_origin"],
                "same-request-origin",
            )

    def test_response_security_classifies_wildcard_without_persisting_header_value(self) -> None:
        recorder = HttpEvidenceRecorder()
        record = recorder.record_exchange(
            method="OPTIONS",
            url="https://app.example.test/api/public",
            status=204,
            content_type="",
            request_headers={"Origin": "https://attacker.invalid"},
            response_headers={
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "public, max-age=60",
            },
            request_body_bytes=0,
            response_body_bytes=0,
            authentication_context=None,
        )
        self.assertEqual(record.response_security.cors_allow_origin, "wildcard")
        self.assertTrue(record.response_security.cache_public)
        self.assertFalse(record.response_security.cache_private)

    def test_redirect_trace_redacts_query_values_and_preserves_method_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "http.jsonl"
            recorder = HttpEvidenceRecorder(path)
            record = recorder.record_exchange(
                method="POST",
                url="https://app.example.test/final",
                status=200,
                content_type="application/json",
                request_headers={"Authorization": "Bearer secret"},
                response_headers={"Content-Type": "application/json"},
                request_body_bytes=10,
                response_body_bytes=12,
                authentication_context="persona:buyer",
                redirect_count=2,
                redirect_hops=[
                    {
                        "status": 302,
                        "from_method": "POST",
                        "to_method": "GET",
                        "from_url": "https://app.example.test/start?token=never-store",
                        "to_url": "https://app.example.test/next?code=never-store-either",
                    },
                    {
                        "status": 307,
                        "from_method": "GET",
                        "to_method": "GET",
                        "from_url": "https://app.example.test/next?code=never-store-either",
                        "to_url": "https://app.example.test/final?state=also-secret",
                    },
                ],
            )

            self.assertEqual(record.redirect_count, 2)
            self.assertEqual(len(record.redirect_hops), 2)
            self.assertEqual(record.redirect_hops[0].from_method, "POST")
            self.assertEqual(record.redirect_hops[0].to_method, "GET")
            self.assertIn("token=[REDACTED]", record.redirect_hops[0].from_url)
            self.assertIn("code=[REDACTED]", record.redirect_hops[0].to_url)
            self.assertIn("state=[REDACTED]", record.redirect_hops[1].to_url)

            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("never-store", raw)
            self.assertNotIn("never-store-either", raw)
            self.assertNotIn("also-secret", raw)
            parsed = json.loads(raw)
            self.assertEqual(len(parsed["redirect_hops"]), 2)

    def test_redirect_trace_rejects_count_mismatch_and_non_redirect_status(self) -> None:
        recorder = HttpEvidenceRecorder()
        common = dict(
            method="GET",
            url="https://app.example.test/final",
            status=200,
            content_type="text/plain",
            request_headers={},
            response_headers={},
            request_body_bytes=0,
            response_body_bytes=0,
            authentication_context=None,
        )
        with self.assertRaises(ValueError):
            recorder.record_exchange(
                **common,
                redirect_count=2,
                redirect_hops=[
                    {
                        "status": 302,
                        "from_method": "GET",
                        "to_method": "GET",
                        "from_url": "https://app.example.test/a",
                        "to_url": "https://app.example.test/b",
                    }
                ],
            )
        with self.assertRaises(ValueError):
            recorder.record_exchange(
                **common,
                redirect_count=1,
                redirect_hops=[
                    {
                        "status": 200,
                        "from_method": "GET",
                        "to_method": "GET",
                        "from_url": "https://app.example.test/a",
                        "to_url": "https://app.example.test/b",
                    }
                ],
            )

    def test_simple_anonymous_get_can_be_marked_replayable(self) -> None:
        recorder = HttpEvidenceRecorder()
        record = recorder.record_exchange(
            method="GET",
            url="https://app.example.test/health",
            status=200,
            content_type="application/json",
            request_headers={"Accept": "application/json"},
            response_headers={"Content-Type": "application/json"},
            request_body_bytes=0,
            response_body_bytes=12,
            authentication_context=None,
        )
        self.assertTrue(record.replayable)
        self.assertEqual(record.replay_blockers, ())

    def test_api_client_records_exchange_without_body_or_header_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "http.jsonl"
            recorder = HttpEvidenceRecorder(path)
            gateway = PolicyToolGateway(scope=scope(), repository_root=tmp)
            client = AuthorizedApiClient(scope(), gateway, evidence_recorder=recorder)

            with patch(
                "sechelix_runner.pentest.api_client.build_opener",
                return_value=_Opener(),
            ):
                response = client.request(
                    "GET",
                    "https://app.example.test/api/me",
                    headers={"Authorization": "Bearer request-secret"},
                    authentication_context="persona:buyer",
                )

            self.assertEqual(response.status, 200)
            records = recorder.records()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].authentication_context, "persona:buyer")
            self.assertIn("authorization", records[0].request_header_names)
            self.assertGreaterEqual(records[0].elapsed_ms, 0)
            self.assertEqual(records[0].redirect_count, 0)
            self.assertEqual(len(records[0].response_sample_sha256), 64)
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("request-secret", raw)
            self.assertNotIn("response-secret", raw)
            self.assertIn("token=[REDACTED]", raw)
            self.assertEqual(len(records[0].set_cookie_security), 1)
            self.assertTrue(records[0].set_cookie_security[0].secure)
            self.assertTrue(records[0].set_cookie_security[0].http_only)
            parsed = json.loads(raw)
            self.assertFalse(parsed["replayable"])
            self.assertEqual(parsed["set_cookie_security"][0]["same_site"], "lax")


if __name__ == "__main__":
    unittest.main()
