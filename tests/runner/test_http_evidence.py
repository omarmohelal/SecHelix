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

    def items(self):
        return super().items()


class _Response:
    status = 200

    def __init__(self) -> None:
        self.headers = _Headers({
            "Content-Type": "application/json",
            "Set-Cookie": "session=super-secret",
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
                    "Set-Cookie": "session=response-secret",
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
            self.assertNotIn("session=response-secret", raw)
            self.assertIn("api_key=REDACTED", raw)
            self.assertIn("item=REDACTED", raw)
            self.assertFalse(record.replayable)
            self.assertIn("method-is-not-read-only", record.replay_blockers)
            self.assertIn("request-body-not-persisted", record.replay_blockers)
            self.assertIn("query-values-redacted", record.replay_blockers)
            self.assertIn("sensitive-request-headers-not-persisted", record.replay_blockers)

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
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("request-secret", raw)
            self.assertNotIn("response-secret", raw)
            self.assertIn("token=REDACTED", raw)
            parsed = json.loads(raw)
            self.assertFalse(parsed["replayable"])


if __name__ == "__main__":
    unittest.main()
