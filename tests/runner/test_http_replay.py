from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sechelix_runner.pentest.api_client import ApiResponse
from sechelix_runner.pentest.http_evidence import (
    HttpEvidenceRecorder,
    HttpReplayDenied,
    load_safe_replay,
)
from sechelix_runner.pentest.http_replay import SafeHttpReplayExecutor


class _FakeClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def request(self, method, url, *, headers=None, body=None, authentication_context=None):
        self.calls.append({
            "method": method,
            "url": url,
            "headers": headers,
            "body": body,
            "authentication_context": authentication_context,
        })
        return ApiResponse(200, url, method, "application/json", "{}")


class HttpSafeReplayTests(unittest.TestCase):
    def test_anonymous_body_free_get_replays_without_secret_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "http.jsonl"
            recorder = HttpEvidenceRecorder(path)
            recorder.record_exchange(
                method="GET",
                url="https://app.example.test/health",
                status=200,
                content_type="application/json",
                request_headers={"Accept": "application/json"},
                response_headers={"Content-Type": "application/json"},
                request_body_bytes=0,
                response_body_bytes=2,
                authentication_context=None,
            )
            client = _FakeClient()
            response = SafeHttpReplayExecutor(client).replay(path, sequence=1)
            self.assertEqual(response.status, 200)
            self.assertEqual(client.calls, [{
                "method": "GET",
                "url": "https://app.example.test/health",
                "headers": {},
                "body": None,
                "authentication_context": None,
            }])

    def test_authenticated_context_is_not_replayable_even_if_artifact_flag_is_tampered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "http.jsonl"
            recorder = HttpEvidenceRecorder(path)
            record = recorder.record_exchange(
                method="GET",
                url="https://app.example.test/api/me",
                status=200,
                content_type="application/json",
                request_headers={"Accept": "application/json"},
                response_headers={"Content-Type": "application/json"},
                request_body_bytes=0,
                response_body_bytes=10,
                authentication_context="persona:admin",
            )
            payload = record.as_dict()
            payload["replayable"] = True
            payload["replay_blockers"] = []
            path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

            with self.assertRaises(HttpReplayDenied) as ctx:
                load_safe_replay(path, sequence=1)
            self.assertIn("authenticated-context", str(ctx.exception))

    def test_sensitive_header_tampering_cannot_turn_record_into_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "http.jsonl"
            recorder = HttpEvidenceRecorder(path)
            record = recorder.record_exchange(
                method="GET",
                url="https://app.example.test/api/me",
                status=200,
                content_type="application/json",
                request_headers={"Authorization": "Bearer secret"},
                response_headers={"Content-Type": "application/json"},
                request_body_bytes=0,
                response_body_bytes=10,
                authentication_context=None,
            )
            payload = record.as_dict()
            payload["replayable"] = True
            payload["replay_blockers"] = []
            path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

            with self.assertRaises(HttpReplayDenied) as ctx:
                load_safe_replay(path, sequence=1)
            self.assertIn("sensitive-request-headers", str(ctx.exception))

    def test_redacted_query_is_never_reconstructed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "http.jsonl"
            recorder = HttpEvidenceRecorder(path)
            recorder.record_exchange(
                method="GET",
                url="https://app.example.test/search?q=private",
                status=200,
                content_type="text/html",
                request_headers={},
                response_headers={"Content-Type": "text/html"},
                request_body_bytes=0,
                response_body_bytes=20,
                authentication_context=None,
            )
            with self.assertRaises(HttpReplayDenied):
                load_safe_replay(path, sequence=1)

    def test_duplicate_sequence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "http.jsonl"
            recorder = HttpEvidenceRecorder(path)
            record = recorder.record_exchange(
                method="GET",
                url="https://app.example.test/health",
                status=200,
                content_type="application/json",
                request_headers={},
                response_headers={},
                request_body_bytes=0,
                response_body_bytes=2,
                authentication_context=None,
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record.as_dict()) + "\n")
            with self.assertRaises(HttpReplayDenied) as ctx:
                load_safe_replay(path, sequence=1)
            self.assertIn("duplicate", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
