"""OpenRouter provider contract tests.

No test here touches the network. ``urlopen`` is replaced with a fake so CI
proves the request shape, JSON parsing, token/cost accounting, fail-closed
boundaries, and -- most importantly -- that the API key never leaves the
Authorization header for an exception, ``raw``, or a log line.
"""

from __future__ import annotations

import io
import json
import unittest
import urllib.error
from unittest.mock import patch

from sechelix_runner.providers.base import (
    NODE_OUTPUT_SCHEMA,
    ProviderError,
    strictify,
)
from sechelix_runner.providers.openrouter import (
    KEY_ENV,
    ENV_MODEL,
    OpenRouterExecutor,
    _parse_completion,
)

_KEY = "sk-or-SECRETKEY-должна-never-appear"


class FakeResponse:
    def __init__(self, payload: str, status: int = 200) -> None:
        self._payload = payload.encode("utf-8")
        self.status = status
        self.closed = False

    def read(self) -> bytes:
        return self._payload

    def close(self) -> None:
        self.closed = True


def _ok_body(**over: object) -> str:
    body = {
        "id": "gen-123",
        "model": "openai/gpt-4o-mini",
        "choices": [{"message": {"role": "assistant", "content": "hello"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7, "cost": 0.0003},
    }
    body.update(over)
    return json.dumps(body)


class ParseTests(unittest.TestCase):
    def test_happy_path_copies_accounting(self) -> None:
        result = _parse_completion(_ok_body(), fallback_model="fallback")
        self.assertEqual(result.text, "hello")
        self.assertEqual(result.provider, "openrouter")
        self.assertEqual(result.model, "openai/gpt-4o-mini")
        self.assertEqual(result.input_tokens, 11)
        self.assertEqual(result.output_tokens, 7)
        self.assertAlmostEqual(result.cost_usd, 0.0003)
        self.assertEqual(result.session_id, "gen-123")
        self.assertEqual(result.raw, {"finish_reason": "stop"})

    def test_missing_usage_is_none_not_zero(self) -> None:
        result = _parse_completion(
            json.dumps({"choices": [{"message": {"content": "x"}}]}),
            fallback_model="fallback",
        )
        self.assertIsNone(result.input_tokens)
        self.assertIsNone(result.output_tokens)
        self.assertIsNone(result.cost_usd)
        self.assertEqual(result.model, "fallback")

    def test_boolean_token_count_is_rejected(self) -> None:
        result = _parse_completion(
            json.dumps(
                {"choices": [{"message": {"content": "x"}}], "usage": {"prompt_tokens": True}}
            ),
            fallback_model="fallback",
        )
        self.assertIsNone(result.input_tokens)

    def test_empty_content_fails_closed(self) -> None:
        with self.assertRaises(ProviderError):
            _parse_completion(
                json.dumps({"choices": [{"message": {"content": "   "}}]}),
                fallback_model="fallback",
            )

    def test_no_choices_fails_closed(self) -> None:
        with self.assertRaises(ProviderError):
            _parse_completion(json.dumps({"choices": []}), fallback_model="fallback")

    def test_invalid_json_fails_closed(self) -> None:
        with self.assertRaises(ProviderError):
            _parse_completion("not json", fallback_model="fallback")

    def test_error_body_fails_closed(self) -> None:
        with self.assertRaises(ProviderError):
            _parse_completion(
                json.dumps({"error": {"message": "model unavailable"}}),
                fallback_model="fallback",
            )


class InvokeTests(unittest.TestCase):
    def test_missing_key_is_unavailable_and_invoke_raises(self) -> None:
        provider = OpenRouterExecutor(api_key=None, model="m")
        provider.api_key = None
        self.assertFalse(provider.available)
        with self.assertRaises(ProviderError):
            provider.invoke("prompt", timeout=1)

    def test_missing_model_fails_closed(self) -> None:
        provider = OpenRouterExecutor(api_key=_KEY, model=None)
        self.assertTrue(provider.available)
        with self.assertRaises(ProviderError) as ctx:
            provider.invoke("prompt", timeout=1)
        self.assertNotIn(_KEY, str(ctx.exception))

    def test_request_carries_bearer_and_endpoint(self) -> None:
        captured = {}

        def fake_urlopen(request, timeout=None):
            captured["url"] = request.full_url
            captured["auth"] = request.headers.get("Authorization")
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse(_ok_body())

        provider = OpenRouterExecutor(api_key=_KEY, model="openai/gpt-4o-mini")
        with patch("urllib.request.urlopen", fake_urlopen):
            result = provider.invoke("analyze this", timeout=5)

        self.assertEqual(result.text, "hello")
        self.assertEqual(captured["url"], "https://openrouter.ai/api/v1/chat/completions")
        self.assertEqual(captured["auth"], f"Bearer {_KEY}")
        self.assertEqual(captured["body"]["model"], "openai/gpt-4o-mini")
        self.assertEqual(captured["body"]["messages"][0]["content"], "analyze this")

    def test_http_error_surfaces_message_without_key(self) -> None:
        err = urllib.error.HTTPError(
            url="https://openrouter.ai/api/v1/chat/completions",
            code=402,
            msg="Payment Required",
            hdrs=None,
            fp=io.BytesIO(json.dumps({"error": {"message": "insufficient credits"}}).encode()),
        )

        def fake_urlopen(request, timeout=None):
            raise err

        provider = OpenRouterExecutor(api_key=_KEY, model="m")
        with patch("urllib.request.urlopen", fake_urlopen):
            with self.assertRaises(ProviderError) as ctx:
                provider.invoke("prompt", timeout=5)
        message = str(ctx.exception)
        self.assertIn("402", message)
        self.assertIn("insufficient credits", message)
        self.assertNotIn(_KEY, message)

    def test_url_error_fails_closed_without_key(self) -> None:
        def fake_urlopen(request, timeout=None):
            raise urllib.error.URLError("name resolution failed")

        provider = OpenRouterExecutor(api_key=_KEY, model="m")
        with patch("urllib.request.urlopen", fake_urlopen):
            with self.assertRaises(ProviderError) as ctx:
                provider.invoke("prompt", timeout=5)
        self.assertNotIn(_KEY, str(ctx.exception))

    def test_key_never_appears_in_result_raw(self) -> None:
        def fake_urlopen(request, timeout=None):
            return FakeResponse(_ok_body())

        provider = OpenRouterExecutor(api_key=_KEY, model="m")
        with patch("urllib.request.urlopen", fake_urlopen):
            result = provider.invoke("prompt", timeout=5)
        self.assertNotIn(_KEY, json.dumps(result.raw))
        self.assertNotIn(_KEY, repr(result))


class StructuredOutputTests(unittest.TestCase):
    def test_strictify_tightens_without_mutating(self) -> None:
        original = {
            "type": "object",
            "required": ["candidates"],
            "properties": {
                "candidates": {"type": "array", "items": {
                    "type": "object",
                    "required": ["claim"],
                    "properties": {"claim": {"type": "string"}, "why": {"type": "string"}},
                }},
                "notes": {"type": "string"},
            },
        }
        before = json.dumps(original, sort_keys=True)
        strict = strictify(original)
        self.assertEqual(json.dumps(original, sort_keys=True), before)  # not mutated
        self.assertFalse(strict["additionalProperties"])
        self.assertEqual(set(strict["required"]), {"candidates", "notes"})
        item = strict["properties"]["candidates"]["items"]
        self.assertFalse(item["additionalProperties"])
        self.assertEqual(set(item["required"]), {"claim", "why"})

    def test_response_format_sent_only_when_schema_given(self) -> None:
        bodies = []

        def fake_urlopen(request, timeout=None):
            bodies.append(json.loads(request.data.decode("utf-8")))
            return FakeResponse(_ok_body())

        provider = OpenRouterExecutor(api_key=_KEY, model="m")
        with patch("urllib.request.urlopen", fake_urlopen):
            provider.invoke("p", timeout=5)
            provider.invoke("p", timeout=5, response_schema=NODE_OUTPUT_SCHEMA)

        self.assertNotIn("response_format", bodies[0])
        rf = bodies[1]["response_format"]
        self.assertEqual(rf["type"], "json_schema")
        self.assertTrue(rf["json_schema"]["strict"])
        self.assertFalse(rf["json_schema"]["schema"]["additionalProperties"])


class EnvTests(unittest.TestCase):
    def test_env_key_and_model_are_read(self) -> None:
        with patch.dict("os.environ", {KEY_ENV: _KEY, ENV_MODEL: "env/model"}, clear=False):
            provider = OpenRouterExecutor()
        self.assertTrue(provider.available)
        self.assertEqual(provider.model, "env/model")


if __name__ == "__main__":
    unittest.main()
