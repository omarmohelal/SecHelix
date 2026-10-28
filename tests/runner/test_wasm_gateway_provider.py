"""Wasm gateway provider contract tests (no network).

Parsing is shared with OpenRouter and covered there; these tests pin the
wasm-specific request shape (conservative, standard OpenAI chat completion, no
OpenRouter-only fields), the defaults, and the key-safety boundary.
"""

from __future__ import annotations

import io
import json
import unittest
import urllib.error
from unittest.mock import patch

from sechelix_runner.providers.base import ProviderError
from sechelix_runner.providers.wasm_gateway import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    KEY_ENV,
    WasmGatewayExecutor,
)

_KEY = "wasm-SECRETKEY-never-appears"


class FakeResponse:
    def __init__(self, payload: str, status: int = 200) -> None:
        self._payload = payload.encode("utf-8")
        self.status = status

    def read(self) -> bytes:
        return self._payload

    def close(self) -> None:
        pass


def _ok_body() -> str:
    return json.dumps(
        {
            "id": "cmpl-1",
            "model": DEFAULT_MODEL,
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3},
        }
    )


class WasmGatewayTests(unittest.TestCase):
    def test_defaults(self) -> None:
        provider = WasmGatewayExecutor(api_key=_KEY)
        self.assertEqual(provider.base_url, DEFAULT_BASE_URL)
        self.assertEqual(provider.model, DEFAULT_MODEL)
        self.assertTrue(provider.available)

    def test_missing_key_fails_closed(self) -> None:
        provider = WasmGatewayExecutor(api_key=None)
        provider.api_key = None
        self.assertFalse(provider.available)
        with self.assertRaises(ProviderError):
            provider.invoke("prompt", timeout=1)

    def test_request_is_conservative_openai_shape(self) -> None:
        captured = {}

        def fake_urlopen(request, timeout=None):
            captured["url"] = request.full_url
            captured["auth"] = request.headers.get("Authorization")
            captured["headers"] = dict(request.headers)
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse(_ok_body())

        provider = WasmGatewayExecutor(api_key=_KEY)
        with patch("urllib.request.urlopen", fake_urlopen):
            result = provider.invoke("analyze", timeout=5)

        self.assertEqual(result.provider, "wasm-gateway")
        self.assertEqual(result.text, "ok")
        self.assertEqual(captured["url"], f"{DEFAULT_BASE_URL}/chat/completions")
        self.assertEqual(captured["auth"], f"Bearer {_KEY}")
        # Conservative: only model + messages, none of OpenRouter's extras.
        self.assertEqual(set(captured["body"].keys()), {"model", "messages"})
        # No OpenRouter attribution headers.
        self.assertNotIn("Http-referer", captured["headers"])
        self.assertNotIn("X-title", captured["headers"])

    def test_http_error_without_key_leak(self) -> None:
        err = urllib.error.HTTPError(
            url=f"{DEFAULT_BASE_URL}/chat/completions",
            code=401,
            msg="Unauthorized",
            hdrs=None,
            fp=io.BytesIO(json.dumps({"error": {"message": "bad key"}}).encode()),
        )

        def fake_urlopen(request, timeout=None):
            raise err

        provider = WasmGatewayExecutor(api_key=_KEY)
        with patch("urllib.request.urlopen", fake_urlopen):
            with self.assertRaises(ProviderError) as ctx:
                provider.invoke("prompt", timeout=5)
        message = str(ctx.exception)
        self.assertIn("401", message)
        self.assertNotIn(_KEY, message)

    def test_env_key_is_read(self) -> None:
        with patch.dict("os.environ", {KEY_ENV: _KEY}, clear=False):
            provider = WasmGatewayExecutor()
        self.assertTrue(provider.available)


if __name__ == "__main__":
    unittest.main()
