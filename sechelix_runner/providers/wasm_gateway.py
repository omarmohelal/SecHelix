"""Reasoning through the wasm OpenAI-compatible gateway (ai.wasmjsvm.com).

A second HTTP provider, built on the same fail-closed primitives as
:mod:`sechelix_runner.providers.openrouter`. The brief is explicit that this
gateway may not implement every OpenAI feature, so the request is deliberately
**conservative**: a plain ``model`` + ``messages`` chat completion, no
OpenRouter-only fields (``usage.include``) and no attribution headers. Anything
the gateway does not support therefore cannot silently change the request shape.

Its real capability matrix (tool calling, streaming, JSON mode, token
accounting) is **unverified** until a key is present: run
``scripts/probe_provider.py --key-env SECHELIX_WASM_API_KEY --base
https://ai.wasmjsvm.com/v1 --model deepseek-v4.1-flash`` and record the result in
SECHELIX-PROVIDERS.md before trusting any of them.

The key is read from the environment, confined to the ``Authorization`` header,
and never written to ``raw``, an exception, or a log line.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from .base import ProviderError, ProviderResult, strictify
from .openrouter import _parse_completion, _safe_error_body

KEY_ENV = "SECHELIX_WASM_API_KEY"
ENV_MODEL = "SECHELIX_WASM_MODEL"
ENV_BASE_URL = "SECHELIX_WASM_BASE_URL"
DEFAULT_BASE_URL = "https://ai.wasmjsvm.com/v1"
DEFAULT_MODEL = "deepseek-v4.1-flash"


class WasmGatewayExecutor:
    """Invoke one narrow reasoning task through the wasm OpenAI-compatible gateway."""

    name = "wasm-gateway"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get(KEY_ENV)
        self.model = model or os.environ.get(ENV_MODEL) or DEFAULT_MODEL
        self.base_url = (base_url or os.environ.get(ENV_BASE_URL) or DEFAULT_BASE_URL).rstrip("/")
        self._response = None

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def cancel(self) -> None:
        response = self._response
        if response is not None:
            try:
                response.close()
            except Exception:
                pass

    def invoke(
        self,
        prompt: str,
        *,
        timeout: float = 300.0,
        response_schema: dict[str, Any] | None = None,
    ) -> ProviderResult:
        if not self.api_key:
            raise ProviderError(
                f"{KEY_ENV} is not set; export a wasm gateway key or choose another executor"
            )

        request_body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
        }
        if response_schema is not None:
            # The gateway's structured-output support is unverified; send the
            # standard OpenAI shape and fail closed if the gateway rejects it.
            request_body["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "sechelix_node",
                    "strict": True,
                    "schema": strictify(response_schema),
                },
            }
        body = json.dumps(request_body).encode("utf-8")

        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )

        try:
            self._response = urllib.request.urlopen(request, timeout=timeout)  # noqa: S310 - fixed https endpoint
            try:
                status = getattr(self._response, "status", 200)
                payload = self._response.read().decode("utf-8", "replace")
            finally:
                self._response.close()
                self._response = None
        except urllib.error.HTTPError as exc:
            raise ProviderError(
                f"wasm gateway returned HTTP {exc.code}: {_safe_error_body(exc)}"
            ) from None
        except urllib.error.URLError as exc:
            raise ProviderError(f"could not reach wasm gateway: {exc.reason}") from None
        except TimeoutError:
            raise ProviderError(f"wasm gateway timed out after {timeout:.0f}s") from None

        if status < 200 or status >= 300:
            raise ProviderError(f"wasm gateway returned HTTP {status}")

        return _parse_completion(payload, fallback_model=self.model, provider="wasm-gateway")


__all__ = ["WasmGatewayExecutor", "KEY_ENV", "ENV_MODEL", "ENV_BASE_URL", "DEFAULT_BASE_URL", "DEFAULT_MODEL"]
