"""Live wasm-gateway connectivity check -- opt-in, never in CI by default.

Skipped unless SECHELIX_WASM_API_KEY is set. Run deliberately once a key exists:

    SECHELIX_WASM_API_KEY=... python -m pytest -q tests/runner/test_wasm_gateway_live.py -rs

Because the gateway's feature support is unverified, this asserts only the
baseline: a real, non-empty chat completion. Richer capabilities should be
confirmed with scripts/probe_provider.py and recorded before being relied on.
"""

from __future__ import annotations

import os
import unittest

from sechelix_runner.providers.wasm_gateway import KEY_ENV, WasmGatewayExecutor

_HAS_KEY = bool(os.environ.get(KEY_ENV))


@unittest.skipUnless(_HAS_KEY, f"{KEY_ENV} not set; skipping live wasm gateway call")
class WasmGatewayLiveTests(unittest.TestCase):
    def test_real_chat_completion(self) -> None:
        provider = WasmGatewayExecutor()
        result = provider.invoke("Reply with exactly the word: pong", timeout=60.0)
        self.assertTrue(result.text.strip(), "expected a non-empty completion")
        self.assertEqual(result.provider, "wasm-gateway")


if __name__ == "__main__":
    unittest.main()
