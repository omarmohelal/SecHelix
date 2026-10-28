"""Live OpenRouter connectivity check -- opt-in, never run in CI by default.

This is the one test that actually reaches the network. It is skipped unless
``SECHELIX_OPENROUTER_API_KEY`` (and a model) are present, so CI and offline
contributors never hit it and never consume quota. Run it deliberately once a
key is exported:

    SECHELIX_OPENROUTER_API_KEY=... SECHELIX_OPENROUTER_MODEL=openai/gpt-4o-mini \\
        python -m pytest -q tests/runner/test_openrouter_live.py -rs

It proves real chat completion, a non-empty response, and that token accounting
comes back measured rather than guessed. The key is read from the environment
and never printed.
"""

from __future__ import annotations

import os
import unittest

from sechelix_runner.providers.openrouter import KEY_ENV, ENV_MODEL, OpenRouterExecutor

_HAS_KEY = bool(os.environ.get(KEY_ENV))
_MODEL = os.environ.get(ENV_MODEL) or "openai/gpt-4o-mini"


@unittest.skipUnless(_HAS_KEY, f"{KEY_ENV} not set; skipping live OpenRouter call")
class OpenRouterLiveTests(unittest.TestCase):
    def test_real_chat_completion(self) -> None:
        provider = OpenRouterExecutor(model=_MODEL)
        result = provider.invoke(
            "Reply with exactly the word: pong", timeout=60.0
        )
        self.assertTrue(result.text.strip(), "expected a non-empty completion")
        self.assertEqual(result.provider, "openrouter")
        # Token accounting should be measured on a real OpenRouter call.
        self.assertIsNotNone(result.input_tokens)
        self.assertIsNotNone(result.output_tokens)


if __name__ == "__main__":
    unittest.main()
