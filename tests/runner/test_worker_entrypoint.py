from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = ROOT / "deploy" / "worker" / "entrypoint.sh"


class WorkerEntrypointStrixProviderTests(unittest.TestCase):
    def test_strix_provider_variables_are_exact_and_gated_by_enable_strix(self) -> None:
        text = ENTRYPOINT.read_text(encoding="utf-8")

        start = text.index('if [ "${WORKER_ENABLE_STRIX:-0}" = "1" ]; then')
        end = text.index("\nfi\n", start) + len("\nfi\n")
        block = text[start:end]

        for name in (
            "STRIX_LLM",
            "LLM_API_KEY",
            "LLM_API_BASE",
            "STRIX_API_TYPE",
            "STRIX_REASONING_EFFORT",
            "STRIX_OPENROUTER_STICKY_SESSIONS",
            "STRIX_CACHE_BLOCK_TOKENS",
            "STRIX_DEDUPE_MODEL",
            "DEDUPE_LLM_API_KEY",
            "DEDUPE_LLM_API_BASE",
        ):
            self.assertIn(f"--pass-env {name}", block)

        self.assertNotIn("--pass-env-prefix", block)
        self.assertNotIn("echo \"${LLM_API_KEY", block)
        self.assertNotIn("printf \"${LLM_API_KEY", block)


if __name__ == "__main__":
    unittest.main()
