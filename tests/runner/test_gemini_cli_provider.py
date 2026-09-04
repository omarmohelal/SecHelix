"""Gemini CLI provider contract tests.

No test here calls Gemini or the network. The provider process is replaced with a
small fake so CI proves the isolation, JSON, accounting and fail-closed
boundaries without needing an account or consuming quota.
"""

from __future__ import annotations

import ast
import inspect
import json
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from sechelix_runner.providers.base import ProviderError
from sechelix_runner.providers import gemini_cli
from sechelix_runner.providers.gemini_cli import (
    GeminiCliExecutor,
    _LOCKED_SETTINGS,
    _accounting,
    _parse_envelope,
    _tool_calls,
)


class FakeProcess:
    def __init__(self, stdout: str, stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.killed = False

    def communicate(self, timeout=None):
        return self.stdout, self.stderr

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def poll(self):
        return self.returncode


class EnvelopeTests(unittest.TestCase):
    def test_leading_warning_is_tolerated(self) -> None:
        value = _parse_envelope('warning first\n{"response":"ok","stats":{}}\n')
        self.assertEqual(value["response"], "ok")

    def test_unterminated_envelope_fails_closed(self) -> None:
        with self.assertRaises(ProviderError):
            _parse_envelope('{"response":')

    def test_tool_count_is_copied_not_guessed(self) -> None:
        self.assertEqual(_tool_calls({"tools": {"totalCalls": 0}}), 0)
        self.assertEqual(_tool_calls({"tools": {"totalCalls": 3}}), 3)
        self.assertIsNone(_tool_calls({}))

    def test_model_token_accounting_sums_reported_values(self) -> None:
        model, tin, tout = _accounting(
            {
                "models": {
                    "gemini-a": {"tokens": {"input": 10, "candidates": 4}},
                    "gemini-b": {"tokens": {"input": 2, "candidates": 1}},
                }
            }
        )
        self.assertEqual((model, tin, tout), ("gemini-a+gemini-b", 12, 5))

    def test_unreported_accounting_stays_none(self) -> None:
        self.assertEqual(_accounting({}), (None, None, None))


class IsolationPolicyTests(unittest.TestCase):
    def test_system_settings_disable_ambient_capabilities(self) -> None:
        self.assertEqual(_LOCKED_SETTINGS["tools"]["core"], [])
        self.assertTrue(_LOCKED_SETTINGS["security"]["disableYoloMode"])
        self.assertTrue(_LOCKED_SETTINGS["security"]["disableAlwaysAllow"])
        self.assertTrue(_LOCKED_SETTINGS["admin"]["secureModeEnabled"])
        self.assertFalse(_LOCKED_SETTINGS["admin"]["extensions"]["enabled"])
        self.assertFalse(_LOCKED_SETTINGS["admin"]["mcp"]["enabled"])
        self.assertFalse(_LOCKED_SETTINGS["admin"]["skills"]["enabled"])
        self.assertFalse(_LOCKED_SETTINGS["telemetry"]["enabled"])
        self.assertNotEqual(_LOCKED_SETTINGS["context"]["fileName"], "GEMINI.md")

    def test_provider_popen_sets_shell_false_as_a_boolean(self) -> None:
        """Inspect syntax, not comments that may contain the phrase shell=True."""
        tree = ast.parse(textwrap.dedent(inspect.getsource(GeminiCliExecutor.invoke)))
        popen_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "Popen"
        ]
        self.assertEqual(len(popen_calls), 1)
        shell_keywords = [kw for kw in popen_calls[0].keywords if kw.arg == "shell"]
        self.assertEqual(len(shell_keywords), 1)
        value = shell_keywords[0].value
        self.assertIsInstance(value, ast.Constant)
        self.assertIs(value.value, False)

    def test_windows_npm_path_does_not_use_cmd_or_powershell_evaluation(self) -> None:
        source = inspect.getsource(gemini_cli._command).lower()
        self.assertNotIn("cmd /c", source)
        self.assertNotIn("-command", source)
        self.assertIn("node_modules", source)


class InvocationTests(unittest.TestCase):
    def _invoke(self, envelope: dict, *, returncode: int = 0):
        capture: dict = {}

        def fake_popen(command, **kwargs):
            capture["command"] = command
            capture["cwd"] = kwargs["cwd"]
            capture["shell"] = kwargs["shell"]
            capture["settings"] = json.loads(
                Path(kwargs["env"]["GEMINI_CLI_SYSTEM_SETTINGS_PATH"]).read_text(
                    encoding="utf-8"
                )
            )
            return FakeProcess(json.dumps(envelope), returncode=returncode)

        def fake_which(name):
            if str(name) in {"gemini", "/usr/bin/gemini"}:
                return "/usr/bin/gemini"
            return None

        with patch.object(gemini_cli.shutil, "which", side_effect=fake_which):
            with patch.object(gemini_cli.subprocess, "Popen", side_effect=fake_popen):
                result = GeminiCliExecutor(binary="gemini").invoke(
                    'return {"candidates": []}', timeout=5
                )
        return result, capture

    def test_success_uses_empty_cwd_locked_settings_and_no_tools(self) -> None:
        result, capture = self._invoke(
            {
                "session_id": "s",
                "response": '{"candidates": []}',
                "stats": {
                    "models": {"gemini-x": {"tokens": {"input": 7, "candidates": 3}}},
                    "tools": {"totalCalls": 0},
                },
            }
        )
        self.assertEqual(result.text, '{"candidates": []}')
        self.assertEqual(result.provider, "google-gemini-cli")
        self.assertEqual(
            (result.model, result.input_tokens, result.output_tokens),
            ("gemini-x", 7, 3),
        )
        self.assertFalse(capture["shell"])
        self.assertEqual(capture["settings"], _LOCKED_SETTINGS)
        self.assertTrue(Path(capture["cwd"]).name.startswith("sechelix-gemini-"))
        self.assertIn("--output-format", capture["command"])
        self.assertIn("json", capture["command"])

    def test_any_reported_tool_call_fails_closed(self) -> None:
        with self.assertRaisesRegex(ProviderError, "least-context violation"):
            self._invoke(
                {
                    "response": '{"candidates": []}',
                    "stats": {"tools": {"totalCalls": 1}},
                }
            )

    def test_error_envelope_fails_closed(self) -> None:
        with self.assertRaisesRegex(ProviderError, "quota"):
            self._invoke(
                {"error": {"type": "QuotaError", "message": "quota exhausted"}},
                returncode=1,
            )

    def test_empty_response_fails_closed(self) -> None:
        with self.assertRaisesRegex(ProviderError, "non-empty response"):
            self._invoke({"response": "", "stats": {"tools": {"totalCalls": 0}}})

    def test_missing_binary_reports_clearly(self) -> None:
        with patch.object(gemini_cli.shutil, "which", return_value=None):
            with patch.object(gemini_cli.os.path, "isfile", return_value=False):
                executor = GeminiCliExecutor(binary="definitely-missing-gemini")
                self.assertFalse(executor.available)
                with self.assertRaisesRegex(ProviderError, "not found"):
                    executor.invoke("hi", timeout=1)


if __name__ == "__main__":
    unittest.main()
