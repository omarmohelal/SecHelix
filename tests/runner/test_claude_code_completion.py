"""Regression tests for Claude Code CLI completion semantics.

A real Windows Claude Code 2.1.248 run returned a non-zero process status while
the JSON envelope reported ``subtype=success`` and ``stop_reason=stop_sequence``.
That is a usable text completion, not evidence that the reasoning node failed.
The adapter accepts only that narrow compatibility case; truncation, tool
continuation and explicit error envelopes still fail closed.
"""

import unittest

from sechelix_runner.providers.claude_code import _completion_problem


class ClaudeCompletionSemanticsTests(unittest.TestCase):
    def test_nonzero_success_stop_sequence_is_usable(self) -> None:
        envelope = {
            "subtype": "success",
            "stop_reason": "stop_sequence",
            "is_error": False,
            "result": '{"candidates": []}',
        }
        self.assertIsNone(_completion_problem(envelope, 1))

    def test_nonzero_success_end_turn_is_usable(self) -> None:
        envelope = {
            "subtype": "success",
            "stop_reason": "end_turn",
            "is_error": False,
            "result": '{"candidates": []}',
        }
        self.assertIsNone(_completion_problem(envelope, 1))

    def test_nonzero_max_tokens_stays_fail_closed(self) -> None:
        envelope = {
            "subtype": "success",
            "stop_reason": "max_tokens",
            "is_error": False,
            "result": '{"candidates": [',
        }
        problem = _completion_problem(envelope, 1)
        self.assertIsNotNone(problem)
        self.assertIn("max_tokens", problem)

    def test_nonzero_tool_use_stays_fail_closed(self) -> None:
        envelope = {
            "subtype": "success",
            "stop_reason": "tool_use",
            "is_error": False,
            "result": "tool pending",
        }
        self.assertIsNotNone(_completion_problem(envelope, 1))

    def test_nonzero_success_requires_a_result(self) -> None:
        envelope = {
            "subtype": "success",
            "stop_reason": "stop_sequence",
            "is_error": False,
            "result": "   ",
        }
        self.assertIsNotNone(_completion_problem(envelope, 1))

    def test_explicit_error_always_wins_even_with_zero_exit(self) -> None:
        envelope = {
            "subtype": "error_during_execution",
            "stop_reason": "stop_sequence",
            "is_error": True,
            "result": '{"candidates": []}',
        }
        self.assertIsNotNone(_completion_problem(envelope, 0))

    def test_zero_exit_keeps_historical_success_behavior(self) -> None:
        envelope = {
            "subtype": "success",
            "stop_reason": "stop_sequence",
            "is_error": False,
            "result": '{"candidates": []}',
        }
        self.assertIsNone(_completion_problem(envelope, 0))


if __name__ == "__main__":
    unittest.main()
