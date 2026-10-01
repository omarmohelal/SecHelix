from __future__ import annotations

import json
import subprocess
import unittest
from unittest.mock import PropertyMock, patch

from sechelix_runner.providers.base import ProviderError
from sechelix_runner.providers.nexus_cli import NexusCliExecutor, _parse_nexus_events
from sechelix_runner.roles import NodeRole


def event(event_type: str, payload: dict[str, object]) -> str:
    return json.dumps({"v": 2, "type": event_type, "payload": payload})


class NexusEventParserTests(unittest.TestCase):
    def test_extracts_final_message_status_and_usage(self) -> None:
        stdout = "\n".join(
            [
                event("task.start", {"taskId": "t1"}),
                event(
                    "assistant.message",
                    {
                        "taskId": "t1",
                        "lane": "qwen-local",
                        "model": "qwen3.8-27b",
                        "text": '{"candidates": [], "examined": ["AUTHZ"], "notes": ""}',
                    },
                ),
                event(
                    "usage",
                    {
                        "lane": "qwen-local",
                        "provider": "local",
                        "model": "qwen3.8-27b",
                        "usage": {"inputTokens": 120, "outputTokens": 30, "costUsd": 0},
                    },
                ),
                event("task.end", {"taskId": "t1", "status": "done", "lane": "qwen-local"}),
            ]
        )
        messages, status, usage = _parse_nexus_events(stdout)
        self.assertEqual(status, "done")
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["payload"]["model"], "qwen3.8-27b")
        self.assertEqual(usage["provider"], "local")

    def test_invalid_jsonl_fails_closed(self) -> None:
        with self.assertRaisesRegex(ProviderError, "invalid JSON"):
            _parse_nexus_events('{"type":"task.start"}\nnot-json')


class _FakeProcess:
    returncode = 0

    def __init__(self, command: list[str], **kwargs) -> None:
        self.command = command

    def communicate(self, timeout: float | None = None):
        del timeout
        stdout = "\n".join(
            [
                event(
                    "assistant.message",
                    {
                        "taskId": "t1",
                        "lane": "qwen-local",
                        "model": "qwen3.8-27b",
                        "text": '{"candidates": [], "examined": [], "notes": ""}',
                        "usage": {"inputTokens": 10, "outputTokens": 5},
                    },
                ),
                event("task.end", {"taskId": "t1", "status": "done", "lane": "qwen-local"}),
            ]
        )
        return stdout, ""

    def poll(self):
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9


class NexusExecutorTests(unittest.TestCase):
    def test_invocation_is_read_only_safe_and_has_no_session(self) -> None:
        captured: list[str] = []

        def fake_popen(command, **kwargs):
            captured.extend(command)
            self.assertFalse(kwargs.get("shell"))
            return _FakeProcess(command, **kwargs)

        executor = NexusCliExecutor(binary="/usr/bin/nexus", lane="qwen-local")
        with patch.object(type(executor), "available", new_callable=PropertyMock, return_value=True), patch.object(
            executor, "_launch_prefix", return_value=["/usr/bin/nexus"]
        ), patch(
            "sechelix_runner.providers.nexus_cli.subprocess.Popen",
            side_effect=fake_popen,
        ):
            result = executor.invoke("return JSON only", timeout=30)

        self.assertEqual(result.model, "qwen3.8-27b")
        self.assertEqual(result.input_tokens, 10)
        self.assertIn("review", captured)
        self.assertIn("--read-only", captured)
        self.assertIn("--permission", captured)
        self.assertIn("safe", captured)
        self.assertIn("--no-session", captured)
        self.assertIn("--no-checkpoints", captured)
        self.assertIn("--json", captured)
        self.assertIn("--lane", captured)
        self.assertIn("qwen-local", captured)

    def test_architecture_role_routes_to_nexus_architect(self) -> None:
        captured: list[str] = []

        def fake_popen(command, **kwargs):
            captured.extend(command)
            return _FakeProcess(command, **kwargs)

        executor = NexusCliExecutor(binary="/usr/bin/nexus", lane="qwen-local")
        with patch.object(
            type(executor), "available", new_callable=PropertyMock, return_value=True
        ), patch.object(
            executor, "_launch_prefix", return_value=["/usr/bin/nexus"]
        ), patch(
            "sechelix_runner.providers.nexus_cli.subprocess.Popen",
            side_effect=fake_popen,
        ):
            executor.invoke_for_role(NodeRole.ARCHITECTURE, "x", timeout=30)

        role_index = captured.index("--role")
        self.assertEqual(captured[role_index + 1], "architect")
        self.assertIn("qwen-local", captured)

    def test_verifier_does_not_inherit_worker_lane_pin(self) -> None:
        captured: list[str] = []

        def fake_popen(command, **kwargs):
            captured.extend(command)
            return _FakeProcess(command, **kwargs)

        executor = NexusCliExecutor(binary="/usr/bin/nexus", lane="worker-model")
        with patch.dict("os.environ", {}, clear=False), patch.object(
            type(executor), "available", new_callable=PropertyMock, return_value=True
        ), patch.object(
            executor, "_launch_prefix", return_value=["/usr/bin/nexus"]
        ), patch(
            "sechelix_runner.providers.nexus_cli.subprocess.Popen",
            side_effect=fake_popen,
        ):
            executor.invoke_for_role(NodeRole.INDEPENDENT_VERIFIER, "x", timeout=30)

        role_index = captured.index("--role")
        self.assertEqual(captured[role_index + 1], "security-engineer")
        self.assertNotIn("--lane", captured)
        self.assertNotIn("worker-model", captured)

    def test_verifier_lane_requires_explicit_verifier_override(self) -> None:
        captured: list[str] = []

        def fake_popen(command, **kwargs):
            captured.extend(command)
            return _FakeProcess(command, **kwargs)

        executor = NexusCliExecutor(binary="/usr/bin/nexus", lane="worker-model")
        with patch.dict(
            "os.environ", {"SECHELIX_NEXUS_VERIFIER_LANE": "verified-reviewer"}
        ), patch.object(
            type(executor), "available", new_callable=PropertyMock, return_value=True
        ), patch.object(
            executor, "_launch_prefix", return_value=["/usr/bin/nexus"]
        ), patch(
            "sechelix_runner.providers.nexus_cli.subprocess.Popen",
            side_effect=fake_popen,
        ):
            executor.invoke_for_role(NodeRole.INDEPENDENT_VERIFIER, "x", timeout=30)

        lane_index = captured.index("--lane")
        self.assertEqual(captured[lane_index + 1], "verified-reviewer")

    def test_failed_task_is_not_accepted(self) -> None:
        class Failed(_FakeProcess):
            def communicate(self, timeout=None):
                del timeout
                return event("task.end", {"taskId": "t1", "status": "failed", "lane": None}), "failed"

        executor = NexusCliExecutor(binary="/usr/bin/nexus")
        with patch.object(type(executor), "available", new_callable=PropertyMock, return_value=True), patch.object(
            executor, "_launch_prefix", return_value=["/usr/bin/nexus"]
        ), patch(
            "sechelix_runner.providers.nexus_cli.subprocess.Popen",
            return_value=Failed([]),
        ):
            with self.assertRaisesRegex(ProviderError, "did not complete"):
                executor.invoke("x", timeout=30)


if __name__ == "__main__":
    unittest.main()
