from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from sechelix_runner.pentest.scope import ScopeEndpoint, ScopeError, TargetScope
from sechelix_runner.pentest.strix_adapter import (
    StrixAdapterError,
    StrixEngine,
    normalize_strix_vulnerabilities,
    write_strix_result,
)
from sechelix_runner.sandbox import ExecutionMode


def local_scope() -> TargetScope:
    return TargetScope(
        primary_url="http://127.0.0.1:3000",
        mode=ExecutionMode.LOCAL,
        endpoints=(ScopeEndpoint("127.0.0.1", ("http",), (3000,)),),
    )


def staging_scope() -> TargetScope:
    return TargetScope(
        primary_url="https://staging.example.com",
        mode=ExecutionMode.STAGING,
        endpoints=(ScopeEndpoint("staging.example.com"),),
        ownership_verified=True,
        verification_method="dns-txt",
    )


def fake_strix_process(
    workspace: Path,
    *,
    returncode: int,
    status: str,
    findings: list[dict[str, object]],
):
    def fake_run(command, **kwargs):
        if command[0] != "strix" or command[1] != "-n":
            raise AssertionError("Strix must run through the headless adapter")
        if kwargs.get("shell") is not False:
            raise AssertionError("Strix must never run through a shell")
        run_dir = workspace / "strix_runs" / "run-001"
        run_dir.mkdir(parents=True)
        (run_dir / "run.json").write_text(
            json.dumps({"status": status}),
            encoding="utf-8",
        )
        (run_dir / "vulnerabilities.json").write_text(
            json.dumps(findings),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(
            command,
            returncode,
            stdout="raw output not persisted",
            stderr="",
        )

    return fake_run


class StrixAdapterTests(unittest.TestCase):
    def test_local_loopback_builds_headless_bounded_command_without_proof(self) -> None:
        command = StrixEngine().build_command(
            scope=local_scope(),
            scan_mode="quick",
            max_turns=50,
        )
        self.assertEqual(
            command[:5],
            (
                "strix",
                "-n",
                "--target",
                "http://127.0.0.1:3000",
                "--scan-mode",
            ),
        )
        self.assertEqual(command[5], "quick")
        self.assertEqual(command[6:8], ("--max-turns", "50"))
        self.assertNotIn("--target-list", command)
        self.assertNotIn("--resume", command)
        self.assertIn("--instruction", command)
        self.assertIn("127.0.0.1", command[-1])

    def test_non_loopback_cannot_hide_behind_local_mode(self) -> None:
        scope = TargetScope(
            primary_url="https://example.com",
            mode=ExecutionMode.LOCAL,
            endpoints=(ScopeEndpoint("example.com"),),
        )
        with self.assertRaisesRegex(ScopeError, "ownership/authorization proof"):
            StrixEngine().build_command(scope=scope)

    def test_verified_staging_target_is_allowed(self) -> None:
        command = StrixEngine().build_command(scope=staging_scope())
        self.assertEqual(command[2:4], ("--target", "https://staging.example.com"))

    def test_invalid_scan_modes_are_refused(self) -> None:
        for mode in ("", "turbo", "QUICKEST"):
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(StrixAdapterError, "scan_mode"):
                    StrixEngine().build_command(scope=local_scope(), scan_mode=mode)

    def test_invalid_turn_budgets_are_refused(self) -> None:
        for turns in (0, -1, 5001):
            with self.subTest(turns=turns):
                with self.assertRaisesRegex(StrixAdapterError, "max_turns"):
                    StrixEngine().build_command(scope=local_scope(), max_turns=turns)

    def test_invalid_cost_budgets_are_refused(self) -> None:
        for budget in (0, -1, float("inf")):
            with self.subTest(budget=budget):
                with self.assertRaisesRegex(StrixAdapterError, "max_budget_usd"):
                    StrixEngine().build_command(
                        scope=local_scope(),
                        max_budget_usd=budget,
                    )

    def test_production_active_testing_remains_refused(self) -> None:
        scope = TargetScope(
            primary_url="https://example.com",
            mode=ExecutionMode.PRODUCTION,
            endpoints=(ScopeEndpoint("example.com"),),
            ownership_verified=True,
            verification_method="dns-txt",
        )
        with self.assertRaisesRegex(ScopeError, "PRODUCTION"):
            StrixEngine().build_command(scope=scope)

    def test_finding_is_neutralized_and_does_not_carry_raw_poc(self) -> None:
        rows = [
            {
                "id": "vuln-0001",
                "title": "Broken object authorization",
                "severity": "high",
                "cwe": ["CWE-639"],
                "endpoint": "https://staging.example.com/api/orders/1",
                "method": "GET",
                "poc_script_code": "SECRET_EXPLOIT_PAYLOAD()",
                "technical_analysis": "model conclusion must not become evidence",
                "code_locations": [{"file": "src/orders.py", "line": 42}],
            }
        ]
        candidates = normalize_strix_vulnerabilities(
            rows,
            payload_sha256="sha256:" + "a" * 64,
            run_name="run-test",
        )
        self.assertEqual(len(candidates), 1)
        item = candidates[0]
        self.assertEqual(item["status"], "CANDIDATE")
        self.assertEqual(item["assessment"], "UNASSESSED")
        self.assertEqual(item["verification"], "UNASSESSED")
        self.assertEqual(item["source"]["tool"], "strix")
        self.assertEqual(item["location"], {"path": "src/orders.py", "line": 42})
        self.assertFalse(item["tool_signal"]["trusted_for_assessment"])
        self.assertEqual(item["tool_signal"]["cwe"], ["CWE-639"])
        self.assertTrue(item["properties"]["poc_script_available"])
        rendered = json.dumps(item)
        self.assertNotIn("SECRET_EXPLOIT_PAYLOAD", rendered)
        self.assertNotIn("model conclusion must not become evidence", rendered)

    def test_exit_two_with_completed_run_is_successful_candidate_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = StrixEngine()
            fake = fake_strix_process(
                root,
                returncode=2,
                status="completed",
                findings=[
                    {
                        "id": "vuln-1",
                        "title": "Candidate",
                        "endpoint": "http://127.0.0.1:3000/a",
                    }
                ],
            )
            with patch.object(engine, "available", return_value=True), patch(
                "sechelix_runner.pentest.strix_adapter.subprocess.run",
                side_effect=fake,
            ):
                result = engine.run(scope=local_scope(), cwd=root, timeout=10)

            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.run_status, "completed")
            self.assertTrue(result.succeeded)
            self.assertTrue(result.vulnerabilities_found)
            self.assertEqual(len(result.candidates), 1)
            self.assertTrue((root / "tool-decisions.jsonl").is_file())

    def test_stopped_budget_run_never_counts_as_complete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = StrixEngine()
            with patch.object(engine, "available", return_value=True), patch(
                "sechelix_runner.pentest.strix_adapter.subprocess.run",
                side_effect=fake_strix_process(
                    root,
                    returncode=0,
                    status="stopped",
                    findings=[],
                ),
            ):
                result = engine.run(scope=local_scope(), cwd=root, timeout=10)
            self.assertFalse(result.succeeded)
            self.assertFalse(result.vulnerabilities_found)

    def test_run_refuses_to_reuse_stale_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stale = root / "strix_runs" / "old"
            stale.mkdir(parents=True)
            (stale / "run.json").write_text(
                '{"status":"completed"}',
                encoding="utf-8",
            )
            (stale / "vulnerabilities.json").write_text("[]", encoding="utf-8")

            engine = StrixEngine()
            with patch.object(engine, "available", return_value=True), patch(
                "sechelix_runner.pentest.strix_adapter.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    ["strix"],
                    1,
                    "",
                    "fatal",
                ),
            ):
                with self.assertRaisesRegex(StrixAdapterError, "fresh run directory"):
                    engine.run(scope=local_scope(), cwd=root, timeout=10)

    def test_normalized_handoff_does_not_persist_stdout_stderr_or_poc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = StrixEngine()
            with patch.object(engine, "available", return_value=True), patch(
                "sechelix_runner.pentest.strix_adapter.subprocess.run",
                side_effect=fake_strix_process(
                    root,
                    returncode=2,
                    status="completed",
                    findings=[
                        {
                            "id": "vuln-1",
                            "title": "Candidate",
                            "poc_script_code": "DO_NOT_COPY_THIS",
                        }
                    ],
                ),
            ):
                result = engine.run(scope=local_scope(), cwd=root, timeout=10)

            output = root / "normalized.json"
            write_strix_result(output, result)
            rendered = output.read_text(encoding="utf-8")
            self.assertNotIn("DO_NOT_COPY_THIS", rendered)
            self.assertNotIn("raw output not persisted", rendered)
            self.assertIn('"stdout_persisted": false', rendered)


if __name__ == "__main__":
    unittest.main()
