from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from sechelix_runner.pentest.scope import ScopeEndpoint, ScopeError, TargetScope
from sechelix_runner.pentest.strix_adapter import (
    STRIX_TESTED_UPSTREAM_COMMIT,
    STRIX_TESTED_VERSION,
    StrixAdapterError,
    StrixEngine,
    StrixEngineHealth,
    _default_health_timeout,
    _prepare_fcc_strix_environment,
    coverage_out_of_scope_hosts,
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


STRIX_HELP = (
    "usage: strix [--non-interactive] --target TARGET "
    "--scan-mode MODE --max-turns N --max-budget USD --instruction TEXT"
)


def fake_strix_process(
    workspace: Path,
    *,
    returncode: int,
    status: str,
    findings: list[dict[str, object]],
    version: str = STRIX_TESTED_VERSION,
    help_text: str = STRIX_HELP,
    write_vulnerability_index: bool = True,
    coverage: dict | None = None,
):
    def fake_run(command, **kwargs):
        if kwargs.get("shell") is not False:
            raise AssertionError("Strix must never run through a shell")
        if command == ["strix", "--version"]:
            return subprocess.CompletedProcess(
                command,
                0,
                f"Strix {version}\n",
                "",
            )
        if command == ["strix", "--help"]:
            return subprocess.CompletedProcess(command, 0, help_text, "")
        if command[0] != "strix" or command[1] != "-n":
            raise AssertionError("Strix must run through the headless adapter")
        run_dir = workspace / "strix_runs" / "run-001"
        run_dir.mkdir(parents=True)
        (run_dir / "run.json").write_text(
            json.dumps({"status": status}),
            encoding="utf-8",
        )
        if write_vulnerability_index:
            (run_dir / "vulnerabilities.json").write_text(
                json.dumps(findings),
                encoding="utf-8",
            )
        if coverage is not None:
            (run_dir / "coverage.json").write_text(
                json.dumps(coverage),
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
    def test_engine_health_accepts_only_the_tested_upstream_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = StrixEngine()
            with patch.object(engine, "available", return_value=True), patch(
                "sechelix_runner.pentest.strix_adapter.subprocess.run",
                side_effect=fake_strix_process(
                    Path(tmp),
                    returncode=0,
                    status="completed",
                    findings=[],
                ),
            ):
                health = engine.health()

        self.assertTrue(health.compatible)
        self.assertEqual(health.compatibility, "TESTED")
        self.assertEqual(health.version, STRIX_TESTED_VERSION)
        self.assertEqual(
            health.tested_upstream_commit,
            STRIX_TESTED_UPSTREAM_COMMIT,
        )
        self.assertEqual(health.missing_flags, ())

    def test_engine_health_rejects_an_untested_upstream_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = StrixEngine()
            with patch.object(engine, "available", return_value=True), patch(
                "sechelix_runner.pentest.strix_adapter.subprocess.run",
                side_effect=fake_strix_process(
                    Path(tmp),
                    returncode=0,
                    status="completed",
                    findings=[],
                    version="1.6.3",
                ),
            ):
                health = engine.health()
                self.assertEqual(health.compatibility, "UNTESTED_VERSION")
                with self.assertRaisesRegex(StrixAdapterError, "has not passed"):
                    engine.require_compatible()

    def test_engine_health_rejects_required_flag_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = StrixEngine()
            help_without_instruction = STRIX_HELP.replace("--instruction TEXT", "")
            with patch.object(engine, "available", return_value=True), patch(
                "sechelix_runner.pentest.strix_adapter.subprocess.run",
                side_effect=fake_strix_process(
                    Path(tmp),
                    returncode=0,
                    status="completed",
                    findings=[],
                    help_text=help_without_instruction,
                ),
            ):
                health = engine.health()

        self.assertFalse(health.compatible)
        self.assertEqual(health.compatibility, "INCOMPATIBLE_CLI")
        self.assertIn("--instruction", health.missing_flags)

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

    def test_fcc_preflight_falls_back_to_first_tool_capable_model(self) -> None:
        env = {
            "SECHELIX_STRIX_USE_FCC": "1",
            "FCC_BASE_URL": "http://127.0.0.1:8082/v1",
            "SECHELIX_STRIX_FCC_MODEL": "anthropic/open_router/z-ai/glm-5.3",
            "SECHELIX_STRIX_FCC_MODELS": (
                "anthropic/open_router/z-ai/glm-5.3,"
                "anthropic/open_router/qwen/qwen3.8-27b"
            ),
        }
        with patch(
            "sechelix_runner.pentest.strix_adapter._probe_fcc_tool_model",
            side_effect=[
                (False, "no structured ping function_call was observed"),
                (True, "structured function_call verified"),
            ],
        ) as probe:
            selected = _prepare_fcc_strix_environment(env)

        self.assertEqual(probe.call_count, 2)
        self.assertEqual(
            selected["SECHELIX_STRIX_FCC_MODEL"],
            "anthropic/open_router/qwen/qwen3.8-27b",
        )
        self.assertEqual(
            selected["STRIX_LLM"],
            "openai/anthropic/open_router/qwen/qwen3.8-27b",
        )
        self.assertEqual(selected["STRIX_FORCE_API"], "responses")
        self.assertEqual(selected["LLM_DISABLE_STREAMING"], "false")
        self.assertEqual(selected["LLM_API_KEY"], "sechelix-fcc-local-noauth")
        self.assertEqual(selected["OPENAI_API_KEY"], "sechelix-fcc-local-noauth")

    def test_fcc_preflight_overrides_stale_disable_streaming(self) -> None:
        env = {
            "SECHELIX_STRIX_USE_FCC": "1",
            "FCC_BASE_URL": "http://127.0.0.1:8082/v1",
            "SECHELIX_STRIX_FCC_MODEL": "anthropic/open_router/qwen/qwen3.8-27b",
            "LLM_DISABLE_STREAMING": "true",
        }
        with patch(
            "sechelix_runner.pentest.strix_adapter._probe_fcc_tool_model",
            return_value=(True, "structured function_call verified"),
        ):
            selected = _prepare_fcc_strix_environment(env)

        self.assertEqual(selected["LLM_DISABLE_STREAMING"], "false")

    def test_fcc_run_uses_stream_backed_compatibility_runner(self) -> None:
        captured: dict[str, object] = {}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = StrixEngine()

            def fake_run(command, **kwargs):
                if command == ["strix", "--version"]:
                    return subprocess.CompletedProcess(command, 0, "Strix 1.6.2\n", "")
                if command == ["strix", "--help"]:
                    return subprocess.CompletedProcess(command, 0, STRIX_HELP, "")
                captured["command"] = tuple(command)
                captured["env"] = dict(kwargs.get("env") or {})
                run_dir = root / "strix_runs" / "run-fcc"
                run_dir.mkdir(parents=True)
                (run_dir / "run.json").write_text(
                    json.dumps({"status": "completed"}), encoding="utf-8"
                )
                (run_dir / "vulnerabilities.json").write_text("[]", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch.object(engine, "available", return_value=True), patch(
                "sechelix_runner.pentest.strix_adapter._probe_fcc_tool_model",
                return_value=(True, "structured function_call verified"),
            ), patch(
                "sechelix_runner.pentest.strix_adapter.subprocess.run",
                side_effect=fake_run,
            ):
                result = engine.run(
                    scope=local_scope(),
                    cwd=root,
                    timeout=10,
                    env={
                        "SECHELIX_STRIX_USE_FCC": "1",
                        "FCC_BASE_URL": "http://127.0.0.1:8082/v1",
                        "SECHELIX_STRIX_FCC_MODEL": "anthropic/open_router/qwen/qwen3.8-27b",
                    },
                )

        command = captured["command"]
        self.assertEqual(command[:3], (
            sys.executable,
            "-m",
            "sechelix_runner.pentest.strix_fcc_runner",
        ))
        self.assertEqual(command[3], "-n")
        self.assertTrue(result.succeeded)

    def test_fcc_preflight_preserves_dedicated_gateway_key(self) -> None:
        env = {
            "SECHELIX_STRIX_USE_FCC": "1",
            "FCC_BASE_URL": "http://127.0.0.1:8082/v1",
            "SECHELIX_STRIX_FCC_MODEL": "anthropic/open_router/qwen/qwen3.8-27b",
            "SECHELIX_PENTEST_FCC_API_KEY": "EXAMPLE_LOCAL_GATEWAY_TOKEN",
        }
        with patch(
            "sechelix_runner.pentest.strix_adapter._probe_fcc_tool_model",
            return_value=(True, "structured function_call verified"),
        ):
            selected = _prepare_fcc_strix_environment(env)

        self.assertEqual(selected["LLM_API_KEY"], "EXAMPLE_LOCAL_GATEWAY_TOKEN")
        self.assertEqual(selected["OPENAI_API_KEY"], "EXAMPLE_LOCAL_GATEWAY_TOKEN")

    def test_fcc_preflight_refuses_remote_gateway(self) -> None:
        with self.assertRaisesRegex(StrixAdapterError, "trusted local FCC base URL"):
            _prepare_fcc_strix_environment(
                {
                    "SECHELIX_STRIX_USE_FCC": "1",
                    "FCC_BASE_URL": "https://provider.example/v1",
                    "SECHELIX_STRIX_FCC_MODEL": "model",
                }
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

    def test_normalizer_rejects_out_of_scope_endpoint_from_untrusted_strix_output(self) -> None:
        rows = [
            {
                "id": "vuln-escape",
                "title": "Redirected candidate",
                "endpoint": "https://third-party.example/api",
            }
        ]
        with self.assertRaisesRegex(StrixAdapterError, "outside the approved pentest scope"):
            normalize_strix_vulnerabilities(
                rows,
                payload_sha256="sha256:" + "b" * 64,
                run_name="run-test",
                scope=staging_scope(),
            )

    def test_normalizer_accepts_in_scope_endpoint_when_scope_is_supplied(self) -> None:
        rows = [
            {
                "id": "vuln-ok",
                "title": "Scoped candidate",
                "endpoint": "https://staging.example.com/api/orders/1",
            }
        ]
        candidates = normalize_strix_vulnerabilities(
            rows,
            payload_sha256="sha256:" + "c" * 64,
            run_name="run-test",
            scope=staging_scope(),
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0]["properties"]["endpoint"],
            "https://staging.example.com/api/orders/1",
        )

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

    def test_completed_clean_run_without_vulnerability_index_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = StrixEngine()
            with patch.object(engine, "available", return_value=True), patch(
                "sechelix_runner.pentest.strix_adapter.subprocess.run",
                side_effect=fake_strix_process(
                    root,
                    returncode=0,
                    status="completed",
                    findings=[],
                    write_vulnerability_index=False,
                ),
            ):
                result = engine.run(scope=local_scope(), cwd=root, timeout=10)

        self.assertTrue(result.succeeded)
        self.assertEqual(result.candidates, ())
        self.assertFalse(result.vulnerability_index_present)
        self.assertEqual(result.payload_sha256, "sha256:" + hashlib.sha256(b"[]").hexdigest())

    def test_coverage_out_of_scope_hosts_flags_sibling_surfaces(self) -> None:
        coverage = {
            "schema_version": 1,
            "scope": {"targets": [{"original": "http://127.0.0.1:3000"}]},
            "entries": [
                {"surface": "http://127.0.0.1:3000 (authenticated API)"},
                {"surface": "http://127.0.0.1:9999 (sibling admin service)"},
            ],
            "gaps": [
                {"surface": 'ws://127.0.0.1:8070 (WebSocket "SiblingServer")'},
                {"surface": "http://evil.example.com/ (third-party host in a link)"},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "coverage.json").write_text(json.dumps(coverage), encoding="utf-8")
            escaped = coverage_out_of_scope_hosts(run_dir, local_scope())
        self.assertEqual(
            escaped,
            (
                "http://127.0.0.1:9999",
                "http://evil.example.com/",
                "ws://127.0.0.1:8070",
            ),
        )

    def test_coverage_out_of_scope_hosts_accepts_in_scope_only(self) -> None:
        coverage = {
            "entries": [{"surface": "http://127.0.0.1:3000 (authenticated API)"}],
            "gaps": [{"surface": "http://127.0.0.1:3000/reports (needs follow-up)"}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "coverage.json").write_text(json.dumps(coverage), encoding="utf-8")
            self.assertEqual(coverage_out_of_scope_hosts(run_dir, local_scope()), ())

    def test_missing_coverage_is_not_treated_as_a_scope_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(coverage_out_of_scope_hosts(Path(tmp), local_scope()), ())

    def test_health_timeout_override_is_bounded(self) -> None:
        import os
        from unittest.mock import patch as _patch

        cases = {"": 5.0, "20": 20.0, "30": 30.0, "0": 5.0, "-1": 5.0, "99": 5.0, "x": 5.0}
        for raw, expected in cases.items():
            with _patch.dict(os.environ, {"SECHELIX_STRIX_HEALTH_TIMEOUT": raw}):
                self.assertEqual(_default_health_timeout(), expected)

    def test_coverage_guard_allows_sandbox_aliases_under_isolation(self) -> None:
        coverage = {
            "entries": [
                {"surface": "http://sechelix-target:8077 (target via proxy)"},
                {"surface": "http://sechelix-gateway:8082/v1 (reasoning gateway)"},
            ],
            "gaps": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "coverage.json").write_text(json.dumps(coverage), encoding="utf-8")
            # Without the alias allowlist the proxy hostnames look out of scope.
            self.assertTrue(coverage_out_of_scope_hosts(run_dir, local_scope()))
            # Under isolated-network containment the aliases are legitimate.
            self.assertEqual(
                coverage_out_of_scope_hosts(
                    run_dir,
                    local_scope(),
                    allowed_hosts=frozenset({"sechelix-target", "sechelix-gateway"}),
                ),
                (),
            )

    def test_normalizer_allows_sandbox_alias_endpoint_under_isolation(self) -> None:
        rows = [{"id": "v1", "title": "x", "endpoint": "http://sechelix-target:8077/api"}]
        with self.assertRaisesRegex(StrixAdapterError, "outside the approved pentest scope"):
            normalize_strix_vulnerabilities(
                rows, payload_sha256="sha256:0", run_name="r", scope=local_scope()
            )
        out = normalize_strix_vulnerabilities(
            rows,
            payload_sha256="sha256:0",
            run_name="r",
            scope=local_scope(),
            allowed_hosts=frozenset({"sechelix-target"}),
        )
        self.assertEqual(len(out), 1)

    def test_completed_run_that_escaped_scope_is_refused(self) -> None:
        coverage = {
            "entries": [
                {"surface": "http://127.0.0.1:3000 (target)"},
                {"surface": "http://127.0.0.1:8082 (sibling LLM gateway)"},
            ],
            "gaps": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = StrixEngine()
            with patch.object(engine, "available", return_value=True), patch(
                "sechelix_runner.pentest.strix_adapter.subprocess.run",
                side_effect=fake_strix_process(
                    root,
                    returncode=0,
                    status="completed",
                    findings=[],
                    write_vulnerability_index=False,
                    coverage=coverage,
                ),
            ):
                with self.assertRaisesRegex(
                    StrixAdapterError,
                    r"outside the authorized scope: http://127\.0\.0\.1:8082",
                ):
                    engine.run(scope=local_scope(), cwd=root, timeout=10)

    def test_completed_run_with_in_scope_coverage_is_accepted(self) -> None:
        coverage = {
            "entries": [{"surface": "http://127.0.0.1:3000 (target)"}],
            "gaps": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = StrixEngine()
            with patch.object(engine, "available", return_value=True), patch(
                "sechelix_runner.pentest.strix_adapter.subprocess.run",
                side_effect=fake_strix_process(
                    root,
                    returncode=0,
                    status="completed",
                    findings=[],
                    write_vulnerability_index=False,
                    coverage=coverage,
                ),
            ):
                result = engine.run(scope=local_scope(), cwd=root, timeout=10)
        self.assertTrue(result.succeeded)

    def test_findings_exit_without_vulnerability_index_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = StrixEngine()
            with patch.object(engine, "available", return_value=True), patch(
                "sechelix_runner.pentest.strix_adapter.subprocess.run",
                side_effect=fake_strix_process(
                    root,
                    returncode=2,
                    status="completed",
                    findings=[{"id": "vuln-1", "title": "Candidate"}],
                    write_vulnerability_index=False,
                ),
            ):
                with self.assertRaisesRegex(
                    StrixAdapterError,
                    "reported findings but vulnerabilities.json is missing",
                ):
                    engine.run(scope=local_scope(), cwd=root, timeout=10)

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
                with self.assertRaisesRegex(StrixAdapterError, "not complete"):
                    engine.run(scope=local_scope(), cwd=root, timeout=10)

    def test_failed_process_artifacts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = StrixEngine()
            with patch.object(engine, "available", return_value=True), patch(
                "sechelix_runner.pentest.strix_adapter.subprocess.run",
                side_effect=fake_strix_process(
                    root,
                    returncode=1,
                    status="completed",
                    findings=[{"id": "should-not-import", "title": "Partial"}],
                ),
            ):
                with self.assertRaisesRegex(StrixAdapterError, "unexpected status 1"):
                    engine.run(scope=local_scope(), cwd=root, timeout=10)

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
            compatible = StrixEngineHealth(
                available=True,
                executable="strix",
                resolved_executable="strix",
                version=STRIX_TESTED_VERSION,
                compatibility="TESTED",
            )
            with patch.object(
                engine,
                "require_compatible",
                return_value=compatible,
            ), patch(
                "sechelix_runner.pentest.strix_adapter.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    ["strix"],
                    1,
                    "",
                    "fatal",
                ),
            ):
                with self.assertRaisesRegex(StrixAdapterError, "unexpected status 1"):
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


class FailClosedContainmentGate(unittest.TestCase):
    """A protected (isolated) scan is accepted only if containment is proven.

    These exercise the adapter's fail-closed gate deterministically, with the
    real docker lifecycle replaced by a controllable ``firewalled_strix_sandbox``
    stand-in (acceptance criterion A).
    """

    @staticmethod
    def _fake_containment(*, failure=None, contained=False):
        import contextlib as _contextlib

        from sechelix_runner.pentest.strix_sandbox_net import FirewalledSandbox

        @_contextlib.contextmanager
        def _cm(**_kwargs):
            state = FirewalledSandbox(target_port=3000)
            state.saw_sandbox = True
            state.failure = failure
            if contained:
                state.contained.set()
            yield state

        return _cm

    def _run_isolated(self, fake_cm):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = StrixEngine()
            with patch.object(engine, "available", return_value=True), patch(
                "sechelix_runner.pentest.strix_adapter.subprocess.run",
                side_effect=fake_strix_process(
                    root, returncode=0, status="completed", findings=[]
                ),
            ), patch(
                "sechelix_runner.pentest.strix_adapter.firewalled_strix_sandbox",
                side_effect=fake_cm,
            ):
                return engine.run(
                    scope=local_scope(),
                    cwd=root,
                    timeout=10,
                    env={"SECHELIX_STRIX_ISOLATE_NETWORK": "1"},
                )

    def test_refused_when_containment_fails(self) -> None:
        cm = self._fake_containment(failure="egress is not bounded")
        with self.assertRaises(StrixAdapterError) as ctx:
            self._run_isolated(cm)
        self.assertIn("containment failed", str(ctx.exception))

    def test_refused_when_containment_never_proven(self) -> None:
        cm = self._fake_containment(failure=None, contained=False)
        with self.assertRaises(StrixAdapterError) as ctx:
            self._run_isolated(cm)
        self.assertIn("never proven", str(ctx.exception))

    def test_accepted_when_containment_proven(self) -> None:
        cm = self._fake_containment(contained=True)
        result = self._run_isolated(cm)
        self.assertTrue(result.succeeded)


if __name__ == "__main__":
    unittest.main()
