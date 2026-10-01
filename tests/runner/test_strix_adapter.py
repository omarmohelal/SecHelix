from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

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


def test_local_loopback_builds_headless_bounded_strix_command_without_proof() -> None:
    command = StrixEngine().build_command(
        scope=local_scope(),
        scan_mode="quick",
        max_turns=50,
    )
    assert command[:5] == (
        "strix",
        "-n",
        "--target",
        "http://127.0.0.1:3000",
        "--scan-mode",
    )
    assert command[5] == "quick"
    assert command[6:8] == ("--max-turns", "50")
    assert "--target-list" not in command
    assert "--resume" not in command
    assert "--instruction" in command
    assert "127.0.0.1" in command[-1]


def test_non_loopback_cannot_hide_behind_local_mode() -> None:
    scope = TargetScope(
        primary_url="https://example.com",
        mode=ExecutionMode.LOCAL,
        endpoints=(ScopeEndpoint("example.com"),),
    )
    with pytest.raises(ScopeError, match="ownership/authorization proof"):
        StrixEngine().build_command(scope=scope)


def test_verified_staging_target_is_allowed() -> None:
    command = StrixEngine().build_command(scope=staging_scope())
    assert command[2:4] == ("--target", "https://staging.example.com")


@pytest.mark.parametrize("mode", ["", "turbo", "QUICKEST"])
def test_invalid_scan_mode_is_refused(mode: str) -> None:
    with pytest.raises(StrixAdapterError, match="scan_mode"):
        StrixEngine().build_command(scope=local_scope(), scan_mode=mode)


@pytest.mark.parametrize("turns", [0, -1, 5001])
def test_invalid_turn_budget_is_refused(turns: int) -> None:
    with pytest.raises(StrixAdapterError, match="max_turns"):
        StrixEngine().build_command(scope=local_scope(), max_turns=turns)


@pytest.mark.parametrize("budget", [0, -1, float("inf")])
def test_invalid_cost_budget_is_refused(budget: float) -> None:
    with pytest.raises(StrixAdapterError, match="max_budget_usd"):
        StrixEngine().build_command(scope=local_scope(), max_budget_usd=budget)


def test_production_active_testing_remains_refused() -> None:
    scope = TargetScope(
        primary_url="https://example.com",
        mode=ExecutionMode.PRODUCTION,
        endpoints=(ScopeEndpoint("example.com"),),
        ownership_verified=True,
        verification_method="dns-txt",
    )
    with pytest.raises(ScopeError, match="PRODUCTION"):
        StrixEngine().build_command(scope=scope)


def test_strix_finding_is_neutralized_and_does_not_carry_raw_poc() -> None:
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
    assert len(candidates) == 1
    item = candidates[0]
    assert item["status"] == "CANDIDATE"
    assert item["assessment"] == "UNASSESSED"
    assert item["verification"] == "UNASSESSED"
    assert item["source"]["tool"] == "strix"
    assert item["location"] == {"path": "src/orders.py", "line": 42}
    assert item["tool_signal"]["trusted_for_assessment"] is False
    assert item["tool_signal"]["cwe"] == ["CWE-639"]
    assert item["properties"]["poc_script_available"] is True
    assert "SECRET_EXPLOIT_PAYLOAD" not in json.dumps(item)
    assert "model conclusion must not become evidence" not in json.dumps(item)


def _fake_strix_process(
    workspace: Path,
    *,
    returncode: int,
    status: str,
    findings: list[dict],
):
    def fake_run(command, **kwargs):
        assert command[0] == "strix"
        assert command[1] == "-n"
        assert kwargs["shell"] is False
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


def test_exit_two_with_completed_run_is_successful_candidate_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = StrixEngine()
    monkeypatch.setattr(engine, "available", lambda: True)
    monkeypatch.setattr(
        "sechelix_runner.pentest.strix_adapter.subprocess.run",
        _fake_strix_process(
            tmp_path,
            returncode=2,
            status="completed",
            findings=[
                {
                    "id": "vuln-1",
                    "title": "Candidate",
                    "endpoint": "http://127.0.0.1:3000/a",
                }
            ],
        ),
    )
    result = engine.run(scope=local_scope(), cwd=tmp_path, timeout=10)

    assert result.returncode == 2
    assert result.run_status == "completed"
    assert result.succeeded is True
    assert result.vulnerabilities_found is True
    assert len(result.candidates) == 1
    assert (tmp_path / "tool-decisions.jsonl").is_file()


def test_stopped_budget_run_never_counts_as_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = StrixEngine()
    monkeypatch.setattr(engine, "available", lambda: True)
    monkeypatch.setattr(
        "sechelix_runner.pentest.strix_adapter.subprocess.run",
        _fake_strix_process(
            tmp_path,
            returncode=0,
            status="stopped",
            findings=[],
        ),
    )
    result = engine.run(scope=local_scope(), cwd=tmp_path, timeout=10)
    assert result.succeeded is False
    assert result.vulnerabilities_found is False


def test_run_refuses_to_reuse_stale_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stale = tmp_path / "strix_runs" / "old"
    stale.mkdir(parents=True)
    (stale / "run.json").write_text('{"status":"completed"}', encoding="utf-8")
    (stale / "vulnerabilities.json").write_text("[]", encoding="utf-8")

    engine = StrixEngine()
    monkeypatch.setattr(engine, "available", lambda: True)
    monkeypatch.setattr(
        "sechelix_runner.pentest.strix_adapter.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1, "", "fatal"),
    )
    with pytest.raises(StrixAdapterError, match="fresh run directory"):
        engine.run(scope=local_scope(), cwd=tmp_path, timeout=10)


def test_normalized_handoff_does_not_persist_stdout_stderr_or_poc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = StrixEngine()
    monkeypatch.setattr(engine, "available", lambda: True)
    monkeypatch.setattr(
        "sechelix_runner.pentest.strix_adapter.subprocess.run",
        _fake_strix_process(
            tmp_path,
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
    )
    result = engine.run(scope=local_scope(), cwd=tmp_path, timeout=10)
    output = tmp_path / "normalized.json"
    write_strix_result(output, result)
    rendered = output.read_text(encoding="utf-8")
    assert "DO_NOT_COPY_THIS" not in rendered
    assert "raw output not persisted" not in rendered
    assert '"stdout_persisted": false' in rendered
