"""Executable, fail-closed remediation checks for a scratch workspace.

This module does not apply patches. It executes only named regression/test
capabilities inside SecHelix's network-disabled sandbox, converts the observed
results into the canonical remediation StageResult contract, and leaves the
existing independent-verification and differential-review gates intact.

There is deliberately no generic shell/argv surface here.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Callable, Sequence

from sechelix_core.remediation import (
    FAIL,
    NOT_RUN,
    PASS,
    StageResult,
)
from sechelix_runner.proof_exec import ProofBehavior, ProofExecutionResult
from sechelix_runner.sandbox import SandboxSpec
from sechelix_runner.sandbox_exec import SandboxResult, SandboxRunner
from sechelix_runner.pentest.gateway import PolicyToolGateway, ToolOperation


class RemediationExecutionError(RuntimeError):
    """A requested remediation check is unsafe or malformed."""


_TARGET = re.compile(r"^[A-Za-z0-9_./:-]+$")


@dataclass(frozen=True)
class NamedTestSpec:
    """One fixed-shape, sandboxed test capability.

    The first V5 slice supports Python unittest because SecHelix itself can
    exercise this path without a package-manager/network bootstrap. Additional
    ecosystems must be added as separate named builders, not by exposing a
    generic command.
    """

    capability: str
    targets: tuple[str, ...]
    timeout_seconds: float = 180.0

    def __post_init__(self) -> None:
        if self.capability != "python-unittest":
            raise RemediationExecutionError(
                f"unsupported remediation test capability {self.capability!r}"
            )
        if not self.targets:
            raise RemediationExecutionError("at least one unittest target is required")
        if not 1 <= self.timeout_seconds <= 900:
            raise RemediationExecutionError("timeout_seconds must be between 1 and 900")
        for target in self.targets:
            value = str(target).strip()
            if not value or not _TARGET.fullmatch(value) or ".." in Path(value).parts:
                raise RemediationExecutionError(
                    f"unsafe unittest target {target!r}; targets must be simple "
                    "module/file identifiers inside the scratch workspace"
                )

    def command(self) -> tuple[str, ...]:
        return ("python", "-m", "unittest", "-q", *self.targets)


@dataclass(frozen=True)
class ExecutedCheck:
    stage: StageResult
    capability: str
    command: tuple[str, ...]
    exit_code: int | None
    timed_out: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage.as_dict(),
            "capability": self.capability,
            "command": list(self.command),
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
        }


class RemediationCheckRunner:
    """Run named checks against only a supplied scratch workspace."""

    def __init__(
        self,
        workspace: Path | str,
        *,
        sandbox_runner: SandboxRunner | None = None,
    ) -> None:
        self.workspace = Path(workspace).resolve()
        if not self.workspace.is_absolute():
            raise RemediationExecutionError("scratch workspace must be absolute")
        if str(self.workspace) in {self.workspace.anchor, "/"}:
            raise RemediationExecutionError("filesystem root cannot be a remediation workspace")
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.gateway = PolicyToolGateway(
            repository_root=self.workspace,
            evidence_log=self.workspace / ".sechelix-remediation-tool-decisions.jsonl",
        )
        self.sandbox_runner = sandbox_runner or SandboxRunner(
            SandboxSpec(network_enabled=False)
        )

    def run_test(self, stage_name: str, spec: NamedTestSpec) -> ExecutedCheck:
        if stage_name not in {"existing_tests", "vulnerability_regression"}:
            raise RemediationExecutionError(
                "named test execution is limited to existing_tests and "
                "vulnerability_regression stages"
            )
        command = spec.command()
        self.gateway.authorize(
            ToolOperation(
                tool="remediation-test",
                target=str(self.workspace),
                network=False,
                risk="LOW",
                evidence_output=f"{stage_name}.json",
                purpose=f"bounded {stage_name} execution in remediation scratch workspace",
                metadata={"capability": spec.capability},
            )
        )
        result = self.sandbox_runner.run(
            command,
            workspace=self.workspace,
            timeout=spec.timeout_seconds,
        )
        stage = _stage_from_sandbox(stage_name, result)
        return ExecutedCheck(
            stage=stage,
            capability=spec.capability,
            command=command,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
        )


def _stage_from_sandbox(stage_name: str, result: SandboxResult) -> StageResult:
    if result.timed_out:
        return StageResult(stage_name, FAIL, "sandboxed test timed out")
    if result.exit_code == 0:
        return StageResult(stage_name, PASS, "sandboxed named test passed")
    return StageResult(
        stage_name,
        FAIL,
        f"sandboxed named test failed with exit code {result.exit_code}",
    )


def regression_stage_from_proof(result: ProofExecutionResult) -> StageResult:
    """Translate a bounded original-proof replay into remediation semantics."""

    if result.behavior is ProofBehavior.SECURE_BEHAVIOR:
        return StageResult(
            "vulnerability_regression",
            PASS,
            "original bounded proof now observes secure behavior",
        )
    if result.behavior is ProofBehavior.VULNERABLE_BEHAVIOR:
        return StageResult(
            "vulnerability_regression",
            FAIL,
            "original bounded proof still observes vulnerable behavior",
        )
    return StageResult(
        "vulnerability_regression",
        NOT_RUN,
        "original proof replay was inconclusive or blocked; remediation cannot "
        "claim the vulnerability regression passed",
    )
