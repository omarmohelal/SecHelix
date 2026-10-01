"""Reasoning through the local Nexus orchestration CLI.

SecHelix remains the evidence authority. Nexus only selects and runs a reasoning
lane and returns one structured assistant message. Each invocation is isolated,
read-only, uses Nexus safe permissions, disables Nexus persistence, and never
uses a shell.

On Windows, npm commonly resolves Nexus to a CMD shim. This adapter refuses an
unknown batch shape and invokes the referenced Node entry point directly.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any

from ..roles import NodeRole
from .base import ProviderError, ProviderResult


_NPM_NODE_TARGET = re.compile(
    r'["%]dp0[%]?[\\/](?P<target>[^"\\r\\n]+?\\.js)"',
    re.IGNORECASE,
)

_NEXUS_ROLE_FOR_NODE: dict[NodeRole, str] = {
    NodeRole.MAPPER: "repo-explorer",
    NodeRole.ARCHITECTURE: "architect",
    NodeRole.AUTHENTICATION: "security-engineer",
    NodeRole.AUTHORIZATION: "security-engineer",
    NodeRole.BUSINESS_LOGIC: "security-engineer",
    NodeRole.INJECTION_DATAFLOW: "security-engineer",
    NodeRole.API_PROTOCOL: "security-engineer",
    NodeRole.BROWSER: "security-engineer",
    NodeRole.FILES_PARSERS: "security-engineer",
    NodeRole.SUPPLY_CHAIN: "security-engineer",
    NodeRole.CLOUD_CONFIGURATION: "security-engineer",
    NodeRole.AI_MCP: "security-engineer",
    NodeRole.RUNTIME_VERIFICATION: "security-engineer",
    NodeRole.VARIANT_HUNTER: "security-engineer",
    NodeRole.INDEPENDENT_VERIFIER: "review",
    NodeRole.REMEDIATOR: "lead-engineer",
    NodeRole.PATCH_VERIFIER: "qa-engineer",
    NodeRole.RELEASE_GATE: "release-engineer",
}


class NexusCliExecutor:
    """Route one no-tools SecHelix reasoning node through Nexus."""

    name = "nexus"

    def __init__(
        self,
        *,
        binary: str | None = None,
        lane: str | None = None,
        role: str = "security-engineer",
    ) -> None:
        self.binary = (
            binary
            or os.environ.get("NEXUS_CLI")
            or shutil.which("nexus")
            or "nexus"
        )
        self.lane = lane
        self.role = role
        self._process: subprocess.Popen[str] | None = None

    @property
    def available(self) -> bool:
        path = shutil.which(self.binary) or self.binary
        return Path(path).is_file()

    def cancel(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            process.kill()

    def _launch_prefix(self) -> list[str]:
        resolved = shutil.which(self.binary) or self.binary
        path = Path(resolved)
        if os.name != "nt" or path.suffix.lower() not in {".cmd", ".bat"}:
            return [str(path)]

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ProviderError(f"cannot read Nexus npm shim: {exc}") from exc

        match = _NPM_NODE_TARGET.search(text)
        if match is None:
            raise ProviderError(
                "Nexus resolves to an unrecognized Windows batch shim; refusing "
                "to pass a security prompt through cmd.exe"
            )
        raw_target = match.group("target").replace("%~dp0", "").replace("%dp0%", "")
        raw_target = raw_target.lstrip("\\/")
        target = (
            path.parent / Path(raw_target.replace("\\", os.sep))
        ).resolve()
        if not target.is_file():
            raise ProviderError(f"Nexus npm shim target does not exist: {target}")
        node = shutil.which("node")
        if not node:
            raise ProviderError(
                "Node.js is required to invoke the Nexus npm shim safely"
            )
        return [node, str(target)]

    def invoke_for_role(
        self,
        node_role: NodeRole,
        prompt: str,
        *,
        timeout: float = 300.0,
    ) -> ProviderResult:
        """Use Nexus role staffing while keeping verifier routing independent."""
        role = _NEXUS_ROLE_FOR_NODE.get(node_role, self.role)
        lane = self.lane
        if node_role is NodeRole.INDEPENDENT_VERIFIER:
            lane = os.environ.get("SECHELIX_NEXUS_VERIFIER_LANE") or None
        return self._invoke(prompt, timeout=timeout, role=role, lane=lane)

    def invoke(self, prompt: str, *, timeout: float = 300.0) -> ProviderResult:
        return self._invoke(prompt, timeout=timeout, role=self.role, lane=self.lane)

    def _invoke(
        self,
        prompt: str,
        *,
        timeout: float,
        role: str,
        lane: str | None,
    ) -> ProviderResult:
        if not self.available:
            raise ProviderError(
                f"{self.binary} not found; install/link Nexus or choose another executor"
            )
        if timeout <= 0:
            raise ProviderError("provider timeout must be positive")

        minutes = max(1, int((timeout + 59) // 60))
        command = [
            *self._launch_prefix(),
            "review",
            prompt,
            "--read-only",
            "--permission",
            "safe",
            "--no-session",
            "--no-checkpoints",
            "--json",
            "--timeout",
            str(minutes),
            "--role",
            role,
        ]
        if lane:
            command.extend(["--lane", lane])

        process: subprocess.Popen[str] | None = None
        try:
            with tempfile.TemporaryDirectory(
                prefix="sechelix-nexus-"
            ) as cwd, open(os.devnull, "rb") as devnull:
                process = subprocess.Popen(
                    command,
                    stdin=devnull,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=cwd,
                    shell=False,
                )
                self._process = process
                try:
                    stdout, stderr = process.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                    raise ProviderError(
                        f"Nexus provider timed out after {timeout:.0f}s"
                    ) from None
        except OSError as exc:
            raise ProviderError(f"could not start Nexus: {exc}") from exc
        finally:
            self._process = None

        if process is None:
            raise ProviderError("Nexus process did not start")

        messages, task_status, usage = _parse_nexus_events(stdout)
        if process.returncode != 0 or task_status not in {None, "done"}:
            detail = (stderr or stdout or "").strip()[-500:]
            raise ProviderError(
                f"Nexus did not complete (exit={process.returncode}, "
                f"task_status={task_status or 'unknown'}): "
                f"{detail or 'no output'}"
            )
        if not messages:
            raise ProviderError("Nexus produced no assistant.message event")

        last = messages[-1]
        payload = last.get("payload", {})
        model = _string(payload.get("model")) or _string(usage.get("model"))
        provider = _string(usage.get("provider")) or _string(payload.get("lane"))
        use = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
        if not use:
            use = usage.get("usage") if isinstance(usage.get("usage"), dict) else {}

        return ProviderResult(
            text=str(payload.get("text", "")),
            model=model,
            provider=provider,
            input_tokens=_int(use.get("inputTokens")),
            output_tokens=_int(use.get("outputTokens")),
            cost_usd=_number(use.get("costUsd")),
            raw={
                "host": "nexus",
                "lane": payload.get("lane"),
                "event_schema": last.get("v"),
                "task_status": task_status,
            },
        )


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _number(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def _parse_nexus_events(
    stdout: str,
) -> tuple[list[dict[str, Any]], str | None, dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    status: str | None = None
    usage: dict[str, Any] = {}

    for number, line in enumerate((stdout or "").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProviderError(
                f"Nexus JSONL contains invalid JSON on line {number}: {exc}"
            ) from exc
        if not isinstance(event, dict):
            raise ProviderError(f"Nexus JSONL line {number} is not an object")
        event_type = event.get("type")
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        if event_type == "assistant.message":
            messages.append(event)
        elif event_type == "task.end":
            raw = payload.get("status")
            status = raw if isinstance(raw, str) else status
        elif event_type == "usage":
            usage = payload

    return messages, status, usage


__all__ = ["NexusCliExecutor", "_parse_nexus_events"]
