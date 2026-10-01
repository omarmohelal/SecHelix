"""Reasoning through the local Nexus Engineering OS.

SecHelix remains the security control plane and evidence authority. Nexus owns
provider/lane selection, failover and provider authentication. This adapter
consumes only Nexus's stable JSON event stream and never treats a Nexus/model
assertion as SecHelix verification evidence.

The boundary is intentionally narrow and fail-closed: Nexus runs from a fresh
empty directory in read-only/safe mode; checkpoints are disabled; persisted
events must use the supported event schema; any tool, command, permission or
workspace-diff event invalidates the node; and only accounting/provenance plus
the final assistant message cross into the SecHelix run record.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, Mapping

from ..roles import NodeRole
from .base import ProviderError, ProviderResult


NEXUS_EVENT_SCHEMA_VERSION = 2
NEXUS_INTEGRATION_CONTRACT = "nexus-event-stream-v2"
_MAX_STDOUT_BYTES = 8 * 1024 * 1024
_VERSION_RE = re.compile(r"\\bnexus\\s+(\\d+\\.\\d+\\.\\d+(?:[-+][0-9A-Za-z.-]+)?)\\b", re.I)

_ROLE_ROUTE: dict[NodeRole, str] = {
    NodeRole.ARCHITECTURE: "research",
    NodeRole.AUTHENTICATION: "review",
    NodeRole.AUTHORIZATION: "review",
    NodeRole.BUSINESS_LOGIC: "review",
    NodeRole.INJECTION_DATAFLOW: "review",
    NodeRole.API_PROTOCOL: "review",
    NodeRole.BROWSER: "review",
    NodeRole.RUNTIME_VERIFICATION: "review",
    NodeRole.FILES_PARSERS: "review",
    NodeRole.SUPPLY_CHAIN: "review",
    NodeRole.CLOUD_CONFIGURATION: "review",
    NodeRole.AI_MCP: "review",
    NodeRole.VARIANT_HUNTER: "review",
    NodeRole.INDEPENDENT_VERIFIER: "review",
}

_FORBIDDEN_ACTIVITY = frozenset(
    {
        "tool.start",
        "tool.end",
        "command.start",
        "command.end",
        "checkpoint.created",
        "checkpoint.restored",
        "permission.request",
        "permission.response",
    }
)


@dataclass(frozen=True)
class NexusStreamResult:
    text: str
    model: str | None
    provider: str | None
    input_tokens: int | None
    output_tokens: int | None
    cost_usd: float | None
    session_id: str | None
    raw: dict[str, Any]


def _non_negative_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _non_negative_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return result if math.isfinite(result) and result >= 0 else None


def _required_string(payload: Mapping[str, Any], key: str, event_type: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ProviderError(f"Nexus {event_type} is missing non-empty {key}")
    return value


def _parse_nexus_stream(
    stdout: str,
    *,
    returncode: int,
    requested_role: str,
    nexus_version: str,
) -> NexusStreamResult:
    """Parse the stable Nexus JSONL surface and return one provider result."""

    raw_bytes = (stdout or "").encode("utf-8", errors="replace")
    if len(raw_bytes) > _MAX_STDOUT_BYTES:
        raise ProviderError(
            f"Nexus event stream exceeded {_MAX_STDOUT_BYTES} bytes; refusing oversized output"
        )

    session_id: str | None = None
    last_ordinal = 0
    task_id: str | None = None
    task_end: dict[str, Any] | None = None
    route_chain: list[str] = []
    route_role: str | None = None
    attempts: list[dict[str, Any]] = []
    handoffs: list[dict[str, str]] = []
    messages: list[dict[str, str]] = []
    usage_events: list[dict[str, Any]] = []
    estimated_cost = 0.0
    have_estimated_cost = False
    violation: str | None = None
    event_count = 0

    for line_number, line in enumerate((stdout or "").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProviderError(
                f"Nexus stdout line {line_number} is not JSON: {exc}"
            ) from exc
        if not isinstance(event, dict):
            raise ProviderError(f"Nexus stdout line {line_number} is not an event object")

        event_type = event.get("type")
        payload = event.get("payload")
        if not isinstance(event_type, str) or not isinstance(payload, dict):
            raise ProviderError(
                f"Nexus stdout line {line_number} lacks event type/payload"
            )

        # Nexus intentionally leaves transient lane ticks unenveloped because
        # they are not session history. They carry no completion semantics.
        if "v" not in event:
            if event_type == "lane.tick":
                continue
            raise ProviderError(
                f"Nexus {event_type} arrived without a versioned event envelope"
            )

        if event.get("v") != NEXUS_EVENT_SCHEMA_VERSION:
            raise ProviderError(
                f"unsupported Nexus event schema {event.get('v')!r}; "
                f"expected {NEXUS_EVENT_SCHEMA_VERSION}"
            )
        current_session = event.get("sessionId")
        ordinal = event.get("ordinal")
        if not isinstance(current_session, str) or not current_session:
            raise ProviderError("Nexus event is missing sessionId")
        if session_id is None:
            session_id = current_session
        elif current_session != session_id:
            raise ProviderError("Nexus event stream changed sessionId mid-run")
        if not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal <= last_ordinal:
            raise ProviderError("Nexus event ordinals are missing or non-monotonic")
        last_ordinal = ordinal
        event_count += 1

        if event_type == "task.start":
            this_task = _required_string(payload, "taskId", event_type)
            if task_id is not None and this_task != task_id:
                raise ProviderError("Nexus stream contains more than one task")
            task_id = this_task
            role = _required_string(payload, "role", event_type)
            if role != requested_role:
                raise ProviderError(
                    f"Nexus routed task as role {role!r}, expected {requested_role!r}"
                )
        elif event_type == "route.selected":
            this_task = _required_string(payload, "taskId", event_type)
            if task_id is not None and this_task != task_id:
                raise ProviderError("Nexus route.selected references another task")
            route_role = _required_string(payload, "role", event_type)
            if route_role != requested_role:
                raise ProviderError(
                    f"Nexus selected role {route_role!r}, expected {requested_role!r}"
                )
            chain = payload.get("chain")
            if not isinstance(chain, list) or any(not isinstance(item, str) for item in chain):
                raise ProviderError("Nexus route.selected chain is malformed")
            route_chain = list(chain)
        elif event_type == "lane.start":
            this_task = _required_string(payload, "taskId", event_type)
            if task_id is not None and this_task != task_id:
                raise ProviderError("Nexus lane.start references another task")
            attempts.append(
                {
                    "lane": _required_string(payload, "lane", event_type),
                    "model": _required_string(payload, "model", event_type),
                    "family": _required_string(payload, "family", event_type),
                    "attempt": payload.get("attempt"),
                    "cli_version": payload.get("cliVersion")
                    if isinstance(payload.get("cliVersion"), str)
                    else None,
                }
            )
        elif event_type == "handoff":
            this_task = _required_string(payload, "taskId", event_type)
            if task_id is not None and this_task != task_id:
                raise ProviderError("Nexus handoff references another task")
            handoffs.append(
                {
                    "from": _required_string(payload, "from", event_type),
                    "to": _required_string(payload, "to", event_type),
                    "reason": _required_string(payload, "reason", event_type),
                }
            )
        elif event_type == "assistant.message":
            this_task = _required_string(payload, "taskId", event_type)
            if task_id is not None and this_task != task_id:
                raise ProviderError("Nexus assistant.message references another task")
            messages.append(
                {
                    "lane": _required_string(payload, "lane", event_type),
                    "model": _required_string(payload, "model", event_type),
                    "text": str(payload.get("text", "")),
                }
            )
        elif event_type == "usage":
            event_task = payload.get("taskId")
            if event_task is not None and (
                not isinstance(event_task, str) or (task_id is not None and event_task != task_id)
            ):
                raise ProviderError("Nexus usage event references another task")
            usage = payload.get("usage")
            if not isinstance(usage, dict):
                raise ProviderError("Nexus usage event is missing usage object")
            usage_events.append(
                {
                    "lane": _required_string(payload, "lane", event_type),
                    "provider": _required_string(payload, "provider", event_type),
                    "model": _required_string(payload, "model", event_type),
                    "input": _non_negative_int(usage.get("inputTokens")),
                    "output": _non_negative_int(usage.get("outputTokens")),
                    "cost": _non_negative_number(usage.get("costUsd")),
                }
            )
            estimate = _non_negative_number(usage.get("estimatedCostUsd"))
            if estimate is not None:
                estimated_cost += estimate
                have_estimated_cost = True
        elif event_type == "diff":
            files = payload.get("files")
            if isinstance(files, list) and files:
                violation = "Nexus emitted a workspace diff during a read-only SecHelix node"
        elif event_type in _FORBIDDEN_ACTIVITY:
            violation = (
                f"Nexus emitted {event_type}; least-context SecHelix reasoning nodes "
                "must not call tools, commands, permissions or checkpoints"
            )
        elif event_type == "task.end":
            if task_end is not None:
                raise ProviderError("Nexus stream contains multiple task.end events")
            this_task = _required_string(payload, "taskId", event_type)
            if task_id is not None and this_task != task_id:
                raise ProviderError("Nexus task.end references another task")
            task_end = dict(payload)

    if violation:
        raise ProviderError(violation)
    if task_id is None:
        raise ProviderError("Nexus stream did not contain task.start")
    if task_end is None:
        raise ProviderError("Nexus stream did not contain task.end")
    if route_role is None:
        raise ProviderError("Nexus stream did not contain route.selected")
    if returncode != 0:
        status = task_end.get("status")
        raise ProviderError(
            f"Nexus exited {returncode} with task status {status!r}; output is not usable"
        )
    if task_end.get("status") != "done":
        raise ProviderError(f"Nexus task did not complete: {task_end.get('status')!r}")

    final_lane = task_end.get("lane")
    if not isinstance(final_lane, str) or not final_lane:
        raise ProviderError("completed Nexus task has no final lane")
    final_messages = [item for item in messages if item["lane"] == final_lane]
    if not final_messages or not final_messages[-1]["text"].strip():
        raise ProviderError("completed Nexus task has no non-empty final assistant message")
    final_message = final_messages[-1]

    input_values = [row["input"] for row in usage_events if row["input"] is not None]
    output_values = [row["output"] for row in usage_events if row["output"] is not None]
    cost_values = [row["cost"] for row in usage_events if row["cost"] is not None]
    final_usage = [row for row in usage_events if row["lane"] == final_lane]
    providers = sorted({str(row["provider"]) for row in final_usage})
    models = sorted({str(row["model"]) for row in final_usage})

    family = next(
        (str(item["family"]) for item in reversed(attempts) if item["lane"] == final_lane),
        None,
    )
    return NexusStreamResult(
        text=final_message["text"],
        model="+".join(models) or final_message["model"] or None,
        provider="+".join(providers) or "nexus",
        input_tokens=sum(input_values) if input_values else None,
        output_tokens=sum(output_values) if output_values else None,
        cost_usd=sum(cost_values) if cost_values else None,
        session_id=session_id,
        raw={
            "contract": NEXUS_INTEGRATION_CONTRACT,
            "event_schema": NEXUS_EVENT_SCHEMA_VERSION,
            "nexus_version": nexus_version,
            "task_id": task_id,
            "requested_role": requested_role,
            "route_chain": route_chain,
            "final_lane": final_lane,
            "final_family": family,
            "attempts": attempts,
            "handoffs": handoffs,
            "event_count": event_count,
            "usage_event_count": len(usage_events),
            "estimated_cost_usd": estimated_cost if have_estimated_cost else None,
            "least_context_tool_events": 0,
        },
    )


class NexusCliExecutor:
    """Delegate provider/lane orchestration to Nexus through its v2 JSON stream."""

    name = "nexus-cli"

    def __init__(
        self,
        *,
        binary: str | None = None,
        lane: str | None = None,
    ) -> None:
        self.binary = binary or shutil.which("nexus") or "nexus"
        self.lane = lane
        self._process: subprocess.Popen[str] | None = None
        self._version: str | None = None

    @property
    def available(self) -> bool:
        return shutil.which(self.binary) is not None or os.path.isfile(self.binary)

    def cancel(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            process.kill()

    def invoke(self, prompt: str, *, timeout: float = 300.0) -> ProviderResult:
        return self.invoke_for_role(
            prompt,
            role=NodeRole.AUTHORIZATION,
            timeout=timeout,
        )

    def invoke_for_role(
        self,
        prompt: str,
        *,
        role: NodeRole,
        timeout: float = 300.0,
    ) -> ProviderResult:
        if not self.available:
            raise ProviderError(
                f"{self.binary} not found; install/link Nexus or choose another executor"
            )
        nexus_role = _ROLE_ROUTE.get(role)
        if nexus_role is None:
            raise ProviderError(f"Nexus routing is not defined for SecHelix role {role.value}")
        if timeout <= 0:
            raise ProviderError("Nexus timeout must be positive")

        version = self._probe_version()
        with tempfile.TemporaryDirectory(prefix="sechelix-nexus-") as tmp:
            env = os.environ.copy()
            env.pop("NEXUS_NO_SESSION", None)
            env["NO_COLOR"] = "1"
            command = [
                *self._command_prefix(),
                "run",
                prompt,
                "--json",
                "--read-only",
                "--permission",
                "safe",
                "--no-checkpoints",
                "--role",
                nexus_role,
                "--timeout",
                str(max(1, math.ceil(timeout / 60.0))),
            ]
            if self.lane:
                command += ["--lane", self.lane]

            try:
                with open(os.devnull, "rb") as devnull:
                    self._process = subprocess.Popen(  # noqa: S603 - argv only; shell=False
                        command,
                        stdin=devnull,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        cwd=tmp,
                        env=env,
                        shell=False,
                    )
                    try:
                        stdout, stderr = self._process.communicate(timeout=timeout + 15.0)
                    except subprocess.TimeoutExpired:
                        self._process.kill()
                        self._process.communicate()
                        raise ProviderError(
                            f"Nexus provider timed out after {timeout:.0f}s"
                        ) from None
            except OSError as exc:
                raise ProviderError(f"could not start Nexus: {exc}") from exc
            finally:
                process, self._process = self._process, None

        try:
            parsed = _parse_nexus_stream(
                stdout,
                returncode=process.returncode,
                requested_role=nexus_role,
                nexus_version=version,
            )
        except ProviderError as exc:
            detail = (stderr or "").strip()
            if detail:
                raise ProviderError(f"{exc}; Nexus stderr: {detail[:300]}") from None
            raise
        return ProviderResult(
            text=parsed.text,
            model=parsed.model,
            provider=parsed.provider,
            input_tokens=parsed.input_tokens,
            output_tokens=parsed.output_tokens,
            cost_usd=parsed.cost_usd,
            session_id=parsed.session_id,
            raw=parsed.raw,
        )

    def _probe_version(self) -> str:
        if self._version is not None:
            return self._version
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv; shell=False
                [*self._command_prefix(), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ProviderError(f"could not probe Nexus version: {exc}") from exc
        text = (completed.stdout or completed.stderr or "").strip()
        match = _VERSION_RE.search(text)
        if completed.returncode != 0 or match is None:
            raise ProviderError(
                f"Nexus version probe failed (exit={completed.returncode}): {text[:200]!r}"
            )
        self._version = match.group(1)
        return self._version

    def _command_prefix(self) -> list[str]:
        resolved = shutil.which(self.binary) or self.binary
        suffix = Path(resolved).suffix.lower()
        if os.name != "nt" or suffix not in {".cmd", ".bat"}:
            return [resolved]

        node = shutil.which("node")
        if not node:
            raise ProviderError("Nexus resolved to an npm batch shim but node is unavailable")
        shim_dir = Path(resolved).resolve().parent
        package_dir = shim_dir / "node_modules" / "@thenexus" / "nexus"
        manifest = package_dir / "package.json"
        if not manifest.is_file():
            raise ProviderError(
                "Nexus npm batch shim could not be resolved without a shell; "
                "re-link @thenexus/nexus or pass a native/JS-safe nexus executable"
            )
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProviderError(f"Nexus package manifest is unreadable: {exc}") from exc
        if data.get("name") != "@thenexus/nexus":
            raise ProviderError("Nexus npm shim package identity does not match @thenexus/nexus")
        declared = data.get("bin")
        entry_value: str | None = None
        if isinstance(declared, dict) and isinstance(declared.get("nexus"), str):
            entry_value = declared["nexus"]
        elif isinstance(declared, str):
            entry_value = declared
        if not entry_value:
            raise ProviderError("Nexus package manifest has no nexus bin entry")
        root = package_dir.resolve()
        entry = (package_dir / entry_value).resolve()
        try:
            entry.relative_to(root)
        except ValueError as exc:
            raise ProviderError("Nexus bin entry escapes its package directory") from exc
        if not entry.is_file():
            raise ProviderError("Nexus bin entry does not exist")
        return [node, str(entry)]


__all__ = [
    "NEXUS_EVENT_SCHEMA_VERSION",
    "NEXUS_INTEGRATION_CONTRACT",
    "NexusCliExecutor",
]
