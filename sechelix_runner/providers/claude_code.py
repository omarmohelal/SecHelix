"""Reasoning through an already-authenticated Claude Code CLI.

The adapter keeps each reasoning call isolated, invokes the CLI without a shell,
and treats the JSON envelope as the authoritative completion record. Claude Code
versions may return a non-zero process status even when the envelope itself says
``subtype=success`` and terminates on a normal ``stop_sequence``. In that case we
accept the envelope only when it contains a non-empty result and a known natural
stop reason; downstream JSON/schema validation still fails closed if that result
is incomplete or malformed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any

from .base import ProviderError, ProviderResult

_PERMISSION_MODE = "plan"
_DENIED_TOOLS = (
    "Bash", "Edit", "Write", "Read", "Glob", "Grep", "NotebookEdit",
    "WebFetch", "WebSearch", "Task", "TodoWrite",
)

# A non-zero CLI exit may still accompany a successful JSON envelope. We only
# accept that compatibility case for stop reasons that represent a completed
# textual response. Truncation/tool continuation states stay fail-closed.
_NATURAL_STOP_REASONS = {None, "end_turn", "stop_sequence"}


class ClaudeCodeExecutor:
    """Invoke one narrow reasoning task through the local ``claude`` CLI."""

    name = "claude-code"

    def __init__(
        self,
        *,
        binary: str | None = None,
        model: str | None = None,
        max_turns: int = 4,
        cwd: str | None = None,
    ) -> None:
        self.binary = binary or shutil.which("claude") or "claude"
        self.model = model
        self.max_turns = max_turns
        self.cwd = cwd
        self._process: subprocess.Popen[str] | None = None

    @property
    def available(self) -> bool:
        return shutil.which(self.binary) is not None or os.path.isfile(self.binary)

    def cancel(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            process.kill()

    def invoke(self, prompt: str, *, timeout: float = 300.0) -> ProviderResult:
        if not self.available:
            raise ProviderError(
                f"{self.binary} not found; install Claude Code or choose another executor"
            )

        command = [
            self.binary,
            "-p",
            prompt,
            "--output-format",
            "json",
            "--max-turns",
            str(self.max_turns),
            "--permission-mode",
            _PERMISSION_MODE,
            "--disallowed-tools",
            ",".join(_DENIED_TOOLS),
        ]
        if self.model:
            command += ["--model", self.model]

        try:
            with open(os.devnull, "rb") as devnull:
                self._process = subprocess.Popen(  # noqa: S603 - list args, shell=False
                    command,
                    stdin=devnull,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=self.cwd,
                    shell=False,
                )
                try:
                    stdout, stderr = self._process.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.communicate()
                    raise ProviderError(
                        f"provider timed out after {timeout:.0f}s"
                    ) from None
        except OSError as exc:
            raise ProviderError(f"could not start {self.binary}: {exc}") from exc
        finally:
            process, self._process = self._process, None

        envelope: dict[str, Any] = {}
        try:
            envelope = _parse_envelope(stdout)
        except ProviderError:
            if process.returncode != 0:
                detail = (stderr or stdout or "").strip()[:300]
                raise ProviderError(
                    f"{self.binary} exited {process.returncode}: {detail or 'no output'}"
                ) from None
            raise

        completion_problem = _completion_problem(envelope, process.returncode)
        if completion_problem:
            spent = envelope.get("total_cost_usd")
            spent_note = (
                f"; {spent:.4f} USD already spent"
                if isinstance(spent, (int, float))
                else ""
            )
            raise ProviderError(f"{completion_problem}{spent_note}")

        model, provider, cost, input_tokens, output_tokens = _accounting(envelope)
        return ProviderResult(
            text=str(envelope.get("result", "")),
            model=model,
            provider=provider,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
            session_id=envelope.get("session_id"),
            raw={
                "subtype": envelope.get("subtype"),
                "num_turns": envelope.get("num_turns"),
                "stop_reason": envelope.get("stop_reason"),
                "exit_code": process.returncode,
            },
        )


def _completion_problem(envelope: dict[str, Any], returncode: int) -> str | None:
    """Return an error description when a CLI envelope is not a usable finish.

    ``is_error`` always wins. A zero process exit keeps the historical behavior
    and is accepted unless the envelope explicitly reports an error. For a
    non-zero process exit we require a positive success envelope, a non-empty
    result, and a natural text-completion stop reason. This handles Claude Code
    CLI versions that use a non-zero status for ``stop_sequence`` while keeping
    max-token/tool-continuation and malformed results fail-closed.
    """

    reason = envelope.get("subtype") or envelope.get("terminal_reason") or "unknown"
    stop_reason = envelope.get("stop_reason")

    if envelope.get("is_error"):
        return f"provider did not complete ({reason}), stop_reason={stop_reason}"

    if returncode == 0:
        return None

    result = envelope.get("result")
    compatible_success = (
        reason == "success"
        and stop_reason in _NATURAL_STOP_REASONS
        and isinstance(result, str)
        and bool(result.strip())
    )
    if compatible_success:
        return None

    return (
        f"provider did not complete ({reason}), stop_reason={stop_reason}, "
        f"exit_code={returncode}"
    )


def _parse_envelope(stdout: str) -> dict[str, Any]:
    """Find the CLI result object, tolerating a leading warning line."""
    text = (stdout or "").strip()
    start = text.find("{")
    if start == -1:
        raise ProviderError(f"provider produced no JSON envelope: {text[:200]!r}")
    try:
        return json.loads(text[start:])
    except json.JSONDecodeError as exc:
        raise ProviderError(f"provider envelope is not valid JSON: {exc}") from exc


def _accounting(
    envelope: dict[str, Any],
) -> tuple[str | None, str | None, float | None, int | None, int | None]:
    """Copy usage out of the envelope. Absent stays absent."""
    usage = envelope.get("modelUsage") or {}
    if not isinstance(usage, dict) or not usage:
        cost = envelope.get("total_cost_usd")
        return None, None, cost if isinstance(cost, (int, float)) else None, None, None

    models: list[str] = []
    providers: list[str] = []
    cost = 0.0
    have_cost = False
    input_tokens = 0
    output_tokens = 0
    have_tokens = False

    for key, entry in usage.items():
        if not isinstance(entry, dict):
            continue
        models.append(str(entry.get("canonicalModel") or key))
        if entry.get("provider"):
            providers.append(str(entry["provider"]))
        if isinstance(entry.get("costUSD"), (int, float)):
            cost += float(entry["costUSD"])
            have_cost = True
        if isinstance(entry.get("inputTokens"), int):
            input_tokens += entry["inputTokens"]
            have_tokens = True
        if isinstance(entry.get("outputTokens"), int):
            output_tokens += entry["outputTokens"]
            have_tokens = True

    return (
        "+".join(sorted(set(models))) or None,
        "+".join(sorted(set(providers))) or None,
        cost if have_cost else None,
        input_tokens if have_tokens else None,
        output_tokens if have_tokens else None,
    )
