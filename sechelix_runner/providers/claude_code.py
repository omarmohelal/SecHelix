"""Reasoning through an already-authenticated Claude Code CLI.

Chosen because it needs no new account and no API key: if the owner can run
``claude``, the runner can reason. Nothing about SecHelix is bound to it -- this
is one implementation of :class:`~sechelix_runner.providers.base.ProviderExecutor`
and the evidence contracts never mention a vendor.

Four things this adapter is careful about, each learned by probing the real CLI:

**No shell.** The command is a list and ``shell`` stays false, so a prompt
containing backticks, quotes or semicolons is data. A prompt is built from
repository content, which is exactly the input that must never reach a shell.

**Fresh session per call.** ``--resume`` and ``--continue`` are never passed, so
two nodes cannot share conversation memory. That is what makes the independent
verifier independent: if it inherited the hunter's session it would be reviewing
a conclusion it had already been told, not reconstructing one.

**Warnings are not JSON.** The CLI prints a stdin warning before its JSON when
stdin is a pipe. stdin is redirected from devnull and the parser finds the first
balanced object rather than assuming stdout starts with ``{``.

**Accounting is copied, never estimated.** ``modelUsage`` reports the canonical
model, provider, token counts and ``costUSD``; those are passed through
verbatim. Anything the host does not report stays ``None``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any

from .base import ProviderError, ProviderResult

#: Permission mode for every invocation. ``plan`` is the most restrictive mode
#: that still lets the model read and reason: it cannot edit files or run
#: commands. A reasoning node has no business doing either.
_PERMISSION_MODE = "plan"

#: Tools denied to every reasoning node.
#:
#: Not a safety measure -- ``plan`` mode already prevents writes. This preserves
#: the least-context guarantee. A node is given a projected view of the target
#: precisely so its answer is attributable to that view; a node that can read
#: the whole repository has silently reacquired the full context the projection
#: exists to withhold, and the context digest recorded against its output would
#: no longer describe what it actually saw.
#:
#: Denying tools does not stop the model *attempting* one, and an attempt costs
#: a turn. That is why ``max_turns`` defaults to 4 rather than 1: turn one may be
#: a denied tool call, and the answer arrives on a later turn. With ``max_turns
#: 1`` the CLI exited ``error_max_turns`` having produced nothing -- while still
#: charging for the attempt.
_DENIED_TOOLS = (
    "Bash", "Edit", "Write", "Read", "Glob", "Grep", "NotebookEdit",
    "WebFetch", "WebSearch", "Task", "TodoWrite",
)


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
        """Terminate an in-flight invocation, if any."""
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

        # Parse before checking the exit code. A non-zero exit still carries a
        # full envelope naming the reason (`error_max_turns`, `error_during_
        # execution`) and the cost already incurred. Discarding it would report
        # a useless truncated blob and lose spend that genuinely happened.
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

        if process.returncode != 0 or envelope.get("is_error"):
            reason = envelope.get("subtype") or envelope.get("terminal_reason") or "unknown"
            spent = envelope.get("total_cost_usd")
            spent_note = f"; {spent:.4f} USD already spent" if isinstance(spent, (int, float)) else ""
            raise ProviderError(
                f"provider did not complete ({reason}), "
                f"stop_reason={envelope.get('stop_reason')}{spent_note}"
            )

        model, provider, cost, input_tokens, output_tokens = _accounting(envelope)
        return ProviderResult(
            text=str(envelope.get("result", "")),
            model=model,
            provider=provider,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
            session_id=envelope.get("session_id"),
            raw={k: envelope.get(k) for k in ("subtype", "num_turns", "stop_reason")},
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

    # One node is one request, so there is normally a single model here. If a
    # host ever reports several, the counts are summed and the canonical names
    # joined rather than one being picked arbitrarily.
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
