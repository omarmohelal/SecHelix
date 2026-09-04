"""Reasoning through the official Gemini CLI headless JSON interface.

This adapter invokes the official ``gemini`` executable; it does not read,
export, or reuse Gemini OAuth credentials itself. Authentication remains owned by
the CLI. Every SecHelix node is a fresh headless process.

The important boundary is least-context isolation. A reasoning node receives only
the projected Evidence block that SecHelix built for it. To keep Gemini CLI from
silently reacquiring repository or user-agent context, each invocation:

* runs from a fresh empty temporary working directory;
* supplies a highest-precedence system settings file with no core tools;
* disables MCP, extensions, skills, YOLO/always-allow behavior, and telemetry;
* changes the context filename to a SecHelix-specific impossible default so a
  normal global/project ``GEMINI.md`` is not loaded;
* verifies after the call that Gemini reported zero tool calls.

If any of those assumptions fail, the provider fails closed and downstream graph
nodes are blocked. Unreported accounting stays ``None`` rather than being
invented.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .base import ProviderError, ProviderResult


_LOCKED_SETTINGS: dict[str, Any] = {
    "context": {"fileName": "__SECHELIX_NO_CONTEXT__"},
    "tools": {"core": []},
    "security": {
        "disableYoloMode": True,
        "disableAlwaysAllow": True,
    },
    "admin": {
        "secureModeEnabled": True,
        "extensions": {"enabled": False},
        "mcp": {"enabled": False},
        "skills": {"enabled": False},
    },
    "telemetry": {"enabled": False},
}


class GeminiCliExecutor:
    """Invoke one narrow reasoning task through an authenticated Gemini CLI."""

    name = "gemini-cli"

    def __init__(
        self,
        *,
        binary: str | None = None,
        model: str | None = None,
    ) -> None:
        self.binary = binary or shutil.which("gemini") or "gemini"
        self.model = model
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
                f"{self.binary} not found; install Gemini CLI or choose another executor"
            )

        with tempfile.TemporaryDirectory(prefix="sechelix-gemini-") as tmp:
            root = Path(tmp)
            settings = root / "system-settings.json"
            settings.write_text(
                json.dumps(_LOCKED_SETTINGS, indent=2, sort_keys=True),
                encoding="utf-8",
            )

            env = os.environ.copy()
            env["GEMINI_CLI_SYSTEM_SETTINGS_PATH"] = str(settings)
            env["NO_COLOR"] = "1"

            command, env = _command(self.binary, prompt, self.model, env)

            try:
                with open(os.devnull, "rb") as devnull:
                    self._process = subprocess.Popen(  # noqa: S603 - argv/env, never shell=True
                        command,
                        stdin=devnull,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        cwd=str(root),
                        env=env,
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

        error = envelope.get("error")
        if process.returncode != 0 or error:
            if isinstance(error, dict):
                detail = error.get("message") or error.get("type") or repr(error)
            else:
                detail = str(error or (stderr or "provider error")).strip()
            raise ProviderError(
                f"provider did not complete (exit={process.returncode}): {detail[:300]}"
            )

        response = envelope.get("response")
        if not isinstance(response, str) or not response.strip():
            raise ProviderError("provider completed without a non-empty response")

        stats = envelope.get("stats") if isinstance(envelope.get("stats"), dict) else {}
        tool_calls = _tool_calls(stats)
        if tool_calls not in (None, 0):
            raise ProviderError(
                f"least-context violation: Gemini CLI reported {tool_calls} tool call(s)"
            )

        model, input_tokens, output_tokens = _accounting(stats)
        return ProviderResult(
            text=response,
            model=model or self.model,
            provider="google-gemini-cli",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=None,
            session_id=_string_or_none(envelope.get("session_id")),
            raw={
                "tool_calls": tool_calls,
                "warnings": len(envelope.get("warnings") or []),
            },
        )


def _command(
    binary: str,
    prompt: str,
    model: str | None,
    env: dict[str, str],
) -> tuple[list[str], dict[str, str]]:
    """Build a non-evaluating argv for Unix/native binaries and npm .cmd shims.

    On Windows, npm commonly exposes ``gemini.cmd``. Running a batch shim through
    ``cmd /c`` while putting an untrusted prompt on that command line would
    reintroduce shell metacharacter parsing. Instead a fixed PowerShell program
    reads the prompt/model from environment variables and splats them as
    argument values; the prompt is never parsed as code.
    """

    resolved = shutil.which(binary) or binary
    suffix = Path(resolved).suffix.lower()
    if os.name == "nt" and suffix in {".cmd", ".bat"}:
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            raise ProviderError(
                "Gemini CLI is an npm batch shim but PowerShell was not found for safe argv launch"
            )
        env = dict(env)
        env["SECHELIX_GEMINI_BINARY"] = resolved
        env["SECHELIX_GEMINI_PROMPT"] = prompt
        env["SECHELIX_GEMINI_MODEL"] = model or ""
        script = (
            "$a=@('-p',$env:SECHELIX_GEMINI_PROMPT,'--output-format','json');"
            "if($env:SECHELIX_GEMINI_MODEL){$a+=@('--model',$env:SECHELIX_GEMINI_MODEL)};"
            "& $env:SECHELIX_GEMINI_BINARY @a; exit $LASTEXITCODE"
        )
        return [powershell, "-NoProfile", "-NonInteractive", "-Command", script], env

    command = [resolved, "-p", prompt, "--output-format", "json"]
    if model:
        command += ["--model", model]
    return command, env


def _parse_envelope(stdout: str) -> dict[str, Any]:
    """Return the first balanced JSON object, tolerating a leading warning."""

    text = (stdout or "").strip()
    start = text.find("{")
    if start == -1:
        raise ProviderError(f"provider produced no JSON envelope: {text[:200]!r}")

    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    value = json.loads(text[start : index + 1])
                except json.JSONDecodeError as exc:
                    raise ProviderError(f"provider envelope is not valid JSON: {exc}") from exc
                if not isinstance(value, dict):
                    raise ProviderError("provider JSON envelope is not an object")
                return value
    raise ProviderError("provider produced an unterminated JSON envelope")


def _tool_calls(stats: dict[str, Any]) -> int | None:
    tools = stats.get("tools")
    if not isinstance(tools, dict):
        return None
    value = tools.get("totalCalls")
    return value if isinstance(value, int) else None


def _accounting(stats: dict[str, Any]) -> tuple[str | None, int | None, int | None]:
    """Copy Gemini CLI SessionMetrics without guessing absent fields."""

    models = stats.get("models")
    if not isinstance(models, dict) or not models:
        return None, None, None

    names: list[str] = []
    input_tokens = 0
    output_tokens = 0
    have_input = False
    have_output = False

    for name, metrics in models.items():
        if not isinstance(metrics, dict):
            continue
        names.append(str(name))
        tokens = metrics.get("tokens")
        if not isinstance(tokens, dict):
            continue
        value = tokens.get("input")
        if isinstance(value, int):
            input_tokens += value
            have_input = True
        value = tokens.get("candidates")
        if isinstance(value, int):
            output_tokens += value
            have_output = True

    return (
        "+".join(sorted(set(names))) or None,
        input_tokens if have_input else None,
        output_tokens if have_output else None,
    )


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


__all__ = ["GeminiCliExecutor"]
