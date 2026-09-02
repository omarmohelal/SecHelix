"""Running something inside the sandbox.

:mod:`sechelix_runner.sandbox` decides policy. This executes it, and only when a
container runtime is actually present -- ``STATIC`` never needs one, so Docker's
absence degrades the available modes rather than failing a run.

Nothing here relaxes the policy. :class:`~sechelix_runner.sandbox.SandboxSpec`
is validated before a container starts and a spec with problems is refused, so
the only way to loosen confinement is to construct a spec that says so out loud
and then watch it be rejected.

The container is not a security boundary this project would bet a customer on.
It is defence in depth around code that is already only reading files. What it
is genuinely good at is making the *default* safe: no network, no capabilities,
no writes outside a workspace, bounded processes and memory.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .sandbox import SandboxSpec


class SandboxUnavailable(RuntimeError):
    """No container runtime is available."""


class SandboxRefused(PermissionError):
    """The spec would not be safe to run."""


@dataclass
class SandboxResult:
    """What happened inside the container."""

    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    command: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def to_dict(self) -> dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout": self.stdout[-4000:],
            "stderr": self.stderr[-4000:],
            "command": list(self.command),
        }


def runtime_available(binary: str = "docker") -> bool:
    """Whether a usable container runtime is present *and* its daemon is up.

    The binary existing is not enough: a Docker CLI with no running engine is
    the common case on a developer laptop, and reporting it as available would
    turn every sandbox call into a confusing connection error.
    """
    if shutil.which(binary) is None:
        return False
    try:
        probe = subprocess.run(  # noqa: S603 - list args, shell=False
            [binary, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=20, shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0 and bool(probe.stdout.strip())


def _container_user() -> str:
    """The uid:gid the container runs as. Never root, and able to write the mount.

    A hardcoded ``1000:1000`` is wrong on Linux: a bind-mounted host directory
    keeps its host ownership, so a container running as some other uid cannot
    write to its own workspace. Docker Desktop on Windows and macOS hides this
    by translating ownership at the mount layer, which is exactly why the bug
    only appeared on a Linux CI runner.

    On POSIX the invoking user is used so the mount lines up. Root falls back to
    a non-root id rather than running privileged, accepting that a root-owned
    workspace then needs its permissions relaxed by the caller.
    """
    getuid = getattr(os, "getuid", None)
    if getuid is None:  # Windows: Docker Desktop translates ownership anyway.
        return "1000:1000"
    uid, gid = getuid(), os.getgid()
    if uid == 0:
        return "1000:1000"
    return f"{uid}:{gid}"


class SandboxRunner:
    """Executes a command under a validated :class:`SandboxSpec`."""

    def __init__(self, spec: SandboxSpec | None = None, *, binary: str = "docker") -> None:
        self.spec = spec or SandboxSpec()
        self.binary = binary

    def build_command(self, argv: Sequence[str], *, workspace: Path | None = None) -> list[str]:
        """The full ``docker run`` invocation, so a caller can log or assert it."""
        problems = self.spec.validate()
        if problems:
            raise SandboxRefused("; ".join(problems))

        command = [self.binary, "run", *self.spec.docker_args()]
        if workspace is not None:
            # The workspace is the only writable surface, and it is mounted at a
            # fixed path so a proof plan never has to know a host path.
            command += [f"--volume={Path(workspace).resolve()}:{self.spec.workspace}:rw"]
            command += ["--workdir", self.spec.workspace]
        # A read-only root filesystem still needs somewhere to put temporary
        # files; an in-memory tmpfs gives that without a writable host path.
        command += ["--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"]
        command += ["--user", _container_user()]
        command.append(self.spec.image)
        command.extend(argv)
        return command

    def run(
        self,
        argv: Sequence[str],
        *,
        workspace: Path | None = None,
        timeout: float = 120.0,
    ) -> SandboxResult:
        if not runtime_available(self.binary):
            raise SandboxUnavailable(
                f"{self.binary} is not available or its daemon is not running; "
                "STATIC mode does not need it"
            )
        command = self.build_command(argv, workspace=workspace)
        try:
            completed = subprocess.run(  # noqa: S603 - list args, shell=False
                command, capture_output=True, text=True, timeout=timeout, shell=False
            )
        except subprocess.TimeoutExpired as exc:
            return SandboxResult(
                exit_code=124,
                stdout=(exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                stderr="timed out",
                timed_out=True,
                command=tuple(command),
            )
        return SandboxResult(
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            command=tuple(command),
        )
