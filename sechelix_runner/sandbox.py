"""Sandbox policy and network authority.

Deliberately the inverse of what the audit found in the closest competitor.
``usestrix/strix`` runs a Kali base with passwordless sudo, an offensive
toolchain baked in, an *optional* named Docker network (unset means the default
bridge and full egress), and out-of-band callbacks to a public internet service.
That is a pentest environment. None of it is copied here.

The posture instead:

**Egress is denied unless a grant says otherwise.** :class:`NetworkPolicy`
starts empty, and empty means nothing is reachable. There is no "allow all"
switch, because a policy object that can express unrestricted access will
eventually be constructed with it.

**Every grant is scoped and expires.** A grant names a host, a port, a protocol,
a purpose and the run it belongs to. A grant with no purpose is refused: if
nobody can say why a host is reachable, it should not be.

**Public out-of-band services are refused by construction.** ``interactsh`` and
its relatives are how the competitor proves SSRF. Proving a vulnerability by
sending a victim's traffic to a third party is not something this project does,
so those hosts are rejected even if a caller tries to grant them.

**STATIC needs no container.** Docker is used when present and the mode asks for
it; its absence degrades the mode rather than failing the run.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Iterable


class ExecutionMode(str, Enum):
    """Where a run is allowed to act.

    ``PRODUCTION`` exists so it can be named and refused, not so it can be used.
    Nothing in the runner selects it, and dynamic capabilities stay off in it
    unless an operator policy explicitly says otherwise.
    """

    STATIC = "STATIC"
    LOCAL = "LOCAL"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"


#: Hosts that are refused even when a caller tries to grant them. These are
#: public out-of-band interaction services: reaching one proves a vulnerability
#: by routing a target's traffic through a third party.
FORBIDDEN_HOSTS = (
    "interact.sh",
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "oast.me",
    "burpcollaborator.net",
    "requestbin.net",
    "pipedream.net",
    "canarytokens.com",
)

_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", re.I)


class NetworkDenied(PermissionError):
    """A request was not covered by any grant, or was explicitly forbidden."""


@dataclass(frozen=True)
class NetworkGrant:
    """Authority to reach exactly one host and port, for a stated purpose."""

    host: str
    port: int
    protocol: str
    purpose: str
    scope_id: str
    expires_at: datetime

    def covers(self, host: str, port: int, protocol: str, *, now: datetime) -> bool:
        return (
            self.host.lower() == host.lower()
            and self.port == port
            and self.protocol.lower() == protocol.lower()
            and now < self.expires_at
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "purpose": self.purpose,
            "scope_id": self.scope_id,
            "expires_at": self.expires_at.isoformat(),
        }


def is_loopback(host: str) -> bool:
    """Whether ``host`` is the local machine.

    The local callback listener the proof builder uses must be genuinely local,
    so this resolves literal addresses rather than trusting a name.
    """
    if host.lower() in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class NetworkPolicy:
    """Deny-by-default egress authority.

    There is no permissive constructor. A policy with no grants reaches nothing,
    and the only way to widen it is to add a grant that names its purpose.
    """

    def __init__(self, mode: ExecutionMode = ExecutionMode.STATIC) -> None:
        self.mode = mode
        self._grants: list[NetworkGrant] = []
        #: Every decision, allowed or denied, for the run record.
        self.decisions: list[dict[str, Any]] = []

    @property
    def grants(self) -> list[NetworkGrant]:
        return list(self._grants)

    def grant(
        self,
        host: str,
        port: int,
        *,
        protocol: str = "https",
        purpose: str,
        scope_id: str,
        ttl_seconds: int = 3600,
        now: datetime | None = None,
    ) -> NetworkGrant:
        """Authorize one host/port. Raises for anything it will not authorize."""
        if self.mode is ExecutionMode.STATIC:
            raise NetworkDenied(
                "STATIC mode performs no network access; grants require LOCAL or STAGING"
            )
        if not purpose.strip():
            raise NetworkDenied(
                f"refusing to grant {host}:{port} with no stated purpose"
            )
        host = host.strip()
        if not _HOSTNAME.match(host) and not _is_ip(host):
            raise NetworkDenied(f"not a valid host: {host!r}")
        if _is_forbidden(host):
            raise NetworkDenied(
                f"{host} is a public out-of-band interaction service; SecHelix does "
                "not prove findings by routing target traffic through a third party"
            )
        if not 1 <= port <= 65535:
            raise NetworkDenied(f"port out of range: {port}")

        now = now or datetime.now(timezone.utc)
        grant = NetworkGrant(
            host=host,
            port=port,
            protocol=protocol,
            purpose=purpose.strip(),
            scope_id=scope_id,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        self._grants.append(grant)
        self.decisions.append({"action": "grant", **grant.to_dict()})
        return grant

    def check(
        self, host: str, port: int, *, protocol: str = "https", now: datetime | None = None
    ) -> bool:
        """Whether a request is authorized. Records the decision either way."""
        now = now or datetime.now(timezone.utc)
        allowed = any(g.covers(host, port, protocol, now=now) for g in self._grants)
        self.decisions.append(
            {
                "action": "check",
                "host": host,
                "port": port,
                "protocol": protocol,
                "allowed": allowed,
                "mode": self.mode.value,
            }
        )
        return allowed

    def require(
        self, host: str, port: int, *, protocol: str = "https", now: datetime | None = None
    ) -> None:
        """Authorize or raise. The call sites that actually open sockets use this."""
        if not self.check(host, port, protocol=protocol, now=now):
            raise NetworkDenied(
                f"{protocol}://{host}:{port} is not covered by any active grant "
                f"(mode={self.mode.value}); egress is denied by default"
            )

    def snapshot(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "default": "DENY",
            "grants": [g.to_dict() for g in self._grants],
            "decisions": self.decisions,
        }


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_forbidden(host: str) -> bool:
    lowered = host.lower()
    return any(lowered == bad or lowered.endswith("." + bad) for bad in FORBIDDEN_HOSTS)


@dataclass
class SandboxSpec:
    """Container settings for a LOCAL runtime, when one is used at all.

    The defaults are restrictive and the fields exist so a caller has to say
    out loud that it is loosening one. ``privileged`` has no setter path in the
    runner: it is here to be asserted false.
    """

    image: str = "python:3.12-slim"
    read_only_root: bool = True
    no_new_privileges: bool = True
    privileged: bool = False
    network_enabled: bool = False
    drop_capabilities: tuple[str, ...] = ("ALL",)
    add_capabilities: tuple[str, ...] = ()
    memory_limit: str = "2g"
    cpu_limit: float = 2.0
    pids_limit: int = 256
    #: Host paths the container may see, each with an explicit read-only flag.
    mounts: tuple[tuple[str, str, bool], ...] = ()
    workspace: str = "/workspace"

    def validate(self) -> list[str]:
        """Problems that must be fixed before this spec is used."""
        problems: list[str] = []
        if self.privileged:
            problems.append("privileged containers are not permitted")
        if not self.no_new_privileges:
            problems.append("no_new_privileges must stay enabled")
        if "ALL" not in self.drop_capabilities:
            problems.append("all Linux capabilities must be dropped by default")
        for capability in self.add_capabilities:
            problems.append(f"added capability {capability!r} requires explicit review")
        for source, _target, read_only in self.mounts:
            if not read_only and not source.startswith(self.workspace):
                problems.append(f"writable mount outside the workspace: {source}")
        return problems

    def docker_args(self) -> list[str]:
        """Arguments a caller would pass to ``docker run``.

        Returned rather than executed: this module decides policy, and nothing
        here starts a process.
        """
        args = ["--rm", f"--memory={self.memory_limit}", f"--cpus={self.cpu_limit}",
                f"--pids-limit={self.pids_limit}", "--security-opt=no-new-privileges"]
        if self.read_only_root:
            args.append("--read-only")
        for capability in self.drop_capabilities:
            args.append(f"--cap-drop={capability}")
        for capability in self.add_capabilities:
            args.append(f"--cap-add={capability}")
        args.append("--network=none" if not self.network_enabled else "--network=bridge")
        for source, target, read_only in self.mounts:
            args.append(f"--volume={source}:{target}:{'ro' if read_only else 'rw'}")
        return args


def confine_path(candidate: str, workspace: str) -> str:
    """Resolve ``candidate`` inside ``workspace`` or refuse it.

    Traversal is rejected on the resolved path rather than by pattern-matching
    ``..``, because ``a/../../b``, a symlink and an absolute path are three
    different spellings of the same escape and only resolution catches all of
    them.
    """
    from pathlib import Path

    root = Path(workspace).resolve()
    target = (root / candidate).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        raise PermissionError(
            f"path escapes the run workspace: {candidate!r} resolves outside {root}"
        ) from None
    return str(target)
