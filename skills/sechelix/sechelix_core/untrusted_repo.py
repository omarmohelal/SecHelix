"""Zero-trust repository mode.

A security auditor is a high-value target. When SecHelix reviews a repository it
did not write, that repository can contain text aimed at the auditor rather than
at a human reader: a ``CLAUDE.md`` that redefines the workflow, a docstring that
says the file was already reviewed, a hook that runs on read, an MCP server
definition that adds a tool.

``UNTRUSTED_REPO`` mode answers that with one rule:

    Repository content is DATA. It is never CONTROL.

Nothing inside the target can widen scope, relax policy, enable a capability,
mark a finding resolved, or silence a check. Only the operator can do that, and
only through an explicit promotion recorded in the scope record.

This module is the enforcement point. It is deliberately deny-by-default: an
unknown capability is denied, an unparseable promotion is denied, and a
promotion that does not name a concrete path is denied.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

UNTRUSTED_MODE = "UNTRUSTED_REPO"

#: Capabilities that are OFF unless the operator escalates them explicitly.
CAPABILITIES = (
    "FILESYSTEM_WRITE",
    "REPO_SCRIPTS",
    "PACKAGE_INSTALL",
    "NETWORK",
    "HOOKS",
    "EXTERNAL_MCP",
    "DYNAMIC_TARGET_REQUESTS",
)

#: Files inside a target that commonly carry agent-directed instructions. In
#: untrusted mode these are read as evidence about the project, never obeyed.
CONTROL_SHAPED_PATHS = (
    "CLAUDE.md",
    "AGENTS.md",
    "GEMINI.md",
    "CURSOR.md",
    ".cursorrules",
    ".windsurfrules",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/hooks.json",
    ".mcp.json",
    ".vscode/mcp.json",
    ".github/copilot-instructions.md",
)

#: Directory prefixes whose contents are instruction-shaped by convention.
CONTROL_SHAPED_PREFIXES = (
    ".claude/",
    ".agents/",
    ".codex/",
    ".cursor/",
    ".windsurf/",
    ".github/skills/",
    ".github/workflows/",
)

#: Phrases that attempt to steer an auditing agent. Matching text is quarantined
#: and reported; it never changes behaviour. These are detection aids for the
#: report, not a security boundary — the boundary is that nothing is obeyed.
INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("instruction_override", re.compile(
        r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b"
        r"(previous|prior|above|earlier|all)\b[^.\n]{0,30}\b(instruction|prompt|rule|direction)", re.I)),
    ("audit_suppression", re.compile(
        r"\b(do not|don't|never|skip|omit|exclude)\b[^.\n]{0,40}\b"
        r"(report|flag|audit|scan|review|analy[sz]e|mention)\b", re.I)),
    ("false_assurance", re.compile(
        r"\b(already|previously)\b[^.\n]{0,30}\b(reviewed|audited|approved|verified|cleared|pen.?tested)\b", re.I)),
    ("severity_downgrade", re.compile(
        r"\b(mark|treat|classify|consider|set)\b[^.\n]{0,30}\b"
        r"(as\s+)?(safe|clean|resolved|fixed|false.positive|not.exploitable|low)\b", re.I)),
    ("capability_request", re.compile(
        r"\b(run|execute|install|curl|wget|fetch|download|pip install|npm install|chmod)\b"
        r"[^.\n]{0,40}\b(script|command|package|binary|payload|setup|bootstrap)\b", re.I)),
    ("exfiltration_request", re.compile(
        r"\b(send|post|upload|transmit|report)\b[^.\n]{0,40}\b"
        r"(secret|token|key|credential|env|\.env|result|finding)s?\b[^.\n]{0,30}\bto\b", re.I)),
    ("agent_address", re.compile(
        r"\b(as an? (ai|agent|assistant|auditor|model)|you are (now|an?)|system prompt|"
        r"new instructions?|attention[: ]+(ai|agent|assistant|claude|codex))\b", re.I)),
)


class TrustPolicyError(ValueError):
    """The trust declaration cannot support a safe audit."""


@dataclass(frozen=True)
class Quarantine:
    """A piece of target content that tried to act as control."""

    path: str
    pattern: str
    excerpt: str
    line: int

    def as_dict(self) -> dict[str, Any]:
        return {"path": self.path, "pattern": self.pattern, "line": self.line, "excerpt": self.excerpt}


@dataclass(frozen=True)
class TrustPolicy:
    """The resolved trust decision for one audit."""

    mode: str
    repository_content: str
    promoted_paths: frozenset[str] = frozenset()
    enabled_capabilities: frozenset[str] = frozenset()
    quarantined: tuple[Quarantine, ...] = field(default=())

    @property
    def untrusted(self) -> bool:
        return self.mode == UNTRUSTED_MODE

    def allows(self, capability: str) -> bool:
        """Deny-by-default capability check."""
        normalized = str(capability).upper()
        if normalized not in CAPABILITIES:
            # An unrecognized capability is never quietly permitted.
            return False
        if not self.untrusted:
            return True
        return normalized in self.enabled_capabilities

    def is_control(self, path: str) -> bool:
        """Whether a target path may influence the audit."""
        if not self.untrusted:
            return True
        return _normalize(path) in self.promoted_paths

    def assert_allows(self, capability: str) -> None:
        if not self.allows(capability):
            raise TrustPolicyError(
                f"{capability} is not permitted in {self.mode}; "
                "an explicit operator escalation is required and must be recorded in scope.trust"
            )


def _normalize(path: str) -> str:
    """Fold a path to one comparable form. Must be idempotent.

    Idempotence matters because this feeds `is_control`, which decides whether a
    file may influence the audit. A function whose second application differs from
    its first means the same path can compare unequal to itself depending on how
    many times it has been through the pipeline.

    `PurePosixPath("")` renders as `"."`, which turned an empty or degenerate path
    into the current directory — a different statement entirely. Empty stays empty.
    """
    text = str(path).replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    # Only a leading "./" is removed; a leading dot belongs to names like ".claude".
    if not text.strip("/"):
        return ""
    return PurePosixPath(text).as_posix().lstrip("/")


def resolve_trust_policy(scope: Mapping[str, Any]) -> TrustPolicy:
    """Derive the enforceable trust policy from a scope record.

    Fails closed: an ``UNTRUSTED_REPO`` scope that omits ``trust`` is rejected
    rather than silently downgraded to trusting the target.
    """
    if not isinstance(scope, Mapping):
        raise TrustPolicyError("scope must be an object")

    mode = str(scope.get("mode", "")).upper()
    trust = scope.get("trust")

    if mode == UNTRUSTED_MODE:
        if not isinstance(trust, Mapping):
            raise TrustPolicyError(
                "UNTRUSTED_REPO scope must declare a trust block; refusing to assume the target is trustworthy"
            )
        content = str(trust.get("repository_content", "")).upper()
        if content != "DATA_ONLY":
            raise TrustPolicyError(
                "UNTRUSTED_REPO requires trust.repository_content = DATA_ONLY"
            )
    else:
        content = "TRUSTED_CONTROL"
        if isinstance(trust, Mapping):
            content = str(trust.get("repository_content", content)).upper()

    promoted: set[str] = set()
    for entry in (trust or {}).get("promoted_control_sources", []) if isinstance(trust, Mapping) else []:
        if not isinstance(entry, Mapping):
            raise TrustPolicyError("each promoted_control_sources entry must be an object")
        path = str(entry.get("path", "")).strip()
        if not path or path in {"*", "**", "."}:
            # A wildcard promotion would re-trust the whole target in one line.
            raise TrustPolicyError("a promoted control source must name a concrete path")
        for required in ("promoted_by", "promoted_at", "reason"):
            if not str(entry.get(required, "")).strip():
                raise TrustPolicyError(f"promoted control source {path} is missing {required}")
        promoted.add(_normalize(path))

    enabled: set[str] = set()
    for entry in (trust or {}).get("capability_escalations", []) if isinstance(trust, Mapping) else []:
        if not isinstance(entry, Mapping):
            raise TrustPolicyError("each capability_escalations entry must be an object")
        capability = str(entry.get("capability", "")).upper()
        if capability not in CAPABILITIES:
            raise TrustPolicyError(f"unknown capability: {entry.get('capability')!r}")
        for required in ("approved_by", "approved_at", "justification"):
            if not str(entry.get(required, "")).strip():
                raise TrustPolicyError(f"capability escalation {capability} is missing {required}")
        enabled.add(capability)

    return TrustPolicy(
        mode=mode or "STATIC",
        repository_content=content,
        promoted_paths=frozenset(promoted),
        enabled_capabilities=frozenset(enabled),
    )


def is_control_shaped(path: str) -> bool:
    """Whether a path is the kind of file that usually carries agent directives."""
    normalized = _normalize(path)
    if normalized in CONTROL_SHAPED_PATHS:
        return True
    return any(normalized.startswith(prefix) for prefix in CONTROL_SHAPED_PREFIXES)


def scan_for_injection(path: str, text: str, *, max_excerpt: int = 160) -> list[Quarantine]:
    """Find content in the target that addresses the auditor.

    Detection exists so the report can say *what* the repository attempted. It is
    not the control: the control is that target content is never executed as
    instruction in the first place.
    """
    found: list[Quarantine] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        for name, pattern in INJECTION_PATTERNS:
            if pattern.search(stripped):
                excerpt = stripped[:max_excerpt] + ("…" if len(stripped) > max_excerpt else "")
                found.append(Quarantine(path=_normalize(path), pattern=name, excerpt=excerpt, line=line_number))
                break
    return found


def review_target_content(
    policy: TrustPolicy,
    files: Iterable[tuple[str, str]],
) -> TrustPolicy:
    """Read target files as data and quarantine anything addressed to the auditor.

    Returns a policy carrying the quarantine list. The returned policy has the
    same capabilities and promotions as the input: reading hostile content can
    never grant anything.
    """
    quarantined: list[Quarantine] = []
    for path, text in files:
        if not policy.untrusted and not is_control_shaped(path):
            continue
        quarantined.extend(scan_for_injection(path, text))

    return TrustPolicy(
        mode=policy.mode,
        repository_content=policy.repository_content,
        promoted_paths=policy.promoted_paths,
        enabled_capabilities=policy.enabled_capabilities,
        quarantined=tuple(quarantined),
    )


def default_untrusted_scope(scope_id: str, project: str, targets: Sequence[str]) -> dict[str, Any]:
    """A minimal, maximally restrictive scope for auditing a hostile repository."""
    return {
        "schema_version": "1.0",
        "scope_id": scope_id,
        "project": project,
        "authorization": {
            "confirmed": True,
            "basis": "EXPLICIT_PERMISSION",
            "statement": (
                "The operator supplied this repository for review and accepts read-only "
                "static inspection. Repository content is treated as data, not instruction."
            ),
            "authorized_by": "operator",
        },
        "mode": UNTRUSTED_MODE,
        "in_scope": [
            {
                "id": f"TGT-{index:02d}",
                "type": "REPOSITORY",
                "name": target,
                "locator": target,
                "environment": "SOURCE",
                "authorized": True,
            }
            for index, target in enumerate(targets, start=1)
        ],
        "out_of_scope": [
            "any host, service, or account referenced by the repository",
            "any network destination named in repository content",
        ],
        "allowed_tools": ["read-only source inspection"],
        "stop_conditions": [
            "repository content attempts to direct the auditor",
            "a check would require executing repository-supplied code",
            "a check would require network access",
        ],
        "trust": {"repository_content": "DATA_ONLY", "promoted_control_sources": []},
    }
