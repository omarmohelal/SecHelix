"""Local run workspaces.

A run writes everything it did under ``.sechelix/runs/<run-id>/``. That directory
is working data, never repository content -- it is gitignored, and nothing in the
audit pipeline reads a run back out of version control.

The layout is deliberately boring and file-per-concern, so a person can read a
run with ``cat`` and a tool can diff two runs without parsing a database:

    .sechelix/runs/<run-id>/
        run.json         the RunResult: records, routing, budget, context views
        graph.json       the node set and dependencies that were executed
        events.jsonl     append-only, one JSON object per line, in order
        manifest.json    digest of every file above, for tamper detection
        replay/          recorded node outputs, enough to re-run offline
        evidence/  findings/  reports/  patches/  runtime/

**What ``manifest.json`` is for.** Replay is only meaningful if the artifacts
have not moved since they were written. Every file gets a content digest at
close time, and :func:`verify_run` recomputes them. A changed byte anywhere is a
refusal to replay rather than a quietly different answer -- which is the whole
difference between a recording and a claim.

**Redaction is the default.** :func:`write_json` runs values through a redactor
before they touch disk, so a token that reached a node output does not become a
file sitting in a developer workspace forever.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from .digests import canonical_json, digest, digest_bytes

WORKSPACE_DIRNAME = ".sechelix"

#: A run id is an identifier, never a path fragment.
#:
#: Found by auditing this runner with SecHelix: ``run_id`` arrives from the
#: command line (``sechelix replay <id>``, ``sechelix report <id>``) and was
#: joined straight onto the runs directory, so ``../../outside.json`` resolved
#: outside the workspace and ``cmd_report`` would read and print it. Validating
#: the shape is the primary fix; :meth:`RunWorkspace._confined` re-checks the
#: resolved path so a future caller cannot reintroduce the escape by widening
#: this pattern.
RUN_ID_PATTERN = re.compile(r"^RUN-[A-Z0-9][A-Z0-9_-]{0,62}$")


class InvalidRunId(ValueError):
    """The run id is not an identifier this workspace will accept."""
_SUBDIRS = ("replay", "evidence", "findings", "reports", "patches", "runtime")

#: Keys whose values never reach disk in the clear. Matched case-insensitively
#: against the whole key, so ``Authorization`` and ``auth_token`` both redact.
_SECRET_KEY_PATTERN = re.compile(
    r"(authorization|cookie|set-cookie|password|passwd|secret|token|api[_-]?key"
    r"|private[_-]?key|session[_-]?id|credential|bearer)",
    re.IGNORECASE,
)

#: Keys that merely *contain* a secret-shaped word but are measurements, not
#: values. ``input_tokens`` is a count; redacting it corrupts the budget record
#: and, worse, the replay that reads it back. Checked before the secret pattern.
_COUNT_KEY_PATTERN = re.compile(r"(^|_)tokens$|_count$|^max_", re.IGNORECASE)

REDACTED = "[REDACTED]"


def redact(value: Any) -> Any:
    """Replace secret-shaped values, preserving structure.

    Structure is preserved on purpose: a reader can still see that a header was
    present and what it was called, which is usually the security-relevant fact,
    without the value itself surviving in a file.
    """
    if isinstance(value, dict):
        return {key: _redact_pair(key, item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    return value


def _redact_pair(key: Any, value: Any) -> Any:
    """Decide one key/value pair.

    Two rules, both learned from real corruption rather than theory.

    **Only scalars are ever replaced.** A secret is a value, not a namespace. A
    dict or list is recursed into no matter what it is called -- the run record
    is keyed by node id, one of those node ids is ``authorization``, and a
    name-only rule replaced that entire node record with a redaction marker.
    Replay then read the marker back and could not reconstruct the run.

    **A counting key beats the secret pattern.** ``input_tokens`` contains
    "token" but is telemetry the budget and replay both read back. Redacting a
    number protects nothing and corrupts the record.
    """
    if isinstance(value, (dict, list, tuple)):
        return redact(value)
    name = str(key)
    if _COUNT_KEY_PATTERN.search(name):
        return value
    if _SECRET_KEY_PATTERN.search(name):
        return REDACTED
    return value


class RunWorkspace:
    """One run directory, created on demand."""

    def __init__(self, root: Path | str, run_id: str) -> None:
        if not RUN_ID_PATTERN.match(run_id or ""):
            raise InvalidRunId(
                f"{run_id!r} is not a valid run id; a run id is an identifier "
                "matching RUN-[A-Z0-9_-], never a path"
            )
        self.root = Path(root)
        self.run_id = run_id
        self.path = self._confined(run_id)

    def _confined(self, run_id: str) -> Path:
        """Resolve the run directory and prove it stayed inside ``runs/``.

        Belt and braces over :data:`RUN_ID_PATTERN`: the pattern is the real
        control, and this catches the case where someone loosens it later.
        """
        base = (self.root / WORKSPACE_DIRNAME / "runs").resolve()
        candidate = (base / run_id).resolve()
        try:
            candidate.relative_to(base)
        except ValueError:
            raise InvalidRunId(
                f"run id {run_id!r} resolves outside the runs directory"
            ) from None
        return candidate

    # -- lifecycle -----------------------------------------------------------

    def create(self) -> RunWorkspace:
        self.path.mkdir(parents=True, exist_ok=True)
        for name in _SUBDIRS:
            (self.path / name).mkdir(exist_ok=True)
        return self

    @property
    def exists(self) -> bool:
        return self.path.is_dir()

    # -- writing -------------------------------------------------------------

    def write_json(self, name: str, payload: Any, *, redacted: bool = True) -> Path:
        """Write ``payload`` as canonical JSON, redacted unless told otherwise."""
        target = self.path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        body = redact(payload) if redacted else payload
        target.write_text(canonical_json(body), encoding="utf-8")
        return target

    def append_event(self, event: dict[str, Any]) -> None:
        """Append one line to the ordered event log."""
        line = canonical_json(redact(event))
        with (self.path / "events.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    # -- reading -------------------------------------------------------------

    def read_json(self, name: str) -> Any:
        return json.loads((self.path / name).read_text(encoding="utf-8"))

    def events(self) -> list[dict[str, Any]]:
        path = self.path / "events.jsonl"
        if not path.exists():
            return []
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def files(self) -> list[Path]:
        """Every file in the workspace except the manifest itself."""
        return sorted(
            p
            for p in self.path.rglob("*")
            if p.is_file() and p.name != "manifest.json"
        )

    # -- integrity -----------------------------------------------------------

    def write_manifest(self) -> dict[str, str]:
        """Digest every file so tampering is detectable at replay time."""
        entries = {
            str(path.relative_to(self.path)).replace("\\", "/"): digest_bytes(
                path.read_bytes()
            )
            for path in self.files()
        }
        (self.path / "manifest.json").write_text(
            canonical_json({"run_id": self.run_id, "files": entries}), encoding="utf-8"
        )
        return entries

    def verify(self) -> list[str]:
        """Return the paths whose contents no longer match the manifest.

        An empty list means the workspace is byte-identical to what was
        recorded. A non-empty list is a refusal, not a warning: callers must not
        replay a workspace that has drifted.
        """
        manifest_path = self.path / "manifest.json"
        if not manifest_path.exists():
            return ["manifest.json: missing"]
        recorded: dict[str, str] = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )["files"]

        problems: list[str] = []
        present = {
            str(p.relative_to(self.path)).replace("\\", "/"): p for p in self.files()
        }
        for name, expected in sorted(recorded.items()):
            path = present.pop(name, None)
            if path is None:
                problems.append(f"{name}: missing")
            elif digest_bytes(path.read_bytes()) != expected:
                problems.append(f"{name}: content changed")
        for name in sorted(present):
            problems.append(f"{name}: not in manifest")
        return problems


def list_runs(root: Path | str) -> list[str]:
    """Run ids in ``root``, newest directory name last."""
    base = Path(root) / WORKSPACE_DIRNAME / "runs"
    if not base.is_dir():
        return []
    return sorted(p.name for p in base.iterdir() if p.is_dir())


def persist_run(root: Path | str, result: Any, graph: Any) -> RunWorkspace:
    """Write a completed :class:`~sechelix_runner.runner.RunResult` to disk.

    ``replay/outcomes.json`` holds exactly what a :class:`ReplayExecutor` needs,
    so a later replay reconstructs the orchestration without calling anything.
    """
    workspace = RunWorkspace(root, result.run_id).create()
    workspace.write_json("run.json", result.to_dict())
    workspace.write_json(
        "graph.json",
        {
            "graph_digest": result.graph_digest,
            "nodes": [
                {
                    "node_id": node.node_id,
                    "role": node.role.value,
                    "depends_on": sorted(node.depends_on),
                    "mandatory": node.mandatory,
                    "node_version": node.node_version,
                    "reason": node.reason,
                }
                for node in graph.nodes
            ],
            "topological_order": graph.topological_order(),
        },
    )
    workspace.write_json(
        "replay/outcomes.json",
        {
            node_id: {
                "status": record.status.value,
                "output": result.outputs.get(node_id, {}),
                "output_evidence_ids": record.output_evidence_ids,
                "input_tokens": record.input_tokens,
                "output_tokens": record.output_tokens,
                "cost_usd": record.cost_usd,
                "model": record.model,
                "provider": record.provider,
                "error": record.error,
                "blocker": record.blocker,
            }
            for node_id, record in result.records.items()
        },
    )
    for node_id in graph.topological_order():
        record = result.records.get(node_id)
        if record is None:
            continue
        workspace.append_event(
            {
                "event": "node",
                "node_id": node_id,
                "role": record.role.value,
                "status": record.status.value,
                "blocker": record.blocker,
                "error": record.error,
                "record_digest": record.record_digest(),
            }
        )
    workspace.write_manifest()
    return workspace
