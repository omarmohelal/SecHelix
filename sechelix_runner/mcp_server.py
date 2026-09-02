"""An MCP adapter, so a compatible agent can call SecHelix directly.

It wraps the same runner the CLI wraps. There is no second security engine here,
no second definition of a finding, and no path by which the MCP surface can
report something the CLI would not.

Three limits, and the third is the one that matters most:

**Read-only by default.** Only ``sechelix_audit`` changes anything, and only by
creating a run workspace under the path it was given. Nothing edits a finding, a
status or a coverage record.

**No arbitrary shell.** There is no ``run_command`` tool and no argument that
reaches a shell. An agent gets the operations SecHelix defines, not a terminal
wearing an MCP costume.

**Paths are confined to a configured root.** An MCP client is driven by a model
reading untrusted content, so ``../../.ssh`` will eventually be passed as a path
argument. Every path is resolved and checked against the root before use.

Implemented over stdio with the standard library. MCP is JSON-RPC 2.0 over a
line-delimited stream; that is small enough that a dependency would be more
surface than it removes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable, TextIO

from . import RUNNER_VERSION
from .coverage import LEDGER_FILENAME, CoverageLedger, TargetIdentity, observe_world
from .report import RENDERERS
from .storage import InvalidRunId, RunWorkspace, list_runs
from .world import build_world

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "sechelix"


class PathOutsideRoot(PermissionError):
    """A path argument escaped the configured root."""


class SecHelixMCP:
    """The tool surface. Pure functions over a root directory."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root).resolve()

    # -- safety --------------------------------------------------------------

    def _resolve(self, candidate: str | None) -> Path:
        """Resolve a caller-supplied path inside the root, or refuse it.

        Resolution first, comparison second: ``a/../../etc``, a symlink and an
        absolute path are three spellings of the same escape and only the
        resolved form catches all three.
        """
        target = (self.root / (candidate or ".")).resolve()
        try:
            target.relative_to(self.root)
        except ValueError:
            raise PathOutsideRoot(
                f"path {candidate!r} resolves outside the configured root {self.root}"
            ) from None
        return target

    # -- tools ---------------------------------------------------------------

    def sechelix_doctor(self, **_: Any) -> dict[str, Any]:
        """What is available. Never fails for a missing optional component."""
        from .sandbox_exec import runtime_available

        return {
            "runner_version": RUNNER_VERSION,
            "root": str(self.root),
            "runs_recorded": len(list_runs(self.root)),
            "container_runtime": runtime_available(),
            "network_mode": "DENY (static default)",
            "reasoning_executor": "configured per call; default analyses nothing",
        }

    def sechelix_audit(self, path: str = ".", depth: str = "standard", **_: Any) -> dict[str, Any]:
        """Run a STATIC audit. The only tool that writes anything."""
        from .cli import NullExecutor, _default_graph
        from .runner import Runner
        from .storage import persist_run

        target = self._resolve(path)
        world = build_world(target, depth=depth)
        graph = _default_graph(world)
        result = Runner(
            executor=NullExecutor(),
            target_commit=world["target"]["commit"],
            scope_id=world["target"]["scope_id"],
        ).run(graph, world)
        persist_run(target, result, graph)
        return {
            "run_id": result.run_id,
            "nodes": len(result.records),
            "unsatisfied_mandatory": result.unsatisfied_mandatory,
            "incomplete": bool(result.unsatisfied_mandatory),
            "note": (
                "No reasoning executor was configured, so specialist lanes were "
                "BLOCKED. This run makes no security claim in either direction."
            ),
        }

    def sechelix_run_status(self, run_id: str, path: str = ".", **_: Any) -> dict[str, Any]:
        workspace = RunWorkspace(self._resolve(path), run_id)
        if not workspace.exists:
            raise KeyError(run_id)
        run = workspace.read_json("run.json")
        return {
            "run_id": run["run_id"],
            "executor": run["executor"],
            "integrity": workspace.verify() or "ok",
            "unsatisfied_mandatory": run["unsatisfied_mandatory"],
            "statuses": {k: v["status"] for k, v in run["records"].items()},
        }

    def sechelix_findings(self, run_id: str, path: str = ".", **_: Any) -> dict[str, Any]:
        """Findings, always with the reason an empty list is empty."""
        workspace = RunWorkspace(self._resolve(path), run_id)
        if not workspace.exists:
            raise KeyError(run_id)
        run = workspace.read_json("run.json")
        return {
            "findings": run.get("findings", []),
            "unsatisfied_mandatory": run["unsatisfied_mandatory"],
            "note": (
                "An empty list is not a statement that no vulnerabilities exist. "
                "Check unsatisfied_mandatory: if it is non-empty, lanes were "
                "blocked and nothing was examined."
            ),
        }

    def sechelix_report(self, run_id: str, path: str = ".", format: str = "markdown", **_: Any) -> dict[str, Any]:
        if format not in RENDERERS:
            raise ValueError(f"unknown format {format!r}; choose one of {sorted(RENDERERS)}")
        workspace = RunWorkspace(self._resolve(path), run_id)
        if not workspace.exists:
            raise KeyError(run_id)
        return {"format": format, "content": RENDERERS[format](workspace.read_json("run.json"))}

    def sechelix_coverage(self, path: str = ".", **_: Any) -> dict[str, Any]:
        target = self._resolve(path)
        ledger_path = target / ".sechelix" / LEDGER_FILENAME
        world = build_world(target, depth="quick")
        identity = TargetIdentity.from_world(world)
        ledger = CoverageLedger.load(ledger_path, identity)
        observe_world(ledger, world, root=target)
        report = ledger.report(covered_keys=[])
        return {"totals": report["totals"], "blind_spots": report["blind_spots"][:50]}

    def sechelix_verify(self, finding_id: str, **_: Any) -> dict[str, Any]:
        """Build a verification plan. Deliberately does not execute one.

        Executing a proof needs authority an MCP client cannot grant on the
        operator's behalf, so this returns the plan and the authority it would
        require instead of quietly doing less and calling it verification.
        """
        from .proof import ProofClass, build_plan

        plans = {
            cls.value: build_plan(cls, finding_id, available_authority=set()).to_dict()
            for cls in ProofClass
        }
        return {
            "finding_id": finding_id,
            "plans": plans,
            "note": (
                "Plans only. Executing one requires operator-granted authority "
                "and a LOCAL or STAGING environment; without it, observation "
                "would not establish attacker control."
            ),
        }


#: name -> (handler attribute, description, input schema)
TOOLS: dict[str, tuple[str, str, dict[str, Any]]] = {
    "sechelix_doctor": ("sechelix_doctor", "Report which SecHelix components are available.", {
        "type": "object", "properties": {}}),
    "sechelix_audit": ("sechelix_audit", "Run a STATIC SecHelix audit over a directory.", {
        "type": "object",
        "properties": {"path": {"type": "string"},
                       "depth": {"type": "string", "enum": ["quick", "standard", "thorough"]}}}),
    "sechelix_run_status": ("sechelix_run_status", "Node statuses and integrity for a recorded run.", {
        "type": "object", "required": ["run_id"],
        "properties": {"run_id": {"type": "string"}, "path": {"type": "string"}}}),
    "sechelix_findings": ("sechelix_findings", "Findings for a run, with why an empty list is empty.", {
        "type": "object", "required": ["run_id"],
        "properties": {"run_id": {"type": "string"}, "path": {"type": "string"}}}),
    "sechelix_report": ("sechelix_report", "Render a run as markdown, json, sarif or html.", {
        "type": "object", "required": ["run_id"],
        "properties": {"run_id": {"type": "string"}, "path": {"type": "string"},
                       "format": {"type": "string", "enum": ["markdown", "json", "sarif", "html"]}}}),
    "sechelix_coverage": ("sechelix_coverage", "What previous runs did NOT examine.", {
        "type": "object", "properties": {"path": {"type": "string"}}}),
    "sechelix_verify": ("sechelix_verify", "Build safe verification plans for a finding.", {
        "type": "object", "required": ["finding_id"],
        "properties": {"finding_id": {"type": "string"}}}),
}


def handle_request(api: SecHelixMCP, request: dict[str, Any]) -> dict[str, Any] | None:
    """Handle one JSON-RPC message. Returns ``None`` for notifications."""
    method = request.get("method")
    request_id = request.get("id")

    if method == "initialize":
        result: Any = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": RUNNER_VERSION},
        }
    elif method == "tools/list":
        result = {
            "tools": [
                {"name": name, "description": description, "inputSchema": schema}
                for name, (_, description, schema) in sorted(TOOLS.items())
            ]
        }
    elif method == "tools/call":
        params = request.get("params") or {}
        name = params.get("name")
        entry = TOOLS.get(name)
        if entry is None:
            return _error(request_id, -32601, f"unknown tool: {name}")
        handler: Callable[..., Any] = getattr(api, entry[0])
        try:
            payload = handler(**(params.get("arguments") or {}))
        except PathOutsideRoot as exc:
            return _error(request_id, -32602, str(exc))
        except InvalidRunId as exc:
            return _error(request_id, -32602, str(exc))
        except KeyError as exc:
            return _error(request_id, -32602, f"not found: {exc.args[0]}")
        except (ValueError, TypeError) as exc:
            return _error(request_id, -32602, str(exc))
        except Exception as exc:  # never take the server down for one bad call
            return _error(request_id, -32603, f"{type(exc).__name__}: {exc}")
        result = {
            "content": [{"type": "text", "text": json.dumps(payload, indent=2, sort_keys=True)}]
        }
    elif request_id is None:
        return None  # a notification we do not act on
    else:
        return _error(request_id, -32601, f"unknown method: {method}")

    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def serve_stdio(root: Path | str = ".", stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
    """Read JSON-RPC messages from stdin and write replies to stdout."""
    api = SecHelixMCP(root)
    source = stdin or sys.stdin
    sink = stdout or sys.stdout
    for line in source:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            sink.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            sink.flush()
            continue
        response = handle_request(api, request)
        if response is not None:
            sink.write(json.dumps(response) + "\n")
            sink.flush()


if __name__ == "__main__":
    serve_stdio(sys.argv[1] if len(sys.argv) > 1 else ".")
