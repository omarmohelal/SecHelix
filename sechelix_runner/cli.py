"""The ``sechelix`` command line.

Every command works offline and none of them require an account. What they do
*not* do is pretend to have analysed a repository when no reasoning executor is
configured -- see :class:`NullExecutor` below, which is the most important thing
in this module.

Exit codes are stable and meant for CI:

    0   the command succeeded and, for ``audit``, the gate reached a clean state
    1   the command ran and the result is not clean (unsatisfied mandatory nodes)
    2   usage error
    3   the run could not be completed at all (integrity failure, missing run)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

from . import RUNNER_VERSION
from .budget import BudgetGovernor, BudgetLimits
from .coverage import (
    LEDGER_FILENAME,
    CoverageLedger,
    LedgerMismatch,
    TargetIdentity,
    observe_world,
)
from .executor import NodeOutcome
from .graph import GraphNode, ReasonerGraph
from .replay import ReplayError, replay_run
from .report import RENDERERS
from .roles import NodeRole, NodeStatus
from .runner import Runner
from .storage import InvalidRunId, RunWorkspace, list_runs, persist_run
from .world import DEPTHS, build_world, describe_target

EXIT_OK = 0
EXIT_NOT_CLEAN = 1
EXIT_USAGE = 2
EXIT_ERROR = 3

#: Roles that exist to reason about code. Without a configured provider these
#: cannot be answered, and saying so is the only honest outcome.
_REASONING_ROLES = frozenset(NodeRole) - {NodeRole.MAPPER, NodeRole.RELEASE_GATE}


class NullExecutor:
    """The default executor: it analyses nothing and says so.

    This exists because the alternative is worse. If ``sechelix audit .`` ran
    every specialist through a stub that returned "no findings", the report
    would be indistinguishable from a genuine clean audit, and a fail-closed
    release gate would hand out a PASS for a run in which nothing was examined.

    So every reasoning node is ``BLOCKED`` with the reason stated. The gate then
    has unsatisfied mandatory nodes and cannot report a clean result, which is
    exactly right: no analysis happened.
    """

    name = "null"

    def execute(self, node: GraphNode, view: dict[str, Any]) -> NodeOutcome:
        if node.role in _REASONING_ROLES:
            return NodeOutcome(
                status=NodeStatus.BLOCKED,
                blocker=(
                    "no reasoning executor configured; this node analyses code and "
                    "cannot be answered by the runner alone"
                ),
            )
        return NodeOutcome(status=NodeStatus.SUCCEEDED, output={"role": node.role.value})


def _default_graph(world: dict[str, Any]) -> ReasonerGraph:
    """Applicability-selected graph: a lane appears only if its inputs exist.

    A repository with no manifests has no supply-chain node, and that absence is
    a routing decision recorded in the run rather than an empty stage in a
    report.
    """
    from .context import ROLE_CONTEXT

    nodes = [GraphNode("map", NodeRole.MAPPER, (), mandatory=True, reason="always")]
    lanes: list[str] = []
    for role in sorted(_REASONING_ROLES - {NodeRole.INDEPENDENT_VERIFIER}, key=lambda r: r.value):
        required = ROLE_CONTEXT.get(role, {}).get("required", ())
        if not required or not all(world.get(key) for key in required):
            continue
        node_id = role.value.lower()
        nodes.append(
            GraphNode(node_id, role, ("map",), reason="required context present")
        )
        lanes.append(node_id)

    nodes.append(
        GraphNode(
            "verify",
            NodeRole.INDEPENDENT_VERIFIER,
            tuple(lanes) or ("map",),
            mandatory=True,
            reason="every candidate is independently verified",
        )
    )
    nodes.append(
        GraphNode("gate", NodeRole.RELEASE_GATE, ("verify",), mandatory=True, reason="always")
    )
    return ReasonerGraph(nodes)


# -- commands ---------------------------------------------------------------


def cmd_doctor(args: argparse.Namespace) -> int:
    """Report what is available. Optional components are allowed to be absent."""

    def _version(cmd: list[str]) -> str | None:
        binary = shutil.which(cmd[0])
        if not binary:
            return None
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return (out.stdout or out.stderr).strip().splitlines()[0]
        except (OSError, subprocess.SubprocessError, IndexError):
            return None

    root = Path(args.path).resolve()
    report = {
        "runner_version": RUNNER_VERSION,
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "git": _version(["git", "--version"]),
        "docker": _version(["docker", "--version"]),
        "workspace": str(root / ".sechelix"),
        "workspace_exists": (root / ".sechelix").is_dir(),
        "runs_recorded": len(list_runs(root)),
        "network_mode": "DENY (static default)",
        "reasoning_executor": "select with --executor (default NullExecutor)",
        "available_reasoning_executors": {
            "claude-code": bool(shutil.which("claude")),
            "gemini-cli": bool(shutil.which("gemini")),
        },
        "redaction": "enabled",
        "core_contracts": _core_available(),
    }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return EXIT_OK

    print("SecHelix doctor")
    for key, value in report.items():
        shown = "-" if value is None else value
        print(f"  {key:22} {shown}")
    print("\nOptional components may be absent; only 'core_contracts' must be present.")
    return EXIT_OK if report["core_contracts"] else EXIT_ERROR


def _core_available() -> bool:
    try:
        import sechelix_core.contracts  # noqa: F401
    except Exception:
        return False
    return True


def _build_executor(args: argparse.Namespace):
    """Select the executor. The honest default analyses nothing and says so."""
    choice = getattr(args, "executor", "none")
    if choice == "none":
        return NullExecutor()
    if choice == "claude-code":
    from .providers.claude_code import ClaudeCodeExecutor
    from .providers.reasoning import ReasoningExecutor

    provider = ClaudeCodeExecutor(model=getattr(args, "model", None))
    if not provider.available:
        raise RuntimeError(
            "claude CLI not found on PATH; install Claude Code or use --executor none"
        )
    return ReasoningExecutor(provider, timeout=float(getattr(args, "node_timeout", 300)))
    if choice == "gemini-cli":
        from .providers.gemini_cli import GeminiCliExecutor
        from .providers.reasoning import ReasoningExecutor

        provider = GeminiCliExecutor(model=getattr(args, "model", None))
        if not provider.available:
            raise RuntimeError(
      "gemini CLI not found on PATH; install Gemini CLI or use --executor none"
            )
        return ReasoningExecutor(provider, timeout=float(getattr(args, "node_timeout", 300)))
    raise RuntimeError(f"unknown executor: {choice}")


def cmd_audit(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return EXIT_USAGE

    target = describe_target(root)
    world = build_world(root, depth=args.depth)
    graph = _default_graph(world)

    limits = BudgetLimits(
        max_cost_usd=args.max_cost,
        max_duration_seconds=args.max_seconds,
        max_nodes=args.max_nodes,
    )
    try:
        executor = _build_executor(args)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    result = Runner(
        executor=executor,
        budget=BudgetGovernor(limits),
        target_commit=target["commit"],
        scope_id=target["scope_id"],
    ).run(graph, world)

    workspace = persist_run(root, result, graph)

    # Coverage is credited only for nodes that actually delivered. A BLOCKED
    # lane examined nothing, and recording it as covered would convert a gap
    # into a false reassurance on the next run.
    ledger_path = root / ".sechelix" / LEDGER_FILENAME
    identity = TargetIdentity.from_world(world)
    try:
        ledger = CoverageLedger.load(ledger_path, identity)
    except LedgerMismatch as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    ledger.identity = identity
    observe_world(ledger, world, root=root)
    covered_keys: list[str] = []
    if any(r.satisfied for r in result.records.values() if r.role is not NodeRole.MAPPER):
        for path in world.get("file_index", []):
            ledger.cover("file", path, result.run_id)
            covered_keys.append(f"file:{path}")
    ledger.record_run(result.run_id, covered_keys)
    ledger.save(ledger_path)
    coverage_report = ledger.report(covered_keys)
    workspace.write_json("coverage.json", coverage_report)
    workspace.write_manifest()

    if args.json:
        payload = result.to_dict()
        payload["coverage"] = coverage_report
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_run(result, workspace)
        blind = coverage_report["blind_spots"]
        print(f"blind   {len(blind)} item(s) never covered or stale")
    return EXIT_OK if not result.unsatisfied_mandatory else EXIT_NOT_CLEAN


def _print_run(result: Any, workspace: RunWorkspace) -> None:
    print(f"run     {result.run_id}")
    print(f"commit  {result.target_commit}")
    print(f"nodes   {len(result.records)}")
    print()
    for node_id in sorted(result.records):
        record = result.records[node_id]
        detail = record.blocker or record.error or ""
        print(f"  {record.status.value:<10} {node_id:<24} {detail[:60]}")
    print()
    if result.unsatisfied_mandatory:
        print(f"RESULT  INCOMPLETE - unsatisfied mandatory nodes: "
              f"{', '.join(result.unsatisfied_mandatory)}")
        print("        No security claim can be made from this run.")
    else:
        print("RESULT  all mandatory nodes satisfied")
    print(f"\nsaved   {workspace.path}")


def cmd_coverage(args: argparse.Namespace) -> int:
    """What previous runs did and did not examine."""
    root = Path(args.path).resolve()
    ledger_path = root / ".sechelix" / LEDGER_FILENAME
    if not ledger_path.exists():
        print("no coverage ledger yet; run 'sechelix audit .' first", file=sys.stderr)
        return EXIT_ERROR
    world = build_world(root, depth="quick")
    identity = TargetIdentity.from_world(world)
    try:
        ledger = CoverageLedger.load(ledger_path, identity)
    except LedgerMismatch as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    observe_world(ledger, world, root=root)
    report = ledger.report(covered_keys=[])

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return EXIT_OK

    print(f"coverage for {identity.name} @ {identity.commit[:12]}")
    for status, count in sorted(report["totals"].items()):
        if count:
            print(f"  {status:16} {count}")
    blind = report["blind_spots"]
    print()
    print(f"{len(blind)} blind spot(s) - never covered or stale since coverage")
    for key in blind[:20]:
        print(f"  {key}")
    if len(blind) > 20:
        print(f"  ... and {len(blind) - 20} more")
    return EXIT_OK


def cmd_mcp(args: argparse.Namespace) -> int:
    """Serve the MCP adapter over stdio for a compatible agent."""
    from .mcp_server import serve_stdio

    serve_stdio(Path(args.path).resolve())
    return EXIT_OK


def cmd_runs(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    runs = list_runs(root)
    if args.json:
        print(json.dumps({"runs": runs}, indent=2))
        return EXIT_OK
    if not runs:
        print("no runs recorded")
        return EXIT_OK
    for run_id in runs:
        workspace = RunWorkspace(root, run_id)
        problems = workspace.verify()
        integrity = "ok" if not problems else f"TAMPERED ({len(problems)})"
        print(f"  {run_id}  integrity={integrity}")
    return EXIT_OK


def cmd_replay(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    try:
        world = build_world(root, depth="standard")
        _, comparison = replay_run(root, args.run_id, world)
    except ReplayError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.json:
        print(json.dumps(comparison.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"replay {comparison.run_id}")
        print(f"  faithful            {comparison.faithful}")
        print(f"  statuses match      {comparison.statuses_match}")
        print(f"  routing matches     {comparison.routing_matches}")
        print(f"  graph digest match  {comparison.graph_digest_matches}")
        for difference in comparison.differences:
            print(f"  DIFF  {difference}")
    return EXIT_OK if comparison.faithful else EXIT_NOT_CLEAN


def cmd_report(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    run_id = args.run_id or (list_runs(root)[-1] if list_runs(root) else None)
    if not run_id:
        print("error: no runs recorded", file=sys.stderr)
        return EXIT_ERROR
    workspace = RunWorkspace(root, run_id)
    if not workspace.exists:
        print(f"error: no run {run_id!r}", file=sys.stderr)
        return EXIT_ERROR
    data = workspace.read_json("run.json")
    print(RENDERERS[args.format](data))
    return EXIT_OK


# -- entry point -------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sechelix",
        description="SecHelix runner - evidence-first application-security orchestration.",
    )
    parser.add_argument("--version", action="version", version=f"sechelix-runner {RUNNER_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    def _common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--json", action="store_true", help="machine-readable output")

    doctor = sub.add_parser("doctor", help="report available components")
    doctor.add_argument("path", nargs="?", default=".")
    _common(doctor)
    doctor.set_defaults(func=cmd_doctor)

    audit = sub.add_parser("audit", help="run a static audit graph over a repository")
    audit.add_argument("path", nargs="?", default=".")
    audit.add_argument("--depth", choices=sorted(DEPTHS), default="standard")
    audit.add_argument("--max-cost", type=float, default=None, dest="max_cost")
    audit.add_argument("--max-seconds", type=float, default=None, dest="max_seconds")
    audit.add_argument("--max-nodes", type=int, default=None, dest="max_nodes")
    audit.add_argument(
        "--executor", choices=("none", "claude-code", "gemini-cli"), default="none",
        help="reasoning executor; 'none' orchestrates without analysing code",
    )
    audit.add_argument("--model", default=None, help="provider model override")
    audit.add_argument(
        "--node-timeout", type=float, default=300.0, dest="node_timeout",
        help="seconds allowed per reasoning node",
    )
    _common(audit)
    audit.set_defaults(func=cmd_audit)

    runs = sub.add_parser("runs", help="list recorded runs and their integrity")
    runs.add_argument("path", nargs="?", default=".")
    _common(runs)
    runs.set_defaults(func=cmd_runs)

    mcp = sub.add_parser("mcp", help="serve the MCP adapter over stdio")
    mcp.add_argument("path", nargs="?", default=".")
    _common(mcp)
    mcp.set_defaults(func=cmd_mcp)

    coverage = sub.add_parser("coverage", help="what previous runs did not examine")
    coverage.add_argument("path", nargs="?", default=".")
    _common(coverage)
    coverage.set_defaults(func=cmd_coverage)

    replay = sub.add_parser("replay", help="re-execute a recorded run offline")
    replay.add_argument("run_id")
    replay.add_argument("path", nargs="?", default=".")
    _common(replay)
    replay.set_defaults(func=cmd_replay)

    report = sub.add_parser("report", help="render a recorded run")
    report.add_argument("run_id", nargs="?", default=None)
    report.add_argument("--path", default=".")
    report.add_argument(
        "--format", choices=tuple(sorted(RENDERERS)), default="markdown",
        help="markdown | json | sarif | html",
    )
    _common(report)
    report.set_defaults(func=cmd_report)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except InvalidRunId as exc:
        # A rejected run id is bad input, not an internal failure. Surfacing it
        # as a usage error keeps a traceback out of a CI log.
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (json.JSONDecodeError, ValueError) as exc:
        # Run artifacts are read back from disk and may be malformed or hostile.
        # Failing closed with a message beats a stack trace that leaks paths.
        print(f"error: unreadable run artifact: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
