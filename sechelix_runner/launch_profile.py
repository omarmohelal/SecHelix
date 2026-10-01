"""Executable evidence routing for the AI-Built App Launch checks 19-36.

This module deliberately does not turn a checklist into findings.  It routes each
launch check to the SecHelix specialist that owns the relevant boundary, records
whether that lane actually examined the check, and keeps "no candidate" distinct
from PASS.  A clean release decision still belongs to the canonical verification
and release contracts.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterable

from .context import ContextBuilder
from .graph import GraphNode, ReasonerGraph
from .roles import NodeRole, NodeStatus

LAUNCH_EXECUTION_STATES = frozenset(
    {"CANDIDATE", "ASSESSED_NO_CANDIDATE", "UNKNOWN", "BLOCKED", "FAILED"}
)


@dataclass(frozen=True)
class LaunchCheck:
    id: str
    number: str
    title: str
    owner_role: NodeRole
    families: tuple[str, ...]
    evidence_mode: str
    proof_classes: tuple[str, ...]
    fixture_ids: tuple[str, ...]
    evidence_required: str
    refuted_if: str
    safe_test: str

    def context_view(self) -> dict[str, object]:
        return {
            "id": self.id,
            "number": self.number,
            "title": self.title,
            "families": list(self.families),
            "evidence_mode": self.evidence_mode,
            "proof_classes": list(self.proof_classes),
            "fixture_ids": list(self.fixture_ids),
            "evidence_required": self.evidence_required,
            "refuted_if": self.refuted_if,
            "safe_test": self.safe_test,
        }


def _catalog_candidates() -> tuple[Path, ...]:
    package_root = Path(__file__).resolve().parent
    repository_root = package_root.parent
    return (
        repository_root / "catalog" / "launch-checks.json",
        package_root / "_bundled" / "catalog" / "launch-checks.json",
    )


def default_launch_catalog_path() -> Path:
    for candidate in _catalog_candidates():
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("launch-checks.json is not available in the repository or bundled runtime")


def load_launch_checks(path: Path | str | None = None) -> tuple[LaunchCheck, ...]:
    source = Path(path) if path is not None else default_launch_catalog_path()
    payload = json.loads(source.read_text(encoding="utf-8"))
    rows = payload.get("checks")
    if not isinstance(rows, list):
        raise ValueError("launch check catalog must contain a checks array")

    checks: list[LaunchCheck] = []
    seen: set[str] = set()
    for raw in rows:
        if not isinstance(raw, dict):
            raise ValueError("launch check rows must be JSON objects")
        check_id = str(raw.get("id", "")).strip()
        number = str(raw.get("number", "")).strip()
        if not check_id or check_id in seen:
            raise ValueError(f"duplicate or missing launch check id: {check_id!r}")
        seen.add(check_id)
        try:
            role = NodeRole(str(raw.get("owner_role", "")).strip())
        except ValueError as exc:
            raise ValueError(f"{check_id}: unknown owner_role") from exc

        families = tuple(str(item).strip() for item in raw.get("families", []) if str(item).strip())
        proof_classes = tuple(
            str(item).strip() for item in raw.get("proof_classes", []) if str(item).strip()
        )
        fixture_ids = tuple(
            str(item).strip() for item in raw.get("fixture_ids", []) if str(item).strip()
        )
        evidence_required = str(raw.get("evidence_required", "")).strip()
        refuted_if = str(raw.get("refuted_if", "")).strip()
        safe_test = str(raw.get("safe_test", "")).strip()
        if (
            not number
            or not str(raw.get("title", "")).strip()
            or not families
            or not evidence_required
            or not refuted_if
            or not safe_test
        ):
            raise ValueError(
                f"{check_id}: number, title, families and evidence procedures are required"
            )
        checks.append(
            LaunchCheck(
                id=check_id,
                number=number,
                title=str(raw["title"]).strip(),
                owner_role=role,
                families=families,
                evidence_mode=str(raw.get("evidence_mode", "STATIC_PLUS_RUNTIME")).strip(),
                proof_classes=proof_classes,
                fixture_ids=fixture_ids,
                evidence_required=evidence_required,
                refuted_if=refuted_if,
                safe_test=safe_test,
            )
        )
    return tuple(sorted(checks, key=lambda item: item.number))


class LaunchContextBuilder(ContextBuilder):
    """Adds only the launch checks owned by the current specialist."""

    def __init__(self, world: dict[str, Any], checks: Iterable[LaunchCheck]) -> None:
        super().__init__(world)
        self._checks = tuple(checks)

    def build(self, node_id: str, role: NodeRole):
        view = super().build(node_id, role)
        selected = [
            check.context_view() for check in self._checks if check.owner_role is role
        ]
        if selected:
            view.payload["launch_checks"] = selected
            view.source_ids.append("launch_checks")
        return view


def build_launch_graph(checks: Iterable[LaunchCheck]) -> ReasonerGraph:
    selected = tuple(checks)
    nodes = [GraphNode("map", NodeRole.MAPPER, (), mandatory=True, reason="launch mapping")]
    roles = sorted({check.owner_role for check in selected}, key=lambda role: role.value)
    lanes: list[str] = []
    for role in roles:
        node_id = f"launch-{role.value.lower()}"
        nodes.append(
            GraphNode(
                node_id,
                role,
                ("map",),
                mandatory=True,
                reason="owns one or more selected launch checks",
            )
        )
        lanes.append(node_id)
    nodes.append(
        GraphNode(
            "launch-verify",
            NodeRole.INDEPENDENT_VERIFIER,
            tuple(lanes) or ("map",),
            mandatory=True,
            reason="independent verification for launch candidates",
        )
    )
    return ReasonerGraph(nodes)


def _candidate_ids(output: dict[str, Any]) -> set[str]:
    found: set[str] = set()
    for candidate in output.get("candidates", []) if isinstance(output, dict) else []:
        if not isinstance(candidate, dict):
            continue
        ids = candidate.get("hypothesis_ids", [])
        if isinstance(ids, list):
            found.update(item for item in ids if isinstance(item, str))
    return found


def summarize_launch_run(result: Any, checks: Iterable[LaunchCheck]) -> dict[str, Any]:
    """Return per-check execution state without inventing PASS."""

    rows: list[dict[str, object]] = []
    totals = {state: 0 for state in sorted(LAUNCH_EXECUTION_STATES)}
    for check in checks:
        node_id = f"launch-{check.owner_role.value.lower()}"
        record = result.records.get(node_id)
        output = result.outputs.get(node_id, {}) if hasattr(result, "outputs") else {}
        state = "UNKNOWN"

        if record is None:
            state = "UNKNOWN"
        elif record.status is NodeStatus.BLOCKED:
            state = "BLOCKED"
        elif record.status in {NodeStatus.FAILED, NodeStatus.INCOMPLETE}:
            state = "FAILED"
        elif record.status is NodeStatus.SUCCEEDED:
            candidate_ids = _candidate_ids(output)
            examined = {
                item for item in output.get("examined", [])
                if isinstance(item, str)
            } if isinstance(output, dict) else set()
            if check.id in candidate_ids:
                state = "CANDIDATE"
            elif check.id in examined:
                state = "ASSESSED_NO_CANDIDATE"
            else:
                state = "UNKNOWN"

        totals[state] += 1
        rows.append(
            {
                "id": check.id,
                "number": check.number,
                "title": check.title,
                "owner_role": check.owner_role.value,
                "node_id": node_id,
                "node_status": record.status.value if record is not None else None,
                "execution_state": state,
                "proof_classes": list(check.proof_classes),
                "fixture_ids": list(check.fixture_ids),
            }
        )

    return {
        "profile": "AI-Built App Launch Audit / checks 19-36",
        "pass_emitted": False,
        "note": (
            "ASSESSED_NO_CANDIDATE is not PASS. PASS requires concrete evidence "
            "through the canonical SecHelix verification and release contracts."
        ),
        "totals": totals,
        "checks": rows,
    }
