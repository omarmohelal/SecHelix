"""Attack-surface semantic validation and stable Mermaid rendering."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .contracts import validate_contract


def validate_attack_surface(graph: dict[str, Any]) -> None:
    validate_contract("attack-surface", graph)


def _escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("|", "&#124;")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def render_mermaid(graph: dict[str, Any], direction: str = "LR") -> str:
    """Render validated graph data using deterministic aliases and ordering."""

    if direction not in {"LR", "RL", "TB", "BT"}:
        raise ValueError("direction must be one of LR, RL, TB, BT")
    validate_attack_surface(graph)
    nodes = sorted(graph["nodes"], key=lambda item: item["id"])
    aliases = {node["id"]: f"n{index:04d}" for index, node in enumerate(nodes, 1)}
    boundary_by_node = {
        node_id: boundary["id"]
        for boundary in graph["boundaries"]
        for node_id in boundary["node_ids"]
    }
    boundaries = sorted(graph["boundaries"], key=lambda item: item["id"])
    lines = [f"flowchart {direction}"]
    rendered: set[str] = set()
    for boundary_index, boundary in enumerate(boundaries, 1):
        lines.append(f'  subgraph b{boundary_index:04d}["{_escape(boundary["label"])}"]')
        for node in nodes:
            if boundary_by_node.get(node["id"]) == boundary["id"]:
                lines.append(f'    {aliases[node["id"]]}["{_escape(node["label"])}"]')
                rendered.add(node["id"])
        lines.append("  end")
    for node in nodes:
        if node["id"] not in rendered:
            lines.append(f'  {aliases[node["id"]]}["{_escape(node["label"])}"]')
    for edge in sorted(graph["edges"], key=lambda item: item["id"]):
        lines.append(f'  {aliases[edge["from"]]} -->|"{_escape(edge["label"])}"| {aliases[edge["to"]]}')
    return "\n".join(lines) + "\n"


class AttackSurfaceDiffError(ValueError):
    """Two attack-surface graphs cannot be compared safely."""


def _material(value: Any) -> Any:
    """Return a stable structural view that ignores evidence-reference churn."""

    if isinstance(value, dict):
        return {
            key: _material(item)
            for key, item in sorted(value.items())
            if key != "evidence_ids"
        }
    if isinstance(value, list):
        return [_material(item) for item in value]
    return value


def _digest_graph(graph: dict[str, Any]) -> str:
    raw = json.dumps(
        graph,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _by_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row["id"]): row for row in rows}


def _role_key(row: dict[str, Any]) -> str:
    return "::".join(
        str(row.get(name, "")).strip()
        for name in ("role", "object", "action")
    )


def _diff_named(
    before_rows: list[dict[str, Any]],
    after_rows: list[dict[str, Any]],
    *,
    key_fn,
) -> dict[str, list[Any]]:
    before = {key_fn(row): row for row in before_rows}
    after = {key_fn(row): row for row in after_rows}
    added = [after[key] for key in sorted(set(after) - set(before))]
    removed = [before[key] for key in sorted(set(before) - set(after))]
    changed = [
        {
            "key": key,
            "before": before[key],
            "after": after[key],
        }
        for key in sorted(set(before) & set(after))
        if _material(before[key]) != _material(after[key])
    ]
    return {"added": added, "removed": removed, "changed": changed}


def _seed_id(kind: str, change: str, key: str) -> str:
    raw = f"{kind}|{change}|{key}".encode("utf-8")
    return "HYP-ASD-" + hashlib.sha256(raw).hexdigest()[:16].upper()


def _hypothesis_seed(
    *,
    kind: str,
    change: str,
    key: str,
    summary: str,
) -> dict[str, Any]:
    return {
        "hypothesis_id": _seed_id(kind, change, key),
        "status": "NEW_HYPOTHESIS",
        "source": "attack-surface-diff",
        "element_type": kind,
        "element_key": key,
        "change": change,
        "summary": summary,
        "evidence_required": (
            "Re-map the changed surface, trace attacker reachability and the "
            "relevant security boundary, then test the applicable invariant. "
            "This diff alone is not vulnerability evidence."
        ),
    }


def diff_attack_surfaces(
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    """Compare two validated graphs and emit neutral security-hypothesis seeds.

    Stable IDs are treated as identity. Evidence-id-only churn is deliberately
    ignored so a refreshed citation does not manufacture new attack surface.
    Added/removed/changed structure produces a hypothesis seed, never a finding.
    """

    validate_attack_surface(before)
    validate_attack_surface(after)
    if before["scope_id"] != after["scope_id"]:
        raise AttackSurfaceDiffError(
            "attack-surface graphs must share scope_id before they can be compared"
        )

    sections = {
        "nodes": _diff_named(before["nodes"], after["nodes"], key_fn=lambda row: str(row["id"])),
        "edges": _diff_named(before["edges"], after["edges"], key_fn=lambda row: str(row["id"])),
        "boundaries": _diff_named(
            before["boundaries"],
            after["boundaries"],
            key_fn=lambda row: str(row["id"]),
        ),
        "role_object_actions": _diff_named(
            before["role_object_actions"],
            after["role_object_actions"],
            key_fn=_role_key,
        ),
    }

    before_unknowns = set(str(item) for item in before.get("unknowns", []))
    after_unknowns = set(str(item) for item in after.get("unknowns", []))
    unknowns = {
        "added": sorted(after_unknowns - before_unknowns),
        "resolved": sorted(before_unknowns - after_unknowns),
    }

    seeds: list[dict[str, Any]] = []
    labels = {
        "nodes": "attack-surface node",
        "edges": "attack-surface relationship",
        "boundaries": "trust boundary",
        "role_object_actions": "role/object/action authorization rule",
    }
    for section_name, delta in sections.items():
        kind = section_name.upper()
        label = labels[section_name]
        for row in delta["added"]:
            key = str(row.get("id") or _role_key(row))
            seeds.append(
                _hypothesis_seed(
                    kind=kind,
                    change="ADDED",
                    key=key,
                    summary=f"New {label}: {key}.",
                )
            )
        for row in delta["removed"]:
            key = str(row.get("id") or _role_key(row))
            seeds.append(
                _hypothesis_seed(
                    kind=kind,
                    change="REMOVED",
                    key=key,
                    summary=(
                        f"Removed {label}: {key}. Confirm whether a reachable "
                        "surface or security control disappeared."
                    ),
                )
            )
        for row in delta["changed"]:
            key = str(row["key"])
            seeds.append(
                _hypothesis_seed(
                    kind=kind,
                    change="CHANGED",
                    key=key,
                    summary=f"Materially changed {label}: {key}.",
                )
            )

    for value in unknowns["added"]:
        seeds.append(
            _hypothesis_seed(
                kind="UNKNOWN",
                change="ADDED",
                key=value,
                summary=f"New unresolved attack-surface uncertainty: {value}",
            )
        )

    seeds.sort(key=lambda item: item["hypothesis_id"])
    material_changes = sum(
        len(delta["added"]) + len(delta["removed"]) + len(delta["changed"])
        for delta in sections.values()
    ) + len(unknowns["added"]) + len(unknowns["resolved"])

    return {
        "schema_version": "attack-surface-diff-v1",
        "scope_id": before["scope_id"],
        "before": {
            "graph_id": before["graph_id"],
            "sha256": _digest_graph(before),
        },
        "after": {
            "graph_id": after["graph_id"],
            "sha256": _digest_graph(after),
        },
        "material_change_count": material_changes,
        "changed": material_changes > 0,
        "sections": sections,
        "unknowns": unknowns,
        "new_hypotheses": seeds,
        "verification_rule": (
            "Attack-surface deltas create hypotheses only. They remain unverified "
            "until normal SecHelix testing and independent verification."
        ),
    }
