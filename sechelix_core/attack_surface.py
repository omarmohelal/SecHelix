"""Attack-surface semantic validation and stable Mermaid rendering."""

from __future__ import annotations

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
