#!/usr/bin/env python3
"""Validate the SecHelix source registry, graph, lesson cards, and research packet."""

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sechelix_core.contracts import ContractValidationError, validate_contract  # noqa: E402


ARTIFACTS = (
    ("source-registry", ROOT / "knowledge" / "source-registry.json"),
    ("knowledge-graph", ROOT / "knowledge" / "graph" / "relationships.json"),
    ("research-packet", ROOT / "examples" / "research-packet.example.json"),
)


def validate() -> list[str]:
    errors: list[str] = []
    artifacts = list(ARTIFACTS)
    artifacts.extend(
        ("lesson-card", path)
        for path in sorted((ROOT / "knowledge" / "lesson-cards").glob("*.json"))
    )
    for contract, path in artifacts:
        try:
            with path.open(encoding="utf-8") as handle:
                data = json.load(handle)
            validate_contract(contract, data)
        except (OSError, json.JSONDecodeError, ContractValidationError) as exc:
            errors.append(f"{path.relative_to(ROOT)}: {exc}")
    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("SecHelix knowledge engine INVALID")
        for error in errors:
            print(f"- {error}")
        return 1
    lesson_count = len(list((ROOT / "knowledge" / "lesson-cards").glob("*.json")))
    print(f"OK: source registry, knowledge graph, {lesson_count} lesson card(s), and research packet validate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
