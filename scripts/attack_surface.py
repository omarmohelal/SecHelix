#!/usr/bin/env python3
"""Validate or render a canonical SecHelix attack-surface graph."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sechelix_core.attack_surface import (  # noqa: E402
    diff_attack_surfaces,
    render_mermaid,
    validate_attack_surface,
)
from sechelix_core.contracts import load_json  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "render", "diff"))
    parser.add_argument("path", type=Path)
    parser.add_argument(
        "--against",
        type=Path,
        help="newer attack-surface graph when command=diff",
    )
    parser.add_argument("--direction", default="LR", choices=("LR", "RL", "TB", "BT"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        graph = load_json(args.path)
        validate_attack_surface(graph)
        if args.command == "validate":
            print(f"OK: {args.path} is a valid attack-surface graph")
            return 0
        if args.command == "diff":
            if args.against is None:
                raise ValueError("diff requires --against NEW_GRAPH.json")
            newer = load_json(args.against)
            result = diff_attack_surfaces(graph, newer)
            rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
            if args.output:
                args.output.write_text(rendered, encoding="utf-8")
            else:
                print(rendered, end="")
            return 0
        rendered = render_mermaid(graph, args.direction)
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 0
    except (OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
