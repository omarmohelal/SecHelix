#!/usr/bin/env python3
"""Evaluate SecHelix catalog applicability from explicit architecture evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sechelix_core.applicability import evaluate_applicability  # noqa: E402
from sechelix_core.contracts import load_json  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="applicability input JSON")
    parser.add_argument("--catalog", type=Path, default=ROOT / "catalog" / "checks.json")
    parser.add_argument("--output", type=Path, help="write output here; stdout when omitted")
    args = parser.parse_args()
    try:
        result = evaluate_applicability(load_json(args.catalog), load_json(args.input))
    except (OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
