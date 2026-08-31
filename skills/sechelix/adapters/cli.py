"""Normalize a scanner report without assessing its findings.

Usage: python -m adapters.cli semgrep semgrep.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .base import AdapterError
from .registry import ADAPTERS, parse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("adapter", choices=sorted(ADAPTERS))
    parser.add_argument("input", type=Path, help="scanner report path")
    parser.add_argument("-o", "--output", type=Path, help="write normalized JSON to this path")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        records = parse(args.adapter, args.input.read_bytes())
    except (OSError, AdapterError, ValueError) as exc:
        print(f"adapter error: {exc}", file=sys.stderr)
        return 2
    document = {
        "adapter": args.adapter,
        "trust_boundary": "scanner observations are CANDIDATE/UNASSESSED",
        "records": records,
    }
    rendered = json.dumps(document, indent=2 if args.pretty else None, sort_keys=True) + "\n"
    if args.output:
        try:
            args.output.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            print(f"adapter error: {exc}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
