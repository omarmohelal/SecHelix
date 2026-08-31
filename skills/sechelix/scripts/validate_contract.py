#!/usr/bin/env python3
"""Validate a SecHelix JSON artifact against its canonical contract."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sechelix_core.contracts import ContractValidationError, SCHEMAS, load_json, validate_contract  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract", choices=sorted(SCHEMAS))
    parser.add_argument("path", type=Path)
    parser.add_argument("--require-authorization", action="store_true")
    args = parser.parse_args()
    try:
        validate_contract(args.contract, load_json(args.path), require_authorization=args.require_authorization)
    except (OSError, ValueError, ContractValidationError) as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"OK: {args.path} satisfies the {args.contract} contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
