#!/usr/bin/env python3
"""Validate every checked-in Gold Check Pack contract."""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sechelix_core.contracts import ContractValidationError, validate_contract  # noqa: E402


def check(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    paths = sorted((root / "gold-packs").glob("*/pack.json"))
    if not paths:
        return ["gold-packs: no pack.json files found"]
    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            validate_contract("gold-check-pack", data)
        except (json.JSONDecodeError, ContractValidationError) as exc:
            errors.append(f"{path.relative_to(root)}: {exc}")
    return errors


def main() -> int:
    errors = check()
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("OK: Gold Check Packs satisfy structural, provenance, and safety contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
