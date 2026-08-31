#!/usr/bin/env python3
"""Validate the explicit catalog, semantics, frozen IDs, and reproducibility."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sechelix_core.contracts import ContractValidationError, load_json, validate_contract  # noqa: E402

CATALOG = ROOT / "catalog" / "checks.json"


def main() -> int:
    try:
        data = load_json(CATALOG)
        validate_contract("catalog", data)
    except (OSError, ContractValidationError) as exc:
        print(f"SecHelix catalog INVALID\n{exc}")
        return 1
    generated = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate_catalog.py"), "--check"],
        cwd=ROOT,
        check=False,
    )
    if generated.returncode:
        return generated.returncode
    print("OK: 546 explicit hypotheses, 21 families, 26 lenses; IDs and generated metadata are stable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
