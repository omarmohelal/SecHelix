#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog" / "checks.json"


def main() -> int:
    data = json.loads(CATALOG.read_text(encoding="utf-8"))
    families = data.get("families", [])
    lenses = data.get("lenses", [])
    errors = []

    if len(families) != 21:
        errors.append(f"expected 21 families, got {len(families)}")
    if len(lenses) != 26:
        errors.append(f"expected 26 lenses, got {len(lenses)}")

    family_ids = [x.get("id") for x in families]
    lens_ids = [x.get("id") for x in lenses]
    if len(family_ids) != len(set(family_ids)):
        errors.append("duplicate family id")
    if len(lens_ids) != len(set(lens_ids)):
        errors.append("duplicate lens id")

    for item in families:
        for key in ("id", "name", "focus"):
            if not str(item.get(key, "")).strip():
                errors.append(f"family missing {key}: {item}")
    for item in lenses:
        for key in ("id", "name", "question"):
            if not str(item.get(key, "")).strip():
                errors.append(f"lens missing {key}: {item}")

    computed = len(families) * len(lenses)
    declared = int(data.get("computed_hypotheses", -1))
    if computed != 546:
        errors.append(f"cross product must equal 546, got {computed}")
    if declared != computed:
        errors.append(f"declared count {declared} != computed {computed}")

    if errors:
        print("SecHelix catalog INVALID")
        for error in errors:
            print(f"- {error}")
        return 1

    print(f"OK: {computed} structured hypotheses, {len(families)} families, {len(lenses)} lenses")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
