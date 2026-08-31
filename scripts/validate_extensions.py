#!/usr/bin/env python3
"""Validate the curated extension registry and every submitted manifest."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sechelix_core.contracts import ContractValidationError, load_json, validate_contract  # noqa: E402

REGISTRY = ROOT / "extensions" / "registry.json"


def validate() -> list[str]:
    errors: list[str] = []
    try:
        registry = load_json(REGISTRY)
        validate_contract("extension-registry", registry)
    except (OSError, ContractValidationError) as exc:
        return [str(exc)]

    registered = {item["id"]: item for item in registry["extensions"]}
    manifests = sorted((ROOT / "extensions" / "community").glob("*/extension.json"))
    discovered: dict[str, Path] = {}
    for manifest_path in manifests:
        try:
            manifest = load_json(manifest_path)
            validate_contract("extension-manifest", manifest)
        except (OSError, ContractValidationError) as exc:
            errors.append(f"{manifest_path.relative_to(ROOT)}: {exc}")
            continue
        extension_id = manifest["id"]
        discovered[extension_id] = manifest_path
        expected_path = manifest_path.relative_to(ROOT).as_posix()
        entry = registered.get(extension_id)
        if entry is None:
            errors.append(f"{expected_path}: manifest is missing from extensions/registry.json")
        elif entry["manifest"] != expected_path:
            errors.append(f"{expected_path}: registry points to {entry['manifest']!r}")
        if manifest_path.parent.name != extension_id:
            errors.append(f"{expected_path}: directory name must match manifest id {extension_id!r}")

    for extension_id, entry in registered.items():
        if extension_id not in discovered:
            errors.append(f"{entry['manifest']}: registered manifest does not exist or failed validation")
    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("SecHelix extensions INVALID")
        for error in errors:
            print(f"- {error}")
        return 1
    print("OK: extension registry and community manifests satisfy the safety contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
