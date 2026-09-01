#!/usr/bin/env python3
"""Build the self-contained Agent Skills distribution from canonical sources."""

from __future__ import annotations

import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "skills" / "sechelix"

DIRECTORIES = (
    "adapters",
    "agents",
    "catalog",
    "examples",
    "gold-packs",
    "knowledge",
    "policies",
    "references",
    "reports",
    "schemas",
    "sechelix_core",
)

EXCLUDED_PARTS = {"__pycache__", "tests"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}

SCRIPT_FILES = (
    "applicability.py",
    "attack_surface.py",
    "security_gate.py",
    "validate_contract.py",
    "validate_knowledge.py",
    "validate_gold_packs.py",
)

def include(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    return (
        path.is_file()
        and not EXCLUDED_PARTS.intersection(relative.parts)
        and path.suffix.lower() not in EXCLUDED_SUFFIXES
    )


def copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def sync() -> list[Path]:
    copied: list[Path] = []
    copy_file(ROOT / "SKILL.md", DEST / "SKILL.md")
    copied.append(DEST / "SKILL.md")
    copy_file(ROOT / "docs" / "portable-skill.md", DEST / "README.md")
    copied.append(DEST / "README.md")

    for directory in DIRECTORIES:
        source_root = ROOT / directory
        for source in sorted(source_root.rglob("*")):
            if not include(source):
                continue
            destination = DEST / source.relative_to(ROOT)
            copy_file(source, destination)
            copied.append(destination)

    for name in SCRIPT_FILES:
        source = ROOT / "scripts" / name
        destination = DEST / "scripts" / name
        copy_file(source, destination)
        copied.append(destination)

    return copied


def main() -> int:
    copied = sync()
    print(f"OK: synchronized {len(copied)} files into {DEST.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
