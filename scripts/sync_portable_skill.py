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

#: Paths that are repository teaching material rather than skill runtime
#: resources. The portable bundle is what an agent loads to do a review; a
#: runnable demo application is read by people, not by the skill, and mirroring
#: it would roughly double the bundle for something no review step ever opens.
EXCLUDED_TREES = (
    Path("examples/expense-api"),
    # Deliberately vulnerable teaching code for the Action self-test. Shipping it
    # inside an installed skill would put known-vulnerable source on every user's
    # machine for no review step that reads it.
    Path("examples/demo-app"),
    # Renderings derived from examples/report.example.json, which does ship. The
    # renderer reproduces them on demand.
    Path("examples/reports"),
)

#: Authored in place in the bundle, never copied from a canonical source.
AUTHORED_IN_PLACE = frozenset({"SKILL.md"})

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
    if any(relative.is_relative_to(tree) for tree in EXCLUDED_TREES):
        return False
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
    # skills/sechelix/SKILL.md is the canonical Agent Skill entry point and is
    # authored in place; the sync only mirrors the runtime resources around it.
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


def prune(copied: list[Path]) -> list[Path]:
    """Delete bundle files that no canonical source produces any more.

    Without this, a file removed or excluded upstream lives on in every install,
    and the drift check cannot see it because the stale copy is still tracked.
    """
    keep = {path.resolve() for path in copied}
    keep.update((DEST / name).resolve() for name in AUTHORED_IN_PLACE)
    removed = []
    for path in sorted(DEST.rglob("*"), reverse=True):
        if path.is_file() and path.resolve() not in keep:
            path.unlink()
            removed.append(path)
        elif path.is_dir() and not any(path.iterdir()):
            path.rmdir()
    return removed


def main() -> int:
    copied = sync()
    removed = prune(copied)
    print(
        f"OK: synchronized {len(copied)} files into {DEST.relative_to(ROOT)}"
        + (f"; pruned {len(removed)} stale file(s)" if removed else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
