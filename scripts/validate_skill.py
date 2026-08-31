#!/usr/bin/env python3
"""Validate canonical SecHelix skill frontmatter and required adapter surfaces."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADAPTERS = (
    "skills/sechelix/SKILL.md",
    ".claude/skills/sechelix/SKILL.md",
    ".codex/skills/sechelix/SKILL.md",
    ".agents/skills/sechelix/SKILL.md",
    ".github/skills/sechelix/SKILL.md",
)


def validate_skill_file(path: Path) -> list[str]:
    errors = []
    if not path.is_file():
        return [f"missing skill: {path}"]
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return [f"{path}: missing YAML frontmatter"]
    parts = text.split("---", 2)
    if len(parts) < 3:
        return [f"{path}: unterminated YAML frontmatter"]
    front = parts[1]
    name = re.search(r"^name:\s*(.+)$", front, re.MULTILINE)
    description = re.search(r"^description:\s*(.+)$", front, re.MULTILINE)
    if not name or name.group(1).strip() != "sechelix":
        errors.append(f"{path}: name must be sechelix")
    if not description or not 0 < len(description.group(1).strip()) <= 1024:
        errors.append(f"{path}: description must be 1..1024 characters")
    return errors


def main() -> int:
    errors = validate_skill_file(ROOT / "SKILL.md")
    if len((ROOT / "SKILL.md").read_text(encoding="utf-8").splitlines()) >= 500:
        errors.append("SKILL.md must remain under 500 lines")
    for relative in ADAPTERS:
        errors.extend(validate_skill_file(ROOT / relative))
    if errors:
        print("SecHelix skill INVALID")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"OK: canonical skill and {len(ADAPTERS)} adapter surfaces validate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
