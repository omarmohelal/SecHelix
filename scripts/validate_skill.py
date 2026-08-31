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

PORTABLE_REQUIRED = (
    "README.md",
    "catalog/checks.json",
    "catalog/hypothesis-ids.txt",
    "agents/independent-verifier.md",
    "schemas/scope-v1.schema.json",
    "schemas/report-v1.schema.json",
    "sechelix_core/applicability.py",
    "adapters/cli.py",
    "reports/report_renderer.py",
    "scripts/security_gate.py",
    "policies/default.json",
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
    portable = ROOT / "skills" / "sechelix"
    portable_text = (portable / "SKILL.md").read_text(encoding="utf-8")
    if "../../" in portable_text or "../SKILL.md" in portable_text:
        errors.append("portable skill must not depend on repository-parent paths")
    for relative in PORTABLE_REQUIRED:
        if not (portable / relative).is_file():
            errors.append(f"portable skill missing runtime resource: {relative}")
    if errors:
        print("SecHelix skill INVALID")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"OK: canonical skill and {len(ADAPTERS)} adapter surfaces validate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
