#!/usr/bin/env python3
"""Validate canonical SecHelix skill frontmatter and required adapter surfaces."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
#: Every discovery path a host is documented to read. Listing them here means a
#: deleted adapter fails the build instead of quietly becoming a README claim
#: about a directory that is no longer there.
ADAPTERS = (
    "skills/sechelix/SKILL.md",
    ".claude/skills/sechelix/SKILL.md",
    ".agents/skills/sechelix/SKILL.md",
    ".github/skills/sechelix/SKILL.md",
)

#: What an agent must find in an installed skill to run the workflow. All of it is
#: instructions or data; the bundle ships no executable code (see EXECUTABLE_SUFFIXES).
PORTABLE_REQUIRED = (
    "README.md",
    "catalog/checks.json",
    "catalog/hypothesis-ids.txt",
    "agents/independent-verifier.md",
    "references/methodology.md",
    "references/runtime.md",
    "schemas/scope-v1.schema.json",
    "schemas/report-v1.schema.json",
    "schemas/source-registry-v1.schema.json",
    "schemas/knowledge-graph-v1.schema.json",
    "schemas/lesson-card-v1.schema.json",
    "schemas/research-packet-v1.schema.json",
    "schemas/finding-v1.schema.json",
    "gold-packs/SEC-AUTHZ-IDOR-001/pack.json",
    "policies/default.json",
    "knowledge/source-registry.json",
    "knowledge/graph/relationships.json",
    "knowledge/lesson-cards/CWE-918.json",
)

#: An installed skill is read, never executed. Code in the bundle is weight no review step
#: runs and executable surface every install-time audit has to judge: the skills.sh Socket
#: verdict shown on every `npx skills add` was produced from files like these.
EXECUTABLE_SUFFIXES = frozenset({
    ".py", ".pyc", ".pyo", ".pyw", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php", ".exe", ".dll", ".so",
})


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
    canonical = ROOT / "skills" / "sechelix" / "SKILL.md"
    errors = validate_skill_file(canonical)
    if len(canonical.read_text(encoding="utf-8").splitlines()) >= 500:
        errors.append("skills/sechelix/SKILL.md must remain under 500 lines")
    if (ROOT / "SKILL.md").exists():
        errors.append(
            "a root SKILL.md makes the Skills CLI package the whole repository; "
            "the canonical entry point is skills/sechelix/SKILL.md"
        )
    for relative in ADAPTERS:
        errors.extend(validate_skill_file(ROOT / relative))
    portable = ROOT / "skills" / "sechelix"
    portable_text = (portable / "SKILL.md").read_text(encoding="utf-8")
    if "../../" in portable_text or "../SKILL.md" in portable_text:
        errors.append("portable skill must not depend on repository-parent paths")
    for relative in PORTABLE_REQUIRED:
        if not (portable / relative).is_file():
            errors.append(f"portable skill missing required resource: {relative}")
    executable = sorted(
        path.relative_to(portable).as_posix()
        for path in portable.rglob("*")
        if path.is_file() and path.suffix.lower() in EXECUTABLE_SUFFIXES
    )
    if executable:
        errors.append(
            "the installed skill must ship no executable code; found "
            f"{len(executable)}: {executable[:5]}"
        )
    if errors:
        print("SecHelix skill INVALID")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"OK: canonical skill and {len(ADAPTERS)} adapter surfaces validate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
