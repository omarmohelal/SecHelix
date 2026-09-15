#!/usr/bin/env python3
"""Gate the curated public-directory edition so it cannot grow back into the whole product.

`distributions/awesome-copilot/` is a compact, runtime-free Agent Plugin for skill directories.
GitHub's awesome-copilot rejected the full skill (issue #2899) because it was a near-500-line
SKILL.md with about thirty auxiliary files and read as project promotion. This gate encodes that
feedback as limits, and ties the curated text to the canonical contracts so it cannot drift:

- size: SKILL.md line budget, supporting-file budget, total byte budget;
- structure: Agent Plugins v1.0.0 manifest, one skill discovered by convention, frontmatter,
  every referenced file present and every shipped file referenced;
- independence: no instruction depends on the SecHelix Python runtime, catalog or scripts;
- drift: status, applicability, verdict and mode vocabularies come from `schemas/`, and the
  manifest version and identity come from the root `plugin.json`;
- scope: no promotional copy and no SEO/cleanup workflow text;
- hygiene: the repository's high-confidence secret patterns.

It checks limits and vocabularies, not prose, so rewording the skill does not break it.

    python scripts/validate_distribution.py
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.check_no_secrets import scan_text  # noqa: E402

PACKAGE = ROOT / "distributions" / "awesome-copilot"

MAX_SKILL_LINES = 220
MAX_SUPPORT_FILES = 6
MAX_PACKAGE_BYTES = 64_000
MAX_KEYWORDS = 10  # awesome-copilot eng/external-plugin-validation.mjs
MAX_MANIFEST_DESCRIPTION = 500

AGENT_PLUGIN_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
AGENT_PLUGIN_KEYS = frozenset({
    "$schema", "name", "version", "description", "author",
    "homepage", "repository", "license", "keywords", "extensions",
})
AGENT_PLUGIN_NAME = re.compile(r"^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
KEYWORD = re.compile(r"^[a-z0-9-]{1,30}$")
REFERENCE = re.compile(r"\breferences/[A-Za-z0-9._-]+\.md\b")

#: (schema file, JSON pointer path) whose enum must appear verbatim in the curated skill.
CANONICAL_VOCABULARIES = (
    ("finding-v1.schema.json", ("properties", "verification", "properties", "outcome")),
    ("applicability-output-v1.schema.json",
     ("properties", "decisions", "items", "properties", "status")),
    ("report-v1.schema.json", ("properties", "release_recommendation")),
    ("scope-v1.schema.json", ("properties", "mode")),
)
#: Enum members that are placeholders rather than instructions.
VOCABULARY_EXEMPT = frozenset({"NOT_RUN"})
#: Labels the project retired; seeing one means the text was copied from an old source.
RETIRED_LABELS = ("SUSPECTED", "UNKNOWN_NEEDS_EVIDENCE")

#: The curated edition must work with no runtime installed.
RUNTIME_DEPENDENCIES = (
    ("SecHelix Python package", re.compile(r"\bsechelix_(?:core|runner)\b")),
    ("repository script", re.compile(r"\bscripts/[\w.-]+\.py\b")),
    ("catalog file", re.compile(r"\bcatalog/checks\.json\b")),
    ("schema file", re.compile(r"\bschemas/[\w.-]+\.json\b")),
    ("runtime CLI", re.compile(r"\b(?:pipx|uvx|pip)\s+install\s+sechelix\b|\bsechelix\s+(?:audit|doctor|mcp|report)\b")),
    ("python module invocation", re.compile(r"\bpython3?\s+-m\s+\w+")),
)

#: Copy that reads as a product pitch. Kept to phrases, not single words, to avoid false hits.
PROMOTIONAL = re.compile(
    r"\b(?:best[- ]in[- ]class|world[- ]class|state[- ]of[- ]the[- ]art|industry[- ]leading|"
    r"cutting[- ]edge|revolutionary|game[- ]chang\w*|most (?:advanced|powerful|complete)|"
    r"the best|unmatched|guarantee[sd]?|detects everything|star (?:the|this) repo|"
    r"leaderboard|marketplace listing|badge|546|hypothes(?:is|es) catalog|gold pack|"
    r"sechelix\.com)\b",
    re.IGNORECASE,
)
#: Workflows that exist in the full product but are outside this edition's single job.
OUT_OF_SCOPE = re.compile(
    r"\b(?:seo|search console|backlink\w*|indexability|codebase cleanup|dead[- ]code removal)\b",
    re.IGNORECASE,
)


def _frontmatter(text: str) -> dict[str, str] | None:
    if not text.startswith("---\n"):
        return None
    parts = text.split("---", 2)
    if len(parts) < 3:
        return None
    fields = {}
    for line in parts[1].splitlines():
        match = re.match(r"^([A-Za-z][\w-]*):\s*(.*)$", line)
        if match:
            fields[match.group(1)] = match.group(2).strip()
    return fields


def canonical_vocabulary(root: Path = ROOT) -> set[str]:
    terms: set[str] = set()
    for schema_name, pointer in CANONICAL_VOCABULARIES:
        node = json.loads((root / "schemas" / schema_name).read_text(encoding="utf-8"))
        for key in pointer:
            node = node[key]
        terms.update(value for value in node["enum"] if value not in VOCABULARY_EXEMPT)
    return terms


def _normalized_size(path: Path) -> int:
    """Byte size with LF line endings, so a Windows checkout measures the same as CI."""
    return len(path.read_bytes().replace(bytes([13, 10]), bytes([10])))


def package_files(package: Path) -> list[Path]:
    return sorted(path for path in package.rglob("*") if path.is_file())


def check_manifest(package: Path, root: Path = ROOT) -> list[str]:
    path = package / "plugin.json"
    if not path.is_file():
        return ["plugin.json is missing at the plugin root"]
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        return [f"plugin.json is not valid JSON: {error}"]
    canonical = json.loads((root / "plugin.json").read_text(encoding="utf-8"))
    problems = []
    extra = sorted(set(manifest) - AGENT_PLUGIN_KEYS)
    if extra:
        problems.append(f"plugin.json fields not in Agent Plugins v1.0.0: {extra}")
    if manifest.get("$schema") != AGENT_PLUGIN_SCHEMA:
        problems.append(f"plugin.json $schema must be {AGENT_PLUGIN_SCHEMA}")
    name = manifest.get("name")
    if not isinstance(name, str) or not 1 <= len(name) <= 64 or not AGENT_PLUGIN_NAME.match(name):
        problems.append("plugin.json name violates Agent Plugins naming rules")
    description = manifest.get("description")
    if not isinstance(description, str) or not description.strip():
        problems.append("plugin.json description is required")
    elif len(description) > MAX_MANIFEST_DESCRIPTION:
        problems.append(f"plugin.json description exceeds {MAX_MANIFEST_DESCRIPTION} characters")
    if manifest.get("version") != canonical.get("version"):
        problems.append(
            f"plugin.json version {manifest.get('version')!r} must match the release version "
            f"{canonical.get('version')!r} in the root plugin.json"
        )
    for field in ("license", "repository"):
        if manifest.get(field) != canonical.get(field):
            problems.append(f"plugin.json {field} must match the root plugin.json")
    keywords = manifest.get("keywords")
    if not isinstance(keywords, list) or not keywords:
        problems.append("plugin.json keywords must be a non-empty list")
    else:
        if len(keywords) > MAX_KEYWORDS:
            problems.append(f"plugin.json has {len(keywords)} keywords; the limit is {MAX_KEYWORDS}")
        bad = [k for k in keywords if not isinstance(k, str) or not KEYWORD.match(k)]
        if bad:
            problems.append(f"plugin.json keywords must be lowercase-hyphen tags <=30 chars: {bad}")
    return problems


def discovered_skills(package: Path) -> list[Path]:
    """Agent Plugins v1.0.0 discovers skills by convention at skills/<name>/SKILL.md."""
    return sorted((package / "skills").glob("*/SKILL.md"))


def check_skill(package: Path, root: Path = ROOT) -> list[str]:
    skills = discovered_skills(package)
    if len(skills) != 1:
        return [f"expected exactly one skill under skills/*/SKILL.md, found {len(skills)}"]
    skill_md = skills[0]
    skill_dir = skill_md.parent
    text = skill_md.read_text(encoding="utf-8")
    problems = []

    fields = _frontmatter(text)
    if fields is None:
        return [f"{skill_md.relative_to(package)} must start with YAML frontmatter"]
    if fields.get("name") != skill_dir.name:
        problems.append(f"frontmatter name {fields.get('name')!r} must equal folder {skill_dir.name!r}")
    if fields.get("name") == "sechelix":
        problems.append(
            "the curated skill must not reuse the canonical name 'sechelix'; `gh skill install` "
            "discovers nested skills and would install the wrong one"
        )
    if not 10 <= len(fields.get("description", "")) <= 1024:
        problems.append("frontmatter description must be 10..1024 characters")

    lines = len(text.splitlines())
    if lines > MAX_SKILL_LINES:
        problems.append(f"SKILL.md is {lines} lines; the budget is {MAX_SKILL_LINES}")

    support = [p for p in package_files(skill_dir) if p != skill_md]
    if len(support) > MAX_SUPPORT_FILES:
        problems.append(f"{len(support)} supporting files; the budget is {MAX_SUPPORT_FILES}")
    for path in support:
        relative = path.relative_to(skill_dir)
        if path.suffix != ".md":
            problems.append(f"supporting file {relative} is not Markdown; this edition ships no code")
        if len(relative.parts) != 2 or relative.parts[0] != "references":
            problems.append(f"supporting file {relative} must live directly under references/")

    corpus = text + "".join(p.read_text(encoding="utf-8") for p in support if p.suffix == ".md")
    referenced = set(REFERENCE.findall(corpus))
    shipped = {p.relative_to(skill_dir).as_posix() for p in support}
    for missing in sorted(referenced - shipped):
        problems.append(f"{missing} is referenced but not shipped")
    unreferenced = sorted(shipped - set(REFERENCE.findall(text)))
    for orphan in unreferenced:
        problems.append(f"{orphan} is shipped but SKILL.md never tells the agent to load it")

    missing_terms = sorted(
        term for term in canonical_vocabulary(root) if not re.search(rf"\b{re.escape(term)}\b", corpus)
    )
    if missing_terms:
        problems.append(f"canonical vocabulary missing from the curated skill: {missing_terms}")
    for label in RETIRED_LABELS:
        if re.search(rf"\b{label}\b", corpus):
            problems.append(f"retired label {label} appears in the curated skill")
    return problems


def check_content(package: Path) -> list[str]:
    problems = []
    for path in package_files(package):
        relative = path.relative_to(package).as_posix()
        text = path.read_text(encoding="utf-8")
        for label, pattern in RUNTIME_DEPENDENCIES:
            match = pattern.search(text)
            if match:
                problems.append(f"{relative}: depends on the {label} ({match.group(0)!r})")
        for match in PROMOTIONAL.finditer(text):
            problems.append(f"{relative}: promotional or product copy {match.group(0)!r}")
        for match in OUT_OF_SCOPE.finditer(text):
            problems.append(f"{relative}: out-of-scope workflow text {match.group(0)!r}")
        problems.extend(scan_text(path.relative_to(package), text))
    total = sum(_normalized_size(path) for path in package_files(package))
    if total > MAX_PACKAGE_BYTES:
        problems.append(f"package is {total} bytes; the budget is {MAX_PACKAGE_BYTES}")
    return problems


def check_clean_install(package: Path) -> list[str]:
    """Copy the plugin root into an empty install directory and resolve it from there.

    This is what a marketplace install does: the plugin root is copied without the rest of the
    repository. Anything the skill needs from outside that root fails here.
    """
    problems = []
    with tempfile.TemporaryDirectory() as directory:
        installed = Path(directory) / "installed-plugins" / package.name
        shutil.copytree(package, installed)
        if not (installed / "plugin.json").is_file():
            problems.append("clean install: plugin.json not found at the installed root")
        skills = discovered_skills(installed)
        if len(skills) != 1:
            problems.append(f"clean install: expected one discoverable skill, found {len(skills)}")
            return problems
        skill_dir = skills[0].parent
        for reference in sorted(set(REFERENCE.findall(skills[0].read_text(encoding="utf-8")))):
            if not (skill_dir / reference).is_file():
                problems.append(f"clean install: {reference} does not resolve inside the plugin")
        for path in installed.rglob("*.md"):
            if re.search(r"\]\((?:\.\./){2,}|\.\./\.\./", path.read_text(encoding="utf-8")):
                problems.append(f"clean install: {path.relative_to(installed)} reaches outside the plugin")
    return problems


def validate(package: Path = PACKAGE, root: Path = ROOT) -> list[str]:
    if not package.is_dir():
        return [f"missing curated package: {package}"]
    return [
        *check_manifest(package, root),
        *check_skill(package, root),
        *check_content(package),
        *check_clean_install(package),
    ]


def summary(package: Path = PACKAGE) -> str:
    skill_md = discovered_skills(package)[0]
    support = [p for p in package_files(skill_md.parent) if p != skill_md]
    lines = len(skill_md.read_text(encoding="utf-8").splitlines())
    total = sum(_normalized_size(p) for p in package_files(package))
    return (
        f"{skill_md.parent.name}: SKILL.md {lines}/{MAX_SKILL_LINES} lines, "
        f"{len(support)}/{MAX_SUPPORT_FILES} supporting files, {total}/{MAX_PACKAGE_BYTES} bytes"
    )


def main() -> int:
    problems = validate()
    if problems:
        print("Curated distribution INVALID")
        for problem in problems:
            print(f"- {problem}")
        return 1
    print(f"OK: curated distribution ({summary()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
