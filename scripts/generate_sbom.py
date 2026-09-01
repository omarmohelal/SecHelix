#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 SBOM describing this repository's own components.

SecHelix has no third-party runtime dependencies: every module imports only the
Python standard library, and the remaining shipped material is Markdown and
JSON data. This generator therefore describes *what SecHelix actually is* --
its first-party code and data units, each with a content digest -- plus the one
external requirement that genuinely exists: a CPython interpreter.

It deliberately does not invent package coordinates, transitive dependencies,
or a vulnerability posture it cannot substantiate. An empty third-party
dependency set is a truthful, verifiable claim; a fabricated one is not.

Standard library only, so the SBOM can be produced on any runner without first
installing something that would itself need to appear in the SBOM.

Usage:
    python scripts/generate_sbom.py --output sbom.cdx.json
    python scripts/generate_sbom.py            # writes to stdout
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]

PROJECT_NAME = "SecHelix"
PROJECT_GROUP = "com.sechelix"
PROJECT_LICENSE = "Apache-2.0"
PROJECT_REPOSITORY = "https://github.com/omarmohelal/SecHelix"
PROJECT_WEBSITE = "https://sechelix.com"
PROJECT_AUTHOR = "Omar Mohamed Helal Emam"
PLUGIN_MANIFEST = Path(".claude-plugin") / "plugin.json"

# Fixed namespace so the same tree always yields the same serial number.
# uuid5 of the DNS namespace for the project's canonical host.
SERIAL_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "sbom.sechelix.com")

EXCLUDED_DIR_NAMES = {"__pycache__", ".git", ".pytest_cache", ".mypy_cache"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".pyd"}

# The minimum interpreter the codebase is written against (PEP 604 unions and
# `from __future__ import annotations` are used throughout; CI pins 3.12).
MIN_PYTHON = "3.10"
CI_PYTHON = "3.12"

CPYTHON_BOM_REF = "runtime/cpython"


class ComponentSpec:
    """One first-party unit of the repository."""

    __slots__ = ("key", "name", "component_type", "description", "paths")

    def __init__(
        self,
        key: str,
        name: str,
        component_type: str,
        description: str,
        paths: Sequence[str],
    ) -> None:
        self.key = key
        self.name = name
        self.component_type = component_type
        self.description = description
        self.paths = tuple(paths)


# Every shipped part of the repository, grouped the way the project is actually
# structured. `component_type` uses CycloneDX 1.5 vocabulary: "library" for
# importable code, "application" for executable entry points, "data" for the
# knowledge/schema/policy assets that carry no executable logic, and "file" for
# the packaged distribution bundle.
COMPONENT_SPECS: tuple[ComponentSpec, ...] = (
    ComponentSpec(
        "sechelix-core",
        "sechelix-core",
        "library",
        "Core review engine: attack-surface modelling, applicability, variant hunting.",
        ["sechelix_core"],
    ),
    ComponentSpec(
        "adapters",
        "sechelix-adapters",
        "library",
        "Thin, optional wrappers around external security tooling plus SARIF normalisation.",
        ["adapters"],
    ),
    ComponentSpec(
        "reports",
        "sechelix-reports",
        "library",
        "Deterministic report rendering for review output.",
        ["reports"],
    ),
    ComponentSpec(
        "scripts",
        "sechelix-scripts",
        "application",
        "Validation, gating, and repository-hygiene entry points executed by CI.",
        ["scripts"],
    ),
    ComponentSpec(
        "catalog",
        "sechelix-catalog",
        "data",
        "Structured hypothesis catalog: security families x verification lenses.",
        ["catalog"],
    ),
    ComponentSpec(
        "schemas",
        "sechelix-schemas",
        "data",
        "JSON Schema contracts for scope, evidence, findings, reports, and extensions.",
        ["schemas"],
    ),
    ComponentSpec(
        "policies",
        "sechelix-policies",
        "data",
        "Release-gate policy definitions.",
        ["policies"],
    ),
    ComponentSpec(
        "gold-packs",
        "sechelix-gold-packs",
        "data",
        "Gold check packs used as regression fixtures for verification behaviour.",
        ["gold-packs"],
    ),
    ComponentSpec(
        "knowledge",
        "sechelix-knowledge",
        "data",
        "Knowledge graph, lesson cards, and source registry.",
        ["knowledge"],
    ),
    ComponentSpec(
        "agents",
        "sechelix-agents",
        "data",
        "Sub-agent role definitions, including the independent verifier.",
        ["agents"],
    ),
    ComponentSpec(
        "references",
        "sechelix-references",
        "data",
        "Reference material loaded on demand by the skill.",
        ["references"],
    ),
    ComponentSpec(
        "extensions",
        "sechelix-extensions",
        "data",
        "Community extension registry and manifests.",
        ["extensions"],
    ),
    ComponentSpec(
        "skill-bundle",
        "sechelix-skill-bundle",
        "file",
        "Self-contained portable Agent Skill distribution built from canonical sources.",
        ["skills"],
    ),
    ComponentSpec(
        "adapter-mirrors",
        "sechelix-adapter-mirrors",
        "file",
        "Harness-specific skill mirrors (.claude and .agents) tracked intentionally.",
        [".claude/skills", ".agents/skills"],
    ),
)


def iter_files(relative_paths: Iterable[str]) -> list[Path]:
    """Collect the deterministic, sorted file set backing one component."""
    collected: set[Path] = set()
    for relative in relative_paths:
        base = ROOT / relative
        if base.is_file():
            collected.add(base)
            continue
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            parts = path.relative_to(ROOT).parts
            if EXCLUDED_DIR_NAMES.intersection(parts):
                continue
            if path.suffix.lower() in EXCLUDED_SUFFIXES:
                continue
            collected.add(path)
    return sorted(collected)


def digest_files(files: Sequence[Path]) -> str:
    """Content digest over (relative path, file bytes) pairs.

    Path names are folded in so that renaming a file changes the digest even
    when its bytes do not.
    """
    hasher = hashlib.sha256()
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        hasher.update(relative.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return hasher.hexdigest()


def read_version() -> str:
    """Read the single source of truth for the project version."""
    manifest = ROOT / PLUGIN_MANIFEST
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:  # fail loudly rather than guess
        raise SystemExit(f"cannot read version from {PLUGIN_MANIFEST}: {exc}") from exc
    version = data.get("version")
    if not isinstance(version, str) or not version:
        raise SystemExit(f"{PLUGIN_MANIFEST} has no usable 'version' field")
    return version


def timestamp() -> str:
    """UTC timestamp, honouring SOURCE_DATE_EPOCH for reproducible builds."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        moment = _dt.datetime.fromtimestamp(int(epoch), tz=_dt.timezone.utc)
    else:
        moment = _dt.datetime.now(tz=_dt.timezone.utc)
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def license_entry() -> list[dict]:
    return [{"license": {"id": PROJECT_LICENSE}}]


def build_components(version: str) -> tuple[list[dict], list[str], str]:
    """Return (components, first-party bom-refs, aggregate tree digest)."""
    components: list[dict] = []
    refs: list[str] = []
    aggregate = hashlib.sha256()

    for spec in COMPONENT_SPECS:
        files = iter_files(spec.paths)
        if not files:
            # Never emit a component for material that is not in the tree.
            continue
        content_hash = digest_files(files)
        aggregate.update(spec.key.encode("utf-8"))
        aggregate.update(content_hash.encode("utf-8"))
        bom_ref = f"sechelix/{spec.key}@{version}"
        refs.append(bom_ref)
        total_bytes = sum(path.stat().st_size for path in files)
        components.append(
            {
                "type": spec.component_type,
                "bom-ref": bom_ref,
                "group": PROJECT_GROUP,
                "name": spec.name,
                "version": version,
                "description": spec.description,
                "scope": "required",
                "licenses": license_entry(),
                "hashes": [{"alg": "SHA-256", "content": content_hash}],
                "properties": [
                    {"name": "sechelix:paths", "value": ", ".join(spec.paths)},
                    {"name": "sechelix:fileCount", "value": str(len(files))},
                    {"name": "sechelix:byteCount", "value": str(total_bytes)},
                    {"name": "sechelix:origin", "value": "first-party"},
                ],
            }
        )

    # The only genuine external requirement: a CPython interpreter. It is not
    # vendored or redistributed, so it is recorded as the runtime platform with
    # an explicit version range rather than as a resolved dependency.
    components.append(
        {
            "type": "platform",
            "bom-ref": CPYTHON_BOM_REF,
            "group": "org.python",
            "name": "cpython",
            "version": f">={MIN_PYTHON}",
            "description": (
                "CPython interpreter supplying the standard library that SecHelix "
                f"runs on. Not vendored or redistributed. CI validates on {CI_PYTHON}."
            ),
            "scope": "required",
            "externalReferences": [
                {"type": "website", "url": "https://www.python.org/"},
                {"type": "vcs", "url": "https://github.com/python/cpython"},
            ],
            "properties": [
                {"name": "sechelix:origin", "value": "runtime-platform"},
                {"name": "sechelix:minimumVersion", "value": MIN_PYTHON},
                {"name": "sechelix:testedVersion", "value": CI_PYTHON},
                {"name": "sechelix:vendored", "value": "false"},
            ],
        }
    )

    return components, refs, aggregate.hexdigest()


def build_bom(version: str) -> dict:
    components, first_party_refs, tree_digest = build_components(version)
    root_ref = f"pkg:github/omarmohelal/SecHelix@{version}"
    serial = uuid.uuid5(SERIAL_NAMESPACE, f"{version}:{tree_digest}")

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "group": PROJECT_GROUP,
                        "name": "generate_sbom.py",
                        "version": version,
                        "description": (
                            "First-party, standard-library-only CycloneDX generator "
                            "shipped in scripts/generate_sbom.py."
                        ),
                    }
                ]
            },
            "authors": [{"name": PROJECT_AUTHOR}],
            "supplier": {
                "name": PROJECT_NAME,
                "url": [PROJECT_WEBSITE],
            },
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "group": PROJECT_GROUP,
                "name": PROJECT_NAME.lower(),
                "version": version,
                "description": (
                    "Evidence-first application-security Agent Skill for authorized "
                    "repositories and environments."
                ),
                "purl": f"pkg:github/omarmohelal/SecHelix@{version}",
                "licenses": license_entry(),
                "externalReferences": [
                    {"type": "vcs", "url": PROJECT_REPOSITORY},
                    {"type": "website", "url": PROJECT_WEBSITE},
                    {"type": "issue-tracker", "url": f"{PROJECT_REPOSITORY}/issues"},
                    {
                        "type": "license",
                        "url": f"{PROJECT_REPOSITORY}/blob/main/LICENSE",
                    },
                    {
                        "type": "security-contact",
                        "url": f"{PROJECT_REPOSITORY}/blob/main/SECURITY.md",
                    },
                ],
                "properties": [
                    {"name": "sechelix:treeDigest", "value": f"sha256:{tree_digest}"},
                    {"name": "sechelix:thirdPartyRuntimeDependencies", "value": "0"},
                    {
                        "name": "sechelix:dependencyPolicy",
                        "value": (
                            "Python standard library only. External security tools are "
                            "invoked as optional out-of-process adapters and are never "
                            "vendored, imported, or installed by this project."
                        ),
                    },
                ],
            },
        },
        "components": components,
        "dependencies": [
            {"ref": root_ref, "dependsOn": sorted(first_party_refs)},
            *[
                {"ref": ref, "dependsOn": [CPYTHON_BOM_REF]}
                for ref in sorted(first_party_refs)
            ],
            {"ref": CPYTHON_BOM_REF, "dependsOn": []},
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Path to write the SBOM to (default: stdout).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the human-readable summary on stderr.",
    )
    args = parser.parse_args(argv)

    version = read_version()
    bom = build_bom(version)
    payload = json.dumps(bom, indent=2, sort_keys=False, ensure_ascii=False) + "\n"

    if args.output is None:
        sys.stdout.write(payload)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")

    if not args.quiet:
        destination = str(args.output) if args.output else "stdout"
        print(
            f"OK: CycloneDX 1.5 SBOM for {PROJECT_NAME} {version} "
            f"({len(bom['components'])} components) -> {destination}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
