#!/usr/bin/env python3
"""Check canonical install command consistency and referenced local scripts."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
CANONICAL_INSTALL = "npx skills@latest add omarmohelal/SecHelix --skill sechelix"
PYTHON_SCRIPT = re.compile(r"\bpython(?:3)?\s+((?:\.?\.?/)?[A-Za-z0-9_.\-/]+\.py)\b")


def tracked_paths(root: Path) -> list[Path]:
    # Tracked files only, like the sibling repository checks: walking the whole
    # tree also descends into .git, virtualenvs, the engine submodule and test
    # scratch copies, which is slow on network/WSL mounts and checks files that
    # are not SecHelix's own install surfaces.
    result = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], check=True, capture_output=True)
    return [root / item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def check(root: Path) -> list[str]:
    findings = []
    required = (root / "README.md",)
    for path in required:
        if not path.is_file():
            findings.append(f"required install surface missing: {path.relative_to(root)}")
            continue
        if CANONICAL_INSTALL not in path.read_text(encoding="utf-8"):
            findings.append(f"canonical install command missing from {path.relative_to(root)}")

    for path in tracked_paths(root):
        if not path.is_file() or path.suffix.lower() not in {".md", ".yml", ".yaml", ".html"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for match in PYTHON_SCRIPT.finditer(text):
            raw = match.group(1)
            candidate = (path.parent / raw).resolve() if raw.startswith(".") else (root / raw).resolve()
            if not candidate.is_file():
                line = text.count("\n", 0, match.start()) + 1
                findings.append(f"{path.relative_to(root)}:{line}: referenced script does not exist: {raw}")
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    findings = check(args.root.resolve())
    if findings:
        print("Install-snippet check FAILED")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print("OK: canonical install snippets and referenced Python scripts are sane")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
