#!/usr/bin/env python3
"""Fail when tracked paths appear to contain the private VNext website source."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
PROHIBITED_SEGMENTS = {
    "site",
    "sechelix-site-private",
    "private-site",
    "vnext-site",
    "vnext-site-source",
    "node_modules",
    ".next",
    ".vercel",
    ".wrangler",
}
PROHIBITED_FILENAMES = {"do-not-push.md", ".env", ".env.local", ".env.production"}


def tracked_paths(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        capture_output=True,
        text=False,
    )
    return [item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def find_violations(paths: Iterable[str]) -> list[str]:
    violations = []
    for raw in paths:
        path = PurePosixPath(raw.replace("\\", "/"))
        parts = {part.lower() for part in path.parts}
        name = path.name.lower()
        reasons = []
        if parts & PROHIBITED_SEGMENTS:
            reasons.append(f"private/build directory segment: {sorted(parts & PROHIBITED_SEGMENTS)}")
        if name in PROHIBITED_FILENAMES:
            reasons.append(f"prohibited filename: {name}")
        if path.suffix.lower() == ".map":
            reasons.append("source map")
        if reasons:
            violations.append(f"{raw}: {', '.join(reasons)}")
    return violations


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        violations = find_violations(tracked_paths(args.root.resolve()))
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"private-site leakage check failed closed: {exc}")
        return 1
    if violations:
        print("Private-site leakage check FAILED")
        for violation in violations:
            print(f"- {violation}")
        return 1
    print("OK: no prohibited private-site paths or source maps are tracked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
