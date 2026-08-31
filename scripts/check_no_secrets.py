#!/usr/bin/env python3
"""High-confidence secret-pattern check for tracked text files."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path
from typing import Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
TOKEN_PATTERNS = (
    ("private key block", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("OpenAI-style token", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
)
ASSIGNMENT = re.compile(
    r"(?i)[\"']?(api[_-]?key|client[_-]?secret|mnemonic|password|private[_-]?key|seed[_-]?phrase|token)[\"']?\s*[:=]\s*[\"']([^\"'\r\n]{16,})[\"']"
)
SAFE_EXACT = {"[REDACTED]", "NOT_MEASURED"}
SAFE_PREFIXES = ("YOUR_", "EXAMPLE_", "TEST-ONLY-", "${{")


def tracked_paths(root: Path) -> list[Path]:
    result = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], check=True, capture_output=True)
    return [root / item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def scan_text(path: Path, text: str) -> list[str]:
    findings = []
    for label, pattern in TOKEN_PATTERNS:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(f"{path}:{line}: {label}")
    for match in ASSIGNMENT.finditer(text):
        value = match.group(2).upper()
        if value.strip() in SAFE_EXACT or value.strip().startswith(SAFE_PREFIXES):
            continue
        line = text.count("\n", 0, match.start()) + 1
        findings.append(f"{path}:{line}: assigned value for {match.group(1)}")
    return findings


def scan_paths(paths: Iterable[Path]) -> list[str]:
    findings = []
    for path in paths:
        try:
            data = path.read_bytes()
        except OSError as exc:
            findings.append(f"{path}: unreadable ({exc})")
            continue
        if len(data) > 2_000_000 or b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(scan_text(path, text))
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        findings = scan_paths(tracked_paths(args.root.resolve()))
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"secret check failed closed: {exc}")
        return 1
    if findings:
        print("Secret-pattern check FAILED")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print("OK: no high-confidence secret patterns found in tracked text files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
