#!/usr/bin/env python3
"""Check local Markdown and HTML file references without network access."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
HTML_LINK = re.compile(r"\b(?:href|src)=[\"']([^\"']+)[\"']", re.IGNORECASE)
SKIP_SCHEMES = {"http", "https", "mailto", "data", "javascript"}

FENCED_BLOCK = re.compile(r"^(?P<fence>```+|~~~+)[^\n]*\n.*?^(?P=fence)[^\n]*$", re.M | re.S)
INLINE_CODE = re.compile(r"(?P<ticks>`+)(?!`).*?(?<!`)(?P=ticks)(?!`)", re.S)


def _blank(match: re.Match[str]) -> str:
    """Replace a span with spaces, keeping newlines so line numbers stay true."""
    return "".join("\n" if char == "\n" else " " for char in match.group(0))


def mask_code(text: str) -> str:
    """Hide fenced blocks and inline code spans from link matching.

    Documentation that quotes Markdown — a submission draft showing the entry
    line it will post, for instance — contains link syntax that is displayed
    literally and is never navigable. Treating it as a link reports a break in
    someone else's repository as a break in this one.
    """
    return INLINE_CODE.sub(_blank, FENCED_BLOCK.sub(_blank, text))


def tracked_paths(root: Path) -> list[Path]:
    result = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], check=True, capture_output=True)
    return [root / item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def _target_path(source: Path, raw_target: str) -> Path | None:
    target = raw_target.strip().strip("<>").split(maxsplit=1)[0]
    if not target or target.startswith("#"):
        return None
    parsed = urlsplit(target)
    if parsed.scheme.lower() in SKIP_SCHEMES or parsed.netloc:
        return None
    relative = unquote(parsed.path)
    if not relative:
        return None
    return (source.parent / relative).resolve()


def check_file(path: Path) -> list[str]:
    if path.suffix.lower() not in {".md", ".html"}:
        return []
    text = path.read_text(encoding="utf-8")
    is_markdown = path.suffix.lower() == ".md"
    if is_markdown:
        text = mask_code(text)
    pattern = MARKDOWN_LINK if is_markdown else HTML_LINK
    findings = []
    for match in pattern.finditer(text):
        target = _target_path(path, match.group(1))
        if target is not None and not target.exists():
            line = text.count("\n", 0, match.start()) + 1
            findings.append(f"{path}:{line}: missing {match.group(1)}")
    return findings


def check_paths(paths: Iterable[Path]) -> list[str]:
    findings = []
    for path in paths:
        try:
            findings.extend(check_file(path))
        except (OSError, UnicodeDecodeError) as exc:
            findings.append(f"{path}: cannot inspect ({exc})")
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        findings = check_paths(tracked_paths(args.root.resolve()))
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"local-link check failed closed: {exc}")
        return 1
    if findings:
        print("Local-link check FAILED")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print("OK: tracked Markdown and HTML local links resolve")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
