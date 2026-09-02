#!/usr/bin/env python3
"""Fail when a public commit carries tooling trailers or a development diary.

Public git history is a permanent, reader-facing artifact. It should read like a
changelog written by the project, not like a transcript of how the project was
built. Assistant co-author trailers, session URLs and multi-paragraph reasoning
belong in a pull request, where they are reviewable and then archived — not in
`git log`, where they are load-bearing forever.

This is scoped to commits **after** a declared baseline. Existing history is not
rewritten: rewriting published commits breaks every reference anyone already
holds, and the cure is worse than untidy trailers.

    python scripts/check_commit_hygiene.py                 # since the baseline
    python scripts/check_commit_hygiene.py --since <ref>   # a specific range
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Commits at or before this are pre-policy and are checked by nobody. It is the
#: V3.3 merge — the last commit created under the old settings.
BASELINE = "1598faa20306"

#: Trailers that must not appear in a public commit.
FORBIDDEN = (
    ("assistant co-author trailer", re.compile(r"^\s*Co-Authored-By:\s*Claude", re.I | re.M)),
    ("assistant session URL", re.compile(r"^\s*Claude-Session:", re.I | re.M)),
    ("session permalink", re.compile(r"claude\.ai/code/session_", re.I)),
    ("generated-by attribution", re.compile(r"Generated with \[?Claude Code", re.I)),
    ("co-author trailer for any assistant", re.compile(
        r"^\s*Co-Authored-By:.*(anthropic|openai|copilot|noreply@anthropic)", re.I | re.M)),
)

#: A body longer than this reads as a development diary rather than a summary.
#: Generous on purpose — the goal is to stop transcripts, not to enforce brevity.
MAX_BODY_LINES = 25


def commits_since(ref: str) -> list[tuple[str, str]]:
    """Return (sha, full message) for each commit after ref, oldest first."""
    result = subprocess.run(
        ["git", "-C", str(ROOT), "log", "--format=%H%x00%B%x1e", f"{ref}..HEAD"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        # An unknown baseline (shallow clone, fresh fork) is not a violation.
        return []
    entries = []
    for chunk in result.stdout.split("\x1e"):
        if "\x00" not in chunk:
            continue
        sha, message = chunk.split("\x00", 1)
        entries.append((sha.strip(), message.strip()))
    return list(reversed(entries))


def check_message(sha: str, message: str) -> list[str]:
    problems = []
    for label, pattern in FORBIDDEN:
        if pattern.search(message):
            problems.append(f"{sha[:12]}: contains {label}")

    body = message.split("\n", 1)[1].strip() if "\n" in message else ""
    lines = [l for l in body.splitlines() if l.strip()]
    if len(lines) > MAX_BODY_LINES:
        problems.append(
            f"{sha[:12]}: body is {len(lines)} lines; a public commit body should be a "
            f"summary, not a development diary (limit {MAX_BODY_LINES})"
        )
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", default=BASELINE,
                        help=f"baseline ref; commits after it are checked (default {BASELINE})")
    args = parser.parse_args(argv)

    entries = commits_since(args.since)
    if not entries:
        print(f"OK: no commits after {args.since[:12]} to check")
        return 0

    problems = []
    for sha, message in entries:
        problems.extend(check_message(sha, message))

    if problems:
        print("Commit hygiene check FAILED")
        for problem in problems:
            print(f"- {problem}")
        print(
            "\nPublic history is reader-facing and permanent. Reasoning belongs in the pull "
            "request. Do NOT rewrite already-published commits to satisfy this — amend only "
            "what has not been merged."
        )
        return 1

    print(f"OK: {len(entries)} commit(s) after {args.since[:12]} are clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
