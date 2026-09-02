#!/usr/bin/env python3
"""Rewrite documented counts to match the tree.

`check_doc_consistency.py` reports drift; this fixes it. They share ground truth,
so a clean run of this is followed by a clean run of that.

It exists because the counts move whenever a schema, Gold Pack, adapter or
fixture is added, and hand-editing a dozen files each time is how the numbers got
out of step in the first place.

**It only rewrites phrasings the checker already validates.** Anything the checker
does not check, this does not touch — otherwise the two would disagree about what
a claim even is.

    python scripts/sync_doc_counts.py --dry-run
    python scripts/sync_doc_counts.py
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.check_doc_consistency import (  # noqa: E402
    EXCLUDED,
    EXCLUDED_PREFIXES,
    RULES,
    SNAPSHOT_MARKER,
    ground_truth,
)


def tracked_docs() -> list[Path]:
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z", "*.md"], check=True, capture_output=True
    )
    paths = []
    for raw in out.stdout.split(b"\0"):
        if not raw:
            continue
        rel = raw.decode("utf-8")
        if rel in EXCLUDED or rel.startswith(EXCLUDED_PREFIXES):
            continue
        paths.append(ROOT / rel)
    return paths


def rewrite(text: str, facts: dict[str, int]) -> tuple[str, int]:
    """Replace only the captured number, leaving the surrounding phrasing intact."""
    changes = 0
    for fact, pattern in RULES:
        expected = facts.get(fact)
        if expected is None:
            continue

        def substitute(match, expected=expected):
            nonlocal changes
            claimed = match.group(1)
            if claimed == str(expected):
                return match.group(0)
            changes += 1
            # Rebuild the match with only group 1 replaced, so phrasing survives.
            start, end = match.span(1)
            offset = match.start()
            whole = match.group(0)
            return whole[: start - offset] + str(expected) + whole[end - offset :]

        text = re.sub(pattern, substitute, text)
    return text, changes


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    facts = ground_truth()
    total = 0
    for path in tracked_docs():
        original = path.read_text(encoding="utf-8")
        if SNAPSHOT_MARKER in original:
            continue  # a dated record is correct precisely because it is stale
        updated, changes = rewrite(original, facts)
        if changes:
            total += changes
            rel = path.relative_to(ROOT).as_posix()
            print(f"  {'would update' if args.dry_run else 'updated'} {rel} ({changes})")
            if not args.dry_run:
                path.write_text(updated, encoding="utf-8")

    print(f"{'Would change' if args.dry_run else 'Changed'} {total} count(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
