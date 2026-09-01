#!/usr/bin/env python3
"""Classify the security deltas in a diff.

Reads a unified diff and reports what the change did to the security posture:
NEW_RISK, RISK_REDUCED, UNCHANGED, or UNKNOWN. Every delta is a hypothesis to
verify, never a finding.

Examples:
    git diff main...HEAD | python scripts/diff_review.py -
    python scripts/diff_review.py change.patch --json-output
    gh pr diff 42 | python scripts/diff_review.py - --fail-on-new-risk

Exit codes: 0 normally; 1 when --fail-on-new-risk is set and a NEW_RISK delta
exists; 2 when the input cannot be read.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sechelix_core.diff_review import NEW_RISK, review_diff, scoped_families  # noqa: E402


def _print_human(result: dict) -> None:
    print(f"Overall: {result['overall']}")
    print(f"Files changed: {result['files_changed']}")
    counts = result["counts"]
    print(
        f"Deltas: {counts['NEW_RISK']} new risk · {counts['RISK_REDUCED']} reduced · "
        f"{counts['UNCHANGED']} unchanged · {counts['UNKNOWN']} unknown"
    )
    families = scoped_families(result)
    if families:
        print(f"Scoped catalog families: {', '.join(families)}")
    if result["deltas"]:
        print()
    for delta in result["deltas"]:
        location = f"{delta['path']}:{delta['line']}" if delta["line"] else delta["path"]
        print(f"[{delta['direction']}] {delta['kind']} — {location}")
        print(f"    {delta['snippet']}")
        print(f"    ? {delta['question']}")
    if result["deltas"]:
        print()
        for note in result["notes"]:
            print(f"note: {note}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("diff", help="path to a unified diff, or - for stdin")
    parser.add_argument("--json-output", action="store_true", help="emit the classification as JSON")
    parser.add_argument(
        "--fail-on-new-risk", action="store_true",
        help="exit 1 when the change introduces a NEW_RISK delta (useful in CI)",
    )
    args = parser.parse_args(argv)

    try:
        text = sys.stdin.read() if args.diff == "-" else Path(args.diff).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"cannot read diff: {exc}", file=sys.stderr)
        return 2

    result = review_diff(text)
    if args.json_output:
        print(json.dumps(result, indent=2))
    else:
        _print_human(result)

    if args.fail_on_new_risk and result["counts"][NEW_RISK]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
