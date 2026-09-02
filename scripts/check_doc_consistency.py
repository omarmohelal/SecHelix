#!/usr/bin/env python3
"""Fail when the documentation states a count the repository contradicts.

Every count in this project's docs is a claim, and claims decay. The eval suite
grew from 19 fixtures to 33 and the Gold Packs from 5 to 12 while the README, the
launch drafts, the research reports, and the website all went on stating the old
numbers. The published keyword baseline was worse: it had been scored against the
19-fixture suite and never regenerated, so it was a real measurement of a suite
that no longer existed.

None of that was caught, because no gate read prose as assertions. The catalog
validator checks the catalog, the contract validators check contracts, and the
unit tests check code — and a README claiming 5 Gold Packs beside a directory
holding 12 passes all of them.

This script closes that gap. Ground truth comes from the tree; the docs are
checked against it. When a count legitimately changes, this fails until the docs
are updated, which is the point.

    python scripts/check_doc_consistency.py
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Documentation that records history rather than current state. A changelog entry
#: describing what was true at the time is correct precisely because it is stale.
EXCLUDED = {
    "CHANGELOG.md",
}
EXCLUDED_PREFIXES = (
    "skills/",           # generated copy of canonical sources
    "docs/releases/",    # dated release notes describe their own release
    "docs/case-studies/",  # a case study describes one point in time
    "node_modules/",
)


def ground_truth() -> dict[str, int]:
    """Count what is actually in the tree."""
    facts: dict[str, int] = {}

    facts["gold_packs"] = len(list(ROOT.glob("gold-packs/*/pack.json")))
    facts["schemas"] = len(list(ROOT.glob("schemas/*.schema.json")))
    facts["agents"] = len(list(ROOT.glob("agents/*.md")))
    facts["lesson_cards"] = len(list(ROOT.glob("knowledge/lesson-cards/*.json")))

    registry = ROOT / "adapters" / "registry.py"
    if registry.exists():
        sys.path.insert(0, str(ROOT))
        from adapters.registry import ADAPTERS  # noqa: E402

        facts["adapters"] = len(ADAPTERS)

    catalog = ROOT / "catalog" / "checks.json"
    if catalog.exists():
        data = json.loads(catalog.read_text(encoding="utf-8"))
        families = data.get("families", [])
        facts["families"] = len(families)
        lenses = data.get("lenses")
        if isinstance(lenses, list):
            facts["lenses"] = len(lenses)
            facts["hypotheses"] = len(families) * len(lenses)

    fixtures = sorted(ROOT.glob("evals/fixtures/*.json"))
    fixtures = [f for f in fixtures if f.name != "index.json"]
    if fixtures:
        facts["fixtures"] = len(fixtures)
        facts["cases"] = len(fixtures) * 2

    cases_file = ROOT / "evals" / "blind-packet" / "cases.json"
    if cases_file.exists():
        payload = json.loads(cases_file.read_text(encoding="utf-8"))
        cases = payload if isinstance(payload, list) else payload.get("cases", [])
        facts["blind_cases"] = len(cases)
        facts["eval_families"] = len({c.get("family") for c in cases if c.get("family")})

    return facts


#: Each rule pairs a fact with the phrasings that assert it. The number is group 1.
#: Patterns are deliberately narrow: a rule that fires on unrelated prose gets
#: disabled by whoever it annoys, and then it guards nothing.
RULES: tuple[tuple[str, str], ...] = (
    ("gold_packs", r"(\d+)\s+[Gg]old\s+(?:Check\s+)?[Pp]acks"),
    ("gold_packs", r"[Gg]old\s+(?:Check\s+)?[Pp]acks?\s*[:=]\s*(\d+)"),
    ("fixtures", r"(\d+)\s+paired\s+(?:eval\s+|vulnerable/clean\s+)?fixtures"),
    ("fixtures", r"(\d+)\s+fixtures\s*/"),
    ("blind_cases", r"(\d+)\s+blind\s+cases"),
    # "N cases across M families" describes the fixture corpus (2x fixtures), which
    # is a different number from the blind packet's case count. They happen to be
    # equal today; checking prose about one against the other would either
    # false-fail or stop catching drift the moment they diverge.
    ("cases", r"(\d+)\s+cases\s+across"),
    ("cases", r"(\d+)\s+(?:paired\s+)?eval(?:uation)?\s+cases"),
    ("schemas", r"(\d+)\s+JSON\s+Schema"),
    ("agents", r"(\d+)\s+specialist\s+(?:role|agent)"),
    ("adapters", r"(\d+)\s+(?:read-only\s+|evidence\s+)?adapters"),
    ("families", r"(\d+)\s+families\s*(?:×|x)\s*\d+\s+lenses"),
    # The second number in "21 families x 26 lenses" was captured by nothing, so a
    # doc could claim 20 lenses and pass — against the one count CLAUDE.md pins.
    ("lenses", r"\d+\s+families\s*(?:×|x)\s*(\d+)\s+lenses"),
    ("lenses", r"(\d+)\s+verification\s+lenses"),
    # Requires a qualifier so ordinary prose ("3 hypotheses were generated") is not
    # read as a claim about the frozen catalog. The lookbehind keeps the lens count
    # in "21 x 26 structured hypothesis catalog" from being read as the total.
    ("hypotheses",
     r"(?<![×x] )(?<!\d)(\d+)\s+(?:structured|catalog|explicit|stable)\s+(?:security\s+)?hypothes"),
    ("lesson_cards", r"(\d+)\s+lesson\s+cards"),
)


def tracked_docs() -> list[Path]:
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z", "*.md"],
        check=True, capture_output=True,
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


#: A document that records what was true on a date is correct precisely because
#: it is stale. Declaring it is required so the exemption is a decision someone
#: made, visible in the file, rather than a filename quietly added to a list here.
SNAPSHOT_MARKER = "<!-- doc-consistency: snapshot -->"


def check_document(path: Path, facts: dict[str, int]) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    rel = path.relative_to(ROOT).as_posix()
    if SNAPSHOT_MARKER in text:
        return []
    findings = []
    for fact, pattern in RULES:
        expected = facts.get(fact)
        if expected is None:
            continue
        for match in re.finditer(pattern, text):
            claimed = int(match.group(1))
            if claimed != expected:
                line = text.count("\n", 0, match.start()) + 1
                findings.append(
                    f"{rel}:{line}: claims {claimed} for {fact}, tree has {expected} "
                    f"— {match.group(0).strip()!r}"
                )
    return findings


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--show-facts", action="store_true", help="print ground truth and exit")
    args = parser.parse_args(argv)

    facts = ground_truth()
    if args.show_facts:
        for key, value in sorted(facts.items()):
            print(f"{key:16s} {value}")
        return 0

    findings: list[str] = []
    for path in tracked_docs():
        try:
            findings.extend(check_document(path, facts))
        except OSError as exc:
            findings.append(f"{path}: cannot inspect ({exc})")

    if findings:
        print("Documentation consistency check FAILED")
        for finding in findings:
            print(f"- {finding}")
        print(
            "\nThe tree is the source of truth. Run `python scripts/sync_doc_counts.py` to "
            "update every claim at once, or if the tree is wrong, fix the tree — but do not "
            "silence this by loosening a rule."
        )
        return 1

    print(f"OK: documented counts match the tree ({len(facts)} facts checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
