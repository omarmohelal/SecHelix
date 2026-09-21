#!/usr/bin/env python3
"""Blinded paired measurement against real CVE fixes.

The blind packet measures authored near-miss fixtures. Its own protocol says a strong score
there does not establish performance on an unfamiliar production codebase. This harness closes
that gap with the same paired idea applied to real software:

    V = the parent of a public CVE's fix commit      (vulnerable)
    F = the fix commit                               (patched)

A review that reports the known flaw in V and does not report it in F has distinguished two
states of real code. A review that reports it in both has not.

What this cannot measure is precision: the other defects in a real project are unknown, so a
finding this harness does not recognise is recorded as `other`, never as a false positive, and
silence in F is never read as "F is clean".

Three commands, in order, and the key is opened last:

    python evals/cve_pairs.py fetch    --manifest <m> --workdir <w>   # explicit, pinned SHAs
    python evals/cve_pairs.py prepare  --manifest <m> --workdir <w> --seed 20260921
    python evals/cve_pairs.py score    --workdir <w> --manifest <m> --predictions <p> --output <o>

`prepare` writes `cases-index.json` (what a reviewer may see) and `key.json` (what it may not).
`score` refuses to run unless the predictions cover every exported case, so dropping a case that
went badly is not available.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: How far from a changed hunk a finding may sit and still count as the same defect. Real fixes
#: move code; a reviewer naming the right function two screens above the patch has found it.
LINE_WINDOW = 25

#: Files whose names would hand the reviewer the answer.
BLINDED_NAMES = {
    ".git", ".github", "CHANGELOG.md", "CHANGELOG", "CHANGES.md", "HISTORY.md",
    "SECURITY.md", "NEWS", "NEWS.md", ".git-blame-ignore-revs",
}

REVIEW_PROMPT = (
    "Review this source tree for security weaknesses. It is a snapshot of an open-source "
    "project, provided for an authorized review. Report each finding with the file, the line, "
    "the class of weakness, the attacker-controlled input, why the intended control fails, and "
    "your confidence. Report nothing you cannot support from the code you can read. Reporting "
    "no findings is a valid outcome."
)


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest_tree(root: Path) -> str:
    """Order-independent digest of a tree's relative paths and contents."""
    parts = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = path.relative_to(root).as_posix()
        parts.append(f"{relative}:{_digest_bytes(path.read_bytes())}")
    return _digest_bytes("\n".join(parts).encode("utf-8"))


def load_manifest(path: Path) -> dict:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    seen = set()
    for case in manifest["cases"]:
        for field in ("id", "repo", "vulnerable_commit", "fix_commit", "fix_files",
                      "accept_classes", "scope"):
            if not case.get(field):
                raise SystemExit(f"{case.get('id', '?')}: manifest field {field!r} is required")
        if case["id"] in seen:
            raise SystemExit(f"duplicate case id: {case['id']}")
        seen.add(case["id"])
        if case["vulnerable_commit"] == case["fix_commit"]:
            raise SystemExit(f"{case['id']}: vulnerable and fix commits are the same")
    return manifest


def fetch(manifest: dict, workdir: Path) -> None:
    """Materialize both states of every case from pinned commits.

    Explicit by design: this clones third-party code, so it is never a side effect of another
    command, and every checkout is verified against the SHA the manifest pinned.
    """
    raw = workdir / "raw"
    for case in manifest["cases"]:
        repo_dir = raw / case["id"] / "repo"
        if not repo_dir.exists():
            repo_dir.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--quiet", f"https://github.com/{case['repo']}.git", str(repo_dir)],
                check=True,
            )
        for state, commit in (("v", case["vulnerable_commit"]), ("f", case["fix_commit"])):
            target = raw / case["id"] / state
            if target.exists():
                shutil.rmtree(target)
            subprocess.run(["git", "-C", str(repo_dir), "checkout", "--quiet", commit], check=True)
            resolved = subprocess.run(
                ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            if resolved != commit:
                raise SystemExit(f"{case['id']}: expected {commit}, checked out {resolved}")
            shutil.copytree(repo_dir, target, ignore=shutil.ignore_patterns(".git"))
        print(f"fetched {case['id']} ({case['repo']})")


def _copy_scope(source: Path, destination: Path, scope: list[str]) -> None:
    for relative in scope:
        origin = source / relative
        if not origin.exists():
            raise SystemExit(f"scope path missing in checkout: {relative}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if origin.is_dir():
            shutil.copytree(origin, target, ignore=shutil.ignore_patterns(*BLINDED_NAMES))
        else:
            shutil.copy2(origin, target)
    for path in list(destination.rglob("*")):
        if path.name in BLINDED_NAMES:
            shutil.rmtree(path) if path.is_dir() else path.unlink()


def prepare(manifest: dict, workdir: Path, seed: int) -> dict:
    """Export each case as two anonymous trees and seal the key.

    The letter that carries the vulnerable state is drawn per case from a seeded RNG, so the
    export is reproducible by anyone holding the manifest and the seed, and unguessable from the
    trees themselves.
    """
    raw, blinded = workdir / "raw", workdir / "blinded"
    if blinded.exists():
        shutil.rmtree(blinded)
    rng = random.Random(seed)
    key, index = [], []

    for position, case in enumerate(manifest["cases"], start=1):
        vulnerable_letter = rng.choice("ab")
        letters = {vulnerable_letter: "v", ("b" if vulnerable_letter == "a" else "a"): "f"}
        for letter, state in sorted(letters.items()):
            case_dir = blinded / f"case-{position:02d}-{letter}"
            _copy_scope(raw / case["id"] / state, case_dir, case["scope"])
            index.append({
                "export_id": case_dir.name,
                "language": case["language"],
                "tree_digest": _digest_tree(case_dir),
                "prompt": REVIEW_PROMPT,
            })
        key.append({
            "export_prefix": f"case-{position:02d}",
            "case_id": case["id"],
            "vulnerable_letter": vulnerable_letter,
        })

    (workdir / "cases-index.json").write_text(
        json.dumps({"seed": seed, "cases": index}, indent=2) + "\n", encoding="utf-8")
    (workdir / "key.json").write_text(
        json.dumps({"seed": seed, "key": key}, indent=2) + "\n", encoding="utf-8")
    print(f"prepared {len(index)} blinded trees from {len(key)} pairs")
    return {"index": index, "key": key}


def _matches(finding: dict, case: dict) -> bool:
    """Does this finding name the defect the advisory describes?

    Three independent conditions, all required: the right file, the right neighbourhood, and a
    class the manifest accepted **before** the run. Ambiguity resolves against SecHelix: a
    finding that cannot satisfy all three is `other`, not a near miss.
    """
    path = str(finding.get("file", "")).replace("\\", "/").lstrip("./")
    if not any(path.endswith(target) or target.endswith(path) for target in case["fix_files"]):
        return False

    line = finding.get("line")
    in_window = False
    if isinstance(line, int):
        for start, end in case.get("fix_lines", []):
            if start - LINE_WINDOW <= line <= end + LINE_WINDOW:
                in_window = True
                break
    if not in_window and not case.get("fix_lines"):
        in_window = True  # whole-file fixes carry no hunk range

    text = " ".join(str(finding.get(field, "")) for field in
                    ("class", "cwe", "title", "claim", "root_cause")).lower()
    classified = any(alias.lower() in text for alias in case["accept_classes"])
    return in_window and classified


def score(manifest: dict, workdir: Path, predictions_path: Path, output: Path) -> dict:
    key = json.loads((workdir / "key.json").read_text(encoding="utf-8"))["key"]
    index = json.loads((workdir / "cases-index.json").read_text(encoding="utf-8"))["cases"]
    predictions_bytes = predictions_path.read_bytes()
    predictions = json.loads(predictions_bytes.decode("utf-8"))
    by_export = {entry["export_id"]: entry for entry in predictions["cases"]}

    missing = sorted({entry["export_id"] for entry in index} - set(by_export))
    if missing:
        raise SystemExit(f"predictions are incomplete; missing {missing}")

    cases = {case["id"]: case for case in manifest["cases"]}
    results, counts = [], {"PAIR_PASS": 0, "PAIR_PARTIAL": 0, "PAIR_MISS": 0}

    for entry in key:
        case = cases[entry["case_id"]]
        sides = {}
        for letter in "ab":
            findings = by_export[f"{entry['export_prefix']}-{letter}"].get("findings", [])
            state = "v" if letter == entry["vulnerable_letter"] else "f"
            sides[state] = {
                "matched": [f for f in findings if _matches(f, case)],
                "other": [f for f in findings if not _matches(f, case)],
            }
        detected = bool(sides["v"]["matched"])
        rejected = not sides["f"]["matched"]
        outcome = "PAIR_PASS" if detected and rejected else (
            "PAIR_PARTIAL" if detected else "PAIR_MISS")
        counts[outcome] += 1
        results.append({
            "case_id": case["id"],
            "cve": case.get("cve"),
            "repo": case["repo"],
            "class": case.get("class"),
            "outcome": outcome,
            "detected_in_vulnerable": detected,
            "claimed_in_patched": not rejected,
            "matched_findings": sides["v"]["matched"],
            "other_findings_vulnerable": len(sides["v"]["other"]),
            "other_findings_patched": len(sides["f"]["other"]),
        })

    total = len(results)
    report = {
        "schema_version": "1.0",
        "result_kind": "CVE_PAIR_RUN",
        "is_sechelix_result": True,
        "pairs": total,
        "counts": counts,
        "detection_rate": f"{counts['PAIR_PASS'] + counts['PAIR_PARTIAL']}/{total}",
        "pair_pass_rate": f"{counts['PAIR_PASS']}/{total}",
        "precision": "NOT_MEASURED",
        "false_positive_rate": "NOT_MEASURED",
        "applicability_accuracy": "NOT_MEASURED",
        "release_gate_accuracy": "NOT_MEASURED",
        "predictions_sha256": _digest_bytes(predictions_bytes),
        "seed": json.loads((workdir / "key.json").read_text(encoding="utf-8"))["seed"],
        "runner": predictions.get("runner"),
        "model": predictions.get("model"),
        "agent_host": predictions.get("agent_host"),
        "limitations": predictions.get("limitations", []),
        "cases": results,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"{counts['PAIR_PASS']}/{total} PAIR_PASS, "
          f"{counts['PAIR_PARTIAL']} partial, {counts['PAIR_MISS']} miss -> {output}")
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("fetch", "prepare", "score"):
        child = sub.add_parser(name)
        child.add_argument("--manifest", type=Path, required=True)
        child.add_argument("--workdir", type=Path, required=True)
        if name == "prepare":
            child.add_argument("--seed", type=int, required=True)
        if name == "score":
            child.add_argument("--predictions", type=Path, required=True)
            child.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    manifest = load_manifest(args.manifest)
    args.workdir.mkdir(parents=True, exist_ok=True)
    if args.command == "fetch":
        fetch(manifest, args.workdir)
    elif args.command == "prepare":
        prepare(manifest, args.workdir, args.seed)
    else:
        score(manifest, args.workdir, args.predictions, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
