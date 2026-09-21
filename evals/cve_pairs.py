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
    command, and every checkout is verified against the SHA the manifest pinned. The clone is
    blobless and sparse - these are real projects, and only the reviewed scope is needed.
    """
    raw = workdir / "raw"
    for case in manifest["cases"]:
        repo_dir = raw / case["id"] / "repo"
        cone = sorted({s if "." not in Path(s).name else str(Path(s).parent).replace("\\", "/")
                       for s in case["scope"]})
        if not repo_dir.exists():
            repo_dir.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout",
                            f"https://github.com/{case['repo']}.git", str(repo_dir)], check=True)
            subprocess.run(["git", "-C", str(repo_dir), "sparse-checkout", "init", "--cone"],
                           check=True)
            subprocess.run(["git", "-C", str(repo_dir), "sparse-checkout", "set", *cone], check=True)

        for state, commit in (("v", case["vulnerable_commit"]), ("f", case["fix_commit"])):
            target = raw / case["id"] / state
            if target.exists():
                shutil.rmtree(target)
            subprocess.run(["git", "-C", str(repo_dir), "checkout", "--quiet", "--detach", commit],
                           check=True)
            resolved = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
                                      check=True, capture_output=True, text=True).stdout.strip()
            if resolved != commit:
                raise SystemExit(f"{case['id']}: expected {commit}, checked out {resolved}")
            shutil.copytree(repo_dir, target, ignore=shutil.ignore_patterns(".git"))
        print(f"fetched {case['id']} ({case['repo']}) scope={cone}")


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


def _same_defect_class(finding: dict, case: dict) -> bool:
    """Does the finding name the class of defect the advisory describes?

    The aliases come from the manifest and were fixed before any review ran; adjudication may
    not add to them afterwards.
    """
    text = " ".join(str(finding.get(field, "")) for field in
                    ("class", "cwe", "title", "claim", "root_cause")).lower()
    return any(alias.lower() in text for alias in case["accept_classes"])


def _same_file(finding: dict, case: dict) -> bool:
    path = str(finding.get("file", "")).replace("\\", "/").lstrip("./")
    return any(path.endswith(target) or target.endswith(path) for target in case["fix_files"])


def _in_window(finding: dict, case: dict) -> bool:
    if not case.get("fix_lines"):
        return True  # a whole-file fix carries no hunk range
    line = finding.get("line")
    if not isinstance(line, int):
        return False
    return any(start - LINE_WINDOW <= line <= end + LINE_WINDOW
               for start, end in case["fix_lines"])


def matches_strict(finding: dict, case: dict) -> bool:
    """Pre-registered rule: right file, right neighbourhood, accepted class.

    Ambiguity resolves against SecHelix: a finding that cannot satisfy all three is `other`.
    """
    return (_same_file(finding, case) and _same_defect_class(finding, case)
            and _in_window(finding, case))


def is_candidate(finding: dict, case: dict) -> bool:
    """Right file and accepted class, but outside the patched neighbourhood.

    These exist because a defect and its patch are not always in the same place. In case-01 the
    fix changed a `before_action` declaration at the top of a controller while the review named
    the action seventy lines below that the declaration fails to protect: one defect, two
    locations. They are also exactly how a *different* defect in the same file looks, which is
    why they are never credited automatically. Each is judged by hand and the judgement, with
    its reason, is published beside the result.
    """
    return (_same_file(finding, case) and _same_defect_class(finding, case)
            and not _in_window(finding, case))


def _judgement_key(case_id: str, finding: dict) -> str:
    path = str(finding.get("file", "")).replace("\\", "/").lstrip("./")
    return f"{case_id}|{path}|{finding.get('line')}"


def score(manifest: dict, workdir: Path, predictions_path: Path, output: Path,
          manual_path: Path | None = None) -> dict:
    sealed = json.loads((workdir / "key.json").read_text(encoding="utf-8"))
    key, seed = sealed["key"], sealed["seed"]
    index = json.loads((workdir / "cases-index.json").read_text(encoding="utf-8"))["cases"]
    predictions_bytes = predictions_path.read_bytes()
    predictions = json.loads(predictions_bytes.decode("utf-8"))
    by_export = {entry["export_id"]: entry for entry in predictions["cases"]}

    missing = sorted({entry["export_id"] for entry in index} - set(by_export))
    if missing:
        raise SystemExit(f"predictions are incomplete; missing {missing}")

    manual = {}
    if manual_path is not None:
        manual = json.loads(manual_path.read_text(encoding="utf-8"))["judgements"]

    cases = {case["id"]: case for case in manifest["cases"]}
    results = []
    blank = {"PAIR_PASS": 0, "PAIR_PARTIAL": 0, "PAIR_MISS": 0}
    counts = {"strict": dict(blank), "adjudicated": dict(blank)}

    for entry in key:
        case = cases[entry["case_id"]]
        findings = {}
        for letter in "ab":
            state = "v" if letter == entry["vulnerable_letter"] else "f"
            findings[state] = by_export[f"{entry['export_prefix']}-{letter}"].get("findings", [])

        record = {
            "case_id": case["id"], "cve": case.get("cve"), "repo": case["repo"],
            "class": case.get("class"), "language": case.get("language"),
            "findings_vulnerable": len(findings["v"]), "findings_patched": len(findings["f"]),
            "outcomes": {}, "candidates": [],
        }

        strict = {state: [f for f in findings[state] if matches_strict(f, case)]
                  for state in ("v", "f")}
        confirmed = {state: list(strict[state]) for state in ("v", "f")}
        for state in ("v", "f"):
            for finding in findings[state]:
                if not is_candidate(finding, case):
                    continue
                judgement = manual.get(_judgement_key(case["id"], finding), {})
                same = bool(judgement.get("same_defect"))
                record["candidates"].append({
                    "state": "vulnerable" if state == "v" else "patched",
                    "file": finding.get("file"), "line": finding.get("line"),
                    "title": finding.get("title"),
                    "same_defect": same if judgement else "NOT_ADJUDICATED",
                    "reason": judgement.get(
                        "reason", "no judgement recorded; counted as not the same defect"),
                })
                if same:
                    confirmed[state].append(finding)

        for name, matched in (("strict", strict), ("adjudicated", confirmed)):
            outcome = ("PAIR_PASS" if matched["v"] and not matched["f"] else
                       "PAIR_PARTIAL" if matched["v"] else "PAIR_MISS")
            counts[name][outcome] += 1
            record["outcomes"][name] = {
                "outcome": outcome,
                "detected_in_vulnerable": bool(matched["v"]),
                "claimed_in_patched": bool(matched["f"]),
                "matched_findings": matched["v"],
            }
        results.append(record)

    total = len(results)
    report = {
        "schema_version": "2.0",
        "result_kind": "CVE_PAIR_RUN",
        "is_sechelix_result": True,
        "pairs": total,
        "headline": {
            "adjudication": "strict",
            "pair_pass": f"{counts['strict']['PAIR_PASS']}/{total}",
            "detected": f"{counts['strict']['PAIR_PASS'] + counts['strict']['PAIR_PARTIAL']}/{total}",
        },
        "adjudications": {
            "strict": {
                "pre_registered": True,
                "rule": "same file, within a changed hunk +/-25 lines, class accepted before the run",
                "counts": counts["strict"],
                "pair_pass": f"{counts['strict']['PAIR_PASS']}/{total}",
                "detected": f"{counts['strict']['PAIR_PASS'] + counts['strict']['PAIR_PARTIAL']}/{total}",
            },
            "adjudicated": {
                "pre_registered": False,
                "rule": ("strict matches plus candidates outside the line window that were judged by "
                         "hand to describe the same defective control; every judgement and its reason "
                         "is in cases[].candidates. Added after case-01, where the fix changed a "
                         "declaration and the review named the action it fails to protect. Unjudged "
                         "candidates count as not the same defect."),
                "counts": counts["adjudicated"],
                "pair_pass": f"{counts['adjudicated']['PAIR_PASS']}/{total}",
                "detected": f"{counts['adjudicated']['PAIR_PASS'] + counts['adjudicated']['PAIR_PARTIAL']}/{total}",
                "manual_judgements": len(manual),
            },
        },
        "precision": "NOT_MEASURED",
        "false_positive_rate": "NOT_MEASURED",
        "applicability_accuracy": "NOT_MEASURED",
        "release_gate_accuracy": "NOT_MEASURED",
        "unadjudicated_findings_note": (
            "Findings outside the known defect are counted, never classified. In real software the "
            "other defects are unknown, so they are neither false positives nor confirmed issues, and "
            "silence in the patched tree is not evidence that it is clean."
        ),
        "predictions_sha256": _digest_bytes(predictions_bytes),
        "seed": seed,
        "runner": predictions.get("runner"),
        "model": predictions.get("model"),
        "agent_host": predictions.get("agent_host"),
        "limitations": predictions.get("limitations", []),
        "cases": results,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + chr(10), encoding="utf-8")
    for name in ("strict", "adjudicated"):
        counted = counts[name]
        label = "pre-registered" if name == "strict" else "post-hoc, disclosed"
        print(f"{name:12} ({label}): {counted['PAIR_PASS']}/{total} pass, "
              f"{counted['PAIR_PARTIAL']} partial, {counted['PAIR_MISS']} miss")
    print(f"-> {output}")
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
            child.add_argument("--manual", type=Path, default=None,
                               help="hand judgements for candidates outside the line window")
    args = parser.parse_args(argv)

    manifest = load_manifest(args.manifest)
    args.workdir.mkdir(parents=True, exist_ok=True)
    if args.command == "fetch":
        fetch(manifest, args.workdir)
    elif args.command == "prepare":
        prepare(manifest, args.workdir, args.seed)
    else:
        score(manifest, args.workdir, args.predictions, args.output, args.manual)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
