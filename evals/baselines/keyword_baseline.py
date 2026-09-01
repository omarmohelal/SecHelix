#!/usr/bin/env python3
"""A deterministic keyword baseline for the SecHelix fixture suite.

This is not a security tool and it is not SecHelix. It exists for two reasons:

1. It exercises the scoring harness end to end with no model or network, so the
   metric pipeline can be validated reproducibly in CI.
2. It measures how far naive pattern matching gets on the fixture suite. If a
   keyword matcher scored well, the fixtures would be too easy to be evidence of
   anything. A near-chance score is evidence that the cases require dataflow,
   state, or authorization reasoning.

Usage:
    # regenerate the published floor, end to end
    python evals/baselines/keyword_baseline.py --score \
        --output evals/results/baseline-keyword-v1.json

    # or emit just the prediction packet
    python evals/baselines/keyword_baseline.py --cases work/blind-cases.json \
        --output work/baseline-predictions.json

The published result must stay regenerable. An earlier copy was committed with no
recorded suite version, so when the fixture suite grew from 19 fixtures to 33 the
number silently became a statement about a suite that no longer existed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CASES = ROOT / "evals" / "blind-packet" / "cases.json"

# Patterns a naive reviewer would treat as "smells". They are intentionally the
# sort of surface signal a grep-based rule or an unsophisticated model uses.
RISK_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\burlopen\(|requests?\.get\(|http_client\.get\(", "outbound fetch"),
    (r"\bos\.path\.join\(|\bopen\(", "filesystem write"),
    (r"f\"SELECT|f'SELECT|\bexecute\(\s*f", "string-built SQL"),
    (r"innerHTML|dangerouslySetInnerHTML", "markup sink"),
    (r"subprocess\.(run|Popen|call)", "subprocess execution"),
    (r"\beval\(|\bexec\(", "dynamic evaluation"),
    (r"secrets\.token|hashlib\.sha256", "credential or digest handling"),
    (r"\bdelete\(|DELETE FROM", "destructive operation"),
    (r"UPDATE\s+\w+\s+SET", "state mutation"),
    (r"PermissionError|require_role|roles", "authorization decision"),
)


def predict_label(source: str) -> tuple[str, list[str]]:
    """Flag a case as VULNERABLE when any risk pattern appears."""
    hits = [label for pattern, label in RISK_PATTERNS if re.search(pattern, source)]
    return ("VULNERABLE" if hits else "CLEAN"), hits


def _git_head() -> str:
    """Record which tree produced the number, so it can be reproduced."""
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "UNKNOWN"
    return out.stdout.strip() if out.returncode == 0 else "UNKNOWN"


def build_predictions(cases: list[dict[str, Any]], *, cases_sha256: str = "NOT_MEASURED") -> dict[str, Any]:
    rows = []
    for case in cases:
        label, hits = predict_label(case["source"])
        rows.append({
            "case_id": case["case_id"],
            "predicted_label": label,
            # The baseline performs no verification; saying otherwise would
            # inflate verified precision with unverified guesses.
            "verification_status": "NOT_RUN",
            "scanner_sources": ["keyword-baseline"] if hits else [],
            "notes": ", ".join(hits) if hits else "no risk pattern matched",
        })
    return {
        "model": "keyword-baseline-v1 (no model)",
        "provider": "none (deterministic regex)",
        "runner": "evals/baselines/keyword_baseline.py",
        "agent_host": "none",
        "execution_mode": "STATIC",
        "tools": ["python-re"],
        "prompt_reference": "not applicable; this baseline uses no prompt",
        "time_seconds": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cost": 0,
        "sechelix_commit": _git_head(),
        "fixture_suite_version": f"{len(rows)} cases",
        "cases_sha256": cases_sha256,
        "result_kind": "HARNESS_BASELINE",
        # Load-bearing: this number is a statement about fixture difficulty, and
        # must never be readable as SecHelix performance.
        "is_sechelix_result": False,
        "limitations": [
            "This baseline is a naive pattern matcher, not a security review and not SecHelix.",
            "It performs no verification, so verified precision is not meaningful for this run.",
            "Its purpose is to validate the scoring harness and to evidence fixture difficulty.",
        ],
        "predictions": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES, help="blind case export")
    parser.add_argument("--output", type=Path, help="output file; stdout when omitted")
    parser.add_argument("--score", action="store_true",
                        help="score the packet against the fixtures and emit the result")
    args = parser.parse_args(argv)

    raw = args.cases.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    cases = payload if isinstance(payload, list) else payload["cases"]
    predictions = build_predictions(cases, cases_sha256=hashlib.sha256(raw).hexdigest())

    if args.score:
        sys.path.insert(0, str(ROOT))
        from evals.run_evals import load_fixtures, score

        result = score(predictions, load_fixtures())
        metrics = result["metrics"]
        print(f"precision {metrics['precision']}  recall {metrics['recall']}")
        predictions = result

    text = json.dumps(predictions, indent=2, ensure_ascii=False, sort_keys=args.score) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
