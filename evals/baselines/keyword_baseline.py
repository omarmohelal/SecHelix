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
    python evals/baselines/keyword_baseline.py --cases work/blind-cases.json \
        --output work/baseline-predictions.json
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

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


def build_predictions(cases: list[dict[str, Any]]) -> dict[str, Any]:
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
        "limitations": [
            "This baseline is a naive pattern matcher, not a security review and not SecHelix.",
            "It performs no verification, so verified precision is not meaningful for this run.",
            "Its purpose is to validate the scoring harness and to evidence fixture difficulty.",
        ],
        "predictions": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, required=True, help="blind case export")
    parser.add_argument("--output", type=Path, help="prediction packet; stdout when omitted")
    args = parser.parse_args(argv)

    payload = json.loads(args.cases.read_text(encoding="utf-8"))
    predictions = build_predictions(payload["cases"])
    text = json.dumps(predictions, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"wrote {len(predictions['predictions'])} baseline predictions to {args.output}")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
