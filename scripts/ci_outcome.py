#!/usr/bin/env python3
"""Turn a recorded runner result into one CI word.

The vocabulary is not invented here. ``PASS``, ``PASS_WITH_KNOWN_RISK``,
``BLOCKED`` and ``INCOMPLETE`` come from :mod:`sechelix_core.pr_review`, which
is the same vocabulary ``scripts/security_gate.py`` uses for canonical reports.
This module is the mapping for the *runner's* artifact, not a second gate with
its own opinions.

The ordering rule is the one that matters: **an unsatisfied mandatory node wins
over an empty finding list.** A run whose reasoning lanes were blocked produces
no findings, and so does a run over genuinely clean code. Reading the first as
the second is the specific failure this file exists to prevent, so
``INCOMPLETE`` is decided before findings are looked at at all.

Exit codes match ``security_gate.py`` so both can sit in the same job:
0 for PASS/PASS_WITH_KNOWN_RISK, 1 for BLOCKED, 2 for INCOMPLETE or bad input.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sechelix_core.pr_review import (  # noqa: E402
    BLOCKED,
    INCOMPLETE,
    PASS,
    PASS_WITH_KNOWN_RISK,
    VERIFIED,
)

#: Severities that block a release when a finding carrying one is VERIFIED.
#: Same two words ``policies/default.json`` blocks on.
BLOCKING_SEVERITIES = frozenset({"CRITICAL", "HIGH"})

#: Resolutions that mean the finding is no longer outstanding.
CLOSED_RESOLUTIONS = frozenset({"FIXED", "FALSE_POSITIVE", "DUPLICATE_ROOT_CAUSE"})

EXIT_FOR = {PASS: 0, PASS_WITH_KNOWN_RISK: 0, BLOCKED: 1, INCOMPLETE: 2}


class RunArtifactError(ValueError):
    """The run artifact cannot support a CI decision."""


def _findings(run: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Findings, tolerating the runner's ``null`` for "the key is not used"."""
    raw = run.get("findings") or []
    if not isinstance(raw, list):
        raise RunArtifactError("'findings' must be an array when present")
    return [f for f in raw if isinstance(f, Mapping)]


def _is_open(finding: Mapping[str, Any]) -> bool:
    resolution = str(finding.get("resolution", "OPEN")).upper()
    return resolution not in CLOSED_RESOLUTIONS


def _blocks(finding: Mapping[str, Any]) -> bool:
    """A finding blocks only when it is verified, severe and still open.

    Every clause is load-bearing. A severe *hypothesis* does not block — that is
    the whole point of separating candidates from findings — and neither does a
    severe finding that has already been fixed.
    """
    return (
        str(finding.get("status", "")).upper() == VERIFIED
        and str(finding.get("severity", "")).upper() in BLOCKING_SEVERITIES
        and _is_open(finding)
    )


def decide(run: Mapping[str, Any]) -> dict[str, Any]:
    """Map one ``run.json`` onto an outcome, a reason and the evidence for it."""
    if not isinstance(run, Mapping):
        raise RunArtifactError("run artifact must be a JSON object")

    unsatisfied = run.get("unsatisfied_mandatory", [])
    if not isinstance(unsatisfied, list):
        raise RunArtifactError("'unsatisfied_mandatory' must be an array")

    if unsatisfied:
        undelivered = [
            f"{node}={record.get('status', '?')}"
            for node, record in sorted((run.get("records") or {}).items())
            if isinstance(record, Mapping)
            and record.get("status") not in ("SUCCEEDED", "SKIPPED")
        ]
        return {
            "outcome": INCOMPLETE,
            "reason": (
                "Mandatory nodes did not deliver, so this run supports no security "
                "claim in either direction. It does not say the code is safe, and it "
                "does not say the code is unsafe."
            ),
            "unsatisfied_mandatory": sorted(str(n) for n in unsatisfied),
            "undelivered": undelivered,
            "blocking_findings": [],
            "open_findings": 0,
            "run_id": run.get("run_id", ""),
        }

    findings = _findings(run)
    blocking = [f for f in findings if _blocks(f)]
    open_count = sum(1 for f in findings if _is_open(f))

    if blocking:
        outcome, reason = BLOCKED, (
            f"{len(blocking)} verified finding(s) at CRITICAL or HIGH severity are open."
        )
    elif open_count:
        outcome, reason = PASS_WITH_KNOWN_RISK, (
            f"{open_count} open finding(s), none verified at a blocking severity."
        )
    else:
        outcome, reason = PASS, (
            "All mandatory nodes delivered and no open finding reaches a blocking severity."
        )

    return {
        "outcome": outcome,
        "reason": reason,
        "unsatisfied_mandatory": [],
        "undelivered": [],
        "blocking_findings": [
            str(f.get("id") or f.get("rule_id") or "unnamed") for f in blocking
        ],
        "open_findings": open_count,
        "run_id": run.get("run_id", ""),
    }


def _emit_github_output(decision: Mapping[str, Any]) -> None:
    """Write step outputs, if we are inside a GitHub Actions step.

    Values are written with a randomless heredoc-free form: every value here is
    a single line by construction, so ``key=value`` is safe and cannot be used
    to inject extra output keys.
    """
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    pairs = {
        "outcome": decision["outcome"],
        "reason": decision["reason"].replace("\n", " "),
        "run-id": decision["run_id"],
        "incomplete": "true" if decision["outcome"] == INCOMPLETE else "false",
        "blocking-count": str(len(decision["blocking_findings"])),
    }
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in pairs.items():
            handle.write(f"{key}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ci_outcome",
        description="Map a SecHelix run.json onto PASS / PASS_WITH_KNOWN_RISK / BLOCKED / INCOMPLETE.",
    )
    parser.add_argument("run_json", type=Path, help="path to a recorded run.json")
    parser.add_argument(
        "--github-output", action="store_true",
        help="also append step outputs to $GITHUB_OUTPUT",
    )
    args = parser.parse_args(argv)

    try:
        run = json.loads(args.run_json.read_text(encoding="utf-8"))
        decision = decide(run)
    except (OSError, json.JSONDecodeError, RunArtifactError) as exc:
        # Unreadable input is INCOMPLETE, never PASS. A CI step that cannot read
        # its own evidence has not established anything.
        print(f"error: {exc}", file=sys.stderr)
        print(json.dumps({"outcome": INCOMPLETE, "reason": f"unreadable run artifact: {exc}"}))
        return EXIT_FOR[INCOMPLETE]

    print(json.dumps(decision, indent=2, sort_keys=True))
    if args.github_output:
        _emit_github_output(decision)
    return EXIT_FOR[decision["outcome"]]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
