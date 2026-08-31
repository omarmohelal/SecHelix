#!/usr/bin/env python3
"""Fail a release when the SecHelix report contains unresolved verified blockers.

Expected JSON shape:
{
  "findings": [
    {"id":"SHX-001","severity":"HIGH","status":"VERIFIED","resolution":"OPEN"}
  ]
}
"""
import argparse
import json
from pathlib import Path

BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}
VERIFIED_STATES = {"VERIFIED"}
CLOSED_RESOLUTIONS = {"FIXED", "ACCEPTED_RISK", "FALSE_POSITIVE", "DUPLICATE_ROOT_CAUSE"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--allow-accepted-risk", action="store_true")
    args = parser.parse_args()

    data = json.loads(args.report.read_text(encoding="utf-8"))
    blockers = []
    for finding in data.get("findings", []):
        severity = str(finding.get("severity", "")).upper()
        status = str(finding.get("status", "")).upper()
        resolution = str(finding.get("resolution", "OPEN")).upper()
        closed = resolution in CLOSED_RESOLUTIONS
        if resolution == "ACCEPTED_RISK" and not args.allow_accepted_risk:
            closed = False
        if severity in BLOCKING_SEVERITIES and status in VERIFIED_STATES and not closed:
            blockers.append(finding)

    if blockers:
        print(f"BLOCKED: {len(blockers)} unresolved verified High/Critical finding(s)")
        for finding in blockers:
            print(f"- {finding.get('id','?')} {finding.get('severity','?')}: {finding.get('title','untitled')}")
        return 1

    print("PASS: no unresolved verified High/Critical findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
