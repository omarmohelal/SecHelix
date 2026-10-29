#!/usr/bin/env python3
"""Fail if a workflow would run untrusted code on the self-hosted runner unsafely.

The SecHelix required checks run on a self-hosted runner on a maintainer
workstation (see docs/engineering/SECHELIX-RUNNER-SECURITY.md). The single most
dangerous mistake is to combine that runner with ``pull_request_target``, which
runs a fork's code with repository secrets and a write-scoped token. This guard
makes that combination fail CI instead of relying on review alone.

Checks, per ``.github/workflows/*.yml``:
  1. A workflow that can trigger on ``pull_request_target`` must not use a
     self-hosted runner anywhere.
  2. A workflow that uses a self-hosted runner must not grant a write permission
     at the workflow level (write scopes belong on the specific job that needs
     them, e.g. CodeQL's ``security-events: write``).

Stdlib only; intentionally conservative and line-oriented so it needs no YAML
dependency and errs toward flagging rather than missing.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

WORKFLOWS = Path(".github/workflows")

# A write-scoped permission granted at workflow (top) level, e.g. "contents: write".
_WRITE_PERM = re.compile(r"^[ \t]{0,4}[a-z-]+:[ \t]*write\b", re.MULTILINE)
# The top-level permissions: block (two-space indent is the workflow level).
_TOP_PERMISSIONS = re.compile(r"^permissions:\s*$", re.MULTILINE)


def _uses_self_hosted(text: str) -> bool:
    return "self-hosted" in text


def _triggers_pull_request_target(text: str) -> bool:
    return "pull_request_target" in text


def _top_level_write_permission(text: str) -> bool:
    """True if a write scope is granted before the first job (workflow level)."""
    jobs = re.search(r"^jobs:\s*$", text, re.MULTILINE)
    head = text[: jobs.start()] if jobs else text
    if not _TOP_PERMISSIONS.search(head):
        return False
    return bool(_WRITE_PERM.search(head))


def main() -> int:
    if not WORKFLOWS.is_dir():
        print(f"no {WORKFLOWS} directory; nothing to check")
        return 0

    problems: list[str] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        if not _uses_self_hosted(text):
            continue
        if _triggers_pull_request_target(text):
            problems.append(
                f"{path}: uses a self-hosted runner and can trigger on "
                "pull_request_target; this runs fork code with secrets on the "
                "runner host. Use plain pull_request, or move the job to a "
                "GitHub-hosted runner."
            )
        if _top_level_write_permission(text):
            problems.append(
                f"{path}: self-hosted workflow grants a write permission at the "
                "workflow level; move write scopes onto the specific job that "
                "needs them so untrusted PR code is not handed a write token."
            )

    if problems:
        print("Self-hosted runner safety violations:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print("OK: no self-hosted runner is exposed via pull_request_target or a "
          "workflow-level write token")
    return 0


if __name__ == "__main__":
    sys.exit(main())
