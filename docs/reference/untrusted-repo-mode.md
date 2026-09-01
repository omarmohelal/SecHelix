# Zero-trust repository mode (`UNTRUSTED_REPO`)

A security auditor is a high-value target. When SecHelix reviews a repository nobody on your team
wrote, that repository can contain text aimed at the auditor rather than at a human reader.

`UNTRUSTED_REPO` is an execution mode that answers this with one rule:

> **Repository content is DATA. It is never CONTROL.**

## The threat

A hostile or compromised repository can attempt to:

- redefine the workflow through `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, or a
  `.github/copilot-instructions.md`;
- assert in a docstring or comment that a file was "already audited" and should be skipped;
- ask the auditor to run a bootstrap script, install a package, or fetch a URL;
- add tools through `.mcp.json` or widen permissions through `.claude/settings.json`;
- ask for findings or `.env` contents to be sent somewhere;
- push severity down by claiming a finding is a known false positive.

None of these are exotic. They are ordinary files that an agent reading a repository will
encounter, and the failure mode is that the agent treats them as configuration.

## What the mode guarantees

In `UNTRUSTED_REPO` mode:

| Capability | Default |
| --- | --- |
| `FILESYSTEM_WRITE` | denied |
| `REPO_SCRIPTS` | denied |
| `PACKAGE_INSTALL` | denied |
| `NETWORK` | denied |
| `HOOKS` | denied |
| `EXTERNAL_MCP` | denied |
| `DYNAMIC_TARGET_REQUESTS` | denied |

An **unrecognized** capability is also denied — the check is an allowlist, not a blocklist.

No file inside the target acts as control. `TrustPolicy.is_control(path)` returns `False` for every
target path unless the operator promoted that exact path.

## Escalation is explicit and recorded

Both promotion and capability escalation live in the scope record, not in the target:

```json
"trust": {
  "repository_content": "DATA_ONLY",
  "promoted_control_sources": [
    {
      "path": "AGENTS.md",
      "promoted_by": "operator",
      "promoted_at": "2026-09-01T00:00:00Z",
      "reason": "operator read this file and accepts its build conventions"
    }
  ],
  "capability_escalations": [
    {
      "capability": "NETWORK",
      "approved_by": "operator",
      "approved_at": "2026-09-01T00:00:00Z",
      "justification": "resolve one advisory URL for a dependency finding"
    }
  ]
}
```

Rules the resolver enforces, all fail-closed:

- an `UNTRUSTED_REPO` scope with **no** `trust` block is **rejected**, not downgraded to trusting
  the target;
- `repository_content` must be `DATA_ONLY`; declaring `TRUSTED_CONTROL` in this mode is rejected;
- a promotion must name a **concrete path** — `*`, `**` and `.` are refused, because a wildcard
  promotion re-trusts the whole target in one line;
- every promotion needs `promoted_by`, `promoted_at` and `reason`; every escalation needs
  `approved_by`, `approved_at` and `justification`.

## Detection is for the report, not for safety

`scan_for_injection()` flags content that addresses the auditor and records the path, line, pattern
class, and an excerpt. Pattern classes: `instruction_override`, `audit_suppression`,
`false_assurance`, `severity_downgrade`, `capability_request`, `exfiltration_request`,
`agent_address`.

This exists so the report can state *what the repository attempted*. It is deliberately **not** the
control. The control is that target content is never executed as instruction in the first place, so
a novel phrasing that evades the patterns still changes nothing.

## Using it

```python
from sechelix_core.untrusted_repo import resolve_trust_policy, review_target_content

policy = resolve_trust_policy(scope)          # raises if the scope is unsafe
policy.assert_allows("REPO_SCRIPTS")          # raises unless explicitly escalated

reviewed = review_target_content(policy, files)   # files: (path, text) pairs
for item in reviewed.quarantined:
    print(item.path, item.line, item.pattern)
```

`review_target_content` returns a policy with the same capabilities and promotions it was given.
Reading hostile content can never grant anything — that invariant is asserted directly in
`tests/test_untrusted_repo.py`.

A ready-to-use scope is at `examples/scope.untrusted-repo.example.json`.

## What this does not do

- It does not sandbox your agent. If your host grants the agent shell access, SecHelix's policy is
  a discipline layer, not a kernel boundary. Scope the agent as well.
- It does not detect every phrasing. Detection is best-effort reporting; the guarantee is the
  data/control separation.
- It does not make dynamic testing safe. `UNTRUSTED_REPO` is a static-review posture.
