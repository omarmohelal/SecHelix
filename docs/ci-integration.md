# CI integration

SecHelix is a release input, not a replacement for code review or existing
security controls. Generate the canonical report in an authorized job, then run
the policy gate in a separate fail-closed step.

```bash
python -m reports.report_renderer report.canonical.json --format json --output report.json
python scripts/security_gate.py report.json --policy policies/default.json --json-output
```

Exit codes:

- `0`: `PASS` or `PASS_WITH_KNOWN_RISK`;
- `1`: `BLOCKED`;
- `2`: `INCOMPLETE`, malformed input, or missing policy/evidence.

CI must treat both 1 and 2 as non-green. Preserve the human-readable/JSON gate
decision as an artifact without uploading raw secrets or private policy values.

An illustrative GitHub Actions fragment is available at
[`../examples/ci/security-gate.yml`](../examples/ci/security-gate.yml). It does
not run scanners or models and must be adapted to the organization's report
production and fork-secret policy.

## Pull-request safety

- Do not expose private policies, provider credentials, or signing identity to forked PR code.
- Do not use `pull_request_target` to execute untrusted checkout content with secrets.
- Normalize external scanner artifacts as untrusted input.
- Pin third-party actions to reviewed immutable commits in production workflows.
- Set explicit minimal permissions and artifact retention.
- Require protected-environment approval for risk acceptance or signing.

## Required gate tests

1. unresolved verified Critical/High → `BLOCKED`;
2. fixed Critical/High with complete independent verification → `PASS` if otherwise clear;
3. valid policy-approved accepted risk → `PASS_WITH_KNOWN_RISK`;
4. integrity-critical unknown → `INCOMPLETE` or policy-selected `BLOCKED`;
5. missing required tool → `INCOMPLETE`;
6. empty/malformed report → `INCOMPLETE`, never `PASS`.
