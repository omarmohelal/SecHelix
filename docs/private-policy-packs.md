# Private organization policy packs

The public SecHelix policy examples describe mechanics. A real company pack may
contain sensitive role names, assets, deployment restrictions, known exceptions,
regulated-data classifications, and risk approvals; keep that material outside
the public SecHelix repository.

## Recommended layout

```text
company-sechelix-policy/        # private repository
  policy.json
  trust-boundaries/
  role-object-action/
  severity-overrides/
  safe-test-rules/
  accepted-risk/                # approvals, expiry, ticket references
  retention/
  CODEOWNERS
```

Start from `policies/example-organization.json`. Pin the SecHelix version or
commit the pack supports and record the pack's own semantic version and digest.

## Review rules

- Require security ownership for policy semantics and application ownership for business invariants.
- Require human approval for accepted risk; models may summarize but may not approve.
- Give every accepted risk an owner, reason, compensating control, ticket, approval time, and future expiration.
- Review severity overrides in both directions; lowering severity needs stronger justification than raising it.
- Reject wildcard trust boundaries and broad production-safe permissions.
- Test the pack against synthetic reports before enforcing it on releases.
- Keep policy history and audit every change.

## Runner boundary

Load private packs at runtime from protected storage or a private checkout. Do
not copy them into public build artifacts, SARIF uploads, Pages content, cache
keys, or logs. CI should expose only the resulting gate outcome and redacted
reason summary to untrusted pull requests.

Forked pull requests must never receive private policy or signing credentials.
Run privileged evaluation only after the untrusted build is isolated and its
artifacts are treated as untrusted input.
