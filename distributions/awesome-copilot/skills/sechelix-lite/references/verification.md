# Independent verification

The verifier's job is to **disprove** candidates. Agreement without independent reconstruction
is not verification.

## Separation

- Run the verifier as a separate subagent or a fresh pass that did not write the candidate.
- Give it a neutral packet: candidate ID, the claim, scope and mode, relevant file paths, and any
  known compensating controls. Do **not** include a truth label or a severity to defend.
- The verifier does not implement fixes.
- Dynamic proof stays inside the authorized mode and uses the smallest harmless test.

## Refutation protocol

For each candidate, reconstruct the path from source and try to refute every link. Record the
method and the result (`SUPPORTED`, `REFUTED`, `UNKNOWN`) with file/line evidence.

| Link | Try to show that... |
|---|---|
| Attacker control | the input is fixed, server-derived, signed, or unreachable by the attacker |
| Reachability | no entrypoint reaches the code, or a feature flag/config disables it |
| Boundary failure | a guard exists elsewhere on the executed path (middleware, policy, DB rule) |
| State producibility | the vulnerable state cannot actually be created |
| Preconditions | the required role or state already grants the claimed capability |
| Impact | the effect is weaker than claimed, or not security-relevant |
| Compensating control | encoding, parameterization, sandboxing, rate limits or constraints block it |
| Duplicate | another candidate has the same root cause |

Trace the **executed** path. Do not assume middleware, row-level security or an admin helper
applies without following the call.

## Classification

| Status | Use when |
|---|---|
| `VERIFIED` | every required link is `SUPPORTED` with evidence, and a safe reproduction or equivalent proof exists |
| `LIKELY_BUT_UNPROVEN` | strong signal, but a decisive link is `UNKNOWN` |
| `FALSE_POSITIVE` | at least one required link is `REFUTED` |
| `DUPLICATE_ROOT_CAUSE` | a verified finding already explains the same failure; reference it |
| `BLOCKED_BY_ENVIRONMENT` | proof needs an environment, account or authorization that is legitimately unavailable |

Never promote `LIKELY_BUT_UNPROVEN` to `VERIFIED` to satisfy a release decision. Never promote a
finding because a scanner and a model agree.

## Severity

Assign severity only after classification.

- `CRITICAL`: direct compromise of a core trust boundary with severe impact.
- `HIGH`: serious confidentiality, integrity, tenant-isolation or financial failure.
- `MEDIUM`: meaningful but constrained weakness.
- `LOW`: narrow hardening defect with limited impact.
- `INFO`: design or observability improvement, not a vulnerability.

`HIGH` or `CRITICAL` requires `VERIFIED`. Otherwise use `UNASSIGNED` or a conservative level.
Severity reflects this system's impact and preconditions, not the worst case of the CWE class.

## Attack chains

Per-finding severity can understate real risk: user enumeration (Low) plus a weak reset token
(Medium) plus no MFA on recovery (Medium) is account takeover.

- Only `VERIFIED` findings compose into a confirmed chain.
- A chain with an unverified link is `POTENTIAL`, has no severity, and names the missing link.
- Chain severity comes from the composed outcome, not from raising the worst component.
- Cite every component and prerequisite. Report a confirmed chain as the headline.

## Variant hits

A sibling found by searching for a verified root cause starts as a new candidate. It inherits no
evidence or severity from the original and goes through this protocol on its own.

## Verifier output

```yaml
candidate_id: C-012
classification: FALSE_POSITIVE
refutation_attempts:
  - link: attacker_control
    method: traced `order_id` from route to query
    result: SUPPORTED
    evidence: [api/orders.py:41]
  - link: boundary_failure
    method: followed the request through tenant middleware
    result: REFUTED
    evidence: [middleware/tenant.py:18 scopes every query by tenant_id]
safe_reproduction: {performed: false, reason: "refuted statically"}
root_cause: null
duplicate_of: null
remaining_uncertainty: []
severity: UNASSIGNED
```
