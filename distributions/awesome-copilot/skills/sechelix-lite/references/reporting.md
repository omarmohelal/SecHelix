# Safe proof, reporting and the release verdict

## Safe dynamic proof

Only in `LOCAL`, authorized `STAGING`, or explicitly bounded `PRODUCTION_SAFE` mode.

Prefer, in order:

1. purpose-built local fixtures and seeded test data;
2. two accounts or tenants you control, compared side by side;
3. exact status and response assertions over "it looked wrong";
4. bounded concurrency tests against harmless fixture state;
5. provider mocks instead of real payment, email or messaging providers;
6. read-only observation in production.

Use the minimum test that proves or refutes the hypothesis. Stop if a proof would leave the mode,
touch real user data, or trigger an irreversible side effect. Losing integrity through a security
test is itself a security failure.

## Finding format

Report each `VERIFIED` finding with:

```markdown
### F-003: Cross-tenant invoice read via export endpoint
- Severity / confidence: HIGH / HIGH
- Status: VERIFIED (independent verification: 7 links supported, 0 refuted)
- Surface: GET /api/invoices/export?id=
- Mapping: CWE-639, OWASP API1:2023 (when useful)
- Preconditions: authenticated user in any tenant
- Evidence chain:
  1. attacker control: `id` query parameter (api/invoices.py:88)
  2. reachability: route registered without tenant middleware (routes.py:40)
  3. boundary failure: lookup by id only; tenant_id not in query (repo/invoices.py:17)
- Safe reproduction: tenant A user exported tenant B fixture invoice in LOCAL
- Impact: any user can read any tenant's invoices
- Root cause: ownership checked in list view only, not at data access
- Fix: scope the repository query by tenant_id (commit or diff reference)
- Regression: tests/test_invoice_isolation.py fails before fix, passes after
- Residual risk: other exports reviewed; no sibling found
```

Keep the fields; the wording is illustrative. Never paste real secrets, tokens or personal data
into a finding. Redact and describe the type instead.

Group `DUPLICATE_ROOT_CAUSE` items under the finding they duplicate. Report confirmed attack chains
before individual findings.

## Report sections

1. **Scope and mode:** what was authorized, what was out of scope, revision inspected (commit SHA,
   clean or dirty tree).
2. **Release verdict** with a one-paragraph justification.
3. **Verified findings**, highest severity first, with fix and regression status.
4. **Likely but unproven:** the missing link for each and what would settle it.
5. **Refuted candidates:** what was checked and which link failed. This shows the review was
   done, not skipped.
6. **Coverage:** areas marked `APPLICABLE`, `NOT_APPLICABLE` (with reason), `UNKNOWN` and
   `BLOCKED`.
7. **Tools used**, and which results were treated as candidates.
8. **Limitations:** what this review did not do.

## Regression status values

`PASS` (fails before, passes after) · `FAIL` · `NOT_RUN` · `NOT_PRACTICAL` (with the reason and
the substitute evidence used).

## Release verdict rules

Apply in order; the first match wins.

1. Required evidence missing, malformed, or the report is for a different revision → `INCOMPLETE`.
2. Any unresolved `VERIFIED` High or Critical, or an integrity-critical `UNKNOWN` → `BLOCKED`.
3. Remaining risk exists and the user explicitly accepted it → `PASS_WITH_KNOWN_RISK`.
4. Otherwise → `PASS`.

Rules for the verdict:

- `PASS` is not a security certification. Say what was reviewed.
- Do not produce `PASS` from empty, scanner-only or unverified evidence.
- `LIKELY_BUT_UNPROVEN` High or Critical items do not disappear; list them and state whether they
  block.
- A report is stale once the code changes. Re-check the revision before reusing a verdict.
