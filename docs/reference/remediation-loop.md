# Remediation loop

Patch mode produces a proposal. This decides whether the proposal is any good.

The dangerous moment in security work is not finding the bug — it is the fix. A patch written to
close one hole routinely opens another: an authorization check added to one route and not its
sibling; input validation that rejects the exploit and also rejects legitimate input, turning a
vulnerability into an outage; a "safe" rewrite that drops the tenant predicate while removing the
injection.

Nobody reviews the fix as adversarially as they reviewed the bug, because by then everyone wants to
be finished. So the loop applies the same scrutiny the finding received.

```
verified finding
  → scratch worktree          (never the working tree, never main)
  → candidate patch
  → existing tests            (did we break something)
  → vulnerability regression  (did we actually close it)
  → differential review       (did we open something new)
  → remediation-risk check    (authorization / validation / availability)
  → independent verification  (does a second path agree)
  → PR-ready, or refused with the reason
```

## What it refuses to do

**It never touches `main` and never touches the caller's working tree.** All work happens in a
scratch location the caller supplies; an empty, `.` or `/` workspace is refused. This module computes
and reports — applying anything is a separate human decision, and `applied` is a hardcoded `false`.

**It never remediates an unverified finding.** Changing working code to close something nobody
established happens is not remediation.

**A stage that did not run is not a stage that passed.** Every gate defaults to `NOT_RUN`, and
`NOT_RUN` blocks readiness exactly as `FAIL` does — but the two are recorded distinctly, because "we
did not check" and "we checked and it was fine" are different sentences.

**The remediation-risk check can veto the patch.** It reads a differential review *of the patch
itself* and reports newly introduced authorization, validation or availability defects. A risk class
that was not assessed is not a clean one, and the record names which.

## Execution stays outside

The module runs no tests and shells out to nothing. The caller executes each stage in its own
sandbox and reports the outcome; the loop decides what the combination means.

That is what makes "never touches main" a property of the design rather than a promise in a
docstring.

## Usage

```python
from sechelix_core.remediation import run_loop, StageResult

result = run_loop(
    finding,
    workspace="/tmp/sechelix-scratch/SHX-F-1",
    existing_tests=StageResult("existing_tests", "PASS", "full suite green"),
    vulnerability_regression=StageResult("vulnerability_regression", "PASS", "fails pre-fix"),
    patch_diff_review=review_diff(patch_text),
    independent_verification=StageResult("independent_verification", "PASS", "verifier agrees"),
)
result.ready   # READY_FOR_REVIEW — a patch for a human, not an applied fix
```

## Related

- [Patch mode](patch-mode.md) — where the candidate comes from
- [Campaigns](campaigns.md)
- [Verifier quorum](verifier-quorum.md)
