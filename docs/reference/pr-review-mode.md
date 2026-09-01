# PR review mode

`sechelix_core/pr_review.py` turns a unified diff, plus whatever reports exist, into one pull
request comment: what the change did to the security posture, what it raised that nobody has
checked, what is actually proven, and whether it may ship.

The hard part is not producing the comment. It is not producing it.

## Silence is the default

A bot that comments on every pull request is muted within a week, and a muted bot protects nothing.
So a comment is produced only when something **material** happened. "Material" is defined here, not
left to taste:

| Reason | Fires when |
| --- | --- |
| `NEW_HYPOTHESIS` | The diff produced at least one `NEW_RISK` or `UNKNOWN` delta. |
| `UNREADABLE_DIFF` | A diff was supplied that the classifier could not parse, so nothing was analyzed. |
| `NEW_VERIFIED_FINDING` | A finding is `VERIFIED` in the head report that was not verified in the base report. |
| `CANDIDATE_REFUTED` | A candidate that was open in the base report is refuted in the head report. |
| `COVERAGE_DEGRADED` | More hypotheses are unresolved than before. |
| `DECISION_CHANGED` | The release decision differs from the one supplied for the base. |

Nothing else speaks. A typo, a refactor that moves no security surface, a change that only *adds* a
control, and a coverage improvement all produce `review.comment is None`, `review.nothing_to_say is
True`, and `comment_suppressed_because` naming the reason.

The list is short on purpose. Every reason added to it is a reason the bot speaks more often, and
every extra comment spends some of the attention the next one will need.

**Silence is not approval.** Suppressing the comment never raises the release decision. A pull
request with nothing worth saying and no evidence behind it is `INCOMPLETE` and silent, not `PASS`.

## The decision

The outcome uses the release vocabulary from [`scripts/security_gate.py`](../../scripts/security_gate.py)
— `PASS`, `PASS_WITH_KNOWN_RISK`, `BLOCKED`, `INCOMPLETE` — and is the **least favourable** of three
independently computed constraints:

| Constraint | `INCOMPLETE` when |
| --- | --- |
| `diff` | A `NEW_RISK` or `UNKNOWN` delta exists that nothing in the head report has verified or refuted. |
| `evidence` | No report was supplied, the only report describes the pre-change tree, or the head report is bound to a different commit. |
| `gate` | No gate decision was supplied. |

Combining with a minimum is the whole mechanism: no favourable input can lift the result past a
less favourable one. A diff that introduces `NEW_RISK` nothing has verified is `INCOMPLETE` even
when the gate returned `PASS`, because "we did not look" and "we looked and it is fine" are
different statements and only one of them is a pass.

A report's own `release_recommendation` is never read. The gate does not trust a report's
self-assessment, and neither does this.

## Attribution is path-level, and says so

A delta counts as examined only when a finding in the **head** report cites the same file. That
shows the file was looked at, not that this delta was the thing examined, so each hypothesis carries
an `attribution` string saying exactly that.

A finding from the base report never marks a delta as examined: a report about the pre-change tree
cannot have examined code this diff added. Base-report findings are still shown to the reviewer —
they are worth knowing about — but they are labelled `read_from: BASE_REPORT` in the payload and in
the comment, and they never raise the decision.

## What it does not reimplement

Diff classification comes from [`sechelix_core/diff_review.py`](../../sechelix_core/diff_review.py)
via `review_diff`. One classifier means one place where a rule is wrong and one place to fix it.
`review.security_delta` is that function's output verbatim.

## Usage

```python
from sechelix_core.pr_review import review_pull_request

review = review_pull_request(
    diff_text,
    report=head_report,          # describes the changed tree; optional
    prior_report=base_report,    # describes the tree before it; optional
    gate_decision="PASS",        # from the real release gate; optional
    prior_decision="PASS",       # the base decision, for DECISION_CHANGED; optional
    head_commit="9f2c...",       # binds the head report to this change; optional
)

if review.nothing_to_say:
    return                        # post nothing

post_comment(review.comment)      # Markdown body
publish(review.as_dict())         # machine-readable result
```

Every optional argument that is omitted lowers the decision rather than being assumed away.

## What the comment says about itself

The rendered body ends with what it is *not*: every hypothesis in it is unverified and carries no
severity, `UNKNOWN` is not a pass, and the decision is never better than the evidence behind it.
Findings carry `severity_as_reported` — the value the report recorded. Nothing here assigns one.

## Related

- [Authorization graph](authorization-graph.md) — the same honesty rules applied to policy
- [Patch mode](patch-mode.md) — what happens after a hypothesis is verified
- [Compatibility](compatibility.md)
- [`sechelix_core/pr_review.py`](../../sechelix_core/pr_review.py)
