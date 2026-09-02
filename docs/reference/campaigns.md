# Remediation campaigns

"43 findings" makes a team feel behind and tells them nothing about what to do. It is also usually
wrong about the size of the work: forty-three findings frequently share four root causes, and fixing
four things closes all forty-three.

A campaign is the unit of remediation — one root cause, the findings it explains, who owns it, and
whether the fix has been proven. The headline becomes:

```
43 observations → 11 verified findings → 4 root causes → 4 campaigns
```

## What it refuses to do

**Only verified findings join a campaign.** Grouping hypotheses by root cause invents a cause for
something nobody established happens. Unverified candidates simply do not appear.

**Root causes are read, never inferred.** Findings group on the root-cause text the report already
records. Two findings with similarly-worded but distinct causes stay two campaigns, because merging
them would be this module deciding something the reviewer did not.

**A verified finding with no recorded root cause is listed as unattributed**, not hidden. It is real
work that belongs to no campaign yet, and omitting it would understate the job.

**Patched is not complete.** Patch status and regression status are separate, because "we changed the
code" and "we demonstrated the change works" are different claims and the gap between them is where
remediation theatre lives. A campaign whose findings are all patched with no passing regression
reports `PATCHED_UNPROVEN`.

**Remaining risk names findings, not a percentage.** "90% complete" hides which one is still open.

## Status

| Status | Meaning |
|---|---|
| `NOT_STARTED` | No finding in the campaign has been resolved |
| `IN_PROGRESS` | Some resolved, some not |
| `PATCHED_UNPROVEN` | All resolved, regression proof does not pass |
| `COMPLETE` | All resolved **and** regression passes |
| `BLOCKED` | Cannot proceed; every listed finding stands |

Priority comes from the worst member's severity. Nothing here raises a severity.

An unowned campaign says so in its notes: work nobody owns is work nobody does.

## Usage

```python
from sechelix_core.campaigns import build_campaigns, render_markdown

result = build_campaigns(report["findings"], owners={"Scope reads by tenant.": "omar"})
print(render_markdown(result))
```

## Related

- [Remediation loop](remediation-loop.md) — what happens to one campaign's patch
- [Policy packs](policy-packs.md)
