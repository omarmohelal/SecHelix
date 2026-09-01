# Patch mode

Patch mode turns a verified finding into a **reviewable proposal**: a `.patch` file and a `.md`
rationale, written to an output directory. It never applies anything.

A report that stops at "you should fix this" hands the whole cost of remediation to the reader, who
then re-derives reasoning the review already did. Patch mode closes that gap. It does not close the
review loop — a human still decides.

## What it will not do

| Refusal | Why |
| --- | --- |
| Patch a `HYPOTHESIS` | A patch is a change to working code justified by a guess. |
| Patch a `LIKELY_BUT_UNPROVEN` finding | The most tempting case, and still not proven. |
| Patch a `FALSE_POSITIVE` | It was refuted. There is nothing to fix. |
| Patch a `DUPLICATE_ROOT_CAUSE` | Patch the primary finding for that root cause instead. |
| Patch a `BLOCKED_BY_ENVIRONMENT` finding | Verification never completed. |
| Apply, stage, or commit a patch | The output is an artifact. Ownership of the tree stays with its owner. |
| Report a regression as passing | Only a test run that actually happened can move `NOT_RUN`. |

Only `VERIFIED` produces a proposal. Everything else is recorded as a refusal **with its reason**,
so a reader can see what was considered and rejected rather than silently missing.

The gate exists because a diff is persuasive. A reviewer shown a concrete patch is far more likely
to accept the premise than one shown a paragraph, so that persuasion has to be earned by
verification first.

## What a proposal contains

Each rationale states, in order:

1. **Why this is a real finding** — the evidence chain, link by link.
2. **How it was verified** — outcome, whether the verifier was independent, and the refutation that
   was attempted and failed.
3. **What the patch changes** — the recorded root-cause fix.
4. **What it does not cover** — a minimal patch usually addresses one instance of a root cause.
   Saying so is the difference between a fix and a false sense of completion.
5. **Before you accept this** — the regression command and the assertion it must make.

A `NOT_RUN` regression status is stated plainly: nothing has been demonstrated until the assertion
fails on the old code and passes on the new.

## Usage

```python
from sechelix_core.patch_mode import propose, write_patch_set

patch_set = propose(report["findings"], diffs={"SHX-F-1": diff_text}, output_dir="work/patches")
write_patch_set(patch_set, "work/patches")

print(patch_set.as_dict()["refused_count"])
```

A finding with no supplied diff still gets a rationale. The missing diff is stated, never invented.

## Safety

Finding ids reach a write path, and a report can come from an untrusted repository. Ids are
validated against `^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$` and rejected if the resulting name differs
from the id, so `../../.ssh/authorized_keys` raises rather than resolving. Writes are confined to
the output directory; the audited tree is never touched and nothing shells out to `git apply`.

`write_patch_set` accepts an injected `writer`, so tests exercise the full path without touching
disk.

## Related

- [Untrusted repository mode](../../sechelix_core/untrusted_repo.py) — why report content is treated as data
- [Attack chains](../../sechelix_core/attack_chains.py) — composing verified findings
- [Compatibility](compatibility.md)
