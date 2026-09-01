# Incremental evidence cache

Evidence is the expensive part of an audit. Re-auditing a repository after a two-line change means
producing all of it again, so the honest options are "spend the whole cost again" or "trust
yesterday's answer". The second one is how a stale clean result gets attached to changed code.

The incremental evidence cache removes that choice by making reuse **provable**. Each evidence
record is bound to a *dependency fingerprint* — the repository, the commit, and every file the
record actually read, each with the content hash it had when it was read. On a new revision the
fingerprint is replayed against what changed.

## The four states

Every cached record lands in exactly one state, and the counts always sum to the record count.

| State | Meaning |
| --- | --- |
| `REUSED` | Every recorded dependency still hashes to what it hashed before. |
| `INVALIDATED` | At least one recorded dependency changed. The verdict names which. |
| `RECOMPUTED` | Was invalid, and has since been regenerated against this revision. |
| `UNKNOWN` | The fingerprint is incomplete, so validity cannot be established at all. |

## What it guarantees

**`UNKNOWN` is never `REUSED`.** This is the rule the module exists to enforce. Reusing evidence
whose provenance cannot be established is exactly how a passing result gets attached to code nobody
inspected, and it is invisible afterwards, because a reused record looks identical to a fresh one.
`RecordVerdict.reusable` is true for `REUSED` and nothing else; `must_recompute` is true for both
`INVALIDATED` and `UNKNOWN`, which are treated identically downstream.

**Evidence that claims to depend on nothing is `UNKNOWN`, not universally valid.** A record with an
empty dependency set is far more likely to be a producer that forgot to declare its inputs than a
genuine observation about nothing, and treating the two the same way means the forgetful producer's
output survives every change forever.

**Forgetting the change set costs work, never correctness.** `changed_paths=None` and
`changed_paths=()` mean different things: `()` asserts that nothing changed, `None` says no change
set was supplied. `None` is the default, and it yields `UNKNOWN` for anything no content hash
covers.

**Content beats the change set.** Where `current_hashes` covers a dependency it is authoritative in
both directions. A file that changed without appearing in the change set is still caught; a file
listed as changed whose content came back to what was read is correctly reused.

**Nothing mutates an evidence record.** `schemas/evidence-v1.schema.json` sets
`additionalProperties: false`, and more to the point a cache is bookkeeping *about* evidence rather
than a claim the evidence makes. Fingerprints live alongside records in `CachedEvidence`, so a
cached record still validates against its contract unchanged.

**The verdict is deterministic.** Paths are folded to one form, fingerprint inputs are sorted, and
records are reported in id order, so the same cache and the same revision produce byte-identical
telemetry regardless of the order entries arrived in.

## What it deliberately refuses

| Refusal | Why |
| --- | --- |
| Reuse a record whose fingerprint is incomplete | Unprovable is not the same as unchanged. |
| Reuse a record with no declared dependencies | Depending on nothing is unverifiable, not universal. |
| Reuse a record bound to another repository | It does not describe this tree, whatever changed here. |
| Reuse a record when no change set and no hashes cover its dependencies | Nothing was checked, so nothing was shown. |
| Invalidate per symbol rather than per file | A fingerprint's `context` records which symbol or dataflow the evidence was about, but nothing here can prove an edit missed that symbol. |
| Accept two hashes for one dependency path | The record cannot say what it read; keeping one answer would decide validity by dictionary ordering. |
| Accept two fingerprints for one `evidence_id` | The record's state would depend on iteration order. |
| Mark a `REUSED` record as `RECOMPUTED` | Either the work was done and the saving is misreported, or it was not and the state is a lie. |
| Report on hypotheses it holds no evidence for | An empty rerun queue means nothing needs *re-running*, not that anything has been covered. |

The last one matters most for how the output is read. The cache answers "what stopped being valid",
never "what is covered".

## Usage

```python
from sechelix_core.evidence_cache import (
    cache_entry, content_hash, evaluate_cache, fingerprint,
    hypotheses_to_rerun, mark_recomputed,
)

entry = cache_entry(record, fingerprint(
    repository="owner/app",
    commit="06ab8ca680d477b8005805d67ab44d11507e3321",
    inputs={"src/auth.py": content_hash(auth_source)},
    context="require_owner -> orders.owner_id",
))

verdict = evaluate_cache(
    [entry],
    repository="owner/app",
    commit="a7f1f4799234c5410c872a54de18f3dbbcc316cc",
    changed_paths=["src/routes.py"],          # () means nothing changed; None means unknown
    current_hashes={"src/routes.py": new_hash},
)

print(verdict.counts)                          # {"REUSED": 1, "INVALIDATED": 0, ...}
for item in verdict.as_dict()["invalidations"]:
    print(item["evidence_id"], item["reason"])

rerun = hypotheses_to_rerun(verdict)           # only what actually stopped holding
verdict = mark_recomputed(verdict, verdict.stale_evidence_ids)
```

A hypothesis is queued for re-running when *any* record supporting it is `INVALIDATED` or `UNKNOWN`,
even if its other records were reused: a conclusion drawn from four observations is not
three-quarters valid when one of them stops holding.

## Audit telemetry

`CacheVerdict.as_dict()` is JSON-serializable and carries the per-state counts, every record with
its reason, an `invalidations` list with the changed paths that caused each one, an `unresolved`
list with the reason each `UNKNOWN` could not be established, and the resulting rerun queue. Every
state transition is explained in prose, because "UNKNOWN" with no cause is the kind of result a
reader rounds down to "probably fine".

## What this does not do

- It does not decide whether a *report* still describes a tree. That is
  [revision binding](../../sechelix_core/revision.py), which works at report rather than record
  granularity, and the two are complementary: a fresh report can still contain reused evidence.
- It does not compute fingerprints for you. The producer of a piece of evidence is the only thing
  that knows what it read; a fingerprint inferred afterwards would be a guess wearing a hash.
- It does not persist anything. It is a pure classification over entries the caller holds.
- It does not decide *which* hypotheses a change set implicates. That is
  [`review_diff`](../../sechelix_core/diff_review.py); this module only says which of the ones you
  already have evidence for stopped holding.

## Related

- [`sechelix_core/evidence_cache.py`](../../sechelix_core/evidence_cache.py) — the module
- [`tests/test_evidence_cache.py`](../../tests/test_evidence_cache.py) — the invariants, asserted
- [`schemas/evidence-v1.schema.json`](../../schemas/evidence-v1.schema.json) — the record contract
- [Patch mode](patch-mode.md) — the other place a verified claim has to earn its persuasiveness
- [Untrusted repository mode](untrusted-repo-mode.md) — why nothing read from a target is trusted
- [Compatibility](compatibility.md)
