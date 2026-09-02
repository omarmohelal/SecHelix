# Verifier quorum

A single verifier that shares a model, a prompt lineage and a set of assumptions with the reviewer
is not fully independent. For a material finding you may want several verification paths — a second
reviewer, tool evidence, runtime evidence — and a way to combine them that does not quietly
manufacture agreement.

## The blindness is the mechanism

If verifier B can see verifier A's conclusion before voting, B is not an independent path. It is a
reviewer of A, and the resulting "consensus" is an artifact of ordering.

`SealedQuorum` enforces this structurally rather than by convention:

- a sealed quorum **cannot be inspected** before it opens;
- it **cannot be opened** while any expected voter is outstanding;
- a vote **cannot be submitted** after it opens;
- no voter votes twice, and an unexpected voter is refused.

## Four outcomes

| Outcome | Meaning |
|---|---|
| `CONSENSUS_VERIFIED` | Every voter that reached a conclusion agrees it is real. |
| `CONSENSUS_REFUTED` | Every voter that reached a conclusion agrees it is not. |
| `DISAGREEMENT` | Voters reached opposite conclusions. |
| `INSUFFICIENT_EVIDENCE` | Too few voters reached any conclusion. |

**`DISAGREEMENT` is not a vulnerability. It is also not a clearance.** It means the evidence supports
both readings — a fact about the evidence, and a request for a human. It is not resolved by counting
louder, so **a majority does not overrule a dissent**: two-against-one is still `DISAGREEMENT`.

**An abstention is not a vote for safety.** A path that could not reach a conclusion is recorded as
`ABSTAIN` and never folded into either side; if too few conclude, the outcome is
`INSUFFICIENT_EVIDENCE`.

## What a quorum cannot do

**It never promotes.** A finding the verifier did not verify does not become verified because several
paths later agreed it looked real. A quorum can confirm what verification found, and it can withhold.

Consensus refutation marks a finding `FALSE_POSITIVE`. Disagreement and insufficient evidence leave
the status alone and set `requires_human_review`.

## Evidence quality is recorded, not just the count

Agreement among three reviewers of the same kind is weaker than agreement across a reviewer, a tool
and a runtime observation. The result records which `path_kind`s concluded, and flags a consensus
reached by reviewers alone.

Each result carries a `vote_digest` — order-independent, and it changes when any conclusion changes —
so a recorded tally can be checked later.

## Usage

```python
from sechelix_core.quorum import SealedQuorum, Vote

quorum = SealedQuorum("SHX-F-1", ["reviewer-b", "semgrep", "runtime"])
quorum.submit(Vote("reviewer-b", "REVIEWER", "VERIFIED", "owner predicate absent on the query"))
quorum.submit(Vote("semgrep", "TOOL", "VERIFIED", "rule sechelix-variant-... matched"))
quorum.submit(Vote("runtime", "RUNTIME", "REFUTED", "gateway rejects the cross-tenant request"))

result = quorum.open()   # DISAGREEMENT -> requires_human_review
```

## Related

- [Policy packs](policy-packs.md)
- [Calibration](calibration.md)
