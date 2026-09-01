# SecHelix next roadmap

**Date:** 2026-09-01 · Ordered by credibility value per unit of effort.

The single thing standing between SecHelix and a defensible launch is **one uncontaminated
measurement**. Almost everything below is either that, or protects that.

---

## The next ten tasks

### 1. Produce the first uncontaminated evaluation run — *blocking everything else*
The harness is validated and the export is genuinely blind. What is missing is an evaluator that
did not author the fixtures. Run `--export-cases` in a **fresh session with no repository access**,
produce predictions, score them, and publish with the full run record. Until this exists, every
public claim rests on one case study.
**Done when:** `evals/results/` contains a `MEASURED` record with `sechelix_commit`, `agent_host`,
`model`, `execution_mode`, `tools`, and `limitations` populated.

### 2. Get a second and third case study, at least one on a public repository
The current case study is a private target, so it cannot become a Trophy Case entry. A public
repository with a public fix reference converts the strongest asset — a refuted high-severity
candidate — into something a stranger can verify.
**Done when:** `TROPHY_CASE.md` has its first legitimate entry.

### 3. Cross-model verifier disagreement measurement
The central architectural claim is that an independent verifier catches what a single model
asserts. Nothing measures that yet. Run the same candidate set through two different
model/provider pairs and record the disagreement rate.
**Done when:** a published number for verifier disagreement exists, however small the sample.

### 4. Expand fixture realism beyond single files
Every fixture is one file. Real vulnerabilities span modules, and single-file cases systematically
favour models with narrow context. Add multi-file cases where the vulnerable path crosses a
boundary, and broaden language coverage past Python.
**Done when:** at least five multi-file cases exist across at least three languages.

### 5. Make the gate's contract enforcement unavoidable in CI
`security_gate.py` now fails closed on contract-invalid reports, and `validate_gold_packs.py` is in
CI. Still missing: a CI step that detects `skills/sechelix/` drift from root — a stale portable
bundle currently passes CI, and `adapters/tests/` still never runs in CI.
**Done when:** CI fails on bundle drift and runs the adapter tests.

### 6. Resolve the `UNASSESSED` / `UNASSIGNED` vocabulary split
Adapters and agent profiles emit `UNASSESSED`; `finding-v1` requires `UNASSIGNED`. Both mean "no
severity yet" at different pipeline stages. Two spellings for one concept in a product whose brand
is precise vocabulary is a small wound that a careful reviewer will find.
**Done when:** one spelling is canonical and the other is documented as a stage alias or removed.

### 7. Confirm or remove the `owasp-llm-top-10` registry entry
It was added so the AI knowledge cluster had a legal provenance anchor, with conservative flags,
but nobody has reviewed those terms. Either confirm the rights posture or remove the entry and the
edges that depend on it.
**Done when:** the entry carries a reviewed license status.

### 8. Ship evidence-bundle signing, or stop describing it
`docs/signed-evidence-bundles.md` describes a design that does not exist. For enterprise
conversations this is exactly the kind of document that reads as a shipped feature. Either
implement detached signatures over the canonical report, or relabel the document as a proposal.
**Done when:** the doc's status is unambiguous in its first paragraph.

### 9. Measure Core Web Vitals on the deployed domain
The site is static and dependency-light but LCP, INP and CLS have never been measured on
`sechelix.com`. Also add per-route Open Graph images and `BreadcrumbList` structured data to docs.
**Done when:** a recorded measurement exists for the three vitals on at least home, docs, workbench.

### 10. Publish the launch drafts after human review
Drafts exist in `docs/launch/` and are marked as requiring review. They should not go out before
task 1 lands, because the launch story is *"we refuse to publish numbers we cannot reproduce"* and
that reads very differently once a reproducible number exists alongside it.
**Done when:** at least one channel is published with the case study and a measured result.

---

## Deliberately not next

- **A hosted control plane.** `COMMERCIAL.md` is explicit that pricing should not appear before
  measurable evals and design partners. Building infrastructure now inverts that order.
- **More catalog hypotheses.** 546 is already far more than has been validated. Depth on the five
  gold packs beats breadth.
- **Comparison benchmarks against other tools.** The comparison policy in `docs/EVALUATION.md`
  requires identical targets, ground truth, metric definitions and recorded configs. Nothing close
  to that exists yet.
- **More website surface.** The site now has more pages than the product has measured claims. The
  ratio should move the other way next.

---

## The one-sentence version

Get one honest number from someone who did not write the test, then tell the story that is already
true: SecHelix refuted a high-severity finding that a scanner would have shipped.
