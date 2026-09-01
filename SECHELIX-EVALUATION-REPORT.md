# SecHelix evaluation report

**Date:** 2026-09-01 · **Benchmark status: `NOT_MEASURED`**

This report explains what the evaluation lab now contains, what it measured, and — most
importantly — why no SecHelix performance score is published.

---

## 1. Headline

**There is no SecHelix benchmark number, and publishing one would have been dishonest.**

The fixture suite was expanded on 2026-09-01 by the same assistant session that would otherwise
have been the evaluated model. That session authored 11 of the 19 fixtures. Scoring it would have
measured **recall of its own answers**, not security-review capability.

The blocker is recorded machine-readably in `evals/results/not-measured.json`:

```json
"blocker": {
  "reason": "CONTAMINATED_EVALUATOR",
  "statement": "No uncontaminated SecHelix run exists yet...",
  "what_would_unblock_it": [ ... ],
  "harness_status": "VALIDATED — see evals/results/baseline-keyword-v1.json"
}
```

---

## 2. What *was* measured: the harness

A deterministic keyword baseline (`evals/baselines/keyword_baseline.py`) — no model, no network,
pure regex — was run end to end through the real scoring pipeline. It serves two purposes: it
proves the harness computes metrics correctly, and it measures how far naive pattern matching gets
on the suite.

| Metric | Value |
| --- | --- |
| Precision | **0.500** |
| Detection recall | **0.526** |
| False-positive rate | **0.526** |
| False-positive rejection rate | **0.474** |
| Counts | TP 10 · FP 10 · TN 9 · FN 9 |

On a balanced 19/19 split this is **chance**. That is the desired result: it is evidence that the
fixtures cannot be solved by pattern matching, which the evaluation protocol explicitly requires
("non-trivial enough that a keyword match alone cannot solve it").

The result is committed as `evals/results/baseline-keyword-v1.json` with
`"result_kind": "HARNESS_BASELINE"` and `"is_sechelix_result": false`. A test asserts those fields
so it can never be quietly promoted into a capability claim. A second test asserts the baseline
stays below 0.75 precision — if a future fixture change made the suite keyword-solvable, CI fails.

---

## 3. The fixture suite

| | Before | After |
| --- | --- | --- |
| Fixtures | 8 | **19** |
| Paired cases | 16 | **38** |
| Families | 8 | **10** |
| Typical case size | 6–13 lines | **38–66 lines** |

All ten families the protocol requires for a first public benchmark are covered: authorization
(BOLA/tenant isolation and BFLA), authentication/sessions, SQL/ORM injection, XSS/browser boundary,
SSRF, files/path traversal, business logic/payment invariants, race/idempotency/replay,
secrets/supply-chain integrity, and AI/Agent/MCP tool authority.

The new cases are written as realistic modules — repositories, routes, state machines, agent loops
— where the vulnerable and clean variants differ by a genuine reasoning step rather than a keyword.
Examples:

- **`EVAL-AUTHZ-002`** — the list path is correctly tenant-scoped; the export path re-fetches by
  primary key through a second repository call with no tenant predicate. The correct check creates
  a false impression of safety.
- **`EVAL-SSRF-002`** — the destination is validated, then redirects are followed automatically and
  the redirect target is never revalidated (TOCTOU).
- **`EVAL-INJ-002`** — every value is parameterized; the sort column reaches `ORDER BY` through a
  helper that only strips whitespace.
- **`EVAL-RACE-002`** — a single-use voucher with a check-then-act window that a conditional update
  closes.
- **`EVAL-AI-002`** — retrieved document text is concatenated into the instruction context and the
  dispatcher honours any tool the model names.

Regenerate with `python scripts/build_eval_fixtures.py`.

---

## 4. Harness changes

`evals/run_evals.py` now:

- **Exports genuinely blind cases.** Opaque `CASE-<digest>` identifiers; no `variant`, no
  `fixture_id`, no `rationale`, no `expected`. Deterministic ordering that does not group pairs.
- **Accepts either identifier form**, so previously produced packets still score.
- **Computes the protocol metrics**: precision, detection recall, verified precision,
  false-positive rate, false-positive rejection rate, duplicate-root-cause rate, plus a
  **per-family breakdown**.
- **Refuses to fake the rest.** `applicability_accuracy`, `regression_proof_rate` and
  `release_gate_accuracy` belong to a full audit run, not to label-only fixture scoring. They are
  emitted as the literal string `NOT_MEASURED` rather than a misleading `0.0`.
- **Records the run**: SecHelix commit, fixture suite version, agent host, execution mode, tools,
  prompt reference, timing, tokens, cost, and declared limitations.

---

## 5. How to produce the first legitimate measurement

```bash
# 1. Export blind cases (no ground truth leaves this step)
python evals/run_evals.py --export-cases work/blind-cases.json

# 2. Produce predictions with a model or session that did NOT author the fixtures
#    and does NOT have access to evals/fixtures/. One row per case:
#    {"case_id": "...", "predicted_label": "VULNERABLE|CLEAN",
#     "verification_status": "VERIFIED|FALSE_POSITIVE|NOT_RUN"}

# 3. Score deterministically
python evals/run_evals.py --predictions work/predictions.json --output work/result.json
```

For the result to be publishable, the prediction packet must carry `model`, `provider`,
`sechelix_commit`, `fixture_suite_version`, `agent_host`, `execution_mode`, `tools`,
`prompt_reference`, and `limitations`. A run missing those fields is a number without provenance
and must not be published.

---

## 6. Known limitations of the suite itself

- **Synthetic.** These are authored fixtures, not real repositories. A model can be good at them
  and weak on production code.
- **Single-file per case.** Real vulnerabilities often span modules; these do not.
- **Python-heavy**, with one JavaScript case. Language coverage is narrow.
- **Balanced 19/19 split** does not reflect real base rates, where clean code vastly outnumbers
  vulnerable code. Precision on this suite will overstate precision in the field.
- **Author bias.** The fixtures encode one team's idea of what is hard.

The real-repository track (`docs/case-studies/`) exists precisely because synthetic scores are not
a substitute for audits of real systems, and the protocol keeps the two separate.
