# SecHelix evaluation report

**Date:** 2026-09-02 · **Blind label suite: first uncontaminated run recorded** ·
**Full-workflow metrics: still `NOT_MEASURED`**

This report explains what the evaluation lab contains, what has now been measured, and — just as
importantly — what still has not been.

---

## 1. Headline

**The blind packet has its first uncontaminated run.** It was produced on 2026-09-02 and is
committed as [`evals/results/claude-sonnet-5-blind-2026-09-02.json`](../../evals/results/claude-sonnet-5-blind-2026-09-02.json).

| Metric | This run | Keyword floor |
| --- | --- | --- |
| Precision | **0.950** | 0.511 |
| Detection recall | **1.000** | 0.632 |
| False-positive rate | **0.053** | 0.605 |
| False-positive rejection rate | **0.947** | 0.395 |
| Counts | TP 38 · FP 2 · TN 36 · FN 0 | TP 24 · FP 23 · TN 15 · FN 14 |

The two false positives are one Business Logic / Payments case and one SSRF / URL Fetching case.
Every other family scored zero false positives, and no vulnerable case was missed.

**Read that table narrowly.** Four things it does not say:

1. **It is not a measurement of the SecHelix workflow.** The protocol in
   [`evals/blind-packet/RUN.md`](../../evals/blind-packet/RUN.md) asks the evaluator one question per
   file and takes one label back. There was no attack-surface pass, no independent refutation pass,
   no adapters, no evidence chain and no release gate. `verified_precision` is `0.0` precisely
   because nothing was independently verified — the procedure never asked for it.
2. **`applicability_accuracy`, `regression_proof_rate` and `release_gate_accuracy` remain the
   literal string `NOT_MEASURED`.** Those belong to a full audit run. `evals/results/not-measured.json`
   still stands for them.
3. **The suite is authored, balanced 38/38, mostly single-file and mostly Python.** Section 6 lists
   what that costs. Precision on a balanced synthetic suite overstates precision in the field, where
   clean code vastly outnumbers vulnerable code.
4. **One model, one run.** No repeats, no variance estimate, no comparison to any other tool.

### How contamination was avoided

The run was produced by 76 independent headless `claude -p` processes, each launched from an empty
directory containing only `cases.json`. The repository was never cloned. Tools were disabled, MCP was
disabled, and each process saw exactly one case plus the Step 2 instruction. No process saw a label,
a rationale, a pairing, a variant name, or how many cases were vulnerable.

Two honest caveats are recorded in the result file's `limitations`, not hidden here: the host machine
had a user-scope `sechelix` skill installed, so its name and description could appear in each
process's skill list (methodology only — no fixtures, no labels, and tools were disabled so it could
not be invoked); and the processes loaded user-level Claude Code configuration because no API key was
available to run with `--bare`.

### A defect this run found in the protocol itself

`RUN.md` published the expected packet digest as `c15861ed…`. That value was computed on a **Windows
working copy with CRLF line endings**. Anyone following the documented `curl` download — on any
platform — gets `1ad970d1…` instead and would conclude the suite had changed. The content is
byte-identical apart from 613 carriage returns. `RUN.md` and the packet README now publish the
canonical LF digest and explain the CRLF value, so the sealed-packet check verifies for the people
it was written for.

---

## 2. What *was* measured: the harness

A deterministic keyword baseline (`evals/baselines/keyword_baseline.py`) — no model, no network,
pure regex — was run end to end through the real scoring pipeline. It serves two purposes: it
proves the harness computes metrics correctly, and it measures how far naive pattern matching gets
on the suite.

| Metric | Value |
| --- | --- |
| Precision | **0.511** |
| Detection recall | **0.632** |
| False-positive rate | **0.605** |
| False-positive rejection rate | **0.395** |
| Counts | TP 24 · FP 23 · TN 15 · FN 14 |

On a balanced 38/38 split this is **chance**. That is the desired result: it is evidence that the
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

## 5. How to reproduce, or produce another run

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
- **Balanced 38/38 split** does not reflect real base rates, where clean code vastly outnumbers
  vulnerable code. Precision on this suite will overstate precision in the field.
- **Author bias.** The fixtures encode one team's idea of what is hard.

The real-repository track (`docs/case-studies/`) exists precisely because synthetic scores are not
a substitute for audits of real systems, and the protocol keeps the two separate.
