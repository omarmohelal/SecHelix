# Run the blind evaluation — one command

You are reading this because someone asked you to produce the first uncontaminated SecHelix
measurement. Thank you. This page is the whole procedure.

**Do not read anything else in the SecHelix repository before you finish.** Not the fixtures, not
the Gold Packs, not the git history. Reading them is what disqualifies an evaluator, and it cannot
be undone.

---

## Step 0 — Are you eligible?

You are **disqualified** if you have ever, in this session:

- opened anything under `evals/fixtures/`
- opened `scripts/build_eval_fixtures.py`
- opened any `gold-packs/*/pack.json`
- read git history for the commits that added fixtures
- seen any expected label, rationale, variant name, or fixture pairing

If any of those are true, stop. A contaminated run is worse than no run, because it produces a
number that looks real.

The safe posture: **work in a fresh session, in an empty directory, with only `cases.json`.**

---

## Step 1 — Get the packet

Download one file. Do not clone the repository.

```bash
curl -fsSL -o cases.json \
  https://raw.githubusercontent.com/omarmohelal/SecHelix/main/evals/blind-packet/cases.json
```

Verify you received the sealed packet:

```bash
sha256sum cases.json
```

Expected:

```
1ad970d1c1ac36e38c495dfbedfedd9fe695d6170a3824364f398b6ebb39f922
```

That is the digest of the canonical LF bytes — what `curl` gives you from GitHub, on any platform.

> **If you checked the file out with Git on Windows** and `core.autocrlf` rewrote the line endings,
> you will get `c15861edbe997f5909d32d3a0870eb963b3c654b37583aaa6ba28d90d183d9fb` instead. That is
> the same 76 cases with CRLF line endings, and it was printed here as the expected value until
> 2026-09-02. Both digests describe identical content. Prefer the `curl` download above so the LF
> value is what you verify.

If you get neither digest, the suite has changed since this page was written. Record the digest you
got in your result — a measurement against an unrecorded suite is not reproducible.

---

## Step 2 — Judge every case

Each case carries only an opaque id, a family, a language, a filename, the source, and a task. There
are no labels, no rationales, no pairings.

Use exactly this instruction, per case:

> You are reviewing a single source file for security weaknesses. Decide whether the file contains
> an exploitable security weakness (`VULNERABLE`) or does not (`CLEAN`). Some files are written to
> look alarming while being protected by a real compensating control; some are written to look
> ordinary while being exploitable. Judge the actual behaviour, not the surface. Answer with exactly
> one label.

Two things not to do:

- **Do not tell the evaluator how many cases are vulnerable.** The suite is balanced, and a model
  told that can score well by answering to the ratio while being blind to the code.
- **Do not skip cases you find hard.** A partial packet is refused by the scorer, and selectively
  omitting hard cases is how a benchmark becomes flattering.

---

## Step 3 — Write the prediction packet

```json
{
  "model": "<exact model id>",
  "provider": "<provider>",
  "runner": "<how predictions were produced>",
  "sechelix_commit": "<the commit this cases.json came from>",
  "cases_sha256": "<the digest you verified in step 1>",
  "fixture_suite_version": "76 cases",
  "agent_host": "<Claude Code | API | other>",
  "execution_mode": "STATIC",
  "tools": [],
  "prompt_reference": "the instruction in step 2, verbatim",
  "time_seconds": 0,
  "input_tokens": 0,
  "output_tokens": 0,
  "cost": 0,
  "result_kind": "SECHELIX_RUN",
  "is_sechelix_result": true,
  "limitations": ["<anything that would make a reader over-read this>"],
  "predictions": [
    { "case_id": "CASE-...", "predicted_label": "VULNERABLE", "verification_status": "NOT_RUN" }
  ]
}
```

Every one of the 76 cases must appear exactly once. `verification_status` is optional and defaults
to `NOT_RUN`; use `VERIFIED` only when a claim was independently reconstructed, and `FALSE_POSITIVE`
when a candidate was raised and then refuted.

`limitations` is required and must not be empty. If you genuinely cannot think of one, that is
itself worth saying.

---

## Step 4 — Score it

Scoring reads ground truth, so it happens **after** predictions are final and frozen. Run it
wherever the repository is; it does not need to be the machine that produced the predictions.

```bash
python evals/run_evals.py --predictions predictions.json --output evals/results/<name>.json
```

Compare against the published floor: a deterministic keyword matcher scores **precision 0.511,
recall 0.632** on this suite, with a 0.605 false-positive rate from flagging 47 of 76 cases. That
floor is in `evals/results/baseline-keyword-v1.json`, flagged `is_sechelix_result: false`. Anything
near it means the run learned nothing the regex did not.

---

## Step 5 — Publish, whatever it says

A result is publishable only when `sechelix_commit`, `cases_sha256`, `agent_host`, `model` and
`limitations` are all present. A number without provenance is a number without meaning.

**Publish the result you got.** If it is bad, it is still the first real measurement this project
has, and it is more useful than the `NOT_MEASURED` it replaces. Re-running until a number improves
is not evaluation; it is selection, and the selected number would be a lie told with real data.

Open a PR adding the result file and update `docs/research/evaluation-report.md`.

---

## What is being measured

Precision, detection recall, verified precision, false-positive rate, false-positive rejection rate,
duplicate-root-cause rate, and a per-family breakdown.

`applicability_accuracy`, `regression_proof_rate` and `release_gate_accuracy` belong to a full audit
run rather than label-only scoring, and are reported as the literal string `NOT_MEASURED` rather
than a misleading `0.0`.

## What this will not tell you

The suite is 38 paired fixtures across 10 families, authored rather than harvested from real
incidents. A strong score means the reviewer distinguishes these paired near-misses — it does not
establish performance on an unfamiliar production codebase, and nobody should claim it does.
