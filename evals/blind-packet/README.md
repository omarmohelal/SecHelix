# Blind evaluation packet

This directory contains everything needed to produce **the first uncontaminated SecHelix
measurement**. Benchmark status is `NOT_MEASURED` and stays that way until a run completes under
these conditions.

- `cases.json` — 76 blind cases. SHA-256 `c15861edbe997f5909d32d3a0870eb963b3c654b37583aaa6ba28d90d183d9fb`
- Ground truth is **not** in this directory. It lives in `evals/fixtures/` and is only read at
  scoring time.

---

## Why this exists

The fixture suite was authored by assistant sessions working on this repository. Those sessions
know the answers. Scoring one of them would measure recall of authored content, not
security-review capability, so the result would be worthless — and publishing it would be exactly
the benchmark theater this project refuses.

The blocker is recorded machine-readably in `evals/results/not-measured.json` as
`CONTAMINATED_EVALUATOR`.

## Who is disqualified

An evaluator is disqualified if it has:

- authored or edited any file under `evals/fixtures/`;
- read `evals/fixtures/`, `scripts/build_eval_fixtures.py`, or any fixture `rationale`;
- read `gold-packs/*/pack.json` (packs name their fixtures and describe the bug class);
- read this repository's git history for the commits that added fixtures.

In practice: **run this in a fresh session, on a machine or working directory that does not
contain this repository.** Copy out `cases.json` alone.

## What the evaluator sees

Each case carries only:

```json
{
  "case_id": "CASE-017BEFFEE21C2E76",
  "family": "Authorization / BOLA / BFLA",
  "language": "python",
  "filename": "reports_service.py",
  "source": "...",
  "task": "Decide whether a caller can read or export objects owned by another tenant."
}
```

No variant name, no fixture id, no rationale, no difficulty, no pairing. Case ids are opaque
digests, and the file is ordered by digest so vulnerable and clean cases are not adjacent.

Note: the suite is **balanced 38 / 38**. An evaluator that knows this could game the score by
answering to the ratio, so a run that appears calibrated to exactly 50% should be treated with
suspicion, and the prompt below deliberately does not mention the balance.

## Procedure

**1. Export a fresh packet** (or use the committed `cases.json`):

```bash
python evals/run_evals.py --export-cases work/blind-cases.json
```

**2. In an isolated session with no access to this repository**, present each case and record a
prediction. Suggested instruction to the evaluator, verbatim:

> You are reviewing a single source file for security weaknesses. Decide whether the file
> contains an exploitable security weakness (`VULNERABLE`) or does not (`CLEAN`). Some files are
> written to look alarming while being protected by a real compensating control; some are written
> to look ordinary while being exploitable. Judge the actual behaviour, not the surface. Answer
> with exactly one label.

Do not reveal the family counts, the balance, or that cases are paired.

**3. Write a prediction packet:**

```json
{
  "model": "<model id>",
  "provider": "<provider>",
  "runner": "<how predictions were produced>",
  "sechelix_commit": "<git rev-parse HEAD of the repo the packet came from>",
  "fixture_suite_version": "38 fixtures / 76 cases",
  "agent_host": "<Claude Code | API | other>",
  "execution_mode": "STATIC",
  "tools": ["<any scanner used, or none>"],
  "prompt_reference": "<the exact prompt text or a path to it>",
  "time_seconds": 0,
  "input_tokens": 0,
  "output_tokens": 0,
  "cost": 0,
  "limitations": ["<anything that would make a reader over-read this result>"],
  "predictions": [
    {
      "case_id": "CASE-017BEFFEE21C2E76",
      "predicted_label": "VULNERABLE",
      "verification_status": "VERIFIED",
      "scanner_sources": []
    }
  ]
}
```

`predicted_label` must be `VULNERABLE` or `CLEAN`. `verification_status` is optional and defaults
to `NOT_RUN`; use `VERIFIED` only when the claim was independently reconstructed, and
`FALSE_POSITIVE` when a candidate was raised and then refuted. Every one of the 76 cases must
appear exactly once — the runner refuses a partial packet.

**4. Score** (back in this repository):

```bash
python evals/run_evals.py --predictions work/predictions.json --output evals/results/<name>.json
```

**5. Publish** only if the run record is complete. A number without `sechelix_commit`,
`agent_host`, `model` and `limitations` is a number without provenance and must not be published.

## What gets measured

Precision, detection recall, verified precision, false-positive rate, false-positive rejection
rate, duplicate-root-cause rate, and a per-family breakdown.

`applicability_accuracy`, `regression_proof_rate` and `release_gate_accuracy` belong to a full
audit run rather than label-only scoring, and are reported as the literal string `NOT_MEASURED`
rather than a misleading `0.0`.

## Reference point

`evals/results/baseline-keyword-v1.json` is a deterministic regex matcher — no model, no network —
scored through the same pipeline. It lands at chance on precision (0.511) while its recall (0.632) is bought by flagging 47 of 76 cases — a 0.61 false-positive rate. It exists to validate the
harness and to evidence that the suite resists pattern matching. It is labelled
`result_kind: HARNESS_BASELINE` with `is_sechelix_result: false` and must never be cited as
SecHelix performance.

Any real result should be compared against that floor, not against nothing.
