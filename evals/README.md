# SecHelix evaluation lab

This lab contains synthetic, non-destructive, paired vulnerable and clean
controls. It measures whether a review pipeline finds important defects while
rejecting clean siblings. No model or scanner is called by the repository.

Current published results: the blind label suite is **MEASURED** —
`results/claude-sonnet-5-blind-2026-09-02.json`, the first uncontaminated run.
The **full workflow remains NOT_MEASURED**: `applicability_accuracy`,
`regression_proof_rate` and `release_gate_accuracy` are label-only scoring's
blind spot and keep the literal string, recorded in `results/not-measured.json`.

## Safe workflow

1. Export blind cases without expected labels:

   ```bash
   python evals/run_evals.py --export-cases work/blind-cases.json
   ```

2. Review those cases with an authorized model/scanner pipeline.
3. Supply one prediction for every case using `case_id`, `predicted_label`
   (`VULNERABLE` or `CLEAN`), optional `verification_status`, and optional
   `scanner_sources`.
4. Score only after predictions are fixed:

   ```bash
   python evals/run_evals.py --predictions work/predictions.json --output work/result.json
   ```

The runner reports precision, recall, verified precision, false-positive rate,
duplicate-root-cause rate, time, token cost, model/provider identity, and
scanner contribution when supplied. Missing operational measurements remain
`NOT_MEASURED`; they are never converted to zero.

## Full-workflow Arena

`arena.py` adds a separate fail-closed protocol for the parts of an AppSec
workflow that vulnerable/clean labels cannot measure: applicability decisions,
independent verification, false-positive refutation, root-cause attribution,
regression proof, and release-gate decisions.

Arena does **not** run competitors and does not declare a winner across unlike
capability scopes. It records exact participant versions, the blind packet
digest, run metadata, contamination state, an independent assessment digest,
and explicit publication blockers. A result remains `NOT_MEASURED` until the
complete blind packet has been assessed exactly once and the blindness and
independence conditions are satisfied.

See [`arena/README.md`](arena/README.md) and start from
[`arena/participants.example.json`](arena/participants.example.json).

Fixtures are synthetic source fragments for static reasoning. Do not deploy
them, attach live credentials, or point them at external targets.
