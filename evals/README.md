# SecHelix evaluation lab

This lab contains synthetic, non-destructive, paired vulnerable and clean
controls. It measures whether a review pipeline finds important defects while
rejecting clean siblings. No model or scanner is called by the repository.

Current published result: **NOT_MEASURED**. The committed result placeholder is
not a benchmark score and must remain `NOT_MEASURED` until a reproducible run is
completed.

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

Fixtures are synthetic source fragments for static reasoning. Do not deploy
them, attach live credentials, or point them at external targets.
