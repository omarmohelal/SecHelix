# SecHelix Arena

Arena is a **measurement protocol**, not a marketing leaderboard. It exists to compare full AppSec workflows without turning missing evidence, contaminated evaluators, different capability scopes, or unpinned tool versions into a score.

`evals/run_evals.py` remains the scorer for blind vulnerable/clean labels. `evals/arena.py` covers the workflow properties that label-only scoring cannot establish: applicability, verification, false-positive refutation, root-cause attribution, regression proof, and release-gate decisions.

## What Arena does not do

Arena does not install, execute, sandbox, or grant network access to SecHelix or any competitor. External tools are untrusted software and must be reviewed and run by an authorized operator in an isolated environment. Arena only records the resulting evidence and run metadata.

It also does not declare an overall winner when two tools have different categories or capability scopes. A SAST engine and a multi-agent remediation workflow can both be useful, but collapsing them into one rank would be misleading.

## 1. Pin a participant

Copy one entry from `participants.example.json` into a separate participant file. Replace `PIN_REQUIRED` with the exact tested version or commit. For external tools, replace the placeholder capability scope with capabilities actually established for that pinned version.

## 2. Prepare against the blind packet

```bash
python evals/arena.py prepare \
  --packet evals/blind-packet/cases.json \
  --participant work/participant.json \
  --output work/arena-prepared.json
```

The prepared record contains only opaque case identity/digests and **NOT_MEASURED** fields. It is not a result.

## 3. Run the participant outside Arena

Freeze predictions before revealing truth. Record exact tool version/commit, host, model/provider where applicable, start/end time, tokens/cost when available, and the prediction packet digest.

Do not let the evaluated session read `evals/fixtures/`, the fixture builder, Gold Pack answers, or any ground-truth material before predictions are fixed.

## 4. Independent workflow assessment

An evaluator that did not produce the predictions records applicable observations with these fields:

- `applicability`: boolean or `NOT_APPLICABLE`
- `verification`: boolean or `NOT_APPLICABLE`
- `false_positive_refutation`: boolean or `NOT_APPLICABLE`
- `root_cause`: boolean or `NOT_APPLICABLE`
- `regression_proof`: boolean or `NOT_APPLICABLE`
- `release_gate`: boolean or `NOT_APPLICABLE`

A boolean means whether that workflow decision matched the independently established expected result. `NOT_APPLICABLE` is excluded from the denominator; it is never converted to success.

## 5. Finalize

```bash
python evals/arena.py finalize \
  --manifest work/arena-prepared.json \
  --run work/run.json \
  --blindness work/blindness.json \
  --assessment work/assessment.json \
  --output work/arena-result.json
```

The result stays **NOT_MEASURED** unless all required run metadata exists, the evaluator is independently identified, contamination is explicitly `UNCONTAMINATED`, truth was sealed until after predictions, prediction and truth digests are present, and every full-workflow metric has at least one applicable assessed observation.

## Comparison rule

`arena.comparable(left, right)` only permits an apples-to-apples comparison when both records are `MEASURED`, use the same blind packet, have the same participant category, and declare the same capability scope.

This intentionally prevents a narrow scanner from winning by skipping work and prevents a broad workflow from being penalized for capabilities another participant never attempted.
