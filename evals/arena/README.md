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

## 3.1 Build SecHelix operational run telemetry

For a SecHelix participant, convert the completed `RunResult.to_dict()`
artifact into Arena-compatible run metadata instead of manually adding cost,
token and verifier/gate fields:

```bash
python evals/arena_run.py \
  --run work/arena-run.json \
  --agent-host isolated-eval-host \
  --output work/arena-run.json
```

The helper records wall-clock elapsed time, per-status node counts, provider and
model sets, aggregate tokens/cost when those measurements are complete, and the
actual `INDEPENDENT_VERIFIER` / `RELEASE_GATE` node records. It also reports
per-role node-active time, tokens, cost, provider/model sets and completeness,
plus a node-time-to-wall ratio that makes parallel/serial execution shape
visible without pretending it is a critical-path measurement. Missing telemetry
is `NOT_MEASURED`, never zero. Nodes that were blocked or skipped without
provider execution do not create fake token/cost gaps; missing terminal-node
duration prevents a complete active-time aggregate rather than being treated as
zero.

It also binds the generated metadata to the source run artifact with SHA-256.
This is operational telemetry only: it does not score whether the verifier or
gate was *correct*. That remains the job of the independent Arena assessment.

## 3.2 Bind the persisted SecHelix workspace

For an actual SecHelix run, the evaluator can also bind the persisted run
workspace before scoring verifier/gate behavior:

```bash
python evals/arena_workspace.py \
  --root . \
  --run-id RUN-EXAMPLE \
  --output work/arena-workspace-evidence.json
```

The helper first verifies the workspace `manifest.json`. Any changed, missing,
or unmanifested file is a hard failure. It then emits SHA-256 identities for
`run.json`, `graph.json`, `replay/outcomes.json`, and `manifest.json`, plus
digest-only summaries for independent-verifier, release-gate, remediator and
patch-verifier nodes.

Node output bodies are not copied into the index. The evaluator still opens the
original redacted workspace artifacts when assessing correctness; the index only
proves exactly which bytes and role outputs the assessment references.

## 3.3 Bind run telemetry to manifest-verified workspace evidence

Before an independent evaluator scores verifier or release-gate correctness,
build one fail-closed measurement bundle that proves the operational run record
and workspace evidence refer to the same SecHelix run:

```bash
python evals/arena_measurement_bundle.py \
  --run work/run.json \
  --workspace-root . \
  --run-id RUN-EXAMPLE \
  --agent-host isolated-eval-host \
  --output work/measurement-bundle.json
```

The helper builds Arena operational telemetry, verifies the persisted workspace
manifest, requires both `INDEPENDENT_VERIFIER` and `RELEASE_GATE` evidence,
and refuses mismatched run ID, target commit, scope, or graph digest. The output
contains only operational telemetry, artifact digests and digest-only role
evidence targets.

`READY_FOR_INDEPENDENT_ASSESSMENT` is not a security score. The bundle
explicitly leaves correctness unscored; an independent evaluator must still
produce the evidence-backed assessment described below.

## 3.4 Build a complete manifest-verified batch handoff

When each blind case has its own SecHelix run workspace, bind the full prepared
packet before an evaluator starts scoring:

```bash
python evals/arena_batch.py \
  --manifest work/arena-prepared.json \
  --run-map work/run-map.json \
  --base-dir work \
  --output work/arena-batch-handoff.json
```

The batch handoff requires every prepared CASE- identifier exactly once and
requires each case workspace to pass manifest verification plus measurement
bundle validation. It still contains no workflow correctness score.

## 3.5 Bind independent judgments to the verified batch

After predictions are frozen and the independent evaluator has made explicit
workflow judgments, bind those judgments to the exact manifest-verified bytes
for each case:

```bash
python evals/arena_batch_assessor.py \
  --handoff work/arena-batch-handoff.json \
  --spec work/assessment-spec.json \
  --base-dir work \
  --output work/assessment.json
```

Each scored judgment must cite an `artifact_ref` that already exists in that
case's measurement-bundle `workspace_artifacts` map plus a relative local path
to the same file. The builder re-hashes the file and rejects digest drift,
unmanifested artifacts, path escapes, duplicate/missing cases, or a spec bound to
another handoff/packet.

The resulting assessment is compatible with Arena finalization. This step does
**not** decide correctness or establish evaluator independence; it only proves
which verified run bytes each assessor-supplied judgment cites.

## 4. Independent workflow assessment

An evaluator that did not produce the predictions records applicable observations with these fields:

- `applicability`: boolean or `NOT_APPLICABLE`
- `verification`: boolean or `NOT_APPLICABLE`
- `false_positive_refutation`: boolean or `NOT_APPLICABLE`
- `root_cause`: boolean or `NOT_APPLICABLE`
- `regression_proof`: boolean or `NOT_APPLICABLE`
- `release_gate`: boolean or `NOT_APPLICABLE`

A boolean means whether that workflow decision matched the independently established expected result. Every boolean must also carry an `evidence.<metric>` record with a short basis, one or more stable artifact references, and a SHA-256 digest binding the cited evidence bundle. `NOT_APPLICABLE` is excluded from the denominator and does not require invented evidence.

### Build an evidence-backed assessment packet

`evals/arena_packets.py` helps an independent evaluator bind each explicit
judgment to local run artifacts without copying artifact contents or local paths
into the assessment JSON.

The packet spec still contains the evaluator's own boolean/NOT_APPLICABLE
judgments and human-readable basis. The helper does **not** infer correctness,
establish independence, or reveal blind truth. For each scored judgment it hashes
the referenced files inside a caller-chosen base directory, emits only stable
refs plus one canonical bundle digest, and rejects missing files, duplicate refs,
and path escapes.

```bash
python evals/arena_packets.py \
  --spec work/assessment-spec.json \
  --base-dir work/run-artifacts \
  --output work/assessment.json
```

The resulting `assessment.json` is passed to `arena.py finalize` below.

## 5. Finalize

```bash
python evals/arena.py finalize \
  --manifest work/arena-prepared.json \
  --run work/run.json \
  --blindness work/blindness.json \
  --assessment work/assessment.json \
  --output work/arena-result.json
```

The result stays **NOT_MEASURED** unless all required run metadata exists, the evaluator is independently identified, contamination is explicitly `UNCONTAMINATED`, truth was sealed until after predictions, prediction and truth digests are present, every scored workflow judgment is evidence-backed, and every full-workflow metric has at least one applicable assessed observation.

## Comparison rule

`arena.comparable(left, right)` only permits an apples-to-apples comparison when both records are `MEASURED`, use the same blind packet, have the same participant category, and declare the same capability scope.

This intentionally prevents a narrow scanner from winning by skipping work and prevents a broad workflow from being penalized for capabilities another participant never attempted.
