# SecHelix Benchmarks

SecHelix should earn trust with evals, not marketing claims.

## What to measure

- verified-vulnerability recall on intentionally vulnerable fixtures;
- false-positive rejection on clean sibling fixtures;
- authorization/BOLA/BFLA coverage;
- business-logic and state-machine findings;
- race/idempotency findings;
- time-to-evidence;
- tokens/cost by review lane;
- verifier disagreement rate;
- scanner/model contribution by source;
- regression-proof completion rate.

## Rules

1. Use paired vulnerable + clean fixtures where practical.
2. Do not count a model's unsupported suspicion as a true positive.
3. Keep the verifier blind to the expected answer where possible.
4. Publish fixture provenance and scoring rules.
5. Separate static detection from runtime proof.
6. Record blocked checks instead of treating them as passes.

## Included benchmark packs

- authorization/BOLA/BFLA;
- business logic;
- race/idempotency;
- SSRF and URL-fetch boundaries;
- stored/second-order injection;
- file parsing;
- Agent/MCP/tool authorization;
- supply chain.

Each pack has a synthetic vulnerable case and a clean sibling under `evals/fixtures/`.
The repository runner exports cases without expected labels and scores a complete
external prediction packet only after review.

## Current results

Two layers, measured separately.

**Blind label suite — MEASURED.** The first uncontaminated run is
`evals/results/claude-sonnet-5-blind-2026-09-02.json`: precision 0.950, detection
recall 1.000, false-positive rate 0.053, false-positive rejection rate 0.947,
counts TP 38 · FP 2 · TN 36 · FN 0. It is a label-only run — one question per
file, one label back — and is not a measurement of the complete SecHelix
workflow.

**Full workflow — NOT_MEASURED.** `applicability_accuracy`,
`regression_proof_rate` and `release_gate_accuracy` remain the literal string
`NOT_MEASURED` rather than a fabricated number or a misleading zero;
`verified_precision` is `0.0` only because `verification_status` was `NOT_RUN`
for every case. The machine-readable placeholder for these is
`evals/results/not-measured.json`.

The keyword matcher in `evals/results/baseline-keyword-v1.json` stays separate:
`result_kind: HARNESS_BASELINE`, `is_sechelix_result: false`.

Run instructions and the result schema are documented in `evals/README.md`; the
full write-up with every limitation is `docs/research/evaluation-report.md`.
