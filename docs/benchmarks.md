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

**NOT_MEASURED.** No model, provider, or scanner result is published yet. The
machine-readable placeholder is `evals/results/not-measured.json`; every metric
remains the literal string `NOT_MEASURED` rather than a fabricated number or a
misleading zero.

Run instructions and the result schema are documented in `evals/README.md`.
