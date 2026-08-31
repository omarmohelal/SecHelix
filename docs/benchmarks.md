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

## Planned benchmark packs

- multi-tenant authorization;
- refunds/payouts/inventory;
- webhook/exact-once races;
- SSRF and URL-fetch boundaries;
- stored/second-order injection;
- session and step-up auth;
- Agent/MCP/tool authorization;
- supply-chain and CI;
- browser/server bundle boundaries.
