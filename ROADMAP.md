# Roadmap

SecHelix should earn trust through evals before adding complexity.

> **Maturity: public alpha (`3.0.0-alpha.5`).**
> Sections marked *complete* describe shipped repository capability, not measured
> accuracy. The public benchmark is **`NOT_MEASURED`** and the blocker is
> recorded in [`evals/results/not-measured.json`](evals/results/not-measured.json).
> SecHelix does not claim a winning model, provider, or scanner.
> No dates are published for future milestones; a single maintainer sequences
> this work, and inventing a schedule would be its own dishonest claim.

## v2.1 — portable public foundation — complete

- canonical evidence-first skill;
- Claude/OpenAI/Codex/generic adapters;
- 21 × 26 structured hypothesis catalog;
- validation and release gate scripts;
- company rollout docs;
- polished static landing page;
- crypto-ready support page;
- GitHub validation + Pages workflows.

## v2.2 — evidence adapters — complete

- SARIF normalizer;
- Semgrep adapter;
- CodeQL adapter;
- OSV/dependency adapter;
- Trivy adapter;
- Gitleaks-style secret adapter;
- browser evidence schema;
- scanner-source confidence metadata.

## v2.3 — eval lab foundation — complete

- intentionally vulnerable fixtures;
- patched/control fixtures;
- authorization matrix benchmark;
- race/idempotency fixtures;
- business-logic fixtures;
- AI/MCP tool-boundary fixtures;
- false-positive benchmark;
- model-role comparison harness.

## v2.4 — report and CI ecosystem — complete

- stable JSON report schema;
- SARIF export;
- HTML report;
- signed evidence manifest;
- GitHub PR annotations;
- severity/company-policy gates;
- historical comparison.

## v3.0 alpha — contract-first orchestration foundation — current

- fifteen versioned JSON contracts, including community extensions, source trust,
  knowledge graph, lesson cards, live research packets, and Gold Check Packs;
- deterministic four-state applicability;
- explicit 546-ID catalog and frozen manifest;
- 17 specialist roles;
- safe adapter profiles;
- canonical derived reports and policy gates;
- self-contained skills distribution;
- private product-site source separation.
- curated community extension lifecycle with contract, safety, fixture, and maintainer gates.
- rights-aware source registry with executable restrictions for human-only curricula;
- deterministic live-research confidence and a provenance-backed graph/lesson-card seed.
- Gold Check reference packs (one at 3.0.0-alpha.4, five as of 3.0.0-alpha.5)
  and a deterministic Variant Hunter
  classification foundation;
- V2 Pro overview, Evidence Workbench, Attack Surface, Authorization Matrix,
  Variant Analysis, Benchmark Lab, and Command Center product surfaces.

## v3.1 — expert knowledge engine and credibility program — in progress

Status is per item. Nothing here is marked done without an artifact in the
repository.

- **done** — expand CWE ↔ CAPEC ↔ OWASP ↔ ASVS graph coverage from verified
  release mappings (73 nodes, 96 edges, provenance-backed);
- **done** — grow Gold Check Packs from one to five: IDOR, SSRF,
  race/idempotency, money invariants, AI/MCP tool authority;
- **done** — reconcile the report contract with the renderer, gates, and
  examples;
- **done** — make the release gate fail closed on missing required evidence;
- **done** — fix the blind-eval export/score path and record the
  `CONTAMINATED_EVALUATOR` blocker instead of publishing a contaminated score;
- **done** — validate the scoring harness with a keyword baseline that is
  explicitly not a SecHelix result;
- **done** — publish the first real end-to-end case study with artifacts,
  including a refuted candidate;
- **partial** — expand paired vulnerable/clean fixtures (now 33 fixtures /
  66 cases / 10 families; more families and more per-family depth still needed);
- **partial** — add framework, database, cloud, container, supply-chain, and
  AI-security lesson cards (7 cards exist, all CWE-anchored; the
  framework/cloud/container set is not started);
- **not started** — pin and rights-review selected NIST SARD suites and OWASP
  Benchmark repositories;
- **not started** — build reproducible importers that preserve origin,
  revision, license, and attribution;
- **not started** — run an uncontaminated eval and publish the first
  reproducible measurement;
- **not started** — eight cumulative exam levels with de-identified
  mistake-class memory.

The one item that unblocks every benchmark row is the uncontaminated eval run.
Until it exists, benchmark status stays `NOT_MEASURED`.

## v3.x — orchestration platform (optional)

- multi-provider model mesh;
- budget/rate controls;
- hosted/private runners;
- repository integrations;
- organization policy packs;
- evidence dashboard;
- SSO/RBAC;
- private check packs;
- audit retention;
- design-partner / enterprise program.

## Research backlog

- broader variant-analysis automation after a verified root cause;
- architecture-aware check selection;
- proof minimization (smallest safe reproduction);
- independent verifier calibration;
- cross-model correlated-error measurement;
- trusted release provenance;
- MCP/tool authorization policy packs;
- business-logic invariant extraction from schemas/state machines.

## Non-goals

- indiscriminate internet scanning;
- exploit-volume leaderboards;
- claims that one model is universally the best security model;
- hiding methodology quality behind a paid tier;
- replacing professional judgment with a single scanner score.
