# Roadmap

SecHelix should earn trust through evals before adding complexity.

> **Maturity: public alpha (`4.0.0-alpha.1`).**
> Sections marked *complete* describe shipped repository capability, not measured
> accuracy. The blind label suite is **`MEASURED`** — one uncontaminated run,
> [`evals/results/claude-sonnet-5-blind-2026-09-02.json`](evals/results/claude-sonnet-5-blind-2026-09-02.json).
> The **full SecHelix workflow benchmark is still `NOT_MEASURED`**, and the
> remaining metrics are recorded in
> [`evals/results/not-measured.json`](evals/results/not-measured.json).
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

## v3.0 alpha — contract-first orchestration foundation — complete

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
  release mappings (76 nodes, 100 edges, provenance-backed);
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
- **partial** — expand paired vulnerable/clean fixtures (now 38 fixtures /
  76 cases / 10 families; more families and more per-family depth still needed);
- **done** — framework, database, cloud, container, supply-chain, and AI-security lesson coverage, including dedicated framework authorization, cloud SSRF, and container provenance/confinement cards;
- **done** — pin and rights-review selected NIST SARD Juliet and OWASP Benchmark Java evaluation corpora without vendoring third-party source;
- **done** — offline reproducible corpus importer verifies pinned identity and preserves origin, revision, license, and attribution metadata;
- **done** — an uncontaminated blind label run was published on 2026-09-02;
- **done** — eight cumulative exam levels plus de-identified mistake-class memory that can ask future verification questions but never auto-dismiss findings.

The uncontaminated blind label run exists. What is still missing is an
end-to-end run that exercises applicability, the independent verifier,
remediation with regression proof, and the release gate — until that exists those
rows stay `NOT_MEASURED`.

## v4.0 alpha — optional evidence runtime — current

- **done** — standard-library-only optional runner (`0.1.1`, published on PyPI) with deterministic reasoner DAG, least-context views, budget reservations, durable coverage, replay and four report formats;
- **done** — fail-closed provider isolation with a real Claude Code reasoning adapter and structured-output validation;
- **done** — loopback API and MCP integration without arbitrary shell exposure;
- **done** — Docker-backed sandbox specification and real confinement tests: read-only root, dropped capabilities, non-root user, bounded resources, workspace-only writes and default-deny network;
- **done** — graph-grounded threat modeling plus conservative cross-target false-positive guidance that can ask a future verification question but cannot auto-dismiss a finding;
- **done** — bounded LOCAL proof execution for IDOR, traversal, race/idempotency, webhook and SSRF. LOCAL HTTP proofs use literal loopback only and never follow redirects or ambient proxies; proof results never self-promote to findings;
- **done** — deep protocol packs for GraphQL, WebSocket, gRPC, OAuth/OIDC, SAML, JWT, webhooks and HTTP proxy/cache/desync boundaries;
- **done** — candidate-only native source lane for C, C++ and Rust unsafe/FFI/parser/crypto patterns;
- **done** — Opengrep interoperability beside the existing deterministic scanner adapters;
- **done** — production Workbench V4 at `sechelix.com/workbench/v4` for local `run.json` / `graph.json` / `coverage.json` inspection without uploading artifacts;
- **done** — fail-closed Arena full-workflow measurement protocol with pinned participant versions, explicit capability scope, complete opaque-case coverage, independent assessment and contamination gates;
- **not measured** — the complete V4 workflow. No end-to-end applicability/verification/remediation/regression/release-gate performance number is published yet;
- **done** — runner `0.1.1` is published on PyPI through GitHub OIDC Trusted Publishing, with an explicit release marker and version-drift guard;
- **external evidence needed** — competitor Arena runs and the first public Trophy Case require independently authorized runs, not synthetic claims.

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
