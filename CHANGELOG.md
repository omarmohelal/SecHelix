# Changelog

All notable SecHelix release changes are summarized here. Detailed release notes live in [`docs/releases/`](docs/releases/), and the Git history remains the authoritative development record.

## Runner 0.1.1 - 2026-09-04

- Published the independently versioned Python runner to PyPI using GitHub OIDC Trusted Publishing; no long-lived PyPI token is stored in the repository.
- Fixed Claude Code 2.1.248 compatibility where an explicitly successful JSON envelope ending with `stop_sequence` could accompany a non-zero process status. The adapter accepts only the narrow successful-completion case; truncation, tool continuation, malformed output and explicit errors still fail closed.
- Added an explicit `runner-release.json` publication marker and CI guards binding the marker, `pyproject.toml`, and `RUNNER_VERSION` before release.

## [4.0.0-alpha.1] - 2026-09-03

### V4 evidence runtime

- Added the optional standard-library-only runner with deterministic DAG orchestration, least-context routing, budget/coverage state, replayable evidence, loopback API/MCP integration and fail-closed provider execution.
- Added bounded LOCAL proof execution for authorization/IDOR, traversal, race/idempotency, webhook and SSRF; hardened HTTP proofs to literal loopback with no DNS names, ambient proxies or automatic redirects. Proof behavior never auto-promotes a finding.
- Added graph-grounded threat modeling, conservative false-positive guidance, deep protocol packs and a candidate-only C/C++/Rust native source lane.
- Added Opengrep as deterministic candidate evidence.

### Measurement and product surfaces

- Added the fail-closed Arena protocol for end-to-end applicability, verification, false-positive refutation, root-cause, regression-proof and release-gate measurement. The full workflow remains `NOT_MEASURED`; no competitor score is published in this release.
- Shipped Workbench V4 on `sechelix.com` for local recorded-run inspection without uploading artifacts.
- Preserved the existing uncontaminated 76-case blind-label result and its explicit boundary: precision 0.950, recall 1.000 and FP rate 0.053 describe the label task, not the complete V4 workflow.

### Distribution

- Bumped the Agent Skill/plugin release to `4.0.0-alpha.1` while keeping the optional Python runner at its independent `0.1.0` version.
- Added release notes and automated release/SBOM publication safeguards. At the time `4.0.0-alpha.1` was cut, PyPI publication was still blocked on external publisher setup; runner `0.1.1` is now published through Trusted Publishing.

See [`docs/releases/4.0.0-alpha.1.md`](docs/releases/4.0.0-alpha.1.md) for the full notes.

## [3.4.0-alpha.2] - 2026-09-02

### Evaluation

- Published the first uncontaminated blind-label evaluation: precision 0.950, detection recall 1.000, false-positive rate 0.053, false-positive rejection rate 0.947, counts TP 38 / FP 2 / TN 36 / FN 0.
- Kept the two measurement layers separate everywhere: the **blind label suite is `MEASURED`**, the **full SecHelix workflow remains `NOT_MEASURED`**. `verified_precision` is 0.0 only because `verification_status` was `NOT_RUN` for every case.
- Corrected the blind packet's published digest, which had been computed on a CRLF working copy and therefore failed verification for anyone following the documented download.

### Public record

- Synced the evidence boundary across README, ROADMAP, SUPPORT, evaluation and enterprise documents, the website, and the AI-readable `llms.txt` / `llms-full.txt` surfaces.
- Fixed two 404 links in `llms.txt` (`SKILL.md`, `TROPHY_CASE.md`).

### Discovery

- Added an `/appsec-agent` product-category pillar and a second research piece on reviewing AI-generated code; declined a third page that would have duplicated the pillar.
- Recorded a search-intent baseline together with the Search Console state it was not derived from (zero impressions).
- Named `Google-Extended` explicitly in `robots.txt` with the same public-allow / admin-deny shape, covered by automated assertions. This governs Gemini training and grounding use, not Search ranking.
- Strengthened entity structured data with stable `@id` values. No rating schema was added.

## [3.4.0-alpha.1] - 2026-09-02

### Evidence platform

- Added versioned policy packs with fail-closed applicability and expiring accepted-risk records.
- Added blind verifier quorum outcomes for consensus, disagreement, and insufficient evidence.
- Added root-cause security campaigns and a controlled remediation loop that never applies a patch directly to the caller's primary working tree.
- Added LOCAL/STAGING runtime evidence correlation, dependency exploitability graphs, secret lifecycle tracking, MCP permission/data-flow graphs, and AI security inventory artifacts.
- Added an ablation-benchmark design for comparing the same evaluator with and without SecHelix. The scored public benchmark remains **`NOT_MEASURED`** until an uncontaminated evaluator runs the blind packet.

### Integrity and safety

- Closed an integrity gap where an extra file injected after proof-bundle export could be absent from the manifest yet pass bundle verification.
- Kept runtime observations, dependency advisories, MCP declarations, and AI inventory declarations as evidence inputs rather than automatically promoting them to verified vulnerabilities.
- Preserved the open-core boundary: the local security engine remains open-source and unpaywalled.

### Repository and distribution

- Enforced PR-only, squash-only public history with concise PR-title commits and CI checks against assistant trailers, session URLs, and diary-style commit bodies.
- Kept existing public history and immutable release references intact rather than rewriting provenance for cosmetic reasons.
- Aligned compatibility documentation around `VERIFIED`, `DOCUMENTED`, `MODEL_COMPATIBLE`, `UNVERIFIED`, and `NOT_SHIPPED` states.

### Website and discovery

- Added automated XML sitemap validation, canonical discovery surfaces, RSS/Atom support, trust/early-access pages, and continued `llms.txt` / `llms-full.txt` support.
- Search and directory visibility remain measured separately from implementation; no ranking or recommendation claim is made by this release.

See [`docs/releases/3.4.0-alpha.1.md`](docs/releases/3.4.0-alpha.1.md) for the full notes.

## V3.3 development milestone - 2026-09-01

- Added confidence calibration with withheld metrics until a sufficient uncontaminated sample exists.
- Added incremental evidence caching, proof bundles, authorization graph analysis, and PR security review.
- Added mutation/property tests that found and closed fail-open behavior in the release gate and revision freshness logic.
- Added a one-command blind-evaluation runbook; the public benchmark remained `NOT_MEASURED`.

## [3.2.0-alpha.1] - 2026-09-01

- Fixed Agent Skills packaging so installs use the portable skill bundle rather than copying the whole development repository.
- Moved non-agent documentation out of the executable agent directory and split the Claude marketplace into its own repository.
- Added untrusted-repository mode, differential review, attack-chain correlation, revision binding, patch mode, and variant-rule generation.
- Expanded framework-aware and AI/MCP security guidance while preserving independent verification and fail-closed release semantics.
- Published the first authorized worked case study, including both a verified/fixed finding and a plausible candidate that was independently refuted.

See [`docs/releases/3.2.0-alpha.1.md`](docs/releases/3.2.0-alpha.1.md).

## [3.0.0-alpha.5] - 2026-09-01

- Reconciled the canonical report contract with renderers and release gates.
- Made missing required evidence fail closed as `INCOMPLETE` rather than silently passing.
- Reworked blind evaluation export/scoring and recorded the contaminated-evaluator blocker instead of publishing a contaminated score.
- Expanded the first Gold Check Packs, knowledge graph, and case-study/evidence program.

## [3.0.0-alpha.4] - 2026-09-01

- Finished the V2 Pro private product surfaces for the verification console, Workbench, Attack Surface, Authorization Matrix, Variant Analysis, Benchmark Lab, and Command Center.
- Preserved the separation between severity and verification state and kept benchmark UI honest when no measured result exists.

## [3.0.0-alpha.3] - 2026-09-01

- Added rights-aware source trust, knowledge graph, lesson-card, and live-research contracts.
- Added explicit human-only boundaries for restricted training curricula and provenance-backed security research states.

## [3.0.0-alpha.2] - 2026-09-01

- Added the curated extension registry and extension safety/validation lifecycle.
- Prevented community extensions from self-promoting to official status without maintainer review and fixture evidence.

## [3.0.0-alpha.1] - 2026-08-31

- Materialized the stable hypothesis catalog, versioned contracts, specialist roles, normalized evidence adapters, report formats, and fail-closed release-gate foundation.
- Established self-contained Agent Skills distribution and the public/private website-source boundary.

## [2.2.0] - 2026-08-31

- Rebuilt the public README and repository contribution/security surfaces for open-source launch.
- Standardized Agent Skills installation and added evidence-only Trophy Case and benchmark methodology documentation.

## [2.1.0] - 2026-08-31

- Introduced the portable Agent Skills architecture, composable security-family/verification-lens model, independent verifier methodology, company rollout documentation, and first public site/CI foundation.
- Renamed the early prototype to **SecHelix** and established evidence-based model/tool claims as a project rule.
