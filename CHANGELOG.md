# Changelog

All notable SecHelix release changes are summarized here. Detailed release notes live in [`docs/releases/`](docs/releases/), and the Git history remains the authoritative development record.

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
