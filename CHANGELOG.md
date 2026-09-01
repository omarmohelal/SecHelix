# Changelog

All notable changes to SecHelix are documented here.

## [3.0.0-alpha.3] - 2026-09-01

### Expert knowledge foundation

- Added versioned contracts for a source trust registry, security knowledge
  graph, lesson cards, and live-research packets.
- Added an executable rights/use registry for canonical standards, public
  datasets, vulnerability intelligence, official query sources, and restricted
  curricula.
- Enforced human-only boundaries for PortSwigger Web Security Academy,
  TryHackMe, and Hack The Box: no autonomous retrieval, copying, embeddings,
  training, evaluation, or benchmarking without separate permission.
- Added deterministic `UNVERIFIED`, `SUPPORTED`, `HIGH_CONFIDENCE`, and
  `CONFIRMED` research states; confirmation requires code evidence and bounded
  safe reproduction.
- Seeded a provenance-backed CWE/CAPEC/OWASP/ASVS graph and an original SSRF
  lesson card, plus validation, tests, CI, and portable-bundle integration.
- Documented rights-reviewed SARD/OWASP Benchmark ingestion, isolated labs,
  current-source research, refresh cadence, and de-identified learning memory.
- The release candidate passes 67 core/repository tests and 19 adapter/safety
  tests, plus catalog, skill, extension, knowledge, link, secret, install, and
  private-source-boundary checks.

## [3.0.0-alpha.2] - 2026-09-01

### Community extension forge

- Added a curated extension registry for adapters, catalog/eval/policy packs,
  reporters, specialists, and integrations.
- Added versioned manifest and registry contracts with explicit authority,
  safe-default, evidence, fixture, and lifecycle requirements.
- Prevented community manifests from self-promoting to official status; promotion
  requires a separate maintainer review record and fixture proof.
- Added extension validation to CI, a starter manifest, contributor documentation,
  tests, and a dedicated GitHub proposal form.
- The release candidate passes 78 Python core/adapter tests plus catalog, skill,
  link, secret, install, and private-source-boundary checks.

### Product experience

- Reworked the private VNext product site around an interactive evidence workbench,
  a command palette, an honest measurement ledger, and a visible extension review
  pipeline.

## [3.0.0-alpha.1] - 2026-08-31

### VNext engine

- Materialized all 546 catalog entries as explicit, stable hypothesis IDs across
  21 families and 26 verification lenses.
- Added eight JSON Schema Draft 2020-12 contracts and deterministic
  applicability/attack-surface helpers with fail-closed authorization handling.
- Expanded the model-neutral specialist mesh to 17 role profiles.
- Added normalized adapters for Semgrep, CodeQL/SARIF, OSV, Gitleaks, Trivy,
  npm/pnpm audit, Playwright, ZAP, and Nuclei with bounded safe profiles.
- Added canonical Markdown, redacted JSON, SARIF 2.1.0, and escaped HTML report
  rendering plus configurable organization policy gates.
- Added eight paired vulnerable/clean eval fixture families, blind export, and an
  explicit `NOT_MEASURED` aggregate baseline.
- Added signed evidence-bundle, audit/retention, CI, private-policy-pack, and
  domain-launch designs.

### Distribution and separation

- Made `skills/sechelix/` a self-contained runtime bundle and added cold-install
  validation through the official skills CLI.
- Added public checks that reject private website source paths and source maps.
- Kept the product-grade VNext website in a separate private repository; this
  public tree contains no private website source.

### Verification

- 73 Python unit/adapter tests pass in the release candidate.
- Catalog, schemas, local links, install snippets, secret scanning, public/private
  separation, and skill surfaces validate.
- Benchmark capability claims remain `NOT_MEASURED` until reproducible runs exist.

## [2.2.0] - 2026-08-31

### Public launch polish

- Rebuilt the GitHub README around the patterns that make strong skills repositories easy to understand: visual identity, 30-second installation, host-specific details, methodology, coverage, company rollout, trophy case and roadmap.
- Added a branded README hero and stronger GitHub discovery copy.
- Standardized installation around `npx skills@latest add omarmohelal/SecHelix --skill sechelix` where the host supports the open skills installer.
- Added evidence-only `TROPHY_CASE.md` and a dedicated public-result issue template.
- Added benchmark methodology for vulnerable/clean fixtures, false-positive measurement and model-role evaluation.
- Added `CODE_OF_CONDUCT.md`, pull-request template, issue forms and GitHub Funding metadata.
- Configured the support page with maintainer-provided public crypto receiving addresses and explicit network warnings/copy controls.
- Added `.nojekyll` for static Pages hosting and a workflow capable of deploying the `site/` artifact once Pages is enabled for the repository.

### Safety

- Donation configuration contains public receiving addresses only; no private keys, exchange credentials or withdrawal credentials belong in the repository.
- Trophy-case entries require public evidence and attribution permission.
- Security hypotheses remain bounded to authorized testing and evidence-first verification.

## [2.1.0] - 2026-08-31

### Added

- Cross-agent portable architecture built around the Agent Skills format.
- Claude Code, Codex/OpenAI, GitHub/Copilot-friendly, and generic skill adapters.
- Documented GLM/Z.AI usage through supported coding-agent hosts rather than inventing an undocumented native skill path.
- 21 security families × 26 verification lenses = 546 structured hypothesis slots.
- Independent-verifier methodology for High/Critical findings.
- Evidence-based security release gate.
- Company rollout and open-core/commercial roadmap documentation.
- Static landing page with terminal demo, coverage search, model mesh, install tabs and support page.
- Crypto-ready support configuration.
- GitHub Actions validation and Pages deployment workflows.
- Agent-discovery metadata for the hosted skill.

### Changed

- Project renamed from the early AegisForge prototype to **SecHelix** to avoid brand collision and give the project a distinct identity.
- Coverage representation moved to a composable family × lens model instead of a flat payload/check dump.
- Model claims are evidence-based: providers are assigned roles through evals, not marketing assumptions.

### Safety

- Authorized targets only.
- Dynamic tests default to static/local evidence and bounded staging/production-safe modes.
- Scanner/model output is never automatically promoted to a vulnerability.
