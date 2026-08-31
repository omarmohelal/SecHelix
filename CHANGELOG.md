# Changelog

All notable changes to SecHelix are documented here.

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
