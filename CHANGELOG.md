# Changelog

All notable changes to SecHelix are documented here.

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
- Crypto-ready support configuration with no hardcoded wallet addresses.
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
