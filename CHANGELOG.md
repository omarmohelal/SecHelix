# Changelog

All notable changes to SecHelix are documented here.

## [3.2.0-alpha.1] - 2026-09-01

### Packaging

- Removed the root `SKILL.md`. It made the Skills CLI treat the whole repository
  as the skill, so `npx skills add` installed 354 files / 5.1 MB including tests,
  evals, CI config and a recursive copy of `skills/`. The canonical entry point
  is `skills/sechelix/SKILL.md`, and installs are now **109 files / 1.5 MB**.
  `scripts/validate_skill.py` fails if a root `SKILL.md` reappears.
- Moved the specialist-agent index out of `agents/` to
  `docs/reference/specialist-agents.md`. It was being loaded as an 18th agent.
- Split the plugin marketplace into `omarmohelal/sechelix-marketplace`.
  Co-locating it shadowed plugin validation.

### Security depth

- **Untrusted-repository mode** (`sechelix_core/untrusted_repo.py`). Under
  `UNTRUSTED_REPO`, repository content is data and never control: `CLAUDE.md`,
  `AGENTS.md`, settings files, hooks and docstrings cannot grant a capability,
  promote themselves to instructions, or widen scope. Trust resolution fails
  closed, and wildcard promotions are refused outright.
- **Differential review** (`sechelix_core/diff_review.py`). Classifies a change
  as `NEW_RISK`, `RISK_REDUCED`, `UNCHANGED` or `UNKNOWN` across 18 delta rules.
- **Attack chain correlation** (`sechelix_core/attack_chains.py`). Composes
  verified findings into five named chains. Only `VERIFIED` findings compose;
  severity comes from the chain's outcome rather than from raising a component;
  unverified compositions are `POTENTIAL` and carry no severity.
- **Revision binding** (`sechelix_core/revision.py`). A report records the tree
  it inspected, and the release gate exits `2 INCOMPLETE` rather than reusing a
  report that describes a different commit.
- **Patch mode** (`sechelix_core/patch_mode.py`). Emits a `.patch` and a `.md`
  rationale for `VERIFIED` findings only, and never applies anything. A diff is
  persuasive, so the persuasion has to be earned by verification first. Each
  rationale states what the patch does *not* cover, and a `NOT_RUN` regression
  status is never upgraded.
- **Variant rule generation** (`sechelix_core/variant_rules.py`). Turns a
  verified finding into a Semgrep rule so siblings of the same root cause can be
  swept. Rules are `UNVALIDATED` until run, hits are `HYPOTHESIS`, and severity
  is `INFO` regardless of the seed — a syntactic match inherits none of the
  seed's evidence.
- All six modules are now reachable from `skills/sechelix/SKILL.md`, which
  previously referenced none of them. Capability the workflow cannot reach is
  dead code.

### Evidence and honesty

- The keyword baseline is now reproducible in one command
  (`python evals/baselines/keyword_baseline.py --score`), and the result carries
  its commit, suite version and a SHA-256 of the exact case file. The published
  figure had been scored against the 19-fixture suite and never regenerated, so
  it had silently become a number about a suite that no longer existed. Rescored
  on the current balanced 33/33 suite: **precision 0.512, recall 0.636**. The
  precision is a coin flip and the recall is bought by flagging 41 of 66 cases,
  a 0.61 false-positive rate. Still `is_sechelix_result: false`.
- `score()` now carries `result_kind` and `is_sechelix_result` through from the
  prediction packet, defaulting to `UNDECLARED`. Regenerating the baseline had
  dropped both fields, which would have published an unlabelled number.
- Corrected count drift across the docs (fixtures, gold packs, adapters) and
  broadened the `CONTAMINATED_EVALUATOR` statement, which had been pinned to the
  old suite size.
- Added `evals/blind-packet/` so an uncontaminated evaluator can be run without
  access to this repository. Benchmarks remain **NOT_MEASURED**.

### Discoverability

- Recorded a **measured discovery baseline**: 6 queries run on 2026-09-01, 0
  found, including the brand name itself. Absence is now falsifiable.
- Shipped `.github/skills/sechelix/SKILL.md`, a documented Copilot repository
  skill directory the README already claimed existed.

### Fixed

- `scripts/check_local_links.py` no longer reports Markdown quoted inside code
  spans and fenced blocks as broken links.
- `SKILL.md` documented `diff_review.classify_changes`, which never existed; the
  module exports `review_diff`. Every gate passed while the skill pointed an
  agent at nothing, because none of them read `SKILL.md` as code.
  `tests/test_skill_references.py` now asserts every referenced module imports
  and every referenced attribute exists.
- The README claimed a `.codex/skills/` adapter that was never present, and that
  this project's own compatibility matrix says not to rely on. The claim is gone
  and the row reads `NOT_SHIPPED`.
- `scripts/validate_skill.py` checked three adapter surfaces, so a deleted
  adapter could leave the README asserting a directory nobody would notice was
  missing. It now checks all four.

## [3.0.0-alpha.5] - 2026-09-01

### Credibility and evidence program

- Reconciled the report contract with the renderer, gates, and examples so a
  report that validates also renders and gates identically.
- Made the release gate **fail closed**: missing required evidence now yields
  `INCOMPLETE` rather than a silent pass, and `UNKNOWN`/`BLOCKED` can no longer
  be converted into `NOT_APPLICABLE`.
- Fixed the blind-eval path so cases can be exported without ground truth and
  scored separately, and recorded the `CONTAMINATED_EVALUATOR` blocker that
  keeps the public benchmark at `NOT_MEASURED`.
- Validated the scoring harness with a naive keyword baseline
  (`evals/results/baseline-keyword-v1.json`), explicitly flagged
  `is_sechelix_result: false`. It lands at chance on the balanced suite, which
  evidences fixture difficulty and says nothing about SecHelix.
- Expanded the eval suite to **19 paired fixtures — 38 cases across 11
  families**, and corrected a stale family count in the `NOT_MEASURED` record.
- Grew Gold Check Packs from one to **five** (IDOR, SSRF, race/idempotency,
  money invariants, AI/MCP tool authority).
- Expanded the knowledge graph to **73 nodes and 96 edges** with **7 lesson
  cards**, all provenance-backed.
- Published the **first real case study**
  (`docs/case-studies/gamingops-store-2026-09-01.md`) with its evidence
  artifacts: one MEDIUM clickjacking finding verified, fixed, and
  regression-proved, and one plausible HIGH-severity XSS candidate **refuted**
  by independent verification.

### Packaging and compatibility

- Added `version` and `displayName` to `.claude-plugin/plugin.json`; the
  manifest now passes `claude plugin validate` with no version warning.
- Rewrote `COMPATIBILITY.md` around a four-value status vocabulary
  (`VERIFIED` / `DOCUMENTED` / `MODEL_COMPATIBLE` / `UNVERIFIED`), added a
  "How this was tested" record, and added a row for the Claude Code plugin path.
- Downgraded the repository-local `.codex/skills/` claim to `UNVERIFIED`: Codex
  documents `.agents/skills/` for repositories and `~/.codex/skills/` for global
  skills, so the `.codex/` directory is a mirror, not a discovery path.
- Documented why no `.claude-plugin/marketplace.json` is shipped: a marketplace
  manifest in the same directory shadows plugin validation.
- Fixed a dangling relative link that broke `check_local_links.py` inside the
  portable bundle.
- Removed a README badge that linked to a 404 and added an honest
  `benchmark: NOT_MEASURED` badge.

### Documentation

- Rebuilt `README.md` around proof, limitations, and adoption questions.
- Backfilled the missing `docs/releases/3.0.0-alpha.3.md`.
- Added `docs/launch/` drafts, all marked as requiring human review.

## [3.0.0-alpha.4] - 2026-09-01

### V2 Pro release polish

- Finished the private V2 Pro product surfaces for the interactive verification
  console, Evidence Workbench, Attack Surface, Authorization Matrix, Variant
  Analysis, Benchmark Lab, and Command Center.
- Replaced inactive product navigation with implemented destinations and added
  an accessible mobile application menu.
- Kept finding severity separate from verification state and preserved honest
  `NOT_MEASURED` benchmark semantics.
- Removed obsolete generated QA output, unused UI primitives and dependencies,
  historical CSS generations, and stale preview assets.
- Refreshed the V2 screenshots and 1200×630 social card without publishing
  private website source or production source maps.
- Hardened repository hygiene, mobile legibility, keyboard focus, reduced
  motion, link integrity, and the public/private release boundary.

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
