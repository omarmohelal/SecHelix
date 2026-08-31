# SecHelix VNext master plan

Status: **active execution plan**  
Baseline audited: `main` at `99d3d18` on 2026-08-31  
Working definition: **Evidence-first multi-agent AppSec orchestration and verification framework**

This plan is the coordination contract for VNext. It records the public-repository baseline, the product architecture, capability gaps, file ownership, acceptance gates, and the boundary between the open-source framework and the private/local VNext website.

## Non-negotiable source boundary

- The open-source SecHelix framework remains in this repository.
- The former public `site/` authoring source is removed. VNext is built only from the separate private website repository.
- The VNext site must live in a separate sibling workspace and may point only to a **private** Git remote. If a private remote cannot be created, the site remains local-only with `DO-NOT-PUSH.md`.
- Public SecHelix may receive selected screenshots, public documentation, installation instructions, and a future live-domain link. It must not receive private site source, source maps exposing that source, paid UI source that cannot be redistributed, credentials, API keys, private keys, seed phrases, or commercial design assets.
- VNext site deployment and domain purchase are out of scope until the operator approves a host/domain decision.

## A. Current-state audit

### Repository structure

The audited baseline contains 57 tracked files and no package manifest, lockfile, `components.json`, frontend framework, `evals/`, `adapters/`, `schemas/`, `reports/`, or `policies/` directory.

| Surface | Current state | Audit conclusion |
|---|---|---|
| `SKILL.md` | Comprehensive 14-phase, authorized-use, evidence-first methodology | Strong canonical foundation; implementation contracts remain prose |
| `skills/sechelix/` | Portable wrapper points to files outside its own directory | Not self-contained; cold install is unproven |
| `.claude/`, `.codex/`, `.agents/`, `.github/` skill adapters | Thin host-specific wrappers exist | Useful project-local adapters; CI checks existence only, not semantic synchronization |
| `catalog/checks.json` | 21 families × 26 lenses = 546 computed hypothesis slots | Slots are not rich per-hypothesis records; no JSON Schema or stable explicit record IDs |
| `agents/` | Mapper, Authentication, and Authorization profiles plus a 10-role overview | Three profiles exist; the requested specialist mesh is incomplete |
| `scripts/` | `validate_catalog.py` and a minimal `security_gate.py` | No applicability, graph, normalization, reporting, verifier, install, link, leakage, or secret checks |
| `.github/workflows/` | Catalog/skill/site validation and public Pages deployment | Count/existence assertions only; no test suite, schema validation, adapter tests, or private-source guard |
| `docs/` | Getting started, funding, company rollout, benchmark methodology | Good direction; no VNext plan, model mesh, domain checklist, actual benchmark lab, or closeout |
| `references/` | Methodology, tooling, and standards prose | Strong philosophy; not yet executable contracts |
| `examples/` | One scope YAML | No canonical finding/report/evidence/graph examples |
| GitHub Pages | Source-free handoff to the protected VNext deployment | Keep only the handoff generator and selected preview assets public |
| Governance | Apache-2.0, security policy, contributing, code of conduct, roadmap | Solid public baseline |

Baseline validation passes:

```text
OK: 546 structured hypotheses, 21 families, 26 lenses
```

That statement means 546 structured **hypothesis slots**, not 546 verified vulnerabilities or 546 independently authored exploit checks.

### Release and distribution state

- GitHub repository visibility: public.
- Default branch: `main`; no branch protection or rulesets were observed.
- No local/remote Git tags and no GitHub Release.
- GitHub description, homepage, and topics are empty.
- GitHub Pages forwards `https://omarmohelal.github.io/SecHelix/` to the current protected VNext deployment.
- The advertised `https://skills.sh/omarmohelal/SecHelix` page returned 404 during the audit.
- README advertises `scripts/validate_skill.py`, but that file is absent.
- README lists `evals/`, but that directory is absent.
- The portable skill relies on `../../` resources that a directory-only installer may not copy.

### Tooling and frontend state

- The public repository has no JavaScript package manager state and no runtime UI dependency.
- Local tools observed: Git 2.55.0, GitHub CLI 2.98.0, Node 22.23.2, npm 10.9.8, pnpm 11.19.0, Claude Code 2.1.240, Skills CLI 1.5.23, and shadcn CLI 4.19.1.
- A first-party shadcn MCP server was already configured and reported connected in Claude Code.
- No SecHelix `components.json` existed at audit time.
- Public source is Apache-2.0. UI sources have different licenses and must be evaluated per component; see `docs/UI-AI-TOOLING-MATRIX.md`.

### Technical debt and truth gaps

1. The release gate supports only `PASS` and `BLOCKED`; missing or empty findings can pass.
2. It cannot require independent verification, represent `PASS_WITH_KNOWN_RISK`, or fail closed on integrity-critical unknowns.
3. The public site's terminal depicts a `sechelix` CLI that does not exist and must be labeled simulated unless a real CLI is implemented.
4. Site coverage data duplicates catalog content and can drift.
5. Funding documentation says configuration is empty while public receiving addresses are present.
6. Actions use moving major tags instead of immutable commit SHAs.
7. CI does not check broken links, install snippets, mirror drift, secrets, or private-site leakage.
8. There are no normalized scanner adapters, canonical evidence/finding schemas, report generators, eval fixtures, or real benchmark results.

## B. Product architecture

SecHelix VNext is an **evidence-first multi-agent AppSec orchestration and verification framework**. It is not a giant prompt and it does not certify a target merely because models or scanners agree.

```text
Scope
  -> Attack-surface map
    -> Applicability engine
      -> Specialist lanes
        -> Tool/scanner evidence adapters
          -> Independent verifier
            -> Root-cause remediation
              -> Regression proof
                -> Release gate
                  -> Report / SARIF / evidence bundle
                    -> Eval / benchmark lab
                      -> Organization policy packs
```

### Layer contracts

| Layer | Responsibility | Primary artifacts |
|---|---|---|
| Scope | Record authorization, execution mode, targets, accounts, side effects, tools, and stop conditions | Scope schema and examples |
| Attack-surface map | Represent identities, assets, entrypoints, stores, providers, boundaries, and flows | Versioned graph JSON plus Mermaid rendering |
| Applicability engine | Deterministically reduce the catalog to relevant, irrelevant, unknown, or blocked checks | Architecture input and four-state decision output |
| Specialist lanes | Investigate disjoint security domains under one evidence contract | Standardized profiles and candidate findings |
| Tool/scanner adapters | Normalize tool output without promoting alerts to vulnerabilities | Common evidence records with source provenance |
| Independent verifier | Receive a neutral candidate packet and actively try to refute control, reachability, state, permission, and impact assumptions | `VERIFIED`, `FALSE_POSITIVE`, `DUPLICATE_ROOT_CAUSE`, `LIKELY_UNPROVEN`, or `BLOCKED` |
| Root-cause remediation | Repair the canonical invariant and preserve audit/accounting truth | Remediation decision and fix evidence |
| Regression proof | Demonstrate the property failed before and holds after the fix when practical | Test commands, assertions, artifacts, and environment |
| Release gate | Apply organization policy to verified risk and unknown critical invariants | `PASS`, `PASS_WITH_KNOWN_RISK`, `BLOCKED`, or `INCOMPLETE` |
| Reporting and bundle | Render equivalent Markdown, JSON, SARIF, and escaped HTML without leaking secrets | Canonical report plus derived formats and evidence manifest |
| Eval lab | Measure precision, recall, verified precision, false-positive rate, duplicate rate, time, tokens, provider/model, and scanner contribution | Paired vulnerable/clean fixtures and honest results |
| Organization policy packs | Add private boundaries, severity overrides, retention, accepted risk, and gate rules without forking the methodology | Versioned public examples and private-pack guidance |

### Architectural invariants

- Scanner/model output starts as a hypothesis.
- High/Critical status requires independent verification unless a stricter organization policy blocks earlier.
- Applicability is determined before checks are loaded into agent context.
- Unknown and blocked integrity-critical coverage can never silently produce `PASS`.
- Adapters preserve raw source provenance and use safe/local/staging profiles by default.
- Host adapters remain thin; the canonical methodology and schemas do not fork by model vendor.
- Benchmarks assign roles by measured capability, not brand claims.
- Reports redact secrets and distinguish observation, inference, reproduction, verification, remediation, and regression proof.

## C. Gap matrix

| Capability | Status | Current evidence | VNext target |
|---|---|---|---|
| Authorized-use and safe-test policy | CURRENT | Strong non-negotiable rules in the canonical skill | Preserve and add regression tests for adapter safety |
| Evidence-first methodology | CURRENT | Scope, mapping, evidence, verification, fix, and regression phases exist | Move executable contracts into schemas/modules |
| Product architecture | PARTIAL | Conceptual layers in prose | Implement and document every VNext layer |
| Scope record | PARTIAL | YAML example but no schema | Versioned schema plus validation |
| Coverage catalog | PARTIAL | 21×26 computed slots | 546 stable IDs with rich structured records and validation |
| Applicability engine | MISSING | Prose-only status selection | Deterministic four-state engine with explainable reasons |
| Attack-surface graph | MISSING | Mapping instructions only | JSON Schema, fixtures, and Mermaid renderer |
| Specialist mesh | PARTIAL | 3 profiles, 10 described | At least the 17 requested standardized profiles |
| Model mesh | PARTIAL | README guidance | Dedicated benchmark-driven role policy |
| Evidence/finding contract | MISSING | Illustrative prose/snippets | Canonical JSON Schemas and examples |
| Scanner adapters | MISSING | Roadmap-only | Semgrep, CodeQL, OSV, Trivy, Gitleaks, npm/pnpm audit, SARIF, Playwright, ZAP, and safe Nuclei adapters |
| Independent verifier | PARTIAL | Strong methodology, no executable packet/profile/tests | Blind refutation profile, schema, and classification tests |
| Root-cause/remediation review | PARTIAL | Methodology only | Remediation reviewer and linked regression contract |
| Reports | MISSING | No generators | Markdown, JSON, SARIF, and escaped HTML parity |
| Release gate | PARTIAL | Minimal High/Critical open check | Policy packs and four fail-closed outcomes |
| Eval/benchmark lab | MISSING | Methodology doc only | Paired fixtures, runner, schemas, and `NOT_MEASURED` defaults |
| Company readiness | PARTIAL | Rollout/open-core prose | Policy examples, private-pack guidance, audit/retention/signed-bundle design |
| Cross-agent distribution | PARTIAL | Thin project adapters | Self-contained portable bundle and cold-install tests |
| Discovery/release | PARTIAL | Good copy, broken registry page, no tags/releases/metadata | Working distribution, repository metadata, and release notes |
| CI assurance | PARTIAL | Count/frontmatter/site checks | Schemas, unit tests, adapters, reports, links, snippets, mirrors, leakage, and secrets |
| Public site | CURRENT | Historical static site is live | Freeze; publish only intentional preview assets later |
| Private VNext site | MISSING | No separate workspace | Complete sibling private/local site with evidence-led interactions |
| Private-source leakage guard | MISSING | No explicit repository guard | CI prohibited-path/source-map/secret checks |
| VNext deployment | BLOCKED | Domain/host approval intentionally absent | Prepare only; do not deploy |
| Domain launch preparation | MISSING | No checklist | DNS/HTTPS/canonical/OG/CSP/security.txt/redirect/analytics checklist |

## D. Execution waves

Each wave owns disjoint files. Parallel work uses isolated Git worktrees; a central coordinator integrates, runs the full suite once, reviews licenses, and audits the public/private boundary.

| Wave / lane | Files owned | Dependencies | Acceptance tests | Expected output | Main risks |
|---|---|---|---|---|---|
| 0 — Coordinator: truth and boundary | `docs/VNEXT-MASTER-PLAN.md`, `docs/UI-AI-TOOLING-MATRIX.md`, `docs/TOOLING-INSTALL-REPORT.md` | None | Baseline is evidence-backed; every capability has a status; install claims include proof/rollback | Stable plan and tooling decisions | Starting implementation before contracts stabilize |
| 1 — Lane B: catalog/schema | `catalog/**`, `schemas/**`, catalog validators/tests | Wave 0 | Exactly 546 unique stable IDs; all required fields validate; duplicates/removals fail; mappings/reference formats validate | Coverage catalog v2 and canonical schemas | ID churn, shallow generated metadata, unauthoritative mappings |
| 2 — Lane A: core engine | Canonical `SKILL.md`, applicability/graph modules, core fixtures/tests | Wave 1 contracts | Deterministic output; all four applicability states covered; graph JSON validates; Mermaid stable; no network required | Context-efficient selection and attack-surface artifacts | False `NOT_APPLICABLE` decisions and brittle detection |
| 3 — Lane C: specialist mesh | `agents/**`, `docs/model-mesh.md` | Waves 1–2 | Every required profile has mission, boundaries, inputs, evidence standard, prohibitions, and output contract | Complete model-neutral specialist/verifier mesh | Prompt duplication and methodology drift |
| 4 — Lane D: scanner/evidence adapters | `adapters/**`, adapter fixtures/tests | Wave 1 evidence schema | Golden fixtures normalize; malformed input fails safely; no severity auto-promotion; ZAP/Nuclei reject uncontrolled defaults | Common evidence records for all priority tools | Tool-version drift and unsafe active defaults |
| 5 — Reporting and policy | `reports/**`, report tooling, `scripts/security_gate.py`, `policies/**`, examples/tests | Waves 1 and 4 | Format parity; HTML escaping/redaction; required gate cases pass; malformed/empty reports fail closed | Four report formats and organization-aware release gate | Secret leakage and policy ambiguity |
| 6 — Lane E: eval lab | `evals/**`, benchmark docs/runner | Waves 2–5 | Paired vulnerable/clean fixtures; expected truth isolated; metrics schema complete; absent runs display `NOT_MEASURED` | Reproducible benchmark lab without fabricated results | Overfitting and publishing illustrative numbers as real |
| 7 — Lane F: public docs/distribution | README, compatibility/install/discovery/company docs, portable bundle, changelog/release notes | Stable Waves 2–6 | Cold-directory install resolves all resources; links/snippets pass; claims match implemented features | Professional searchable public repository | Premature claims and adapter forks |
| 8 — Lane G: private website | Separate sibling project only | Tooling/license decisions | Remote is private or absent; all required sections; keyboard/reduced-motion/mobile/browser/Lighthouse proof; no secrets/private-source maps | Complete private VNext site and screenshots | Accidental public commit and license contamination |
| 9 — Lane H: integration QA | CI workflows, `scripts/validate_skill.py`, leakage/link/secret checks, `docs/VNEXT-CLOSEOUT.md` | All waves | Full suite passes centrally; public/private audit passes; install proof documented; benchmark status honest | Evidence-backed VNext release candidate | Green CI with shallow assertions or integration drift |

### Release-gate regression cases

| Input | Required outcome |
|---|---|
| Verified unresolved Critical/High | `BLOCKED` |
| Verified Critical/High fixed with regression proof | `PASS` if nothing else blocks |
| Explicit accepted risk and policy permits it | `PASS_WITH_KNOWN_RISK` |
| Integrity-critical applicability/evidence unknown or blocked | `INCOMPLETE` or policy-selected `BLOCKED`, never `PASS` |
| Scanner-only hypothesis | Non-blocking unless an explicit organization policy is stricter |
| Empty, malformed, or schema-invalid report | Error/`INCOMPLETE`, never `PASS` |

### Website design brief

Audience: application-security leaders and senior engineers evaluating an evidence-first agent workflow.  
Page job: make the verification distinction tangible, then move the visitor to the 30-second install or company rollout path.

Design tokens:

- **Void graphite** `#07090D` — primary canvas.
- **Boundary blue** `#16243D` — trust-boundary planes.
- **Evidence cyan** `#62D9FF` — verified paths and interactive focus.
- **Proof emerald** `#55E6A5` — verified state only.
- **Review violet** `#9B8CFF` — model/verifier lane accent.
- **Mist text** `#D8E3EC` — high-contrast content.

Typography:

- Display: a precise technical grotesk with open counters, used sparingly.
- Body: a highly legible neutral sans optimized for long product explanations.
- Utility/data: a mono face for evidence IDs, commands, and measurements.

Layout concept:

```text
┌─ navbar ─────────────────────────────────────────────────────┐
│ claim + proof language    live evidence console / path map   │
├──────────────────────────────────────────────────────────────┤
│ hypothesis ── refutation ── verified finding (signature)     │
├───────────────┬────────────────┬─────────────────────────────┤
│ model mesh    │ coverage       │ adapters / evidence chain   │
├───────────────┴────────────────┴─────────────────────────────┤
│ graph demo • eval lab • compatibility • install • rollout    │
├──────────────────────────────────────────────────────────────┤
│ open source • trophy • FAQ • support                         │
└──────────────────────────────────────────────────────────────┘
```

Signature interaction: an **evidence helix** that begins as a noisy scanner hypothesis, splits into independent refutation lanes, and resolves into a compact verified chain only when attacker control, reachability, boundary failure, impact, root cause, and regression proof are present. Pointer lighting changes CSS variables without per-mousemove React state; mobile and reduced-motion users receive a clear static sequence.

This direction deliberately spends visual boldness on verification, the core SecHelix differentiator. The surrounding layout remains disciplined and operational rather than adopting generic hacker motifs or an animation-heavy component-demo aesthetic.

## Sequencing and release target

1. Land plan/tooling decisions and public/private guards.
2. Stabilize schemas and stable catalog IDs.
3. Execute engine, specialist, adapter, report, and eval lanes in isolated worktrees.
4. Integrate and run central validation.
5. Build and validate the private/local site without deploying it.
6. Reconcile all public claims, distribution instructions, screenshots, and metadata.
7. Prepare `3.0.0-alpha.1` as the next release candidate; do not publish/tag until cold-install, CI, private-source audit, and operator approval pass.
