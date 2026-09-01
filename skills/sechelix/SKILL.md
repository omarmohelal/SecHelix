---
name: sechelix
description: Evidence-first application-security audit workflow for authorized repositories and environments. Use when reviewing a codebase, pull request, API, web application, AI-generated code, agent or MCP integration, cloud configuration, authorization (BOLA, IDOR, BFLA), business logic, payments, race conditions, secrets, supply chain, or release readiness for security weaknesses. Maps trust boundaries, selects applicable checks, runs parallel specialist review, independently verifies every material finding and refutes false positives, fixes root causes, and requires regression proof before reporting High or Critical issues.
license: Apache-2.0
---

# SecHelix

SecHelix is a portable AppSec review workflow for **authorized** systems. Treat every scanner/model output as a hypothesis until evidence supports it.

## Non-negotiable rules

1. Work only on repositories, applications, accounts, and environments the operator owns or is explicitly authorized to test.
2. Default to `STATIC` or `LOCAL` mode. Never turn a code-review request into uncontrolled internet scanning.
3. Do not use destructive payloads, credential theft, persistence, denial-of-service, malware, or data exfiltration as verification methods.
4. In production, prefer read-only evidence and safe proof. If a test could mutate money, identity, inventory, authorization, external providers, or customer data, require explicit authorization or move the proof to local/staging fixtures.
5. Losing integrity through a security test is itself a security failure. Preserve evidence, auditability, and rollback.
6. A scanner alert is not a vulnerability. A model suspicion is not a vulnerability. Two models agreeing is not independent proof.
7. High/Critical findings require an independent verification pass before final reporting.
8. Report uncertainty honestly. `UNPROVEN`, `BLOCKED`, and `FALSE_POSITIVE` are valid outcomes.

## Execution modes

- `STATIC`: source/config/schema review only.
- `LOCAL`: local application, local database, test fixtures, browser automation, safe dynamic tests.
- `STAGING`: explicitly authorized non-production target with an allowlist and rollback plan.
- `PRODUCTION_SAFE`: non-destructive evidence gathering and bounded verification only.

If the user does not specify a mode, start with `STATIC`, then ask/derive whether `LOCAL` is available before dynamic testing.

## VNext runtime contract

When the repository runtime is available, use its versioned contracts rather
than inventing parallel report shapes:

- fifteen JSON Schema Draft 2020-12 contracts cover scope, attack surface,
  applicability, evidence, findings, reports, catalog, extensions, source trust,
  knowledge graph, lesson cards, live research packets, and Gold Check Packs;
- all 546 catalog hypotheses have explicit, stable IDs from the frozen manifest;
- applicability has exactly four outcomes: `APPLICABLE`, `NOT_APPLICABLE`,
  `UNKNOWN`, and `BLOCKED`;
- reports derive Markdown, redacted JSON, SARIF 2.1.0, and escaped standalone
  HTML from one canonical JSON source;
- release gates fail closed to `INCOMPLETE` for malformed or missing evidence;
- public benchmark results remain `NOT_MEASURED` until a reproducible run emits
  signed inputs, configuration, and outputs.

Never coerce `UNKNOWN` or `BLOCKED` into `NOT_APPLICABLE`. Never turn
`LIKELY_BUT_UNPROVEN` into `VERIFIED` to satisfy a release gate.

## Phase 0 — establish scope

Create a short scope record before hunting:

- repository/service names;
- in-scope hosts/environments;
- explicit out-of-scope systems;
- available test accounts/roles;
- external providers and side effects;
- money/inventory/customer-data paths;
- production restrictions;
- allowed tools;
- stop conditions.

Never infer authorization for a third-party target merely because code references it.

## Phase 1 — map the system

Build an attack-surface map from evidence, not assumptions.

Inventory:

- entrypoints: routes, RPCs, webhooks, workers, cron, queues, browser extensions, CLIs;
- identities: users, admins, sellers, workers, services, agents, API keys, provider accounts;
- trust boundaries: browser/server, tenant/tenant, seller/seller, app/provider, app/database, agent/tool, CI/runtime;
- sensitive assets: secrets, money, payouts, codes, inventory, PII, chat, tokens, admin actions;
- state machines: order, refund, fulfillment, assignment, auth/session, listing, payout;
- persistence: tables, caches, object storage, queues, logs;
- external integrations;
- privileged transitions;
- client/server import boundaries;
- deployment and migration paths.

Produce a `role × object × action` matrix for every authorization-sensitive domain.

## Phase 2 — select applicable coverage

Use `catalog/checks.json` when available. Do not run all checks mechanically. Mark each hypothesis:

- `APPLICABLE` — at least one required architecture capability is evidenced as present;
- `NOT_APPLICABLE` — every required capability is explicitly evidenced as absent;
- `UNKNOWN` — capability evidence is missing or unresolved (the executable replacement for the earlier `UNKNOWN_NEEDS_EVIDENCE` label);
- `BLOCKED` — authorization, environment, access, or another declared constraint prevents a legitimate decision.

Use the deterministic applicability engine and retain its reason code, capability states, and evidence references. Missing evidence must never be treated as absence. An unconfirmed or partly unauthorized scope blocks execution; it does not make checks inapplicable.

Prioritize by potential impact and reachability:

1. authentication/session compromise;
2. authorization/BOLA/BFLA/tenant isolation;
3. money, payouts, refunds, inventory and provider side effects;
4. injection/SSRF/file-processing boundaries;
5. race conditions/idempotency/retry/restart;
6. secrets/crypto/supply chain;
7. browser/client boundaries;
8. AI/agent/MCP/tool boundaries;
9. cloud/CI/release configuration;
10. privacy/logging and operational exposure.

## Phase 2.5 — resolve current knowledge

Read `references/knowledge-engine.md` when a decision depends on an unknown
package, new advisory, recent framework/database/cloud/provider behavior,
conflicting sources, or an unfamiliar runtime claim.

- Resolve sources through `knowledge/source-registry.json` before retrieval or
  ingestion. A public URL is not permission to crawl, copy, embed, train, or
  benchmark.
- Never automate `HUMAN_ONLY` sources. PortSwigger Academy, TryHackMe, and Hack
  The Box stay manual references unless separate written permission exists.
- Prefer subject-vendor/official sources, then OSV/NVD/CISA KEV/GitHub Advisory
  data, then primary research. Cross-check with at least two independent reputable
  sources unless an exact-version official advisory exists.
- Record a `research-packet`; compare dates and exact versions; retain conflicts
  and limitations.
- Use `UNVERIFIED`, `SUPPORTED`, `HIGH_CONFIDENCE`, or `CONFIRMED` exactly as the
  research contract computes them. Only code evidence plus a bounded safe
  reproduction produces `CONFIRMED`.
- Research confidence does not replace finding verification. Return to the local
  evidence chain before reporting a vulnerability.

## Phase 3 — parallel specialist review

Use disjoint review lanes where the agent platform supports subagents/worktrees. Suggested lanes:

### Surface mapper
Trace architecture, inputs, outputs, trust boundaries, privileged sinks and security controls.

### Auth + AuthZ reviewer
Review login, sessions, MFA/step-up, token refresh, role aggregation, tenant/seller/object ownership, direct URLs, RPC policies, fail-open states.

### Input + Web reviewer
Review injection, SSRF, URL fetches, file upload/parsing, XSS, CSP, open redirect, path traversal, unsafe serialization, browser trust boundaries.

### Business-logic reviewer
Review refunds, discounts, entitlement, quantity, partial fulfillment, marketplace state, cost/margin, payout, inventory lifecycle, approval workflows, bypasses.

### Race + exact-once reviewer
Review duplicate callbacks, retries, process crash, timeout, outcome-unknown, TOCTOU, locks, idempotency keys, duplicate writes, stale preview/apply, concurrent admins.

### Supply-chain + CI reviewer
Review dependencies, scripts, actions, artifacts, package install paths, build provenance, secret exposure, unsafe release automation.

### AI / Agent / MCP reviewer
Review prompt/tool boundary, untrusted tool output, MCP authorization, tool scope, agent identity, poisoned context, stored instruction injection, unsafe auto-actions.

### Independent verifier
Receives candidate findings **without being told they are true**. Reconstructs the path and attempts to refute each one.

Do not let every lane run a full project suite concurrently. Focused tests per lane; central verification later.

## Phase 4 — evidence standard

A verified vulnerability should establish, where applicable:

1. **Attacker control** — what input/state can the attacker influence?
2. **Reachability** — how does it reach the vulnerable path?
3. **Boundary failure** — which intended control fails?
4. **Safe reproduction** — local/staging proof or production-safe evidence.
5. **Impact** — concrete confidentiality/integrity/availability/business effect.
6. **Preconditions** — roles, state, timing, configuration.
7. **Root cause** — the defective invariant, not only the symptom.
8. **Fix** — preferably at the canonical boundary.
9. **Regression** — a test that fails against the vulnerable control and passes after the fix.

Severity without proof should be conservative.

## Phase 5 — business-logic and state-machine abuse

For every money/inventory/fulfillment flow, enumerate transitions and ask:

- Can the same action happen twice?
- Can a terminal state be reopened incorrectly?
- Can a partial success be represented as full success?
- Can refund and delivery race?
- Can cost edits rewrite finalized payout truth?
- Can a failed insert occur after a destructive delete?
- Can an external timeout later succeed?
- Can retry buy/deliver twice?
- Can a user replay a stale preview?
- Can a seller act on another seller's object?
- Can null/unknown be coerced into zero/false/safe?
- Can a client-provided status overrule stored truth?
- Can an admin UI success message hide a failed second write?

Require fail-closed handling for unknown external outcomes.

## Phase 6 — authorization review

For each protected object:

- list reader/editor/deleter roles;
- check list endpoints and item endpoints separately;
- check direct URLs, search, exports, bulk actions and background jobs;
- check UI hiding is not the only guard;
- check `null`, missing identity and lookup errors fail closed;
- check mixed roles use intended union/intersection semantics;
- check assignment ownership and historical effective windows;
- check admin/bypass helpers are narrow and auditable;
- check RPC/database policies do not contradict API policy.

A missing identity must not silently produce an unscoped query.

## Phase 7 — injection and parser review

Trace untrusted data to:

- SQL/PostgREST filters/RPC strings;
- shell/process execution;
- template/HTML/Markdown rendering;
- URL fetches and redirects;
- filesystem paths;
- archive extraction;
- image/document parsers;
- regex with attacker-controlled complexity;
- deserialization;
- dynamic imports/eval;
- CI expressions and workflow inputs.

Prefer structural APIs/parameterization. Verify stored/second-order injection, not only request-time injection.

## Phase 8 — secrets, crypto and sessions

Review:

- secret storage and logs;
- client bundle leakage;
- token lifetime/rotation/revocation;
- cookie flags and origin/host behavior;
- CSRF protections where relevant;
- password reset/account recovery;
- session fixation;
- step-up enforcement on money/secret operations;
- cryptographic primitive use;
- key/version migrations;
- deterministic identity/hash compatibility where persisted values depend on it.

Never rotate/rewrite a persisted identity/hash scheme without compatibility proof.

## Phase 9 — supply chain and release

Review:

- lockfiles;
- install scripts;
- unpinned GitHub Actions;
- artifact provenance;
- dependency confusion/typosquatting opportunities;
- secret use in forks/PRs;
- release branch protections;
- migration ordering;
- production build vs typecheck gaps;
- browser/server import boundaries;
- rollback/readiness;
- environment flags that default to shadow/off/fail-open.

A green typecheck is not proof that a browser bundle or production build is valid.

## Phase 10 — safe dynamic proof

Only in authorized `LOCAL`, `STAGING`, or explicitly bounded `PRODUCTION_SAFE` mode.

Prefer:

- purpose-built fixtures;
- two-account/role comparisons;
- browser automation against local/staging;
- exact response/status assertions;
- concurrency tests with harmless fixture state;
- dependency/static scanners;
- local proxy inspection;
- provider mocks.

Avoid broad exploit spraying. Use the minimum test necessary to prove or refute the hypothesis.

## Phase 11 — verification pass

The independent verifier must classify each candidate:

- `VERIFIED`
- `LIKELY_BUT_UNPROVEN`
- `FALSE_POSITIVE`
- `DUPLICATE_ROOT_CAUSE`
- `BLOCKED_BY_ENVIRONMENT`

For High/Critical, the verifier should try to disprove:

- attacker control;
- reachability;
- missing guard assumptions;
- role preconditions;
- impact;
- whether the vulnerable state is actually producible;
- whether a compensating control already blocks the exploit.

Do not promote a finding merely because a scanner and model agree.

## Phase 12 — fix strategy

Fix the canonical invariant, not every symptom.

Examples:

- central authorization helper instead of page-by-page checks;
- atomic RPC instead of delete-then-insert;
- canonical parser instead of many regex copies;
- one exact-once merge instead of multiple dedupe rules;
- stable design-system primitive instead of page-specific CSS patches;
- one provider state machine instead of retry logic in every route.

Preserve historical/accounting/audit evidence during repair.

## Phase 13 — regression proof

For each verified important finding:

1. prove the test fails on the vulnerable control when practical;
2. apply the fix;
3. prove the regression passes;
4. run focused neighboring tests;
5. run central security/release gates once integrated.

Source-text assertions are weak when behavior can be tested. If a refactor moves code, revalidate the property before updating a source assertion.

## Phase 14 — final report

Report only evidence-backed items.

For each finding include:

- ID and title;
- severity + confidence;
- affected surface;
- CWE/OWASP mapping when useful;
- prerequisites;
- evidence chain;
- safe reproduction;
- impact;
- root cause;
- fix;
- regression proof;
- residual risk.

Also report:

- scope;
- mode;
- coverage/applicability summary;
- tools/scanners used;
- verified findings;
- rejected false positives;
- blocked checks;
- release recommendation.

## Release recommendation vocabulary

- `PASS` — no unresolved release-blocking verified findings.
- `PASS_WITH_KNOWN_RISK` — explicit accepted non-blocking risk.
- `BLOCKED` — unresolved Critical/High or integrity-critical unknown.
- `INCOMPLETE` — required evidence unavailable; do not imply security certification.

## Supporting resources

- `references/methodology.md` — evidence and verification philosophy.
- `references/tooling.md` — scanner/tool adapter guidance.
- `references/sources.md` — standards and source references.
- `references/knowledge-engine.md` — source trust, rights, live research,
  confidence, graph, lesson-card, lab, and de-identified learning policy.
- `references/gold-check-packs.md` — reusable check-pack and Variant Hunter
  contracts that cannot bypass applicability or verification.
- `knowledge/` — source registry, provenance graph, and lesson cards.
- `catalog/checks.json` — structured hypothesis catalog.
- `agents/` — specialist reviewer profiles.
- `schemas/` — versioned scope, evidence, finding, and report contracts.
- `adapters/` — normalized Semgrep, CodeQL/SARIF, OSV, Gitleaks, Trivy,
  npm/pnpm audit, Playwright, ZAP, and Nuclei evidence adapters.
- `reports/` — canonical Markdown/JSON/SARIF/HTML report renderer.
- `policies/` — public release-gate policy examples; keep real organization
  policy packs private.
- `examples/` — scope and report examples.
- `scripts/security_gate.py` — report/release gate.
- `scripts/applicability.py` — deterministic applicability decision helper.
- `scripts/attack_surface.py` — attack-surface and Mermaid graph helper.
- `scripts/validate_catalog.py` — catalog validation.
- `scripts/validate_knowledge.py` — knowledge-source, graph, card, and research validation.
- `scripts/validate_gold_packs.py` — Gold Pack provenance, safety, and calibration validation.

Typical repository-runtime commands:

```bash
python scripts/attack_surface.py --help
python scripts/applicability.py --help
python scripts/validate_knowledge.py
python -m adapters.cli --help
python -m reports.report_renderer examples/report.example.json --format markdown
python scripts/security_gate.py examples/report.example.json --policy policies/default.json
```

Remember: the objective is not to generate the most findings. It is to find the important flaws, reject noise, repair root causes, and leave proof that the system is safer.
