<p align="center">
  <img src="assets/brand/readme-hero.png" alt="SecHelix — Security findings are claims. SecHelix proves them." width="100%" />
</p>

<p align="center">
  <strong>Security findings are claims. SecHelix proves them.</strong><br/>
  Map the attack surface → select applicable checks → hunt in parallel → independently verify → fix the root cause → prove the regression → gate the release.
</p>

<p align="center">
  <a href="https://github.com/omarmohelal/SecHelix/actions"><img src="https://img.shields.io/github/actions/workflow/status/omarmohelal/SecHelix/validate.yml?branch=main&style=flat-square&label=validate" alt="validation"/></a>
  <a href="skills/sechelix/SKILL.md"><img src="https://img.shields.io/badge/security%20hypotheses-546-7dd3fc?style=flat-square" alt="546 hypotheses"/></a>
  <a href="#evaluation-and-proof-status"><img src="https://img.shields.io/badge/blind%20eval-MEASURED-34d399?style=flat-square" alt="blind eval MEASURED"/></a>
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/release-4.0.0--alpha.1-9b8cff?style=flat-square" alt="4.0.0 alpha 1"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-a78bfa?style=flat-square" alt="Apache-2.0"/></a>
</p>

<p align="center">
  <a href="#install-in-30-seconds">Install</a> ·
  <a href="docs/QUICKSTART.md">Quickstart</a> ·
  <a href="docs/reference/command-recipes.md">Commands</a> ·
  <a href="#what-proof-exists">Proof</a> ·
  <a href="#coverage">Coverage</a> ·
  <a href="#evaluation-and-proof-status">Evaluation</a> ·
  <a href="#limitations">Limitations</a> ·
  <a href="https://sechelix.com/docs">Docs</a> ·
  <a href="https://sechelix.com/faq">FAQ</a> ·
  <a href="ROADMAP.md">Roadmap</a>
</p>

---

## What is SecHelix?

SecHelix is an **open-source, evidence-first application-security Agent Skill and orchestration methodology** for repositories and environments you are authorized to test.

It is not a scanner wrapper that turns every alert into a vulnerability. SecHelix coordinates code-reading agents, security tools, browser/runtime evidence, and an independent verifier under one shared standard.

> [!IMPORTANT]
> A scanner alert is not a vulnerability.  
> A model suspicion is not a vulnerability.  
> Two models agreeing is not independent proof.

A trusted finding should establish attacker control, reachability, a failed security boundary, bounded safe reproduction, concrete impact, root cause, a fix, and regression proof.

### Current public alpha

| Surface | Current state |
|---|---|
| Coverage | **546 stable security hypothesis IDs** across 21 families × 26 lenses |
| Specialist mesh | **17 model-neutral role profiles**, including an independent verifier |
| Contracts | **22 JSON Schema Draft 2020-12 contracts** for scope, applicability, evidence, findings, reports, extensions, knowledge, and Gold Check Packs |
| Gold Check Packs | **18 deep reference packs** — 12 bug-class (IDOR, SSRF, injection, race/idempotency, money invariants, AI/MCP tool authority, and more) plus 6 framework packs (Next.js, Express/Node, Django, Supabase/PostgREST, Spring Boot, Laravel) |
| Eval fixtures | **38 paired fixtures — 76 cases across 10 families**, each with a vulnerable and a clean variant |
| Knowledge graph | **76 nodes, 100 edges**, provenance-backed, plus **14 lesson cards** |
| Evidence adapters | Semgrep, **Opengrep**, CodeQL/SARIF, OSV, Gitleaks, Trivy, npm/pnpm audit, Playwright, ZAP, Nuclei |
| Reports | Markdown, redacted JSON, SARIF 2.1.0, escaped standalone HTML |
| Release truth | `PASS`, `PASS_WITH_KNOWN_RISK`, `BLOCKED`, or fail-closed `INCOMPLETE` |
| Zero-trust audits | **`UNTRUSTED_REPO` mode** — repository content is data, never control ([details](docs/reference/untrusted-repo-mode.md)) |
| Change review | **Differential security review** — classifies a diff into `NEW_RISK` / `RISK_REDUCED` / `UNCHANGED` / `UNKNOWN` |
| V4 evidence runtime | **Optional stdlib-only runner `0.1.1` on PyPI** — deterministic reasoner DAG, least-context routing, budget governor, coverage ledger, replay, loopback API and MCP |
| Bounded runtime proof | **LOCAL-only** IDOR, traversal, race/idempotency, webhook and SSRF proof executors; literal loopback only, no ambient proxy/redirect following, and no automatic finding promotion |
| Protocol / native lanes | Applicability-gated GraphQL, WebSocket, gRPC, OAuth/OIDC, SAML, JWT, webhook and HTTP proxy/cache review plus candidate-only C/C++/Rust source analysis |
| Full-workflow Arena | **Protocol shipped; result still `NOT_MEASURED`** — complete packet coverage, pinned versions, independent assessment and uncontaminated evidence are required before publication |
| Real-world proof | **1 published case study** — [gamingops-store](docs/case-studies/gamingops-store-2026-09-01.md) |
| Blind label evaluation | **`MEASURED`** — first uncontaminated 76-case run: precision **0.950** · detection recall **1.000** · FP rate **0.053** ([result](evals/results/claude-sonnet-5-blind-2026-09-02.json), [report](docs/research/evaluation-report.md)) |
| Full SecHelix workflow benchmark | **`NOT_MEASURED`** — V4 ships the fail-closed Arena protocol, but no uncontaminated end-to-end applicability → verification → remediation/regression → release-gate run has been published |
| Trophy case | Public attributable results only; **no entries yet** |

The canonical live product is **[sechelix.com](https://sechelix.com)**. The website source remains private; this repository contains the open security framework, portable Agent Skill, adapters, schemas, eval fixtures, and public documentation.

## Install in 30 seconds

### Recommended — Agent Skills CLI

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

Optional V4 evidence runtime, independently versioned and published on PyPI:

```bash
pipx install sechelix
sechelix doctor
```

`uv tool install sechelix` or `python -m pip install sechelix` also work. The portable Agent Skill does not require the Python runner.

Then ask your coding agent:

```text
Use SecHelix for a complete authorized security audit of this repository.
Start STATIC, map the attack surface and trust boundaries, evaluate only applicable hypotheses,
independently verify High/Critical candidates, fix root causes, add regression proof, retest,
and produce the final release gate.
```

**Next:** [5-minute Quickstart](docs/QUICKSTART.md) · [Command cookbook](docs/COMMANDS.md) · [Compatibility](docs/reference/compatibility.md)

<details>
<summary><strong>Claude Code</strong></summary>

Install as a standard Agent Skill:

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

The repository also includes a Claude Code plugin manifest for packaged/team use:

```bash
git clone https://github.com/omarmohelal/SecHelix.git
claude --plugin-dir ./SecHelix
```

Project-local adapter:

```bash
mkdir -p .claude/skills
cp -R skills/sechelix .claude/skills/sechelix
```

</details>

<details>
<summary><strong>OpenAI Codex</strong></summary>

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

The repository ships `.agents/skills/sechelix/`, which is the repository skill directory Codex
documents. There is deliberately no `.codex/skills/` mirror: that path is not a documented Codex
discovery location, and shipping it would invite reliance on something that may never load.

</details>

<details>
<summary><strong>GitHub Copilot / VS Code agents</strong></summary>

The repository includes:

```text
.github/skills/sechelix/SKILL.md
```

GitHub documents `.github/skills/` as a repository skill directory for Copilot, so this adapter is
present for discovery. It has **not** been observed loading in a Copilot session — the compatibility
status is `DOCUMENTED`, not `VERIFIED`. You can also install the portable source with the Agent
Skills CLI.

</details>

<details>
<summary><strong>Cursor / Gemini CLI / GLM / OpenCode / other Agent Skills clients</strong></summary>

Use the cross-client installer when supported:

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

Otherwise use the vendor-neutral `skills/sechelix/` bundle with the host's documented skill loader.

</details>

## What proof exists

Not a benchmark. One real, end-to-end audit, published with its artifacts — including the finding SecHelix **threw away**.

**[Case study: gamingops-store, 2026-09-01](docs/case-studies/gamingops-store-2026-09-01.md)** — authorized owner self-audit of a ~600 LOC Next.js storefront. `STATIC` + `LOCAL` mode, **zero scanners enabled**, nothing outside `127.0.0.1` contacted.

```text
1 external data source → 41 of 546 hypotheses applicable
3 candidates → 1 verified · 2 refuted
1 fix + 1 hardening → 10 regression assertions → PASS after remediation
```

- **Refuted (the interesting one).** Remote config values reached `href`/`src` with only `.trim()` — exactly the shape a scanner or a confident reviewer reports as high-severity XSS. Verification killed it: React 19 rewrote the payload to `href="javascript:throw new Error('React has blocked a javascript: URL as a security precaution.')"`, and attacker control was never established. Recorded as `FALSE_POSITIVE`. A scheme allowlist was still added — and labelled **hardening, not a vulnerability fix**.
- **Verified.** `SHX-F-GOS-HEADERS-001`, **MEDIUM** clickjacking. No `CSP`, `X-Frame-Options`, or `HSTS` on any route; a probe page on a separate origin framed the whole UI including the sign-in entry point. Severity held at MEDIUM on purpose — phishing amplification, not account takeover, because the app performs no authenticated state-changing actions.
- **Regression proof.** The browser's own words on retest: `Framing 'http://localhost:3009/' violates the following Content Security Policy directive: "frame-ancestors 'none'". The request has been blocked.`

The first retest *appeared to fail* — a stale Next.js prerender cache and a server still bound to the old port. That is recorded too, because it is exactly how a real fix silently becomes a false claim of remediation.

## How it works

```text
SCOPE
  ↓
MAP identities • assets • routes • state machines • trust boundaries
  ↓
SELECT only applicable hypotheses
  ↓
HUNT with specialists + scanner/tool evidence
  ↓
INDEPENDENT VERIFIER tries to refute important candidates
  ↓
ROOT-CAUSE FIX
  ↓
SECURITY REGRESSION PROOF
  ↓
RETEST
  ↓
REPORT + RELEASE GATE
```

### Four honest applicability outcomes

- `APPLICABLE` — required architecture capability is evidenced as present.
- `NOT_APPLICABLE` — required capability is explicitly evidenced as absent.
- `UNKNOWN` — evidence is missing or unresolved.
- `BLOCKED` — authorization, access, tooling, or environment prevents a legitimate decision.

Missing evidence is never treated as absence.

### Finding evidence standard

A verified vulnerability should establish:

1. attacker control;
2. reachability;
3. security boundary failure;
4. safe reproducibility;
5. concrete impact;
6. preconditions;
7. root cause;
8. fix;
9. regression proof.

High/Critical candidates receive an independent refutation pass before final reporting.

## Coverage

The catalog contains **546 structured security hypotheses across 21 families**.

| | | |
|---|---|---|
| Authentication | Sessions | Authorization / BOLA / BFLA |
| Injection | API security | Files / uploads |
| SSRF | Browser / client | Business logic |
| Payments / accounting | Race conditions / idempotency | Database / migrations / RPCs |
| Cryptography / secrets | Supply chain | CI/CD |
| Cloud / configuration | Privacy / logging | AI / Agent / MCP |
| Operational security | Release security | Attack-surface mapping |

SecHelix does **not** spray every check at every target. Applicability is determined from architecture evidence first.

## Where SecHelix is different

### Verification is first-class

Important candidates can be routed to a verifier whose job is to **disprove** them. Compensation controls, unreachable states, missing attacker control, or impossible prerequisites are valid reasons to reject a candidate.

### Business logic is first-class

Security bugs often live between individually valid actions:

```text
refund + late provider success
delivery + cancellation
cost edit + finalized payout
two admins + one assignment
timeout + retry + delayed callback
partial fulfillment + "mark full"
seller A + seller B's object
```

SecHelix treats exact-once behavior, state machines, accounting truth, retries, and race windows as security surfaces.

### Runtime proof can outrank static confidence

A typecheck can be green while the browser flow is broken. Unit tests can be green while a real database constraint or authorization boundary behaves differently. SecHelix can require browser, API, database, migration, or local-runtime proof at the layer where the invariant exists.

### AI-built code gets normal AppSec scrutiny

"Built with AI" is not itself a vulnerability class. SecHelix checks the actual implementation for missing server-side authorization, client-controlled identity/price fields, dynamic queries, unsafe HTML, SSRF, weak upload validation, permissive CORS, home-grown auth/JWT logic, missing replay/idempotency controls, unsafe logs, source-map exposure, overprivileged agent tools, and related failure modes.

## Safe execution modes

| Mode | Intended use | Dynamic traffic |
|---|---|---|
| `STATIC` | source/config/schema review | none |
| `LOCAL` | local app + fixtures | local only |
| `STAGING` | explicitly authorized non-production environment | allowlisted |
| `PRODUCTION_SAFE` | bounded non-destructive verification | tightly restricted |

> [!WARNING]
> SecHelix is for systems you own or are explicitly authorized to test. It does not turn code review into uncontrolled internet scanning, credential theft, persistence, destructive payloads, malware, or denial-of-service testing.

See [SECURITY.md](SECURITY.md).

## Evaluation and proof status

**The first uncontaminated blind-label run is now recorded.** It was produced on 2026-09-02 by 76 independent headless processes, each launched from an empty directory holding only `cases.json`. None cloned the repository or saw a label, a rationale, a pairing, or how many cases were vulnerable.

| Metric | Value |
|---|---|
| Precision | **0.950** |
| Detection recall | **1.000** |
| False-positive rate | **0.053** |
| False-positive rejection rate | **0.947** |
| Counts | **TP 38 · FP 2 · TN 36 · FN 0** |

> [!WARNING]
> **This is a label-only synthetic evaluation, not measured performance of the complete SecHelix workflow.** The protocol asks one question per file and takes one label back. It did not run attack-surface mapping, the independent refutation pass, adapters, evidence-chain construction, remediation, regression proof, or the release gate.

Raw result: [`evals/results/claude-sonnet-5-blind-2026-09-02.json`](evals/results/claude-sonnet-5-blind-2026-09-02.json). Full write-up, including every limitation: [`docs/research/evaluation-report.md`](docs/research/evaluation-report.md). The procedure anyone can repeat is [`evals/blind-packet/RUN.md`](evals/blind-packet/RUN.md).

**What is still `NOT_MEASURED`.** `verified_precision` is `0.0` because `verification_status` was `NOT_RUN` for every case — the procedure never asked for verification. `applicability_accuracy`, `regression_proof_rate` and `release_gate_accuracy` remain the literal string `NOT_MEASURED`; they belong to a full audit run, not to label-only scoring, and [`evals/results/not-measured.json`](evals/results/not-measured.json) still stands for them.

**The harness itself is validated separately.** [`evals/results/baseline-keyword-v1.json`](evals/results/baseline-keyword-v1.json) records a naive regex keyword matcher run against all 76 cases. It carries `"result_kind": "HARNESS_BASELINE"` and `"is_sechelix_result": false` and **is not a SecHelix score.** It lands at chance (precision 0.511, recall 0.632, FP rate 0.605) on a balanced 38/38 split, which is a statement about fixture difficulty and nothing else.

Metrics are defined in **[docs/EVALUATION.md](docs/EVALUATION.md)**. A public score is allowed only after a reproducible run records the exact SecHelix commit, fixture version, model/provider configuration, enabled tools, observed outcomes, and supporting artifacts — which is why the run above is published with its provenance and its seven recorded limitations attached.

## Limitations

Read this before adopting.

- **One blind label-suite measurement exists; no full-workflow benchmark exists.** The numbers above describe one model answering one question per file. Nothing measures the verifier, the adapters, remediation, regression proof, or the release gate.
- **One model, one run.** No repeats, no seed control, no variance estimate. A second run would not necessarily produce the same labels.
- **A balanced, authored suite.** 38 pairs, 38/38 vulnerable/clean — not a real base rate, where clean code vastly outnumbers vulnerable code. Precision on this suite overstates precision in the field.
- **Mostly single-file, mostly Python, synthetic.** Real vulnerabilities often span modules; these do not. The fixtures encode one team's idea of what is hard.
- **One case study, `n = 1`.** A ~600 LOC app with no authentication and no server-side state, audited by its own owner. It demonstrates the workflow; it measures nothing about general performance.
- **No public third-party results.** The [trophy case](docs/research/trophy-case.md) is empty on purpose.
- **Alpha.** `4.0.0-alpha.1`. Contracts and runtime interfaces are versioned, but they can still change.
- **SecHelix is a methodology, not a scanner.** Output quality depends on the host agent, the model, and the tools you enable. It does not run itself.
- **It cannot verify what it cannot reach.** Missing evidence yields `UNKNOWN` or `BLOCKED`, never `NOT_APPLICABLE`. That is the design, but it means an under-instrumented run returns honest non-answers rather than coverage.
- **Authorized targets only.** See [SECURITY.md](SECURITY.md).

## Can my company use it?

Yes — Apache-2.0, and the repository is standard-library Python with no runtime dependencies to vet.

- **Nothing phones home.** No telemetry, no accounts, no network calls in the skill bundle or the validators.
- **Your code stays where your agent runs.** SecHelix ships instructions, schemas, and local scripts; it adds no data path of its own.
- **Default mode is `STATIC`.** Dynamic testing is opt-in and bounded.
- **It composes rather than replaces.** Existing SAST/SCA/DAST output is consumed as *evidence*, not as findings.

Recommended rollout:

1. baseline one representative service;
2. measure verified findings and rejected false positives;
3. add organization-specific policy and trust-boundary invariants;
4. gate verified High/Critical regressions in CI;
5. keep `UNKNOWN`/`BLOCKED` visible and fail closed where evidence is required;
6. measure precision, recall on known fixtures, time to verification, regression-proof rate, and recurrence.

Full guide: **[docs/ENTERPRISE-ADOPTION.md](docs/ENTERPRISE-ADOPTION.md)** · commercial boundary: [COMMERCIAL.md](docs/business/commercial.md)

## Model mesh

Different models can own different lanes without creating different security policy.

| Lane | Role |
|---|---|
| Mapper | architecture, entrypoints, trust boundaries |
| Authorization specialist | roles, ownership, BOLA/BFLA, fail-open paths |
| Business-logic specialist | money, inventory, refunds, retries, partial success |
| Variant hunter | sibling paths and repeated unsafe patterns |
| Runtime verifier | browser/API/DB/test evidence |
| Independent verifier | reconstructs and tries to disprove important findings |

**Model reputation never replaces evidence.**

## Documentation

- [Command recipes](docs/reference/command-recipes.md) — one instruction per review lane
- [Repository map](docs/reference/repository-map.md) — what lives where
- [Status vocabulary](docs/reference/status-vocabulary.md) — what `UNKNOWN`, `BLOCKED`, `VERIFIED`, `NOT_MEASURED`, and other SecHelix states actually assert
- [Zero-trust repository mode](docs/reference/untrusted-repo-mode.md) — auditing a hostile repository
- [AI, agent, and MCP security](docs/reference/ai-agent-security.md) — mechanisms, and what evidence refutes each one
- [Specialist agents](docs/reference/specialist-agents.md) — the 17 role profiles

**Evidence and decisions**

- [Policy packs](docs/reference/policy-packs.md) — release rules as versioned data, stamped into the report they decided
- [Verifier quorum](docs/reference/verifier-quorum.md) — independent verification paths that cannot see each other
- [Calibration](docs/reference/calibration.md) — does stated confidence predict the verifier's verdict
- [Proof bundles](docs/reference/proof-bundles.md) — one verified finding, exported so a recipient can check it
- [Campaigns](docs/reference/campaigns.md) — grouping findings by root cause so remediation is finite
- [Remediation loop](docs/reference/remediation-loop.md) — reviewing the fix as adversarially as the bug

**Analysis surfaces**

- [Runtime trace](docs/reference/runtime-trace.md) — correlating runtime observations with static evidence
- [Dependency exploitability](docs/reference/dependency-exploitability.md) — why a CVE being present is not enough
- [Secret lifecycle](docs/reference/secret-lifecycle.md) — detection is the easy part
- [MCP permission graph](docs/reference/mcp-permission-graph.md) — agent, server, tool, permission, data
- [AI-BOM](docs/reference/ai-bom.md) — inventory for an AI-enabled repository
- [Authorization graph](docs/reference/authorization-graph.md) — identity to role to permission to resource
- [Evidence cache](docs/reference/evidence-cache.md) — reuse only what is provably still valid
- [PR review mode](docs/reference/pr-review-mode.md) — silent unless something material changed

**Project**

- [Git history policy](docs/reference/git-history-policy.md) — squash-only, and why history is not rewritten
- [Branch protection](docs/reference/branch-protection.md) — the rulesets, and how they were verified
- [Open-core boundary](docs/architecture/open-core-boundary.md) — what would never be paywalled

- [Quickstart](docs/QUICKSTART.md)
- [Command cookbook](docs/COMMANDS.md)
- [Case study: gamingops-store](docs/case-studies/gamingops-store-2026-09-01.md)
- [Evaluation protocol](docs/EVALUATION.md)
- [Enterprise adoption](docs/ENTERPRISE-ADOPTION.md)
- [Compatibility](docs/reference/compatibility.md)
- [Architecture](ARCHITECTURE.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Extensions](docs/EXTENSIONS.md)
- [Roadmap](ROADMAP.md)
- [Trophy case](docs/research/trophy-case.md)
- [Discovery baseline](docs/research/discovery-baseline.md) — measured, 0 of 6 queries
- [Live docs](https://sechelix.com/docs)
- [FAQ](https://sechelix.com/faq)
- [AI-readable llms.txt](https://sechelix.com/llms.txt)

## Validation

Everything GitHub Actions runs, in order — run all of it before opening a pull request:

```bash
python scripts/validate_catalog.py
python scripts/validate_skill.py
python scripts/validate_extensions.py
python scripts/validate_knowledge.py
python scripts/validate_gold_packs.py
python scripts/check_private_site_leakage.py
python scripts/check_no_secrets.py
python scripts/check_local_links.py
python scripts/check_install_snippets.py
python -m unittest discover -s tests -p 'test_*.py'      # 93 tests
python -m unittest discover -s adapters/tests            # 19 tests
```

If you changed the canonical `SKILL.md` or any shared resource, re-sync the portable bundle and re-run the suite:

```bash
python scripts/sync_portable_skill.py
```

This validates catalog identity, source rights and use boundaries, knowledge provenance, research confidence, the standalone install bundle, schemas, adapters, reporting, policy gates, secrets, private-site separation, and public-release invariants.

## Trophy case

SecHelix only lists findings that have **public, attributable evidence** and permission to be referenced.

Current state: **no public entries yet**. That is deliberate; a new project is better served by an empty trophy case than unverifiable claims.

The [gamingops-store case study](docs/case-studies/gamingops-store-2026-09-01.md) is deliberately *not* a trophy entry — the target repository is private, so the result is not independently verifiable by a reader. It is published as a worked example instead.

Found a real bug using SecHelix? Open a [trophy-case submission](https://github.com/omarmohelal/SecHelix/issues/new?template=trophy-case.yml) with the public repository, SecHelix version, safe evidence, a public fix reference, and attribution permission.

See [TROPHY_CASE.md](docs/research/trophy-case.md).

## Contributing

Useful contributions include:

- false-positive fixtures;
- vulnerable/clean eval pairs;
- security hypothesis proposals;
- verified knowledge mappings and lesson cards;
- scanner/SARIF adapters;
- Gold Check Packs;
- company rollout feedback;
- documentation improvements.

Security checks should be proposed as **testable hypotheses**, not slogans.

[Read the contribution guide](CONTRIBUTING.md) · [Propose an extension](https://github.com/omarmohelal/SecHelix/issues/new?template=extension.yml)

## License

Apache-2.0.

---

<p align="center">
  <strong>SecHelix</strong><br/>
  Verify before you accuse.<br/>
  <a href="https://sechelix.com">sechelix.com</a>
</p>
