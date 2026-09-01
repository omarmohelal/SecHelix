<p align="center">
  <img src="assets/readme-hero.svg" alt="SecHelix — Evidence-first multi-agent AppSec" width="100%" />
</p>

<p align="center">
  <strong>Security findings are claims. SecHelix proves them.</strong><br/>
  Map the attack surface → select applicable checks → hunt in parallel → independently verify → fix the root cause → prove the regression → gate the release.
</p>

<p align="center">
  <a href="https://skills.sh/omarmohelal/SecHelix"><img src="https://img.shields.io/badge/skills.sh-SecHelix-6ee7b7?style=flat-square" alt="skills.sh"/></a>
  <a href="https://github.com/omarmohelal/SecHelix/actions"><img src="https://img.shields.io/github/actions/workflow/status/omarmohelal/SecHelix/validate.yml?branch=main&style=flat-square&label=validate" alt="validation"/></a>
  <a href="SKILL.md"><img src="https://img.shields.io/badge/security%20hypotheses-546-7dd3fc?style=flat-square" alt="546 hypotheses"/></a>
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/release-3.0.0--alpha.4-9b8cff?style=flat-square" alt="3.0.0 alpha 4"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-a78bfa?style=flat-square" alt="Apache-2.0"/></a>
</p>

<p align="center">
  <a href="#install-in-30-seconds">Install</a> ·
  <a href="docs/QUICKSTART.md">Quickstart</a> ·
  <a href="docs/COMMANDS.md">Commands</a> ·
  <a href="#coverage">Coverage</a> ·
  <a href="docs/EVALUATION.md">Evaluation</a> ·
  <a href="docs/ENTERPRISE-ADOPTION.md">Enterprise</a> ·
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
| Coverage | **546 stable security hypothesis IDs** across 21 families and 26 lenses |
| Specialist mesh | **17 model-neutral role profiles**, including an independent verifier |
| Contracts | **15 JSON Schema Draft 2020-12 contracts** for scope, applicability, evidence, findings, reports, extensions, knowledge, and Gold Check Packs |
| Evidence adapters | Semgrep, CodeQL/SARIF, OSV, Gitleaks, Trivy, npm/pnpm audit, Playwright, ZAP, Nuclei |
| Reports | Markdown, redacted JSON, SARIF 2.1.0, escaped standalone HTML |
| Release truth | `PASS`, `PASS_WITH_KNOWN_RISK`, `BLOCKED`, or fail-closed `INCOMPLETE` |
| Public benchmark | **NOT_MEASURED** until a reproducible run satisfies the published evaluation protocol |
| Trophy case | Public attributable results only; no unverifiable entries |

The canonical live product is **[sechelix.com](https://sechelix.com)**. The website source remains private; this repository contains the open security framework, portable Agent Skill, adapters, schemas, eval fixtures, and public documentation.

## Install in 30 seconds

### Recommended — Agent Skills CLI

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

Then ask your coding agent:

```text
Use SecHelix for a complete authorized security audit of this repository.
Start STATIC, map the attack surface and trust boundaries, evaluate only applicable hypotheses,
independently verify High/Critical candidates, fix root causes, add regression proof, retest,
and produce the final release gate.
```

**Next:** [5-minute Quickstart](docs/QUICKSTART.md) · [Command cookbook](docs/COMMANDS.md) · [Compatibility](COMPATIBILITY.md)

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

The repository ships both `.agents/skills/sechelix/` and `.codex/skills/sechelix/` adapters for repo-local discovery patterns.

</details>

<details>
<summary><strong>GitHub Copilot / VS Code agents</strong></summary>

The repository includes:

```text
.github/skills/sechelix/SKILL.md
```

You can also install the portable source with the Agent Skills CLI.

</details>

<details>
<summary><strong>Cursor / Gemini CLI / GLM / OpenCode / other Agent Skills clients</strong></summary>

Use the cross-client installer when supported:

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

Otherwise use the vendor-neutral `skills/sechelix/` bundle with the host's documented skill loader.

</details>

## Common commands

SecHelix is a skill, so the main interface is a clear instruction to the coding agent rather than a single scanner CLI.

### Full audit

```text
Use SecHelix for a complete authorized security audit of this repository.
Map first. Select only applicable checks. Verify important candidates independently.
Fix root causes, add regression tests, retest, and return the release decision.
```

### Authorization / IDOR / BOLA

```text
Use SecHelix to audit authorization.
Build a Guest/User A/User B/Staff/Admin role × object × action matrix.
Focus on BOLA/IDOR, BFLA, tenant isolation, ownership, mass assignment, client-controlled identity/role fields,
UI-only authorization, and storage/RLS policy gaps.
```

### Business logic / payments / races

```text
Use SecHelix to audit business logic, payment/accounting truth, idempotency, and concurrency.
Map state transitions and test replay, duplicate execution, partial success, late callbacks,
price/quantity tampering, negative values, stale state, TOCTOU, and double-spend windows in a safe environment.
```

### AI / Agent / MCP security

```text
Use SecHelix to audit AI/LLM/agent/MCP security.
Map prompt/context sources, RAG, memory, tool permissions, MCP servers, external URLs, and autonomous side effects.
Check prompt injection, tool authorization, unsafe output reaching sinks, cross-user leakage, poisoning,
SSRF through tools, excessive agency, and tool/plugin supply-chain risk.
```

### Pull request security review

```text
Use SecHelix to security-review this PR.
Map changed trust boundaries and dataflows, verify material candidates against existing controls,
and state whether the PR introduces a verified blocker, known risk, or no evidence-backed security regression.
```

### Release gate

```text
Run the SecHelix release gate.
Return PASS, PASS_WITH_KNOWN_RISK, BLOCKED, or INCOMPLETE.
Fail closed for missing required evidence and never convert UNKNOWN/BLOCKED into NOT_APPLICABLE.
```

More recipes: **[docs/COMMANDS.md](docs/COMMANDS.md)**.

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

SecHelix deliberately does not claim a measured accuracy number yet.

A public score is allowed only after a reproducible run records the exact SecHelix commit, target/fixture version, model/provider configuration, enabled tools, expected ground truth, observed outcomes, false positives, false negatives, `UNKNOWN`/`BLOCKED` cases, and supporting artifacts.

Metrics are defined in **[docs/EVALUATION.md](docs/EVALUATION.md)**, including:

- verified precision;
- detection recall on known-ground-truth fixtures;
- false-positive rejection rate;
- applicability accuracy;
- regression-proof rate;
- release-gate accuracy.

Until then, benchmark status remains **`NOT_MEASURED`**.

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

## Enterprise adoption

SecHelix is designed to coexist with existing SAST, SCA, DAST, browser, runtime, cloud, and organization-specific tooling.

Recommended rollout:

1. baseline one representative service;
2. measure verified findings and rejected false positives;
3. add organization-specific policy and trust-boundary invariants;
4. gate verified High/Critical regressions in CI;
5. keep `UNKNOWN`/`BLOCKED` visible and fail closed where evidence is required;
6. measure precision, recall on known fixtures, time to verification, regression-proof rate, and recurrence.

Full guide: **[docs/ENTERPRISE-ADOPTION.md](docs/ENTERPRISE-ADOPTION.md)** · [COMMERCIAL.md](COMMERCIAL.md)

## Repository map

```text
SecHelix/
├── SKILL.md                    # canonical methodology
├── skills/sechelix/           # portable Agent Skills bundle
├── .claude-plugin/            # Claude Code plugin manifest
├── .claude/skills/sechelix/   # Claude Code project adapter
├── .agents/skills/sechelix/   # repo-local Agent Skills adapter
├── .codex/skills/sechelix/    # Codex adapter
├── .github/skills/sechelix/   # GitHub Copilot / VS Code adapter
├── agents/                    # specialist reviewer profiles
├── catalog/                   # 546 structured hypotheses
├── knowledge/                 # source trust, provenance graph, lesson cards
├── schemas/                   # versioned JSON contracts
├── sechelix_core/             # applicability, graph, catalog, contract core
├── adapters/                  # normalized scanner/tool evidence adapters
├── reports/                   # Markdown/JSON/SARIF/HTML renderer
├── policies/                  # release-gate policies
├── references/                # methodology + standards + tooling
├── scripts/                   # validation + release gates
├── examples/                  # scope + report examples
├── extensions/                # community extension registry
├── evals/                     # paired fixtures + NOT_MEASURED baseline
├── docs/                      # quickstart, commands, evaluation, rollout
└── .github/                   # CI + contribution templates
```

## Documentation

- [Quickstart](docs/QUICKSTART.md)
- [Command cookbook](docs/COMMANDS.md)
- [Evaluation protocol](docs/EVALUATION.md)
- [Enterprise adoption](docs/ENTERPRISE-ADOPTION.md)
- [Compatibility](COMPATIBILITY.md)
- [Architecture](ARCHITECTURE.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Extensions](docs/EXTENSIONS.md)
- [Roadmap](ROADMAP.md)
- [Trophy case](TROPHY_CASE.md)
- [Live docs](https://sechelix.com/docs)
- [FAQ](https://sechelix.com/faq)
- [AI-readable llms.txt](https://sechelix.com/llms.txt)

## Validation

```bash
python -m unittest discover -s tests -v
python -m unittest discover -s adapters/tests -v
python scripts/validate_catalog.py
python scripts/validate_extensions.py
python scripts/validate_knowledge.py
python scripts/validate_skill.py
python scripts/check_no_secrets.py
python scripts/check_private_site_leakage.py
npx skills@latest add . --list
```

The repository validates catalog identity, source rights/use boundaries, knowledge provenance, research confidence, the standalone install bundle, schemas, adapters, reporting, policy gates, secrets, private-site separation, and public-release invariants in GitHub Actions.

## Trophy case

SecHelix only lists findings that have **public, attributable evidence** and permission to be referenced.

Current state: **no public entries yet**. That is deliberate; a new project is better served by an empty trophy case than unverifiable claims.

Found a real bug using SecHelix? Use the trophy-case issue template with the public repository, SecHelix version, safe evidence, fix reference, and attribution permission.

See [TROPHY_CASE.md](TROPHY_CASE.md).

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
