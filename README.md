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
  <a href="#evaluation-and-proof-status"><img src="https://img.shields.io/badge/benchmark-NOT__MEASURED-f59e0b?style=flat-square" alt="benchmark NOT_MEASURED"/></a>
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/release-3.0.0--alpha.5-9b8cff?style=flat-square" alt="3.0.0 alpha 5"/></a>
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
| Contracts | **15 JSON Schema Draft 2020-12 contracts** for scope, applicability, evidence, findings, reports, extensions, knowledge, and Gold Check Packs |
| Gold Check Packs | **5 deep reference packs** (IDOR, SSRF, race/idempotency, money invariants, AI/MCP tool authority) |
| Eval fixtures | **19 paired fixtures — 38 cases across 10 families**, each with a vulnerable and a clean variant |
| Knowledge graph | **73 nodes, 96 edges**, provenance-backed, plus **7 lesson cards** |
| Evidence adapters | Semgrep, CodeQL/SARIF, OSV, Gitleaks, Trivy, npm/pnpm audit, Playwright, ZAP, Nuclei |
| Reports | Markdown, redacted JSON, SARIF 2.1.0, escaped standalone HTML |
| Release truth | `PASS`, `PASS_WITH_KNOWN_RISK`, `BLOCKED`, or fail-closed `INCOMPLETE` |
| Zero-trust audits | **`UNTRUSTED_REPO` mode** — repository content is data, never control ([details](docs/reference/untrusted-repo-mode.md)) |
| Change review | **Differential security review** — classifies a diff into `NEW_RISK` / `RISK_REDUCED` / `UNCHANGED` / `UNKNOWN` |
| Real-world proof | **1 published case study** — [gamingops-store](docs/case-studies/gamingops-store-2026-09-01.md) |
| Public benchmark | **`NOT_MEASURED`** — [blocker documented](evals/results/not-measured.json), see [Evaluation](#evaluation-and-proof-status) |
| Trophy case | Public attributable results only; **no entries yet** |

The canonical live product is **[sechelix.com](https://sechelix.com)**. The website source remains private; this repository contains the open security framework, portable Agent Skill, adapters, schemas, eval fixtures, and public documentation.

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

SecHelix has **no measured accuracy number**, and the reason is written down rather than glossed over.

**The blocker is `CONTAMINATED_EVALUATOR`.** The fixture suite was expanded on 2026-09-01 by the same assistant session that would have acted as the evaluated model, so that session had prior knowledge of 11 of the 19 fixtures. Scoring it would measure recall of authored answers, not security-review capability. Full record: [`evals/results/not-measured.json`](evals/results/not-measured.json).

Unblocking it requires a run by a model or session that did not author the fixtures, using blind cases exported with `python evals/run_evals.py --export-cases`.

**The harness itself is validated.** [`evals/results/baseline-keyword-v1.json`](evals/results/baseline-keyword-v1.json) records a naive regex keyword matcher run against all 38 cases. It carries `"is_sechelix_result": false` and **is not a SecHelix score.** It exists to prove two things: the scoring harness works, and the fixtures cannot be solved by pattern matching — the matcher lands at chance on a balanced 19/19 split. That is a statement about fixture difficulty, nothing else.

Metrics are defined in **[docs/EVALUATION.md](docs/EVALUATION.md)**: verified precision, detection recall on known-ground-truth fixtures, false-positive rejection rate, applicability accuracy, regression-proof rate, and release-gate accuracy. A public score is allowed only after a reproducible run records the exact SecHelix commit, fixture version, model/provider configuration, enabled tools, ground truth, observed outcomes, false positives and negatives, `UNKNOWN`/`BLOCKED` cases, and supporting artifacts.

Until then, benchmark status remains **`NOT_MEASURED`**.

## Limitations

Read this before adopting.

- **No benchmark.** See above. Any accuracy claim about SecHelix today would be unsupported.
- **One case study, `n = 1`.** A ~600 LOC app with no authentication and no server-side state, audited by its own owner. It demonstrates the workflow; it measures nothing about general performance.
- **No public third-party results.** The [trophy case](docs/research/trophy-case.md) is empty on purpose.
- **Alpha.** `3.0.0-alpha.5`. Contracts are versioned, but they can still change.
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
- [Zero-trust repository mode](docs/reference/untrusted-repo-mode.md) — auditing a hostile repository
- [Specialist agents](docs/reference/specialist-agents.md) — the 17 role profiles

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
