<p align="center">
  <img src="assets/readme-hero.svg" alt="SecHelix — Evidence-first multi-agent AppSec" width="100%" />
</p>

<p align="center">
  <strong>Multi-agent application security that verifies before it accuses.</strong><br/>
  Map the attack surface → hunt in parallel → independently verify → fix the root cause → prove the regression.
</p>

<p align="center">
  <a href="https://skills.sh/omarmohelal/SecHelix"><img src="https://img.shields.io/badge/skills.sh-SecHelix-6ee7b7?style=flat-square" alt="skills.sh"/></a>
  <a href="https://github.com/omarmohelal/SecHelix/actions"><img src="https://img.shields.io/github/actions/workflow/status/omarmohelal/SecHelix/validate.yml?branch=main&style=flat-square&label=validate" alt="validation"/></a>
  <a href="SKILL.md"><img src="https://img.shields.io/badge/security%20hypotheses-546-7dd3fc?style=flat-square" alt="546 hypotheses"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-a78bfa?style=flat-square" alt="Apache-2.0"/></a>
  <a href="site/support.html"><img src="https://img.shields.io/badge/support-crypto-facc15?style=flat-square" alt="Support SecHelix"/></a>
</p>

<p align="center">
  <a href="#install-in-30-seconds">Install</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#coverage">Coverage</a> ·
  <a href="#model-mesh">Model mesh</a> ·
  <a href="#company-rollout">Companies</a> ·
  <a href="ROADMAP.md">Roadmap</a> ·
  <a href="site/support.html">Support</a>
</p>

---

## What is SecHelix?

SecHelix is an **evidence-first AppSec skill and orchestration methodology** for repositories and environments you are authorized to test.

It is intentionally not “an AI scanner with 500 payloads.” Instead, it coordinates code-reading agents, security tools, browser/runtime evidence, and an independent verifier under one shared standard.

> [!IMPORTANT]
> A scanner alert is not a vulnerability.  
> A model suspicion is not a vulnerability.  
> Two models agreeing is not independent proof.

A finding becomes trusted only when the evidence supports attacker control, reachability, a failed security boundary, a safe reproduction, concrete impact, root cause, and regression proof.

## Install in 30 seconds

### Recommended — skills CLI

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

Then tell your coding agent:

```text
Run a SecHelix security audit on this repository.
Start with scope and attack-surface mapping.
Only execute applicable checks.
Independently verify every High/Critical finding before reporting it.
```

<details>
<summary><strong>Claude Code</strong></summary>

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

Or copy the project-local adapter:

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

The repository also ships a `.codex/skills/sechelix/` adapter.

</details>

<details>
<summary><strong>Z.AI / GLM</strong></summary>

SecHelix stays model-agnostic. Run GLM inside a supported coding host (Claude Code, Cursor, OpenCode, Cline, etc.) and install the skill through that host's skill loader.

Use `skills/sechelix/` as the vendor-neutral source of truth.

</details>

<details>
<summary><strong>Cursor / Copilot / other Agent Skills clients</strong></summary>

Use:

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

If your host has no installer, copy `skills/sechelix/` into its documented Agent Skills directory.

See [COMPATIBILITY.md](COMPATIBILITY.md).

</details>

## How it works

```text
                 ┌──────────────────────────────┐
                 │          SCOPE               │
                 │ authorization + stop rules   │
                 └──────────────┬───────────────┘
                                ↓
      ┌──────────────────────────────────────────────────┐
      │ MAP identities • assets • entrypoints • states  │
      │ trust boundaries • roles • providers • data     │
      └──────────────────────┬───────────────────────────┘
                             ↓
            select APPLICABLE hypotheses only
                             ↓
      ┌──────────┬──────────┬──────────┬──────────┐
      │ Auth/Z   │ Web/API  │ Logic    │ Races    │  ...
      │ reviewer │ reviewer │ reviewer │ reviewer │
      └────┬─────┴────┬─────┴────┬─────┴────┬─────┘
           └──────────┴───────────┴──────────┘
                             ↓
                   INDEPENDENT VERIFIER
                   tries to refute claims
                             ↓
                    ROOT-CAUSE FIX
                             ↓
                    REGRESSION PROOF
                             ↓
                       RELEASE GATE
```

### Evidence standard

A verified vulnerability should establish:

1. **Attacker control**
2. **Reachability**
3. **Boundary failure**
4. **Safe reproduction**
5. **Concrete impact**
6. **Preconditions**
7. **Root cause**
8. **Fix**
9. **Regression proof**

High/Critical candidates get an independent refutation pass before final reporting.

## Model mesh

Different models can own different lanes without creating different security policies.

| Lane | Good fit | Role |
|---|---|---|
| Mapper | large-context model | architecture, entrypoints, trust boundaries |
| Authorization | strong reasoning model | role/object/action matrix, BOLA/BFLA, fail-open paths |
| Business logic | strong reasoning model | money, refunds, inventory, partial success, abuse cases |
| Variants | fast/cheap model | repeated-pattern and sibling-path hunting |
| Runtime | browser + DB + test tools | prove behavior rather than infer it |
| Verifier | **different model/provider** | reconstruct and try to disprove important findings |

SecHelix can sit above Claude, Codex, GLM, Gemini, Cursor-hosted models, and scanners. **Model reputation never replaces evidence.**

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

SecHelix marks each hypothesis `APPLICABLE`, `NOT_APPLICABLE`, or `UNKNOWN_NEEDS_EVIDENCE`. It does **not** spray every check at every target.

## Where SecHelix is different

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

SecHelix treats exact-once, state machines, accounting truth, retries, and race windows as security surfaces.

### Noise gets challenged

Every important candidate can be routed to a verifier whose job is to **disprove** it. Compensation controls, unreachable states, role prerequisites, and impossible attacker inputs are valid reasons to reject a finding.

### Runtime proof can outrank static confidence

Typecheck can be green while the browser bundle is broken. Unit tests can be green while a database constraint rejects the real write. SecHelix can require build, browser, database, or migration proof at the layer where the invariant actually lives.

## Safe execution modes

| Mode | Intended use | Dynamic traffic |
|---|---|---|
| `STATIC` | source/config/schema review | none |
| `LOCAL` | local app + fixtures | local only |
| `STAGING` | authorized non-production environment | allowlisted |
| `PRODUCTION_SAFE` | bounded non-destructive verification | tightly restricted |

> [!WARNING]
> SecHelix is for systems you own or are explicitly authorized to test. It does not turn code review into uncontrolled internet scanning, credential theft, persistence, destructive payloads, or denial-of-service testing.

See [SECURITY.md](SECURITY.md).

## Repository layout

```text
SecHelix/
├── SKILL.md                    # canonical methodology
├── skills/sechelix/            # portable Agent Skills bundle
├── .claude/skills/sechelix/    # Claude Code adapter
├── .codex/skills/sechelix/     # Codex adapter
├── agents/                     # specialist reviewer profiles
├── catalog/                    # structured security hypotheses
├── references/                 # methodology + standards + tooling
├── scripts/                    # validation + release gates
├── examples/                   # scope + report examples
├── evals/                      # benchmark direction
├── docs/                       # rollout + design docs
├── site/                       # landing page + support page
└── .github/                    # CI + Pages + contribution templates
```

## Company rollout

SecHelix is designed so a company can keep the open methodology while adding private policy:

1. baseline one service;
2. measure verified findings and false positives;
3. add organization-specific trust boundaries and policy packs;
4. gate verified High/Critical findings in CI;
5. require browser/staging proof for critical workflows;
6. evaluate model/scanner performance on internal fixtures.

See [docs/company-rollout.md](docs/company-rollout.md) and [COMMERCIAL.md](COMMERCIAL.md).

## Validation

```bash
python scripts/validate_catalog.py
python scripts/validate_skill.py
python scripts/security_gate.py --help
```

The repository validates catalog identity, skill structure, adapters, and public-release invariants in GitHub Actions.

## Trophy case

SecHelix is young, so the trophy case starts empty **on purpose**. We will only list issues where the evidence is public and the project/maintainer permits attribution.

Found a real bug using SecHelix? Open an issue and include the safe public evidence.

See [TROPHY_CASE.md](TROPHY_CASE.md).

## Roadmap

Near-term:

- SARIF normalization
- Semgrep / CodeQL adapters
- OSV / Trivy / Gitleaks evidence adapters
- browser verification packs
- vulnerable + clean eval fixtures
- model-role benchmarks
- false-positive benchmark
- signed evidence bundles
- organization policy packs
- optional multi-provider orchestration

See [ROADMAP.md](ROADMAP.md).

## Support the project

SecHelix is open source. Donations help fund model/API evals, intentionally vulnerable fixtures, scanner adapters, domain/hosting, and maintainer time.

**Official crypto addresses live only in the repository and the official SecHelix domain. Always verify the asset and network before sending.**

[Open the support page →](site/support.html)

## Contributing

Contributions are welcome, especially:

- false-positive fixtures;
- vulnerable/clean eval pairs;
- security hypothesis proposals;
- scanner/SARIF adapters;
- company rollout feedback;
- documentation improvements.

Security checks should be proposed as **testable hypotheses**, not slogans.

Read [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0.

---

<p align="center">
  <strong>SecHelix</strong><br/>
  Verify before you accuse.
</p>
