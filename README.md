# SecHelix

> **Evidence-first multi-agent application security for AI coding agents.**
>
> Map the attack surface, select relevant checks, hunt in parallel, independently verify findings, fix root causes, and prove regressions before release.

[![Agent Skills](https://img.shields.io/badge/Agent%20Skills-compatible-6ee7b7)](https://agentskills.io)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-supported-7dd3fc)](https://code.claude.com/docs/en/slash-commands)
[![OpenAI Skills](https://img.shields.io/badge/OpenAI-SKILL.md-60a5fa)](https://openai.com/academy/skills/)
[![License](https://img.shields.io/badge/license-Apache--2.0-a78bfa)](LICENSE)
[![Security checks](https://img.shields.io/badge/security%20hypotheses-546-f472b6)](catalog/checks.json)

SecHelix is a portable security-audit skill and orchestration methodology for **authorized** application-security work. It is designed to work across skills-capable coding agents and to remain useful when different models are used for different review lanes.

It is not a scanner that declares every alert a vulnerability. A SecHelix finding is promoted only when the evidence chain supports it.

```text
scope
  ↓
map architecture + trust boundaries
  ↓
select applicable hypotheses
  ↓
parallel specialist review
  ↓
independent verification
  ↓
root-cause fix
  ↓
regression proof
  ↓
release gate
```

## Why SecHelix

Security automation often fails in one of two ways: shallow checklists that miss business logic, or noisy scanners that produce findings nobody trusts. SecHelix is built around **evidence, applicability, and independent verification**.

- **546 security hypotheses** across 21 families.
- **Multi-agent review lanes** for auth/authz, web/input, business logic, races, supply chain, AI/MCP, and verification.
- **Business-logic-first coverage** for payouts, refunds, inventory, idempotency, partial fulfillment, tenant isolation, and state-machine abuse.
- **Portable `SKILL.md` core** following the Agent Skills format.
- **Model-agnostic methodology**: Claude, Codex/OpenAI skills, GLM through supported coding tools, Cursor, Copilot, Gemini/OpenCode-compatible workflows where their skill loaders support the open format.
- **Safe execution modes**: static, local, staging, and production-safe.
- **No exploit-by-default behavior**: dynamic testing stays inside explicitly authorized scope.

## What counts as a verified finding?

```text
attacker-controlled input
        ↓
reachable path
        ↓
trust boundary failure
        ↓
safe reproduction
        ↓
concrete impact
        ↓
root cause
        ↓
regression test
```

Two models agreeing is **not** proof. A scanner alert is **not** proof. A suspicious code pattern is a hypothesis until independently verified.

## Quick start

### Claude Code

Project-local installation:

```bash
mkdir -p .claude/skills/sechelix
cp -R skills/sechelix/* .claude/skills/sechelix/
```

Then ask:

```text
Run a SecHelix security audit on this repository. Start with scope and attack-surface mapping, then execute only applicable checks. Verify every High/Critical independently before reporting it.
```

Claude Code follows the Agent Skills open standard and loads project skills from `.claude/skills/<name>/SKILL.md`.

### OpenAI / Codex / Skills API

Use the canonical folder `skills/sechelix/` or upload the skill bundle/ZIP to a skills-capable OpenAI workflow. The canonical skill is vendor-neutral and does not rely on Claude-only syntax.

### Z.AI / GLM

Z.AI officially supports running GLM models through tools such as Claude Code, OpenCode, Cline, Cursor and other coding agents. When GLM is running inside Claude Code, install SecHelix exactly as a Claude Code skill. In generic tools, use `skills/sechelix/` plus `AGENTS.md` as the portable fallback.

See [COMPATIBILITY.md](COMPATIBILITY.md) for tested vs documented support levels. SecHelix intentionally avoids claiming a native skill path where a vendor has not documented one.

## Repository layout

```text
SecHelix/
├── SKILL.md                         # canonical skill entrypoint
├── skills/sechelix/                 # vendor-neutral distributable skill
├── .claude/skills/sechelix/         # Claude Code adapter
├── .codex/skills/sechelix/          # Codex/local adapter
├── .github/skills/sechelix/         # GitHub/Copilot-friendly mirror
├── .agents/skills/sechelix/         # generic Agent Skills mirror
├── agents/                           # specialist reviewer profiles
├── catalog/                          # 546 hypotheses / 21 families
├── references/                       # methodology, sources, tooling
├── scripts/                          # validation and release gates
├── examples/                         # scope + report examples
├── docs/                             # company rollout + authoring docs
├── site/                             # SecHelix landing page
└── .github/workflows/                # validation + GitHub Pages
```

## Security families

Authentication · Sessions · Authorization/BOLA/BFLA · Injection · API security · Files/uploads · SSRF · Browser/client · Business logic · Payments/accounting · Race conditions/idempotency · Database/migrations/RPCs · Cryptography/secrets · Supply chain · CI/CD · Cloud/config · Privacy/logging · AI/Agent/MCP · Operational security · Release security · Attack-surface mapping.

## Safety model

SecHelix is for systems you own or are explicitly authorized to test.

Execution modes:

| Mode | Intended use | Dynamic traffic |
|---|---|---|
| `STATIC` | code/config review | none |
| `LOCAL` | local application + fixtures | local only |
| `STAGING` | authorized non-production environment | allowlisted |
| `PRODUCTION_SAFE` | evidence gathering + non-destructive verification | tightly bounded |

See [SECURITY.md](SECURITY.md) and [references/methodology.md](references/methodology.md).

## For teams and companies

SecHelix can be adopted incrementally:

1. Run the skill against one service.
2. Baseline verified findings and false positives.
3. Add organization-specific policy packs.
4. Gate High/Critical findings in CI.
5. Add browser/staging verification for critical workflows.
6. Track model/scanner performance with eval fixtures.

See [docs/company-rollout.md](docs/company-rollout.md) and [COMMERCIAL.md](COMMERCIAL.md).

## Roadmap

Near-term work includes SARIF normalization, Semgrep/CodeQL/OSV/Trivy/Gitleaks adapters, browser verification packs, model-role evaluation, vulnerable fixtures, signed evidence bundles, organization policies, and an optional multi-provider orchestration layer.

See [ROADMAP.md](ROADMAP.md).

## Support SecHelix

SecHelix is open source. The landing page includes a crypto-ready support flow that can be enabled by adding your public donation addresses or a donation-provider widget configuration. No wallet address is hardcoded in the repository.

See [SUPPORT.md](SUPPORT.md).

## Contributing

Security checks should be proposed as **testable hypotheses**, not slogans. Each high-risk addition should explain applicability, evidence requirements, false-positive traps, and safe verification.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. Enterprise-friendly for the open core, while leaving room for future hosted/managed/enterprise services around the project.

---

**SecHelix** — verify before you accuse.