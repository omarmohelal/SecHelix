<p align="center">
  <img src="assets/brand/readme-hero.png" alt="SecHelix — evidence-first application security for coding agents" width="100%" />
</p>

<p align="center">
  <strong>Security findings are claims. SecHelix verifies them before they become findings.</strong>
</p>

<p align="center">
  <a href="https://github.com/omarmohelal/SecHelix/actions"><img src="https://img.shields.io/github/actions/workflow/status/omarmohelal/SecHelix/validate.yml?branch=main&style=flat-square&label=validate" alt="validation"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-a78bfa?style=flat-square" alt="Apache-2.0"/></a>
</p>

# SecHelix

SecHelix is an open-source **AppSec Agent Skill** for security-reviewing code you own or are authorized to test.

It helps a coding agent:

- map the attack surface and trust boundaries;
- review only security checks that apply to the project;
- investigate authentication, authorization, business logic, injection, SSRF, files, supply chain, AI/MCP and other security surfaces;
- verify important candidates instead of reporting guesses;
- fix the root cause;
- add regression proof and retest;
- return a clear release decision.

SecHelix is **not** a scanner that treats every alert as a vulnerability.

## See it work in 90 seconds

```bash
git clone https://github.com/omarmohelal/SecHelix && cd SecHelix
python examples/expense-api/prove.py
```

A small multi-tenant API with two candidate issues. One is a real cross-tenant
read that a scanner walks past, because the endpoint *does* have an
authorization check — it just checks the wrong thing. The other is f-string SQL
that every pattern matcher flags and that is not exploitable at all.

Walkthrough, root cause, the two-line fix and the regression proof:
**[examples/expense-api](examples/expense-api/README.md)**.

## Install

Recommended for Agent Skills-compatible coding agents:

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

Then open the repository you want to review in your coding agent.

## Use it

### Full security audit

Copy this into your agent:

```text
Use SecHelix for a complete authorized security audit of this repository.
Start STATIC and use LOCAL only if it is safe and useful.
Map the attack surface and trust boundaries first.
Verify important candidates before reporting them.
Fix root causes, add regression tests, retest, and give me the final release gate.
```

### Fast security review

```text
Use SecHelix to triage this repository for security issues.
Prioritize authentication, authorization, business logic, secrets, injection, SSRF, file handling, supply chain, dangerous configuration, and AI/MCP surfaces.
Return evidence-backed findings and clearly mark anything unproven.
```

### AI-built app launch audit

Use this before launching an AI-generated, agent-generated, rapidly prototyped, or vibe-coded application:

```text
Use SecHelix's AI-Built App Launch Audit on this authorized application.
Evaluate launch checks 01-36 from references/ai-built-app-launch.md.
Do not mark PASS without exact code, configuration, policy, test, log, or safe runtime evidence.
For every FAIL or security-relevant UNKNOWN, give the realistic failure mode, smallest root-cause fix, and exact safe verification step.
After fixes, re-run the failed/unknown checks and produce the normal SecHelix release gate.
```

The launch profile covers practical pre-release failures around secrets, auth/authz, cross-user data, database/storage permissions, debug exposure, input validation, SQL/NoSQL injection, XSS/CSRF, uploads, traversal, SSRF, password reset, sessions/JWT, CORS, rate limiting, staging, default credentials, webhooks, payments/entitlements, IDOR/BOLA, sensitive logs, and production artifacts.

### Review a pull request

```text
Review this PR with SecHelix.
Focus on security changes introduced by the diff, verify important candidates, and tell me whether the PR introduces a verified blocker or known risk.
```

### Fix findings

```text
Use SecHelix Fix Mode on the verified findings.
Fix the root cause, look for variants of the same bug, add security regression tests, and retest the original finding.
```

More copy-paste workflows: **[Command Cookbook](docs/COMMANDS.md)**.

## What should I ask SecHelix to do?

| Goal | Ask for |
|---|---|
| Full repository review | `complete security audit` |
| Quick first pass | `security triage` |
| AI-built/vibe-coded app before launch | `AI-Built App Launch Audit` |
| Broken access control | `authorization / IDOR / BOLA audit` |
| Login and sessions | `authentication / session / OAuth audit` |
| Input handling | `injection / XSS / SSRF / files audit` |
| Payments and workflows | `business logic / race / idempotency audit` |
| Dependencies and CI | `supply chain / CI/CD audit` |
| LLMs, agents and tools | `AI / Agent / MCP security audit` |
| A code change | `PR security review` |
| Existing verified issues | `Fix Mode` |
| Release decision | `release gate` |
| Shareable output | `security report` |

You do not need to memorize special slash commands. SecHelix is primarily a skill: tell the coding agent what security job you want done.

## How the review works

```text
scope
  → map attack surface
  → select applicable checks
  → investigate
  → independently verify important candidates
  → fix root cause
  → add regression proof
  → retest
  → report + release gate
```

A scanner match or model suspicion is treated as a **candidate**, not automatically as a vulnerability.

A strong finding should show the affected surface, attacker control or security boundary involved, reachability, impact, root cause, safe evidence, the fix, and regression/retest status.

## Optional CLI runtime

The Agent Skill works without the Python runtime. The runtime is optional and adds stored runs, coverage tracking, replayable evidence, reports, CI-friendly exit codes, and an MCP adapter.

Install it with:

```bash
pipx install sechelix
sechelix doctor
```

`uv tool install sechelix` and `python -m pip install sechelix` are also supported.

### Useful CLI commands

| Command | What it does |
|---|---|
| `sechelix doctor` | Shows available components and reasoning executors |
| `sechelix audit . --executor claude-code` | Runs an audit using Claude Code as the reasoning executor |
| `sechelix audit . --executor gemini-cli` | Runs an audit using Gemini CLI as the reasoning executor |
| `sechelix runs` | Lists saved runs and checks their integrity |
| `sechelix coverage` | Shows what previous runs did not examine |
| `sechelix report` | Renders the latest saved run |
| `sechelix replay <run_id>` | Replays a recorded run offline and checks consistency |
| `sechelix mcp` | Serves the local MCP adapter over stdio |

Example:

```bash
sechelix doctor
sechelix audit . --executor claude-code
sechelix coverage
sechelix report --format markdown
```

> `sechelix audit .` with the default `--executor none` intentionally does **not** pretend to analyze code. Reasoning nodes are blocked and the run remains incomplete until a real executor is configured.

For all CLI flags:

```bash
sechelix --help
sechelix audit --help
```

Advanced runtime guide: **[V4 Runtime Quickstart](docs/v4-quickstart.md)**.

## GitHub Action

```yaml
- uses: omarmohelal/SecHelix@v4.0.0-alpha.2
  with:
    executor: none
```

Outputs `PASS`, `PASS_WITH_KNOWN_RISK`, `BLOCKED` or `INCOMPLETE`, writes SARIF
for code scanning, and uploads the run as an artifact. The default
`executor: none` deliberately reports `INCOMPLETE` rather than a green check it
did not earn — configure a reasoning executor to get an actual review.

Full reference: **[GitHub Action](docs/github-action.md)**.

## Execution modes

| Mode | Use it for |
|---|---|
| `STATIC` | Source, configuration and schema review without dynamic traffic |
| `LOCAL` | Safe dynamic proof against a local app and fixtures |
| `STAGING` | Explicitly authorized non-production testing |
| `PRODUCTION_SAFE` | Bounded, non-destructive verification only |

Only test systems you own or are explicitly authorized to assess. See **[SECURITY.md](SECURITY.md)**.

## Output

Depending on the workflow and available runtime, SecHelix can produce:

- evidence-backed findings and refuted candidates;
- root-cause remediation guidance or fixes;
- security regression tests;
- retest status;
- Markdown, redacted JSON, SARIF or HTML reports;
- a release decision: `PASS`, `PASS_WITH_KNOWN_RISK`, `BLOCKED`, or `INCOMPLETE`.

## Documentation

Start with the practical docs and use the deeper material only when you need it:

- **[Command Cookbook](docs/COMMANDS.md)** — copy-paste security workflows.
- **[AI-Built App Launch Audit](references/ai-built-app-launch.md)** — evidence-gated pre-launch checks for AI-built/vibe-coded apps.
- **[V4 Runtime Quickstart](docs/v4-quickstart.md)** — optional CLI/runtime usage.
- **[GitHub Action](docs/github-action.md)** — SecHelix in GitHub Actions.
- **[CI Integration](docs/ci-integration.md)** — using SecHelix in CI.
- **[Architecture](ARCHITECTURE.md)** — design and internals.
- **[Evaluation](docs/EVALUATION.md)** — evaluation methodology and results.
- **[Extensions](docs/EXTENSIONS.md)** — extending the framework.
- **[Security Policy](SECURITY.md)** — safe use and vulnerability reporting.
- **[Contributing](CONTRIBUTING.md)** — contributing to SecHelix.

The repository also contains detailed schemas, catalogs, adapters, evaluation fixtures and research material. They support the framework; you do not need to read them to start using SecHelix.

## License

Apache-2.0. See [LICENSE](LICENSE).