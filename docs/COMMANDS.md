# SecHelix Command Cookbook

SecHelix is primarily an **Agent Skill**, so the normal interface is a clear instruction to your coding agent.

Install once:

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

Then use one of the recipes below.

## Pick the right workflow

| You want to... | Use |
|---|---|
| Audit the whole repository | Full audit |
| Get a quick first pass | Security triage |
| Check access control | Authorization / IDOR / BOLA |
| Check login, sessions or OAuth | Authentication / sessions |
| Trace dangerous input | Injection / XSS / SSRF / files |
| Check payments and workflows | Business logic / races |
| Check dependencies and pipelines | Supply chain / CI/CD |
| Review an LLM, agent or MCP integration | AI / Agent / MCP |
| Review only a code change | PR security review |
| Repair confirmed problems | Fix Mode |
| Decide whether a release should pass | Release gate |
| Produce shareable output | Report |

## Full audit

```text
Use SecHelix for a complete authorized security audit of this repository.
Start STATIC and use LOCAL only if it is safe and useful.
Map the attack surface and trust boundaries first.
Review only checks that apply to this project.
Verify important candidates before reporting them.
Fix root causes, add regression tests, retest, and produce the final release gate.
```

## Security triage

```text
Use SecHelix to triage this repository for security issues.
Prioritize authentication, authorization, business logic, secrets, injection, SSRF, file handling, supply chain, dangerous configuration, and AI/MCP surfaces.
Return evidence-backed findings and clearly mark anything unproven.
```

## Authorization / IDOR / BOLA

```text
Use SecHelix to audit authorization in this repository.
Build a role × object × action matrix.
Check IDOR/BOLA, BFLA, ownership bypass, tenant leakage, mass assignment, client-controlled identity/role fields, UI-only checks, and storage/RLS policy gaps.
Verify server-side enforcement with safe two-user tests when a LOCAL or authorized STAGING environment is available.
```

## Authentication / sessions / OAuth

```text
Use SecHelix to audit authentication and session security.
Review login, registration, recovery, MFA, reauthentication, cookies, session rotation and revocation, JWT validation, refresh tokens, OAuth/OIDC state/nonce/PKCE, and account-enumeration or abuse controls.
```

## Injection / XSS / SSRF / files

```text
Use SecHelix to trace untrusted input to security-sensitive sinks.
Audit SQL/NoSQL/ORM injection, command/code/template injection, XSS, redirects and headers, SSRF, XXE, deserialization, path traversal, uploads, parsers, and unauthorized downloads.
Do not report a grep match as a vulnerability without reachability and attacker-control evidence.
```

## Business logic / payments / races

```text
Use SecHelix to audit business logic, payment/accounting truth, and concurrency.
Model important state transitions and invariants.
Check replay, idempotency, duplicate execution, partial success, late callbacks, negative/overflow values, price tampering, stale state, TOCTOU, race conditions, and double-spend windows in a safe environment.
```

## Supply chain / CI/CD

```text
Use SecHelix to audit the software supply chain and CI/CD.
Review dependencies, lockfiles, install scripts, workflow permissions, artifact trust, container/base images, secrets, pull-request workflows, and deployment configuration.
Separate vulnerable-version presence from actual reachability and exposure.
```

## AI / Agent / MCP

```text
Use SecHelix to audit AI, LLM, agent, and MCP security.
Map prompts, retrieved context, memory, tool calls, MCP servers, external content, and DB/file/shell/browser permissions.
Check prompt injection, tool authorization, unsafe model output reaching sinks, cross-user leakage, memory poisoning, SSRF through tools, excessive agency, and model/tool/plugin supply-chain risk.
```

## PR security review

```text
Review this PR with SecHelix.
Map security-relevant changes in trust boundaries and data flows.
Verify important candidates against the changed code and existing controls.
Tell me whether the PR introduces a verified blocker, known risk, or no evidence-backed security regression.
```

## Fix Mode

```text
Use SecHelix Fix Mode on all verified findings.
For each finding, identify the root cause and similar variants, implement the smallest class-level secure fix, add a security regression test, rerun relevant tests/tools, and independently retest the original claim.
```

## Release gate

```text
Run the SecHelix release gate.
Return PASS, PASS_WITH_KNOWN_RISK, BLOCKED, or INCOMPLETE.
Fail closed when required evidence is missing.
Do not convert UNKNOWN or BLOCKED checks into NOT_APPLICABLE.
List verified blockers, accepted risks, and regression/retest status.
```

## Report

```text
Generate a SecHelix security report from the run evidence.
Include each verified finding's severity, affected surface, root cause, impact, safe evidence, fix, regression status, and retest status.
Keep refuted candidates separate from verified findings.
```

---

# Optional CLI runtime

The Python CLI is optional. Use it when you want stored runs, coverage tracking, replay, reports, CI-friendly exit codes, or the local MCP adapter.

Install:

```bash
pipx install sechelix
```

## CLI reference

| Command | Purpose |
|---|---|
| `sechelix doctor [path]` | Show installed/available components and reasoning executors |
| `sechelix audit [path]` | Build and run the audit graph |
| `sechelix runs [path]` | List saved runs and verify their integrity |
| `sechelix coverage [path]` | Show blind spots from previous runs |
| `sechelix report [run_id]` | Render a saved run |
| `sechelix replay <run_id> [path]` | Replay a run offline and compare it with the recorded execution |
| `sechelix mcp [path]` | Serve the MCP adapter over stdio |

### Check the setup

```bash
sechelix doctor
```

### Audit with Claude Code

```bash
sechelix audit . --executor claude-code
```

### Audit with Gemini CLI

```bash
sechelix audit . --executor gemini-cli
```

Useful audit controls:

```bash
sechelix audit . --executor claude-code --depth quick
sechelix audit . --executor claude-code --max-seconds 900
sechelix audit . --executor claude-code --max-nodes 10
sechelix audit . --executor claude-code --model <model-name>
```

`--depth` accepts the depths supported by the installed runtime. Run `sechelix audit --help` for the current choices.

> Running `sechelix audit .` with the default `--executor none` intentionally performs no code reasoning. The audit remains incomplete rather than pretending the repository was analyzed.

### View saved runs

```bash
sechelix runs
```

### Check coverage gaps

```bash
sechelix coverage
```

### Render a report

Latest run as Markdown:

```bash
sechelix report --format markdown
```

A specific run as SARIF:

```bash
sechelix report <run_id> --format sarif
```

Supported report formats are shown by:

```bash
sechelix report --help
```

### Replay a run

```bash
sechelix replay <run_id>
```

### Start the MCP adapter

```bash
sechelix mcp
```

### Machine-readable output

Commands that support it accept `--json`, for example:

```bash
sechelix doctor --json
sechelix runs --json
sechelix coverage --json
```

For runtime internals and advanced examples, see [V4 Runtime Quickstart](v4-quickstart.md).
