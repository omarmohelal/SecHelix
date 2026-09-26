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
| Review technical SEO and indexing | SEO Audit |
| Find dead code and maintenance debt | Codebase Cleanup |
| Apply safe SEO and cleanup fixes | SEO + cleanup: audit, fix, verify |
| Get a quick first pass | Security triage |
| Launch an AI-built / vibe-coded app safely | AI-Built App Launch Audit |
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

## AI-Built App Launch Audit

Use this when an application is close to launch and was produced quickly with AI/coding agents or rapid prototyping.

```text
Use SecHelix's AI-Built App Launch Audit on this authorized application.
Start with STATIC evidence, then use LOCAL or authorized STAGING/PRODUCTION_SAFE verification only where it is safe and necessary.
Evaluate launch checks 01-36 from references/ai-built-app-launch.md.
For each relevant check return PASS, FAIL, UNKNOWN, NOT_APPLICABLE, or BLOCKED.
Do not mark PASS without exact evidence from code, configuration, policy, test, log, or a safe runtime observation.
For FAIL and security-relevant UNKNOWN results, give the realistic failure mode, the smallest root-cause fix, and an exact safe verification step.
Prioritize auth, authorization, cross-user/tenant data, private data, payments/entitlements, admin access, secrets, webhooks, AI/tool authority, and spend-sensitive routes.
Do not mutate production data or infrastructure during the audit.
After fixes, re-run the failed/unknown checks and produce the normal SecHelix release gate.
```

The 36-check launch profile is documented in [`references/ai-built-app-launch.md`](../references/ai-built-app-launch.md). It is a practical minimum launch filter over the larger SecHelix catalog, not a replacement for the full audit.

## SEO Audit

```text
Use SecHelix SEO Audit with references/seo-audit.md on this authorized website.
Inventory public routes, locales, intended indexability and deployment configuration.
Audit all SEO-01 through SEO-20 checks, with exact source/runtime evidence and
PASS/FAIL/UNKNOWN/NOT_APPLICABLE/BLOCKED for each. Report sampled versus total coverage.
Give a prioritized fix plan with impact, risks and before/after verification.
Preserve intentional noindex; coordinate slug changes with redirects and canonical/sitemap links.
Distinguish lab performance from field Core Web Vitals. Never claim Search Console
verification, indexing or ranking improvements without evidence. Include a legitimate
backlink strategy; do not send outreach or publish external submissions.
This is audit-only: report the plan before changing application files.
```

## Codebase Cleanup

```text
Use SecHelix Codebase Cleanup with references/codebase-cleanup.md.
Analyze the entire accessible codebase for all eight categories: dead code,
duplicate logic, unused UI, excessive complexity, legacy code, redundant DB/API
work, disconnected files and technical debt. Declare exclusions and inaccessible consumers.
For every issue give paths, evidence, why it provides no value, estimated removal
impact, deletion risks, recommended steps, priority and verification/rollback plan.
Refute non-use by checking dynamic/framework discovery, exports, flags, external
callers, jobs, deployment, migrations and tests. Mark CONFIRMED/UNKNOWN/KEEP/BLOCKED.
Be aggressive but safe: zero search matches is not deletion proof.
This is audit-only; do not delete or refactor application files yet.
```

## SEO + cleanup: audit, fix, verify

```text
Use SecHelix's SEO Audit and Codebase Cleanup references on this authorized project.
First inventory routes, assets, entrypoints, consumers and baseline checks; produce
an evidence-backed prioritized plan covering all 20 SEO checks and eight cleanup categories.
Then implement confirmed, reversible fixes in dependency-ordered commits without
repeated confirmation. Preserve intended functionality, private-page exclusions,
security controls, data, migrations, supported contracts and rollback paths.
Check dynamic/external consumers before deletion; leave uncertain removals in the backlog.
Measure relevant before/after results, run affected tests and required repository gates,
and recheck public routes plus sensitive flows affected by shared code changes.
Deliver the issue matrix, actual savings, completed fixes, remaining blockers and
backlink plan. Keep quality outcomes separate from the security release gate.
Do not publish/deploy, change external services or send outreach unless that action
is already explicitly authorized. Do not invent unavailable runtime or Search Console evidence.
```

These recipes run through the coding agent using the installed Skill. They do not add `sechelix seo` or `sechelix cleanup` CLI commands.

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
| `sechelix fix-check <finding_id> --workspace <scratch>` | Run bounded remediation/retest gates without applying a patch |
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

### Run bounded remediation checks

`fix-check` is the executable half of Fix Mode. It never applies a patch and
refuses to use the current working tree as its scratch workspace. Test execution
is fixed-shape Python `unittest` inside the network-disabled sandbox; there is
no generic shell or argv passthrough.

A partial run is useful and honest: omitted stages remain `NOT_RUN`, so the
result is `INCOMPLETE` rather than a false pass.

```bash
sechelix fix-check SHX-F-1 \
  --workspace /tmp/sechelix-fix-SHX-F-1 \
  --existing-test tests.test_existing_behavior \
  --regression-test tests.test_security_regression \
  --json
```

To reach `READY_FOR_REVIEW`, also provide differential-review evidence and an
independent-verification StageResult:

```bash
sechelix fix-check SHX-F-1 \
  --workspace /tmp/sechelix-fix-SHX-F-1 \
  --existing-test tests.test_existing_behavior \
  --regression-test tests.test_security_regression \
  --patch-review patch-review.json \
  --independent-verification independent-verification.json
```

The independent-verification JSON must declare:

```json
{
  "stage": "independent_verification",
  "status": "PASS",
  "detail": "independent verifier reconstructed the original claim and observed secure behavior",
  "evidence_ids": ["EV-VERIFY-1"]
}
```

`READY_FOR_REVIEW` still means a human-reviewed patch proposal. SecHelix does
not apply or merge the change from this command.

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