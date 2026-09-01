# SecHelix Quickstart

SecHelix is an evidence-first AppSec Agent Skill for repositories and environments you are authorized to test. It is designed to turn scanner/model suspicions into verified security claims, root-cause fixes, regression proof, and an explicit release decision.

## 1. Install

Recommended cross-client install:

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

Project-local alternatives are already included for Claude Code, Codex, GitHub Copilot/Agent Skills-compatible clients, and vendor-neutral `skills/` discovery.

## 2. First run

Use a repository you own or are explicitly authorized to assess.

```text
Run a SecHelix security audit on this repository.
Mode: STATIC first, then LOCAL if the project can be started safely.
Map the attack surface and trust boundaries before hunting.
Use only applicable hypotheses.
Treat scanner/model output as hypotheses, not findings.
Independently verify every High/Critical candidate.
Fix root causes, add regression tests, retest, then produce the release gate decision.
```

Expected lifecycle:

```text
install → scope → map → select → hunt → verify → fix → regress → retest → report → gate
```

## 3. Useful focused runs

### Authorization / multi-tenant

```text
Use SecHelix to audit authorization in this repository.
Build a role × object × action matrix.
Focus on BOLA/IDOR, BFLA, ownership checks, tenant isolation, mass assignment, storage policy, and server-side enforcement.
Use two-user tests in LOCAL/STAGING where safely available.
```

### Business logic / payments

```text
Use SecHelix to audit business logic and money flows.
Map state machines for purchase, fulfillment, refund, cancellation, credit, payout, retries, and webhooks.
Check replay, idempotency, race windows, negative/overflow values, client-controlled price or ownership, partial success, and late provider callbacks.
```

### AI / MCP / agent security

```text
Use SecHelix to audit the AI/agent/MCP attack surface.
Map model inputs, retrieved context, memory, tool permissions, MCP servers, external URLs, file/shell/DB tools, and trust boundaries.
Check direct/indirect prompt injection, tool argument authorization, unsafe model output, cross-user memory leakage, SSRF through tools, excessive agency, poisoning, and supply-chain risk.
```

### Pull request review

```text
Review this PR with SecHelix.
Identify newly introduced trust-boundary, authorization, injection, secrets, supply-chain, state-machine, race, privacy, or release risks.
Verify important candidates against the changed dataflow and existing controls. Do not report grep-only suspicions as vulnerabilities.
```

### Release gate

```text
Run the SecHelix release gate for this repository.
Fail closed if required evidence is missing.
Do not mark UNKNOWN/BLOCKED checks as NOT_APPLICABLE.
List verified blockers, known accepted risks, regression status, and the final PASS / PASS_WITH_KNOWN_RISK / BLOCKED / INCOMPLETE decision.
```

## 4. What a trusted finding needs

A verified finding should establish:

1. attacker control;
2. reachability;
3. failed security boundary;
4. bounded safe reproduction;
5. concrete impact;
6. preconditions;
7. root cause;
8. fix;
9. regression proof.

High/Critical candidates require an independent refutation/verification pass before final reporting.

## 5. Safe execution modes

| Mode | Intended use |
|---|---|
| `STATIC` | source/config/schema review; no dynamic traffic |
| `LOCAL` | local app + fixtures + safe dynamic proof |
| `STAGING` | explicitly authorized non-production target |
| `PRODUCTION_SAFE` | bounded, non-destructive evidence only |

Do not turn a repository review into uncontrolled internet scanning. Do not use destructive payloads, credential theft, persistence, malware, denial of service, or customer-data exfiltration as proof.

## 6. Output

The repository supports one canonical evidence/report contract with derived Markdown, redacted JSON, SARIF 2.1.0, and standalone HTML. A useful run should leave enough evidence that another reviewer can reproduce the reasoning without trusting the first model.

For command recipes, see [`docs/COMMANDS.md`](COMMANDS.md). For evaluation claims and measurable results, see [`docs/EVALUATION.md`](EVALUATION.md). For organizational rollout, see [`docs/ENTERPRISE-ADOPTION.md`](ENTERPRISE-ADOPTION.md).
