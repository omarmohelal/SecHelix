# SecHelix Command Cookbook

SecHelix is a skill, not a shell-only scanner. The most reliable interface is a precise natural-language instruction to the coding agent after installation.

Install once:

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

## Full audit

```text
Use SecHelix for a complete authorized security audit of this repository.
Start STATIC. If a safe local runtime is available, continue in LOCAL.
Do not skip attack-surface mapping or applicability.
Run specialist review in parallel where useful, independently verify High/Critical candidates, fix root causes, add regression tests, retest, and produce the final release gate.
```

## Fast repository triage

```text
Use SecHelix for a security triage of this repository.
Prioritize authentication, authorization, business logic, secrets, injection/SSRF/files, supply chain, dangerous configuration, and AI/MCP surfaces.
Return only evidence-backed candidates and clearly mark anything unproven.
```

## Authorization / IDOR / BOLA

```text
Use SecHelix to audit authorization.
Create a Guest/User A/User B/Staff/Admin matrix across object and function actions.
Look for IDOR/BOLA, BFLA, tenant leakage, ownership bypass, mass assignment, client-controlled userId/role/ownerId, UI-only checks, and storage/RLS policy gaps.
```

## Authentication / sessions / OAuth

```text
Use SecHelix to audit authentication and session security.
Review login, registration, recovery, MFA, reauthentication, cookies, session rotation/revocation, JWT validation, refresh tokens, OAuth/OIDC state/nonce/PKCE, and account enumeration/abuse controls.
```

## Injection / XSS / SSRF / files

```text
Use SecHelix to trace untrusted input from source to security-sensitive sinks.
Audit SQL/NoSQL/ORM injection, command/code/template injection, XSS, redirects/headers, SSRF, XXE, deserialization, traversal, uploads, parsers, and unauthorized downloads.
Do not treat grep matches as proof; establish reachability and attacker control.
```

## Business logic / payments / race conditions

```text
Use SecHelix to audit business logic, payment/accounting truth, and concurrency.
Model state transitions and invariants for create/update/cancel/refund/approve/claim/redeem/withdraw/transfer/purchase/webhook operations.
Test replay, idempotency, duplicate execution, partial success, late callbacks, negative/overflow values, price tampering, stale state, TOCTOU, and double-spend windows in a safe environment.
```

## Supply chain / CI/CD

```text
Use SecHelix to audit the software supply chain and CI/CD.
Review dependencies, lockfiles, install scripts, provenance/SBOM, GitHub Actions or equivalent workflows, artifact trust, container/base images, secrets, token permissions, pull-request workflows, and deployment configuration.
Separate vulnerable-version presence from actual reachability/exposure.
```

## AI / Agent / MCP

```text
Use SecHelix to audit AI/LLM/agent/MCP security.
Map prompt/context sources, RAG/vector stores, memory, tool calls, MCP servers, external content, DB/file/shell/browser permissions, and autonomous side effects.
Check prompt injection, tool authorization, unsafe output reaching sinks, cross-user leakage, memory poisoning, SSRF through tools, excessive agency, and plugin/model/tool supply-chain risk.
```

## PR security review

```text
Use SecHelix to security-review the current pull request/diff.
Map changed trust boundaries and dataflows, identify new or weakened controls, verify important candidates, and state whether the PR introduces a verified blocker, known risk, or no evidence-backed security regression.
```

## Fix verified findings

```text
Use SecHelix Fix Mode on all verified findings.
For each: identify root cause and variants, implement the smallest class-level secure fix, add a security regression test, rerun the relevant scanners/tests, and independently retest the original claim.
Do not patch only one instance if the same unsafe pattern exists elsewhere.
```

## Release gate only

```text
Run the SecHelix release gate.
Return PASS, PASS_WITH_KNOWN_RISK, BLOCKED, or INCOMPLETE.
Fail closed for missing required evidence. Never convert UNKNOWN/BLOCKED to NOT_APPLICABLE.
List verified Critical/High blockers, unresolved authorization/tenant isolation tests, secrets, reachable critical dependencies, auth/session failures, SSRF/upload/webhook/business-logic risks, regression status, and accepted risks.
```

## Generate a shareable report

```text
Generate the SecHelix report from the canonical run evidence.
Produce Markdown plus redacted JSON and SARIF if supported by this checkout.
Each finding must include ID, severity, confidence, affected surface, CWE/OWASP mapping where appropriate, root cause, impact, safe evidence, fix, regression status, and retest status.
```

## Evaluate SecHelix itself

```text
Run the SecHelix evaluation suite reproducibly.
Record the exact repository commit, fixture set/version, model/provider/configuration, enabled tools, execution mode, timestamps, expected labels, observed outcomes, false positives, false negatives, blocked/unknown cases, and raw artifacts needed to reproduce the result.
Do not publish a score unless the run is reproducible and the metric definition is documented.
```

## Useful wording for teams

Instead of asking an agent to "find vulnerabilities", prefer:

```text
Use SecHelix to identify and independently verify security boundary failures in this authorized repository. Optimize for evidence and low false-positive rate, not finding count.
```

That instruction captures the core SecHelix contract: claims must survive verification before they become findings.
