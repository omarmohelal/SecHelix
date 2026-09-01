# Command recipes

Natural-language instructions for each SecHelix review lane. See also [the command cookbook](../COMMANDS.md).

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

More recipes: **[the command cookbook](../COMMANDS.md)**.


