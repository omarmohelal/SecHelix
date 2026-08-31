---
name: sechelix
description: Run SecHelix evidence-first AppSec audits on authorized codebases and environments. Use for deep security review, code-change security review, authorization, business logic, races, payments, supply chain, AI/MCP, and release gates.
---

# SecHelix for Codex

Use the repository root `SKILL.md` as the canonical methodology and evidence standard. Load supporting resources from `catalog/`, `references/`, `agents/`, `examples/`, and `scripts/` only when relevant.

Codex/OpenAI guidance:

- Prefer broad repository understanding before local patching.
- Split independent investigation lanes when concurrency is safe.
- Use browser/runtime proof where static analysis cannot establish a bundling, authorization, or state-machine claim.
- Treat model/scanner outputs as hypotheses; independently verify High/Critical findings.
- Keep production testing non-destructive unless the operator explicitly authorizes a bounded action.

Do not create a second SecHelix methodology in this adapter.