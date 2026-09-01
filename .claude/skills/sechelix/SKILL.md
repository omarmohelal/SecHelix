---
name: sechelix
description: Run SecHelix evidence-first application-security audits on authorized repositories and environments. Use for codebase, API, web, auth/authz, business-logic, payment, race-condition, supply-chain, AI/MCP, cloud, and release-security review.
---

# SecHelix for Claude Code

Read and follow the repository root `SKILL.md` as the canonical workflow. Use the project-local supporting resources under `catalog/`, `references/`, `agents/`, `examples/`, and `scripts/`.

Claude-specific orchestration guidance:

- Use subagents only for disjoint review lanes.
- Give each implementation/fix agent isolated ownership; do not let audit agents mutate the same release tree concurrently.
- Focused tests per lane; centralized heavy verification after integration.
- For High/Critical candidates, spawn an independent verifier that is asked to refute the finding rather than confirm it.
- Do not let dynamic testing leave authorized local/staging scope unless the operator explicitly authorizes a bounded production-safe check.

The methodology, severity rules, safety policy, and evidence standard are defined only in the root `SKILL.md`; do not fork them here.
