---
name: sechelix
description: Evidence-first application-security audit workflow for authorized repositories and environments. Use for security reviews of codebases, APIs, web apps, business logic, authorization, payments, race conditions, supply chain, AI/MCP integrations, cloud configuration, and release readiness. Requires attack-surface mapping, applicable-check selection, independent verification of High/Critical findings, root-cause fixes, and regression proof.
---

# SecHelix portable skill

This directory is the **vendor-neutral distributable bundle**. The full canonical workflow lives in the repository root [`SKILL.md`](../../SKILL.md).

Before executing a SecHelix review, read and follow `../../SKILL.md` in full. Then load only the supporting resources needed for the current task:

- `../../references/methodology.md` — evidence, scope, severity, verification.
- `../../references/tooling.md` — safe scanner/tool integration.
- `../../references/sources.md` — standards and authoritative references.
- `../../catalog/checks.json` — structured hypothesis catalog.
- `../../agents/` — specialist reviewer roles.
- `../../examples/` — example scope/report shapes.

## Portable execution contract

1. Authorized targets only.
2. Start with `STATIC`; escalate to `LOCAL`, `STAGING`, or bounded `PRODUCTION_SAFE` only when the environment is explicitly available and authorized.
3. Build an attack-surface map before selecting checks.
4. Select only applicable hypotheses; do not spray every test.
5. Treat tool/model output as hypotheses.
6. Independently verify High/Critical findings.
7. Fix canonical root causes.
8. Add regression proof.
9. Report uncertainty honestly.
10. Never trade test coverage for destructive behavior.

The portable bundle intentionally contains no model-specific prompt syntax. Model/tool adapters should load this workflow rather than fork the methodology.