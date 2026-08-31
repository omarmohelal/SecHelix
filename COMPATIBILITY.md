# Compatibility

SecHelix separates **format compatibility** from **model compatibility**.

The canonical workflow is plain `SKILL.md` + Markdown/JSON/Python resources and follows the open Agent Skills format. A model does not need a SecHelix-specific API; it needs a coding-agent host that can load the skill or the equivalent files.

`skills/sechelix/` is self-contained: it includes the methodology, 546-item
catalog, role profiles, schemas, safe adapters, report renderer, and public
policy examples. It has no repository-parent references. The canonical skills
CLI command was cold-installed with copy semantics during the VNext release QA.

## Support matrix

| Environment | Integration | Status | Notes |
|---|---|---|---|
| Claude Code | `.claude/skills/sechelix/SKILL.md` | Documented | Claude Code documents Agent Skills and project-local `.claude/skills/`. |
| OpenAI skills | portable `skills/sechelix/` / skill ZIP | Verified bundle | Self-contained bundle; host/API availability still depends on the installed OpenAI surface. |
| Codex workflows | `.codex/skills/sechelix/` + portable bundle | Cold-install verified | Official skills CLI discovery and copied installation verified on 2026-08-31. |
| GitHub Copilot / VS Code agent environments | `.github/skills/sechelix/` | Portable adapter | Agent Skills adoption is documented by the ecosystem; exact feature support varies by host/version. |
| Generic Agent Skills clients | `.agents/skills/sechelix/` or `skills/sechelix/` | Portable | Uses only open-format fields in the canonical skill. |
| Z.AI / GLM via Claude Code | install as Claude skill | Documented host path | Z.AI documents GLM Coding Plan running inside Claude Code; therefore Claude's skill loader remains the host. |
| Z.AI / GLM via OpenCode/Cline/Cursor/other supported tools | portable bundle + host-specific loader | Model-compatible | Z.AI documents supported coding tools; native skill discovery depends on the selected host. Do not claim a Z.AI-native `SKILL.md` directory without vendor documentation. |
| Cursor | portable Agent Skills mirror | Model-compatible | Use the host's current skill/discovery mechanism. |
| Gemini/OpenCode/other agents | portable bundle | Model-compatible | Validate the client loader before claiming native installation support. |

## Z.AI / GLM clarification

SecHelix does not hardcode a GLM model number. Z.AI's current Coding Plan supports multiple GLM generations and can map them into supported coding tools. This is useful for SecHelix because the **host** supplies repository/tool access while GLM supplies reasoning.

Example model-role split:

- GLM reasoning model → business logic / state-machine review;
- Claude/Codex → alternate investigation or verifier;
- fast model → inventory / applicability census.

Do not claim one provider is the "best hacker" without eval evidence.

## Portable fallback

If a coding agent has no native skill loader:

1. place `skills/sechelix/` in the repository;
2. point the agent to `skills/sechelix/SKILL.md` or root `SKILL.md`;
3. use `AGENTS.md` for repository-level instructions;
4. keep scanner/browser/DB tools outside the model-specific methodology.

This preserves one SecHelix workflow rather than maintaining incompatible prompts for every model vendor.
