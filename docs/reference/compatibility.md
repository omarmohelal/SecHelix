# Compatibility

SecHelix separates **format compatibility** from **host verification**.

The canonical workflow is plain `SKILL.md` + Markdown/JSON/Python resources in the open Agent Skills format. A model does not need a SecHelix-specific API; it needs a coding-agent host that can load the skill or the equivalent files.

`skills/sechelix/` is the self-contained portable bundle. It carries the methodology, the 546-item catalog, role profiles, schemas, safe adapters, report renderer, Gold Check Packs, knowledge graph, and public policy examples without relying on a parent checkout.

## Status vocabulary

Every row below uses one of these values. A path is never upgraded because documentation merely says it should work.

| Status | Meaning |
|---|---|
| `VERIFIED` | Cold-installed or loaded and exercised, with the result recorded by this project. |
| `DOCUMENTED` | The host vendor documents the discovery mechanism, but SecHelix was not observed loading in that host here. |
| `MODEL_COMPATIBLE` | The portable bundle is usable as files, but the host's native loader was not verified. |
| `UNVERIFIED` | No recorded test and no vendor documentation backing this specific path. |
| `NOT_SHIPPED` | Deliberately absent; listed so the omission is not mistaken for an oversight. |

## Support matrix

| Environment | Integration | Status | Notes |
|---|---|---|---|
| Portable bundle | `skills/sechelix/` copied anywhere | `VERIFIED` | Exercised from a copy outside the repository with no parent-checkout dependency. |
| Agent Skills CLI installer | `npx skills@latest add … --skill sechelix` | `VERIFIED` | Cold-installed into an empty project and exercised after the V3 packaging fix. |
| Claude Code — plugin | `.claude-plugin/plugin.json` | `VERIFIED` | Plugin validation and a cold marketplace/plugin installation were exercised. |
| Claude Code — project skill | `.claude/skills/sechelix/SKILL.md` | `DOCUMENTED` | Claude Code documents project-local `.claude/skills/`; a dedicated project-skill loading observation is not recorded here. |
| OpenAI Codex | `.agents/skills/sechelix/` (+ portable bundle) | `DOCUMENTED` | Repository-local `.agents/skills/` is the documented repository discovery path used by SecHelix. Native Codex loading was not observed here. |
| Codex convenience mirror | `.codex/skills/sechelix/` | `NOT_SHIPPED` | SecHelix deliberately does not ship this repo-local mirror. Do not document it as a supported repository path. |
| GitHub Copilot / VS Code agents | `.github/skills/sechelix/` | `DOCUMENTED` | GitHub documents repository skill directories including `.github/skills`; native loading was not observed here. |
| Generic Agent Skills clients | `.agents/skills/sechelix/` or `skills/sechelix/` | `MODEL_COMPATIBLE` | Open-format bundle; verify the chosen client's loader before claiming native support. |
| Z.AI / GLM via Claude Code | install as a Claude skill/plugin | `DOCUMENTED` | Claude Code remains the host and supplies the loader. |
| Cursor / Gemini CLI / OpenCode / other agents | portable bundle + host loader | `MODEL_COMPATIBLE` | Use the portable bundle and verify the selected host's loader. |

## What is currently verified

The following claims have direct project evidence:

1. **Portable isolation.** The portable bundle runs outside the parent repository; validators, release gate, renderer, Gold Pack validation, and knowledge validation do not require the development checkout.
2. **Agent Skills CLI cold install.** Installation into an empty project completes successfully and installs the intended portable skill rather than the old whole-repository package.
3. **Claude plugin validation/install.** The plugin manifest validates and the separate SecHelix marketplace has been cold-added and installed successfully.
4. **No repo-local `.codex/skills/` claim.** The public package uses `.agents/skills/sechelix/` for the documented Codex repository path instead of presenting an unverified mirror as native support.

These are packaging/host claims, not security-performance claims. The public security benchmark remains `NOT_MEASURED` until an uncontaminated evaluator runs the blind packet.

## Claude marketplace boundary

SecHelix keeps its marketplace in a separate repository:

`omarmohelal/sechelix-marketplace`

This avoids making the framework repository act as both the plugin and its own marketplace. Users can add the marketplace and install SecHelix without duplicating the framework source.

## Portable fallback

If a coding agent has no verified native skill loader:

1. place `skills/sechelix/` in the repository or an agent-readable skills directory;
2. point the agent at `skills/sechelix/SKILL.md`;
3. keep scanner, browser, database, and other external tooling outside the model-specific methodology;
4. preserve the same authorization, evidence, verification, and release-gate rules regardless of host.

This keeps one SecHelix workflow instead of maintaining divergent prompts for every model vendor.
