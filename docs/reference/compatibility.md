# Compatibility

SecHelix separates **format compatibility** from **model compatibility**.

The canonical workflow is plain `SKILL.md` + Markdown/JSON/Python resources and follows the open Agent Skills format. A model does not need a SecHelix-specific API; it needs a coding-agent host that can load the skill or the equivalent files.

`skills/sechelix/` is a self-contained bundle: methodology, the 546-item catalog, role profiles, schemas, safe adapters, the report renderer, Gold Check Packs, knowledge graph, and public policy examples. It requires only the Python standard library and has no repository-parent code references.

## Status vocabulary

Every row below uses exactly one of these four values. Nothing is upgraded without a recorded test.

| Status | Meaning |
|---|---|
| `VERIFIED` | Cold-installed and executed on this machine, with the commands and results recorded in **How this was tested**. |
| `DOCUMENTED` | The host vendor documents the discovery mechanism, but SecHelix was not loaded in that host here. |
| `MODEL_COMPATIBLE` | The portable bundle is usable as files, but the host's skill loader was not verified. |
| `UNVERIFIED` | No test and no vendor documentation backing this specific path. |

## Support matrix

| Environment | Integration | Status | Notes |
|---|---|---|---|
| Portable bundle (any host) | `skills/sechelix/` copied anywhere | `VERIFIED` | Copied out of the repository to a scratch directory; five entry points ran from inside the copy with no parent-directory access. |
| Agent Skills CLI installer | `npx skills@latest add … --skill sechelix` | `VERIFIED` | Cold-installed into an empty scratch project. Installs to `.agents/skills/sechelix/` with a `.claude/skills/sechelix` symlink. See the packaging caveat below. |
| Claude Code — plugin | `.claude-plugin/plugin.json` | `VERIFIED` | `claude plugin validate .` passes; `claude --plugin-dir .` loads 1 skill and 17 specialist agents at the declared version. |
| Claude Code — project skill | `.claude/skills/sechelix/SKILL.md` | `DOCUMENTED` | Claude Code documents project-local `.claude/skills/`. The adapter file and the installer symlink were checked here; a Claude Code session loading it was not observed. |
| OpenAI Codex | `.agents/skills/sechelix/` (+ portable bundle) | `DOCUMENTED` | `openai/codex` documents that Codex scans `.agents/skills` from the working directory up to the repository root. Placement there is `VERIFIED`; Codex loading it is not tested here. |
| Codex convenience mirror | `.codex/skills/sechelix/` | `UNVERIFIED` | Retained as a mirror only. Repository-local `.codex/skills/` is **not** a documented Codex discovery path — Codex documents `.agents/skills/` for repositories and `~/.codex/skills/` for global skills. Do not rely on this directory. |
| GitHub Copilot / VS Code agents | `.github/skills/sechelix/` | `DOCUMENTED` | GitHub documents `.github/skills`, `.claude/skills`, and `.agents/skills` as repository skill directories for Copilot. Not loaded in Copilot here. |
| Generic Agent Skills clients | `.agents/skills/sechelix/` or `skills/sechelix/` | `MODEL_COMPATIBLE` | Uses only open-format frontmatter fields. Confirm your client's loader before claiming native support. |
| Z.AI / GLM via Claude Code | install as a Claude skill | `DOCUMENTED` | Z.AI documents the GLM Coding Plan running inside Claude Code, so Claude's loader remains the host. |
| Z.AI / GLM via OpenCode / Cline / Cursor / other | portable bundle + host loader | `MODEL_COMPATIBLE` | Z.AI documents supported coding tools; native skill discovery depends on the selected host. Do not claim a Z.AI-native `SKILL.md` directory without vendor documentation. |
| Cursor | portable Agent Skills mirror | `MODEL_COMPATIBLE` | The Agent Skills CLI lists Cursor as an install target; Cursor's own loader was not exercised here. |
| Gemini CLI / OpenCode / other agents | portable bundle | `MODEL_COMPATIBLE` | Validate the client loader before claiming native installation support. |

## How this was tested

Executed on **2026-09-01**, Windows 11 (10.0.26200), Python 3.14, Node 22.23.2, Claude Code 2.1.240, `skills` CLI via `npx skills@latest`.

**1. Portable bundle, cold copy.** `skills/sechelix/` was copied to a scratch directory outside the repository (a second copy had every `__pycache__` removed, so no stale bytecode could mask a missing module). With the working directory set *inside the copy*, all five entry points exited `0`:

```bash
python scripts/validate_contract.py report examples/report.example.json
#   OK: examples/report.example.json satisfies the report contract
python scripts/security_gate.py examples/report.example.json --policy policies/default.json
#   PASS: no unresolved release-blocking conditions
python scripts/validate_gold_packs.py
#   OK: Gold Check Packs satisfy structural, provenance, and safety contracts
python scripts/validate_knowledge.py
#   OK: source registry, knowledge graph, 7 lesson card(s), and research packet validate
python -m reports.report_renderer examples/report.example.json --format markdown
#   rendered the full Markdown report
```

`scripts/applicability.py` and `scripts/attack_surface.py` also loaded and printed usage from inside the copy. **Nothing failed.** The only `../` references in the bundle are relative Markdown links inside `gold-packs/README.md`, which resolve within the bundle.

**2. Claude Code plugin.**

```bash
claude plugin validate .        # ✔ Validation passed with warnings
claude --plugin-dir . plugin details sechelix
#   SecHelix (sechelix) 3.0.0-alpha.4
#   Skills (1)  sechelix
#   Agents (18) … including README
```

**3. Agent Skills CLI, cold install into an empty directory.**

```bash
npx skills@latest add . --list                          # Found 1 skill: sechelix
npx skills@latest add /path/to/SecHelix --skill sechelix # Installed 1 skill
```

### Known packaging caveats (recorded, not hidden)

- **The CLI installs the repository, not the portable bundle.** `npx skills@latest add … --skill sechelix` matches the *root* `SKILL.md` and copies the whole repository tree — 338 files, ~3.8 MB, including `tests/`, `evals/`, `artifacts/`, `assets/`, and `docs/` — into `.agents/skills/sechelix/`. The 108-file `skills/sechelix/` bundle is what you get when you copy it yourself. Both work; only the second is minimal.
- **`agents/README.md` loads as an 18th "agent."** Claude Code scans the whole `agents/` directory, so the index file is loaded alongside the 17 real role profiles and the validator warns that it has no frontmatter. The documented `agents` manifest field does not fix this: on Claude Code 2.1.240, pointing `agents` at individual files loaded **0** agents, and pointing it at `"./agents"` made the plugin fail to load entirely. The field was therefore left at its default and the wart is documented here instead of being papered over.

## Why there is no `.claude-plugin/marketplace.json`

Claude Code does document `marketplace.json`, and a local marketplace is installable with `claude plugin marketplace add <path>` — so the mechanism is real. SecHelix still does not ship one, for three reasons measured here rather than assumed.

First, adding `marketplace.json` beside `plugin.json` **shadows plugin validation**: with both files present in `.claude-plugin/`, `claude plugin validate .` validated only the marketplace manifest and stopped checking the plugin, its skill, and its agents. That is the exact signal the plugin submission pipeline runs, and losing it is a worse outcome than not having a marketplace. Second, a marketplace whose single entry is the repository itself duplicates two install paths that already work (`npx skills@latest add` and `claude --plugin-dir`), creating a second identity for one skill. Third, Anthropic's own documentation treats a combined plugin-and-marketplace repository as conflating two distinct roles rather than as a supported pattern. If SecHelix later distributes more than one plugin, a marketplace belongs in a separate repository where it does not shadow this one's validation.

## Z.AI / GLM clarification

SecHelix does not hardcode a GLM model number. Z.AI's Coding Plan supports multiple GLM generations and can map them into supported coding tools. This is useful for SecHelix because the **host** supplies repository and tool access while GLM supplies reasoning.

Example model-role split:

- GLM reasoning model → business logic / state-machine review;
- Claude / Codex → alternate investigation or verifier;
- fast model → inventory / applicability census.

Do not claim one provider is the "best hacker" without eval evidence. Benchmark status is `NOT_MEASURED`.

## Portable fallback

If a coding agent has no native skill loader:

1. place `skills/sechelix/` in the repository;
2. point the agent at `skills/sechelix/SKILL.md` or the canonical `skills/sechelix/SKILL.md`;
3. use `AGENTS.md` for repository-level instructions;
4. keep scanner, browser, and database tools outside the model-specific methodology.

This preserves one SecHelix workflow rather than maintaining incompatible prompts for every model vendor.
