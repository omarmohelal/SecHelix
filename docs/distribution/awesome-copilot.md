# Curated edition: `sechelix-lite`

`distributions/awesome-copilot/` is a small Agent Plugin for public skill directories. It has one
job: an evidence-first application-security review of a codebase the user is authorized to
assess, with a separate verification pass before material findings are reported.

It is not a second methodology. It is a compressed, runtime-free rendering of the canonical
`skills/sechelix/SKILL.md` workflow, and CI keeps it tied to the canonical contracts.

## Layout

```text
distributions/awesome-copilot/
  plugin.json                              Agent Plugins v1.0.0 manifest
  skills/sechelix-lite/
    SKILL.md                               workflow, rules, six review lanes, verdict
    references/verification.md             refutation protocol, statuses, severity, chains
    references/authz-business-logic.md     authentication, authorization, state machines, races
    references/web-inputs.md               injection, XSS/CSRF, SSRF, files, parsers, client secrets
    references/supply-chain-ai.md          dependencies, CI/CD, AI agent and MCP boundaries
    references/reporting.md                safe proof, finding format, report, verdict rules
```

The skill is named `sechelix-lite`, not `sechelix`, because `gh skill install` discovers nested
`skills/*/SKILL.md` directories. A second skill named `sechelix` would make
`gh skill install omarmohelal/SecHelix sechelix` resolve to this copy instead of the full skill.
The Agent Skills CLI (`npx skills add … --skill sechelix`) does not search nested directories
and is unaffected.

## What it deliberately leaves out

The full skill stays unchanged in `skills/sechelix/`. This edition does not ship the hypothesis
catalog, JSON Schemas, Python runtime, adapters, Gold Check Packs, knowledge engine, specialist
profiles, report renderer, release-gate script, SEO audit, codebase cleanup, AI-built app launch
checklist, examples or product copy.

## Before and after

| | Rejected submission ([github/awesome-copilot#2899](https://github.com/github/awesome-copilot/issues/2899)) | Curated edition |
|---|---|---|
| Submitted at | `v4.0.0-alpha.3`, `0415edb` | this directory |
| Plugin root | repository root (672 tracked files) | `distributions/awesome-copilot` (7 files) |
| `SKILL.md` | 473 lines | 197 lines |
| Files beside `SKILL.md` in the skill | 172 (references, agents, catalog, schemas, runtime, adapters, examples) | 5 Markdown references |
| Skill directory size | 2.04 MB | 32 KB |
| Scope | AppSec plus runtime, catalog, adapters; SEO and cleanup added in alpha.5 | AppSec review only |
| Needs the Python runtime | optional, but referenced throughout | never referenced |

Numbers for the curated edition are measured by `python scripts/validate_distribution.py`, which
prints them; re-run it rather than trusting this table after edits.

## Gates

`scripts/validate_distribution.py` runs in the `validate` workflow and fails when:

- `SKILL.md` exceeds 220 lines, or the skill ships more than 6 supporting files or any non-Markdown
  file;
- the manifest leaves Agent Plugins v1.0.0, exceeds 10 keywords, or its version differs from the
  root `plugin.json`;
- a referenced file is missing, or a shipped file is never referenced;
- the status, applicability, verdict or mode vocabulary in `schemas/` is missing from the text;
- the text depends on the runtime, catalog, schemas or scripts;
- it contains promotional copy, SEO or cleanup workflow text, or a secret pattern;
- a copy of the plugin root alone cannot resolve every reference.

`tests/test_distribution.py` breaks each property on a copy of the package and asserts the gate
notices.

## Verification record

At commit `457fe83` the package passed GitHub's own awesome-copilot intake tooling run locally:
Agent Plugins v1.0.0 spec compliance, `vally lint` (spec compliance and valid references), and
version match. A cold install with Copilot CLI 1.0.83 from a GitHub-sourced marketplace entry
reported one skill installed and copied exactly the seven package files.
