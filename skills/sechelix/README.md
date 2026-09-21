# SecHelix portable bundle

This directory is the Agent Skills distribution of SecHelix: the workflow and the
material it reads. It ships instructions and data only, no executable code, and
depends on nothing outside the installed `sechelix/` directory.

## Included surfaces

- the canonical evidence-first workflow in `SKILL.md`;
- all 546 stable catalog hypotheses and frozen IDs;
- 17 specialist role profiles;
- 22 JSON Schema contracts (Draft 2020-12) spanning the audit lifecycle, extensions,
  source trust, knowledge graph, lesson cards, and live research;
- a rights-aware source registry, provenance graph, and compact lesson cards;
- reusable Gold Check Packs and public release-gate policy examples;
- representative scope, evidence, and report examples.

Teaching material stays in the source repository: the deliberately vulnerable
demo applications and rendered report samples are not installed with the skill.

## Optional executable helpers

The workflow runs without them. When you want them:

- `python -m pip install sechelix` installs the `sechelix` CLI and makes the
  `sechelix_core` helpers that `SKILL.md` names importable. `pipx` and `uv tool`
  install the command but keep the modules in their own environment.
- A clone of https://github.com/omarmohelal/SecHelix adds the release-gate script,
  the report renderer, the scanner adapters and the validators, which are not in
  the wheel.

See `references/runtime.md`.

Start with `SKILL.md`. Load only the referenced resources that are relevant to
the authorized review. Scanner or model output remains a hypothesis until it
meets the evidence contract.

The source repository also contains tests, eval fixtures, contributor tooling,
and release documentation that are intentionally outside this runtime bundle.
