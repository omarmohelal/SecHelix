# SecHelix portable bundle

This directory is the self-contained Agent Skills distribution of SecHelix. It
does not rely on files outside the installed `sechelix/` directory.

## Included surfaces

- the canonical evidence-first workflow in `SKILL.md`;
- all 546 stable catalog hypotheses and frozen IDs;
- 17 specialist role profiles;
- Draft 2020-12 scope, attack-surface, applicability, evidence, finding, report,
  and catalog schemas;
- deterministic applicability and attack-surface helpers;
- evidence adapters and safe execution profiles;
- report rendering, release gates, and public policy examples;
- representative scope, evidence, and report examples.

Start with `SKILL.md`. Load only the referenced resources that are relevant to
the authorized review. Scanner or model output remains a hypothesis until it
meets the evidence contract.

The source repository also contains tests, eval fixtures, contributor tooling,
and release documentation that are intentionally outside this runtime bundle.
