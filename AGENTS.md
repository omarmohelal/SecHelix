# AGENTS.md

## Repository purpose

SecHelix is a portable, evidence-first AppSec skill/methodology for authorized codebases and environments.

## Canonical truth

- `SKILL.md` owns the methodology.
- `catalog/checks.json` owns the coverage model.
- vendor adapters must stay thin.
- the static site must not invent security claims that are not backed by repository evidence/evals.

## Before changing security semantics

1. read `SKILL.md`;
2. read `ARCHITECTURE.md`;
3. read the relevant reference docs;
4. preserve authorized-use and independent-verification requirements;
5. add/adjust validation or eval coverage.

## Do not

- turn SecHelix into an indiscriminate internet scanner;
- add destructive exploit defaults;
- hardcode private keys/secrets/wallet credentials;
- claim model superiority without reproducible evals;
- fork methodology across Claude/Codex/GLM adapters;
- inflate the hypothesis count without improving applicability/evidence quality.

## Validation

```bash
python scripts/validate_catalog.py
```

When report/gate logic changes, validate example reports as well.

## Website

`site/` is static and dependency-light by design. Keep motion subtle and respect `prefers-reduced-motion`. Keep the support page safe when donation configuration is empty.
