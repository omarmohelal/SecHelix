# CLAUDE.md

Use `.claude/skills/sechelix/SKILL.md` to activate the SecHelix workflow when reviewing this repository or when developing the skill.

Repository invariants:

- `skills/sechelix/SKILL.md` is the canonical skill;
- keep adapters thin;
- High/Critical security claims require independent verification in examples/evals;
- dynamic testing must remain authorized and bounded;
- `catalog/checks.json` must remain exactly 21 families × 26 lenses unless a versioned catalog change intentionally updates the model and validation;
- do not edit the public donation configuration with anything except public addresses/links;
- site changes must remain dependency-light, accessible and reduced-motion aware.

Run:

```bash
python scripts/validate_catalog.py
```

before considering catalog/skill structural changes complete.