# Contributing to SecHelix

Contributions are welcome. Security check additions should improve signal, evidence quality, or portability — not simply increase the check count.

## Good contributions

- new applicability rules;
- reproducible eval fixtures;
- false-positive reductions;
- model/tool adapters;
- scanner normalizers;
- browser/runtime verification;
- authorization/business-logic/race-condition cases;
- documentation corrections;
- accessibility/performance improvements to the site.

## Adding coverage

A new family/lens/check proposal should include:

1. **Threat** — what can fail?
2. **Applicability** — what architecture/state makes it relevant?
3. **Evidence** — what proves or refutes it?
4. **False-positive traps** — what commonly looks vulnerable but is not?
5. **Safe verification** — how to prove it without destructive behavior?
6. **Reference** — authoritative standard, advisory, research, or reproducible case.
7. **Eval** — a fixture where practical.

## Pull request quality

Before opening a PR:

```bash
python scripts/validate_catalog.py
```

If your change affects reports/gates, run the relevant example gate as well.

Keep vendor adapters thin. The root `SKILL.md` is canonical; do not fork methodology into several model-specific copies.

## Security research contributions

Do not submit real stolen credentials, private customer data, live third-party targets, weaponized malware, or destructive exploit scripts.

Use synthetic fixtures or targets you own/control.

## Style

- evidence before conclusion;
- concise actionable Markdown;
- portable paths;
- deterministic scripts;
- no fake benchmark claims;
- no model/provider superiority claims without reproducible evals.