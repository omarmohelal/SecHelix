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
python scripts/validate_extensions.py
```

If your change affects reports/gates, run the relevant example gate as well.

Keep vendor adapters thin. The root `SKILL.md` is canonical; do not fork methodology into several model-specific copies.

## Building an extension

Community extensions can add an adapter, catalog pack, eval pack, policy pack,
reporter, specialist, or integration without forking the SecHelix core.

1. Open the [community extension proposal](https://github.com/omarmohelal/SecHelix/issues/new?template=extension.yml).
2. Copy `examples/extension-manifest.example.json` to
   `extensions/community/<extension-id>/extension.json`.
3. Add implementation, documentation, and deterministic synthetic fixtures.
4. Add the manifest to `extensions/registry.json` as `COMMUNITY`.
5. Run the extension validator and test suite before opening the pull request.

Every manifest must declare its network, filesystem, subprocess, and secret access.
New submissions cannot mark themselves `OFFICIAL`; promotion is a separate
maintainer decision after safety review and fixture proof.

Read [the complete extension program](docs/EXTENSIONS.md).

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
