# VNext closeout

## Delivered

- Contract-first SecHelix core, catalog, attack-surface graph, applicability,
  evidence, finding, report, and scope surfaces.
- 546 stable hypotheses, 17 specialist profiles, safe evidence adapters,
  derived reports, release policies, paired eval fixtures, and CI validation.
- A self-contained `skills/sechelix/` distribution plus repository-root skills
  CLI discovery.
- Planning, official tooling evaluation, company rollout, private-policy,
  retention, signed-bundle, domain, compatibility, and release documentation.
- Public/private website separation checks. The separate product-site source is
  not present in this repository.

## Verification target

The release candidate must pass:

```bash
python -m unittest discover -s tests -v
python -m unittest discover -s adapters/tests -v
python scripts/validate_catalog.py
python scripts/validate_skill.py
python scripts/check_no_secrets.py
python scripts/check_private_site_leakage.py
python scripts/check_local_links.py
python scripts/check_install_snippets.py
npx skills@latest add . --list
```

## Deferred by design

- Public model/provider/scanner capability rankings: `NOT_MEASURED`.
- A stable 3.0 schema guarantee: this is `3.0.0-alpha.1`.
- Applying GitHub description/topics or creating a public release: maintainer
  action after reviewing and publishing the source commits.
- Website deployment: explicitly outside this release task.
