> **High-risk security claims are supported by evidence, not model consensus.**

Closes #

## What changed?

<!-- Keep this short and specific. -->

## Why?

<!-- What problem, gap, or false positive does this address? -->

## Security impact

<!-- Pick one: None / Safer default / New hypothesis / Changed verification / Tooling surface / Weaker default (explain) -->

## Contract and invariant checks

- [ ] **No contract change** — or, if a `schemas/*.schema.json` file changed, its
      `version` is bumped and the change is described above as breaking or
      backward-compatible.
- [ ] **No catalog-shape change** — `catalog/checks.json` still validates at exactly
      21 families × 26 lenses = 546 hypotheses, with stable IDs.
- [ ] If the canonical `SKILL.md` or any shared resource changed, I ran
      `python scripts/sync_portable_skill.py` and committed the resulting
      `skills/sechelix/` diff.
- [ ] No `UNKNOWN` or `BLOCKED` state can be converted into `NOT_APPLICABLE` by this change.

## Evidence

- [ ] I tested the changed skill/check/adapter.
- [ ] I included or updated a regression/eval where practical.
- [ ] I did not add secrets, real customer data, or unsafe live-target instructions.
- [ ] Documentation and `COMPATIBILITY.md` notes are updated where needed.
- [ ] No new benchmark, accuracy, or adoption claim is made without a reproducible run.

## Validation

Everything CI runs — paste or confirm it passed locally:

```bash
python scripts/validate_catalog.py
python scripts/validate_skill.py
python scripts/validate_extensions.py
python scripts/validate_knowledge.py
python scripts/validate_gold_packs.py
python scripts/check_private_site_leakage.py
python scripts/check_no_secrets.py
python scripts/check_local_links.py
python scripts/check_install_snippets.py
python -m unittest discover -s tests -p 'test_*.py'
python -m unittest discover -s adapters/tests
```

- [ ] All of the above pass locally.

## Extension lifecycle (if applicable)

- [ ] This extension declares every network, filesystem, subprocess, and secret
      permission it uses, includes synthetic fixtures, and starts in `COMMUNITY`.

<!-- Promotion beyond COMMUNITY is a separate maintainer-reviewed change. -->

## Notes for reviewers

<!-- Include false-positive traps, applicability constraints, or rollout concerns. -->

---

By opening this pull request I agree that my contribution is licensed under the
repository's [Apache-2.0 licence](../LICENSE).
