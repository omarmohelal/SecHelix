# Contributing to SecHelix

Contributions are welcome. Security check additions should improve signal, evidence quality, or portability — not simply increase the check count.

## The most valuable contribution

A **[false-positive or missed-class report](https://github.com/omarmohelal/SecHelix/issues/new?template=false-positive.yml)**
with a minimal reproducing snippet. This project's whole claim is that findings
get verified before they are asserted, so every case where that failed is worth
more than a new check. A good FP report usually becomes an eval fixture directly.

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

> **Read this first.** `catalog/checks.json` is a fixed cross-product of exactly
> **21 families × 26 lenses = 546** hypotheses, and `scripts/validate_catalog.py`
> enforces it. Deepening an existing family × lens cell is straightforward. Adding
> a **new family or lens** changes the catalog model itself, requires a versioned
> catalog change plus updated validation, and is rarely accepted. If your idea does
> not fit an existing cell, a [Gold Check Pack](gold-packs/README.md) or an
> extension is usually the right home.

A new check proposal should include:

1. **Threat** — what can fail?
2. **Applicability** — what architecture/state makes it relevant?
3. **Evidence** — what proves or refutes it?
4. **False-positive traps** — what commonly looks vulnerable but is not?
5. **Safe verification** — how to prove it without destructive behavior?
6. **Reference** — authoritative standard, advisory, research, or reproducible case.
7. **Eval** — a fixture where practical.

## Development environment

There is nothing to install. The skill bundle, the validators, and the tests use
the **Python standard library only** — no virtualenv, no `requirements.txt`, no
lockfile.

- CI runs **Python 3.12**. Anything 3.11+ should work; 3.12 is what is verified.
- Node is needed only to exercise the Agent Skills installer (`npx skills@latest`).

Run a single test file while iterating:

```bash
python -m unittest tests.test_report_renderer -v
```

## Pull request quality

Before opening a PR, run everything CI runs. The earlier three-command list was
incomplete and would leave you red on push:

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

If your change affects reports or gates, run the relevant example gate as well.

### The canonical skill and its adapter mirrors

`skills/sechelix/SKILL.md` is canonical. CI requires the adapter mirrors to exist and stay in
step: `skills/sechelix/`, `.claude/skills/sechelix/`, `.codex/skills/sechelix/`,
`.agents/skills/sechelix/`, and `.github/skills/sechelix/`.

Do not hand-edit them. Edit the canonical sources, then regenerate:

```bash
python scripts/sync_portable_skill.py
```

and commit the resulting `skills/sechelix/` diff. This is the single most common
reason a first PR fails CI.

"Keep vendor adapters thin" means the thin host-specific `SKILL.md` files under
`.claude/`, `.codex/`, `.agents/`, and `.github/` must not restate methodology —
they point at the canonical skill. It does not mean the generated portable bundle
is optional.

Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`).

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

## Contributing knowledge

Knowledge changes must improve provenance, rights clarity, or reusable review
judgment—not copy a third-party curriculum into the repository.

1. Register or update the source in `knowledge/source-registry.json`, including
   publisher independence, exact terms URL, license state, allowed uses, and
   refresh cadence.
2. Pin the source release/revision where possible and retain attribution.
3. Add graph edges only when the referenced release supports the mapping.
4. Write lesson cards as original summaries with detection signals, safe local
   tests, false-positive traps, remediation, and regression proof.
5. Add or update tests, then run `python scripts/validate_knowledge.py`.

Do not submit copied labs, paywalled/private content, restricted-platform text,
embeddings, leaked course material, customer code, exploit dumps, or training data
whose rights and provenance are unclear. `HUMAN_ONLY` sources cannot back lesson
cards or automated research packets.

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

## Licensing

SecHelix is Apache-2.0. By submitting a contribution you agree it is licensed
under [the same terms](LICENSE) (inbound = outbound). There is no CLA and no DCO
sign-off requirement.

Only contribute work you have the right to license. Do not paste code, lab
content, or curriculum text from a source whose terms you have not checked —
`HUMAN_ONLY` sources in `knowledge/source-registry.json` in particular cannot
back lesson cards or automated research packets.

## Review

There is one maintainer and no review SLA. Security reports are prioritized over
everything else — see [SECURITY.md](SECURITY.md). Smaller, single-purpose pull
requests are reviewed faster than large mixed ones.
