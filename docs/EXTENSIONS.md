# SecHelix extension program

SecHelix accepts community-built adapters, catalog packs, eval packs, policy packs,
reporters, specialists, and integrations. The registry is curated: a pull request
can propose an extension, but it cannot make itself official.

## The lifecycle

1. **Propose** — open the extension proposal issue before implementation.
2. **Submit** — fork the repository and add
   `extensions/community/<extension-id>/extension.json` plus the implementation,
   documentation, and synthetic fixtures.
3. **Contract checks** — CI validates the manifest, declared permissions, safe
   defaults, repository paths, registry identity, and test command.
4. **Safety review** — maintainers review data handling, dependencies, network,
   filesystem, subprocess, secret access, and evidence provenance.
5. **Fixture proof** — the extension must pass a vulnerable/clean or
   positive/negative fixture pair where the extension type permits it.
6. **Channel decision** — accepted submissions begin as `COMMUNITY`.
   Maintainers may later promote proven work to `INCUBATING` or `OFFICIAL` in a
   separate reviewed change.

`OFFICIAL` means maintained under the SecHelix release process. It is not a badge a
contributor can set in an extension manifest.

## Start an extension

Copy `examples/extension-manifest.example.json` to
`extensions/community/<extension-id>/extension.json`, replace every example value,
and add the matching entry to `extensions/registry.json` with lifecycle
`COMMUNITY`.

Run:

```bash
python scripts/validate_extensions.py
python -m unittest discover -s tests -p "test_*.py" -v
```

The manifest must declare all authority it needs. Undeclared network, filesystem,
subprocess, or secret access is grounds for rejection. Community extensions must
default to static, local-safe, or staging-safe operation; destructive actions and
production mutation are forbidden by the v1 manifest contract.

## Review evidence

A reviewable submission includes:

- a concise threat and trust-boundary note;
- complete permission and data-handling declarations;
- synthetic fixtures with deterministic expected output;
- a dependency and license inventory;
- redacted logs or evidence artifacts from the test command;
- limitations and known false-positive traps;
- documentation that distinguishes scanner signals from verified findings.

Keep extensions thin. They may contribute observations or policy, but they must not
silently redefine SecHelix severity, authorization, evidence, or verification
semantics.
