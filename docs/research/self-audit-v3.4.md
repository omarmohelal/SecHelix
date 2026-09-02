# Self-audit — V3.4

<!-- doc-consistency: snapshot -->
> **Dated snapshot.** Records what the V3.4 change set looked like when audited on 2026-09-02.

SecHelix reviewed its own V3.4 release using its own modules. As in V3.3, the value was not the
findings — it was discovering where the tool is wrong.

## Scope

| | |
|---|---|
| Target | `omarmohelal/SecHelix`, `v3.4/evidence-platform` |
| Authorization | Owner self-audit |
| Mode | `STATIC` |
| Change set | 76 files, 16,753 diff lines |
| Scanners | none |
| Network | nothing contacted |

## What the self-audit found

The first pass produced 61 deltas. A representative sample:

| Kind | Line |
|---|---|
| `ai_tool` | `"rule_id": "MCP-WRITE-AUTHORIZATION",` |
| `webhook` | `"(^\|_)(value\|secret\|token\|...\|signature)"` |
| `payment_state` | `"surface_patterns": ["payment", "billing", "checkout"]` |
| `dependency` | `"schema_version": "1.0",` |

Every one is a **description of a risk being flagged as the risk**. The first is a policy rule
naming what to look for. The second is a JSON Schema's own redaction pattern. The third is the
policy pack's list of money-path substrings. None of them execute.

**Fixed.** Schema files (`*.schema.json`) and policy packs (`policies/**`) now join prose files as
declarations, where only the `secret` rule applies. Prose files were additionally narrowed to
`secret` alone — a version number written in documentation is documentation, and the dependency that
would matter lives in a lockfile.

Deltas on the release diff fell from 61 to 50. A credential in a schema or in prose is still
reported, `package.json` dependency changes are still read, and application code is untouched. Nine
tests fix the boundary in both directions.

## Defects found by other means

Three came from tests written to break a claim rather than confirm it, and from an independent
review of modules this session wrote.

**A proof bundle accepted injected files.** `verify_bundle` iterated the manifest and stopped, so it
proved every *listed* file intact and said nothing about one added after export. An injected
artifact was unhashed, unlisted, and reported as internally consistent — in the function whose
entire purpose is a recipient checking a bundle they were sent. Now reports any file present but
unlisted.

**The drift gate read two sources of truth.** Ground truth came from the working tree while the prose
it checked came from git, so writing a new schema turned the gate red *before* commit against a dozen
documents the author might not be touching. A contributor scoped to `schemas/` could not legally fix
the failure their own change caused. Both halves now read git.

**Three files stated three versions.** `ROADMAP.md` said `3.0.0-alpha.5` while both manifests said
`3.2.0-alpha.1`. The declared version is now a gated fact.

## A correction worth recording

One commit in this cycle claimed the drift gate had been switched to read from git. The edit had
silently failed to apply, and the claim was false for four commits. It was caught by re-reading the
file rather than by any gate, and the follow-up commit says so in its first line.

That is the same failure class this project exists to catch, in its own commit log: a confident
statement that nothing checked.

## Release decision

`INCOMPLETE` is the honest gate outcome for a change set classified `NEW_RISK` with nothing verified
against it. That is the correct reading of a static differential review with no verification pass
behind it, not a defect in the change.

Every decidable gate passes: 816 unit tests, 19 adapter tests, catalog, skill, knowledge, Gold Pack,
link, install-snippet, secret, commit-hygiene and doc-consistency validation, plus a cold install in
which all nine new modules import and the policy engine runs.

## Limitations

- `STATIC` only; nothing executed, so nothing here establishes runtime behaviour.
- One reviewer, no independent verification pass — which caps every observation above at hypothesis
  under this project's own rules.
- A self-audit is the weakest kind. Author and reviewer share assumptions, which is exactly why the
  benchmark stays `NOT_MEASURED` pending an uncontaminated evaluator.
