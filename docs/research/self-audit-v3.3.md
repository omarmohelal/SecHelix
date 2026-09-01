# Self-audit — V3.3

<!-- doc-consistency: snapshot -->
> **Dated snapshot.** This records what the V3.3 change set looked like when it was audited on
> 2026-09-01; the tree has moved since.

SecHelix reviewed its own V3.3 changes using its own modules. The point of running a security tool
on itself is not the findings — it is discovering where the tool is wrong.

## Scope and authorization

| | |
|---|---|
| Target | `omarmohelal/SecHelix`, branch `v3.3/evidence-intelligence` |
| Authorization | Owner self-audit; the target is this repository |
| Mode | `STATIC` |
| Change set | 38 files, 5,057 diff lines, `main...v3.3/evidence-intelligence` |
| Scanners | none enabled |
| Network | nothing contacted |

## Differential result

`sechelix_core.diff_review.review_diff` over the full diff:

| Direction | Count |
|---|---:|
| `NEW_RISK` | 17 |
| `RISK_REDUCED` | 0 |
| `UNCHANGED` | 0 |
| `UNKNOWN` | 6 |

Overall: `NEW_RISK`. Families in scope: AI, API, AUTHZ, BIZ, CLOUD, CRYPTO, FILE, MONEY, PRIV, RACE,
SUPPLY.

**No delta was promoted to a finding.** Every one is a hypothesis, which is what the module
contracts for. The value of this run was elsewhere.

## What the self-audit actually found: the tool flagging its own prose

The first pass produced deltas like these:

| Kind | Line it matched |
|---|---|
| `storage_access` | `# Below this, a bucket's observed rate is noise` |
| `webhook` | `the digest. Neither is a signature — it detects accidental modification` |
| `storage_access` | `"description": "Below this, a bucket's observed rate is noise"` |

None of those lines do anything. They are a comment, a docstring body, and a JSON Schema
`description`. A reviewer handed them would lose time on all three, which is precisely the
false-positive class this project exists to reject — appearing in the project's own differential
reviewer.

`_is_prose` already skipped `.md` and `.rst` files, but nothing skipped prose *inside* code.

**Fixed.** `diff_review` now suppresses non-`secret` rules on commentary: comment lines across
several comment syntaxes, docstring bodies tracked by triple-quote parity, and prose-valued JSON
keys (`description`, `title`, `rationale`, and similar). A credential in a comment is still
reported, because a credential pasted into a comment is still a credential.

Eight tests fix the boundary in both directions — prose suppressed, real code on the same surface
still flagged, and the parity tracker proven not to swallow the file after a docstring closes.

## What remains, and why it is not being "fixed"

After the fix, deltas like these survive:

| Kind | Line |
|---|---|
| `storage_access` | `for bucket in buckets:` |
| `dependency` | `BUNDLE_VERSION = "1.0"` |

These are real code. "Bucket" genuinely means object storage in most codebases and a sample bucket
in this one; `NAME = "1.0"` genuinely looks like a pinned version. Distinguishing them needs
semantic understanding that a regex classifier does not have.

Suppressing them by name would trade a small amount of noise for a real risk of missing storage
access and dependency pins in code that *is* about those things. The module's contract already says
a delta is a hypothesis carrying no severity, so the honest response is to record the limitation
rather than tune the tool against its own source.

## Other defects found during V3.3

Both were found by testing that tried to break a claim rather than confirm it, and both were
fail-open in modules whose stated contract is fail-closed.

**An unresolved `CRITICAL` hypothesis passed the release gate.** `UNPROVEN_STATES` covered
`LIKELY_BUT_UNPROVEN` and `BLOCKED_BY_ENVIRONMENT` but not `HYPOTHESIS`, so a `CRITICAL` candidate
that was raised and never resolved fell through every branch and returned `PASS`. Now `INCOMPLETE`.

**An empty `current_commit` made every report `FRESH`.** `assess_freshness` compared on
`min(len(a), len(b))` with no floor, so `""` — what `git rev-parse` yields when it produces no
output rather than `None` — compared equal to everything. Comparison now requires seven characters
on both sides.

## Release decision

`INCOMPLETE` would be the honest gate outcome for a change set classified `NEW_RISK` with nothing
verified against it. That is not a defect in the change; it is the correct reading of a static
differential review with no verification pass behind it.

The gates that *are* decidable all pass: 394 unit tests, 19 adapter tests, catalog, skill,
knowledge, Gold Pack, link, install-snippet and doc-consistency validation.

## Limitations

- `STATIC` only. Nothing was executed, so nothing here establishes runtime behaviour.
- One reviewer, no independent verification pass. Under this project's own rules that caps every
  observation above at hypothesis.
- A self-audit is the weakest kind. The author and the reviewer share assumptions, which is exactly
  why the eval benchmark stays `NOT_MEASURED` pending an uncontaminated evaluator.
