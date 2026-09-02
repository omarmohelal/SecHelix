# Secret lifecycle

Finding the secret is the cheap part.

Every scanner does it, and every scanner produces the same thing: a list of places a string that
looks like a credential appears. That list is not a remediation state. It is the first row of one.

The state that matters runs:

```
detected → located → revoked → rotated → artifacts/history/logs cleaned → retested
```

This module models the whole run, because the failures that actually leak credentials happen after
detection, and every one of them is a conflation a list of hits cannot express.

## Exposure surfaces

A credential is not in one place. It is in every place a copy of the file, the build, or the console
output ever reached. Seven surfaces are tracked, and all seven appear in every exported record —
including the ones nobody looked at.

| Surface | The copy it holds |
|---|---|
| `SOURCE` | The working tree, at one revision |
| `GIT_HISTORY` | Every revision, every clone, every fork, every pull-request ref |
| `BUILD_ARTIFACT` | Published packages and release assets that were already downloaded |
| `FRONTEND_BUNDLE` | Shipped JavaScript on other people's machines, CDN edges, archived deploys |
| `LOGS` | The origin log, plus shippers, backups, SIEM indexes and analytics |
| `CI_CONFIG` | Workflow files — which are normally *also* in git and *also* echoed into build logs |
| `CONTAINER_IMAGE` | Layers, which survive a tag deletion while anything still references them |

Each surface carries a `residual_note` stating what a cleanup of it still does not reach. That note
is why revocation is the load-bearing step: it is the only one whose reach extends to copies that
have already left.

## Statuses

Per surface: `NOT_SEARCHED`, `EXPOSED`, `SEARCHED_CLEAN`, `CLEANED`, `NOT_APPLICABLE`.

`NOT_SEARCHED` is the default, and it means **unknown, not clean**. A surface omitted from a report
reads as clean to every reader; a surface present and saying it was never searched reads as what it
is.

Overall: `UNKNOWN`, `EXPOSED`, `PARTIALLY_REMEDIATED`, `REMEDIATED`.

`REMEDIATED` requires *all* of: revocation confirmed with evidence, every located surface cleared by
an action that clears that surface, no surface left unsearched, and a retest showing the old
credential is now rejected. Anything less with something genuinely done is `PARTIALLY_REMEDIATED`.
Anything less with nothing done and an exposure located is `EXPOSED`. Anything less with nothing
done and nothing located is `UNKNOWN`.

## What it refuses to do

**It never holds the secret.** A sighting is reduced at the door to a truncated SHA-256 fingerprint
over a domain-separated encoding, so two sightings of the same credential correlate without either
storing it. `SecretIdentity` has no field that could carry the value — the value is a parameter and a
local in one classmethod, and nothing else. Everything exported also passes through the redaction in
[`proof_bundle`](proof-bundles.md), which is the second line rather than the first: the operator who
pastes a credential into a locator field is a real person who exists.

The fingerprint is not a confidentiality control for a *weak* secret. A truncated hash of `hunter2`
is guessable by anyone who thinks to guess it. It protects a high-entropy token and correlates a
low-entropy one, the domain prefix keeps a published fingerprint out of general-purpose hash tables,
and that is the whole of its guarantee.

**`REMOVED_FROM_SOURCE` cannot satisfy the git-history surface.** This is the single most common
real-world failure here, and it is a conflation rather than an oversight: the fix for one surface
gets recorded as the fix for all of them. So the two are not merely tracked separately — each surface
declares the actions that clear it, those sets are disjoint, and `REMOVED_FROM_SOURCE` appears only
under `SOURCE`. Attaching it to `GIT_HISTORY` raises. There is no flag that makes it work, which is
the only way this stops happening.

Rewriting history is what clears that surface, and even then the residual note stands: a rewrite does
not reach existing clones, forks, pull-request refs, or the provider-side copies of the commits it
leaves dangling.

**Rotation never satisfies revocation.** Issuing a replacement restores the service and does nothing
to the leaked credential, which remains valid at the issuer and present in every copy that already
left. They are separate steps with separate evidence, and a record with rotation confirmed and
revocation missing says so in its blockers, in those words.

**A claim is not a confirmation.** `CONFIRMED` requires at least one evidence id; a step asserted
without one is recorded as `CLAIMED` and satisfies nothing. A clean search is a claim about what is
*not* there and needs evidence too, or the surface stays `NOT_SEARCHED`.

**A surface nobody searched cannot be cleaned.** Cleaning a surface that was never looked at is an
assumption, not a step, and the call raises rather than recording it.

**`UNKNOWN` never renders as remediated.** The Markdown renderer for that state does not contain the
word in any form — not in a heading, not in a negation. A reader skimming a page for it will find it
wherever it appears, caveat or no caveat.

## Usage

```python
from sechelix_core.secret_lifecycle import CONFIRMED, SecretIdentity, SecretLifecycle

record = SecretLifecycle(
    "SEC-1",
    SecretIdentity.from_value(value, kind="aws_access_key", detector="gitleaks"),
)
record.locate("SOURCE", "app/settings.py:12", evidence_ids=["EV-1"])
record.locate("GIT_HISTORY", "commit 9a1f2c3", evidence_ids=["EV-2"])
record.clean("SOURCE", "REMOVED_FROM_SOURCE", evidence_ids=["EV-3"])
record.revoke(status=CONFIRMED, method="provider console", evidence_ids=["EV-4"])

record.state()      # PARTIALLY_REMEDIATED — git history is still exposed
record.blockers()   # every reason REMEDIATED is withheld, in reading order
```

Records validate against
[`schemas/secret-lifecycle-v1.schema.json`](../../schemas/secret-lifecycle-v1.schema.json) via
`validate_contract("secret-lifecycle", record.as_dict())`.

Use `is_remediated(record)` rather than testing the state yourself. It exists so nobody writes
`state != "EXPOSED"`, which reads as "remediated" and silently promotes both `UNKNOWN` and
`PARTIALLY_REMEDIATED`.

## The honest limit

This module records a lifecycle. It does not perform one: it revokes nothing, rewrites nothing, and
checks nothing at a provider. Every status in it is somebody's assertion plus an evidence id, and the
quality of the record is the quality of that evidence.

It also cannot tell you that a fingerprint seen twice is one issued credential rather than two
identical values, and it has no opinion on whether the credential was used. Those are questions for
the issuer's audit log, which is outside this repository.

## Related

- [Proof bundles](proof-bundles.md) — where the redaction comes from
- [Public git history policy](git-history-policy.md) — why rewriting published history is a decision, not a cleanup step
- [AI, agent, and MCP security](ai-agent-security.md) — credentials reachable from a tool argument
