# Policy packs

A release gate answers "may this ship". That answer only means something if you can say **which
rules produced it**.

A report recording `PASS` without recording the policy that passed it is an unfalsifiable claim:
nobody can check it later, and nobody can tell whether the rules changed between the audit and the
release. So a policy pack is versioned, scoped, and stamped into the report it decided.

## Shape

```json
{
  "pack_id": "PROD-DEFAULT",
  "version": "1.0.0",
  "scope": { "environments": ["PRODUCTION"] },
  "rules": [{
    "rule_id": "PROD-NO-UNRESOLVED-HIGH",
    "statement": "Production cannot ship with an unresolved High or Critical finding.",
    "condition": { "severities": ["CRITICAL", "HIGH"], "finding_statuses": ["VERIFIED"],
                   "resolutions": ["OPEN", "DEFERRED"] },
    "outcome": "BLOCK"
  }]
}
```

`statement` is written so a non-engineer can check it. If a rule cannot be stated in one sentence
someone outside the team can verify, it is probably two rules.

Scope dimensions: organization, repository, branch, environment, data sensitivity. Conditions match
on severity, finding status, verification outcome, resolution, catalog family, surface pattern, and
whether regression or independent verification is required.

## What it refuses to do

**`INCOMPLETE` is not a softer `BLOCK`.** `BLOCK` asserts a problem exists. `INCOMPLETE` asserts the
decision cannot be made. Missing evidence produces the second, and it is never downgraded to a pass
because the policy did not happen to mention it.

**A pack with no rules is refused** — checked both when loading from disk and when evaluating an
in-memory pack, because a rule-less pack returning `PASS` is exactly the shape of configuring your
way to green.

**Unresolved scope is `INCOMPLETE`, not `PASS`.** If a pack constrains a dimension the caller did not
supply, applicability is unknown, and a pack whose applicability cannot be established must not
quietly decide nothing.

**Rules that were evaluated and did not fire are recorded.** Without that, a rule that never applied
is indistinguishable from one that passed.

**An accepted risk needs an owner and an expiry.** An acceptance with nobody attached is not a
decision anyone made; one without an expiry is a permanent exception acquired by writing a sentence.
A malformed or passed expiry blocks rather than passing.

## Usage

```python
from sechelix_core.policy_packs import evaluate, load_pack, stamp_report

pack = load_pack("policies/packs/production-default.json")
decision = evaluate(pack, report, {"environment": "PRODUCTION", "repository": "app"})
stamp_report(report, [decision])
```

The shipped pack is [`policies/packs/production-default.json`](../../policies/packs/production-default.json).
It encodes: no unresolved High/Critical in production; no unproven High/Critical candidate; fixed
findings need regression proof; High/Critical need independent verification; money paths need a race
and idempotency review; MCP tools need an authorization review; URL fetchers need an SSRF review.

## Related

- [Verifier quorum](verifier-quorum.md)
- [Proof bundles](proof-bundles.md)
