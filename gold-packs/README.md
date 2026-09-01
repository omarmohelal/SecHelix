# Gold Check Packs

A Gold Check Pack is a reusable **investigation plan** for one security bug
class. It records what to look for, how to look safely, what would refute the
hypothesis, and what a fix has to preserve. It is not a scanner rule, not a
signature, and not a finding.

Packs deepen the existing catalog in [`catalog/checks.json`](../catalog/checks.json).
They do not create a second catalog and they do not add hypothesis IDs of their
own: every pack cites the catalog hypotheses it deepens.

## Claim status

**A pack match is a HYPOTHESIS.** The Variant Hunter classifies a candidate path
as `EXACT`, `VARIANT`, `REFUTED`, or `BLOCKED`; `EXACT` and `VARIANT` are
discovery classifications only. Applicability, evidence, and independent
verification are still required before anything is reported as a finding, and
`verification.independent_required` is `true` in every pack — a pack cannot
waive it.

**No pack claims measured performance.** Every pack in this directory carries
`calibration.measurement_status: "NOT_MEASURED"` with `sample_size: 0`. There is
no precision or recall number here, and none may be added without a reproducible
benchmark run that publishes its inputs, configuration, and outputs.

Packs also default to non-destructive work: `validation.destructive_actions` and
`validation.production_mutation` are `false`, and dynamic steps stay authorized,
local, and bounded.

## The five packs

| Pack | Bug class | Anchor invariant |
| --- | --- | --- |
| [`SEC-AUTHZ-IDOR-001`](SEC-AUTHZ-IDOR-001/pack.json) | Object authorization, missing subject boundary | Every protected object access is constrained by the effective subject at a canonical enforcement boundary |
| [`SEC-MONEY-INVARIANT-001`](SEC-MONEY-INVARIANT-001/pack.json) | Cumulative money invariants, partial-success accounting, ledger reconciliation | Committed outbound movements never exceed the captured value, and each movement is recorded exactly once |
| [`SEC-RACE-IDEMPOTENCY-001`](SEC-RACE-IDEMPOTENCY-001/pack.json) | Check-then-act on single-use resources, duplicate submission, retry and replay, outcome-unknown states | At most one execution commits the consumption; every repeat converges on that first committed outcome |
| [`SEC-SSRF-FETCH-001`](SEC-SSRF-FETCH-001/pack.json) | Server-side fetch destination control: validation-vs-request TOCTOU, redirect revalidation, resolution gaps, metadata endpoints | Every connection, including each redirect hop, terminates at an address that just passed the destination policy |
| [`SEC-AI-MCP-AUTHORITY-001`](SEC-AI-MCP-AUTHORITY-001/pack.json) | Untrusted retrieved content reaching privileged tool calls, tool authority allowlists, prompt and data separation, agent identity | Content that entered a run as data can never widen that run's tools, arguments, or credentials |

## Pack layout

One directory per pack, containing a single `pack.json` that satisfies
[`schemas/gold-check-pack-v1.schema.json`](../schemas/gold-check-pack-v1.schema.json)
(22 required keys, `additionalProperties: false`). The sections are:

- `threat_model` and `applicability` — who, what, and when the pack applies;
- `framework_fingerprints` — leads for where to look, never proof;
- `boundary` and `sinks` — the invariant and the operations that can break it;
- `detection_layers` — signals per layer (`MODEL`, `STATIC`, `CONTRACT`, `DATA`,
  `LOCAL_RUNTIME`, `STAGING_SAFE`);
- `validation` — safe, authorized, bounded reproduction steps;
- `false_positive_filters` and `verification` — what refutes the hypothesis and
  what independent verification must produce;
- `root_causes`, `remediation`, `regression` — the defective invariant, the
  canonical fix, and the fixtures that would catch a regression;
- `variant_strategy`, `mappings`, `calibration`, `limitations` — how the pack
  generalizes, what it maps to, what is unmeasured, and what it cannot tell you.

## Adding a pack

1. Choose an ID matching `^SEC-[A-Z][A-Z0-9-]{4,63}$` and set
   `lifecycle: "REFERENCE"`. Higher lifecycle states are assigned by maintainer
   review, not self-declared.
2. Cite only source IDs that exist in
   [`knowledge/source-registry.json`](../knowledge/source-registry.json), only
   hypothesis IDs that exist in [`catalog/checks.json`](../catalog/checks.json),
   and only fixture IDs that exist in the repository's `evals/fixtures`
   directory (not shipped in the portable skill bundle).
3. Keep `calibration` at `NOT_MEASURED` / `0` unless a reproducible benchmark run
   backs the numbers.
4. Write refutation tests a competent reviewer would actually run, and regression
   assertions that fail on the vulnerable variant *and* keep the legitimate
   operation working on the remediated one — otherwise a blanket denial passes as
   a fix.
5. Validate:

```bash
python scripts/validate_gold_packs.py
python -m unittest tests.test_gold_packs -v
```

The validator ([`scripts/validate_gold_packs.py`](../scripts/validate_gold_packs.py))
checks the schema plus the semantic rules: known provenance, resolvable catalog
and fixture IDs, honest calibration, non-destructive defaults, and mandatory
independent verification.

See [`references/gold-check-packs.md`](../references/gold-check-packs.md) for the
pack and Variant Hunter contracts in full.
