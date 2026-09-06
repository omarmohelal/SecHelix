# The Arena could certify itself — 2026-09-06

The Arena harness was built in the V4 programme and, until today, had never been
run. Running it against SecHelix itself found a defect in the harness, not in
the participant.

## What was tried

A deliberately maximal self-serving submission: SecHelix as the participant,
all 76 blind-packet cases, **every one of the six workflow metrics set to
`true`** — a perfect 1.000 across the board, authored by the project about the
project.

**Declared honestly** (`evaluator_independent: false`,
`assessor.independent: false`), the gate held:

```
measurement_status: NOT_MEASURED
eligible: False
blockers:
  - assessment is not marked independent
  - independent evaluator not established
```

The perfect scores were computed and recorded. They were simply not publishable.
That is the correct behaviour, and it is the behaviour the project claims.

## The defect

Flipping those two booleans to `true` — changing nothing else, adding no
evidence — produced:

```
measurement_status: MEASURED
eligible: True
blockers: []
```

A fabricated perfect score, self-authored, promoted to a publishable
`MEASURED` record by two keystrokes.

Independence was gated on a **self-declaration about a fact the harness has no
way to check**. Every other gate in this project demands an artifact; this one
accepted an assertion. For a benchmark whose entire purpose is to constrain what
its author may claim, that is the worst possible place to take someone's word —
including the author's own.

## The fix

Independence still cannot be *verified* locally; that is fundamental, and
pretending otherwise would repeat the mistake. It can be made **attributable**,
so a reader can check the claim even though the harness cannot:

- `assessor.independence_basis` — must state how independence was established.
- `assessor.attestation_url` — must be a resolvable `https` URL.
- The attestation must **not** be published by the participant's own account or
  point at the participant itself.
- `assessor.independent` and `blindness.evaluator_independent` must agree.

An honestly-declared dependent assessment owes no attestation — it is
unpublishable, not malformed. That distinction is deliberate: self-assessment
should be *recordable and clearly labelled*, never *silently rejected*, or people
stop recording it.

Both attacks are now blocked, and both are regression tests:

```
1. bare booleans flipped     -> NOT_MEASURED (attestation_url missing,
                                              independence_basis missing)
2. attestation on the
   participant's own account -> NOT_MEASURED (cannot attest to its independence)
```

## What this does not fix

A determined author can still publish an attestation from a second account they
control. **No local harness can close that**, and this document should not be
read as claiming otherwise. What changed is the cost and the visibility: the
claim now names a basis and points at an artifact with an owner, so a reader who
doubts it has something specific to check. That is the honest ceiling.

## Standing consequence

The full SecHelix workflow remains **`NOT_MEASURED`**. It cannot become
`MEASURED` through any amount of work by this project alone — by construction, it
now requires an assessor who is not us. The blind label suite
(precision 0.950, FP rejection 0.947) is unaffected: it was independently
executed and remains the only `MEASURED` number.
