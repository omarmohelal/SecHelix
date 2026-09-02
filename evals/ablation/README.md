# Ablation benchmark — does SecHelix actually help?

The blind benchmark answers "how well does this do". This answers the harder and more useful
question: **how much of that is SecHelix, and how much is the model underneath it?**

A methodology that scores well with a strong model may be adding nothing. The only way to know is to
run the same model on the same cases twice — once with the skill and once without — and measure the
difference.

**Status: not run.** Like the blind benchmark, this requires an evaluator that has never seen the
fixtures. The session that wrote this file is disqualified.

## Design

Two arms, one variable.

| | Arm A — control | Arm B — treatment |
|---|---|---|
| Model | identical | identical |
| Temperature / settings | identical | identical |
| Cases | identical (`../blind-packet/cases.json`) | identical |
| Instruction | generic security review | SecHelix skill loaded |

**The only difference permitted is the skill.** Different models, prompts, temperatures or case sets
between arms make the delta unattributable, and an unattributable delta is worse than no measurement
because it looks like one.

### Arm A instruction (verbatim)

> You are reviewing a single source file for security weaknesses. Decide whether the file contains
> an exploitable security weakness (`VULNERABLE`) or does not (`CLEAN`). Some files are written to
> look alarming while being protected by a real compensating control; some are written to look
> ordinary while being exploitable. Judge the actual behaviour, not the surface. Answer with exactly
> one label.

This is the same instruction the blind packet already uses, so Arm A is directly comparable to the
existing keyword floor.

### Arm B instruction (verbatim)

> Use SecHelix to review this file. Follow the skill's methodology, including independent
> verification and refutation, and answer with exactly one label: `VULNERABLE` or `CLEAN`.

Arm B gets the skill and nothing else. No extra tools, no extra context, no larger budget — a
treatment arm with more resources measures the resources.

## What gets measured

| Metric | Why it is in the table |
|---|---|
| Precision | The headline, but alone it rewards a reviewer that says CLEAN to everything |
| Detection recall | Pairs with precision; neither means much without the other |
| **Verified precision** | The claim this project actually makes — a finding that survived refutation |
| **False-positive rejection rate** | The thing the methodology is *for*. If Arm B does not beat Arm A here, the central claim is unsupported |
| Root-cause quality | Scored by a rubric, not by string match; requires a human or a third model |
| Regression quality | Whether the proposed test would actually fail on the vulnerable variant |
| Time and cost | The price of the improvement, which is part of whether it is worth having |

**False-positive rejection is the load-bearing metric.** SecHelix's argument is not "finds more" — it
is "accuses less wrongly". A result showing Arm B with higher recall and identical FP rejection would
mean the skill mostly made the model more eager, which is a different product than the one described.

## Rules

**Multiple runs where budget allows.** A single run of each arm on 76 cases cannot separate a real
effect from sampling noise. Three runs per arm is a reasonable floor; report the spread, not just the
mean. With one run per arm, say so and treat the delta as indicative rather than measured.

**Publish both arms in full**, including the raw prediction packets. A delta without its inputs is
not reproducible.

**Publish a bad result.** If Arm B does not beat Arm A, that is the most valuable measurement this
project could produce, and burying it would make every other honesty claim here worthless. Re-running
until the delta improves is selection, not evaluation.

**Never run this where ground truth has been seen.** Same disqualification rules as
[`../blind-packet/RUN.md`](../blind-packet/RUN.md): no session that has read `evals/fixtures/`,
`scripts/build_eval_fixtures.py`, or `gold-packs/*/pack.json`.

## Procedure

1. Read the eligibility rules in [`../blind-packet/RUN.md`](../blind-packet/RUN.md). Stop if
   disqualified.
2. Download `cases.json` and verify its digest, as that runbook describes.
3. Run Arm A. Save the packet as `arm-a-run-N.json` with `"arm": "CONTROL"`.
4. Run Arm B. Save as `arm-b-run-N.json` with `"arm": "TREATMENT"`.
5. Score each packet with `python evals/run_evals.py --predictions <packet> --output <result>`.
6. Record the delta per metric, with the spread across runs.

Both packets use the schema in `../blind-packet/RUN.md`, plus an `arm` field and an
`ablation_run_id` shared between the two arms of one pairing.

## What a result will not establish

The suite is 38 authored paired fixtures across 10 families. A positive delta shows the methodology
helps *on near-miss pairs designed to punish surface reading* — which is the case it was built for,
and therefore the case most favourable to it.

It does not establish performance on an unfamiliar production codebase, and no result from this
benchmark should be described that way.
