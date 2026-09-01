# Confidence calibration

Every finding states a confidence. Nothing checked whether that word meant anything.

If candidates marked `HIGH` are verified 55% of the time, then `HIGH` is decoration — and a
reader who trusts it is being misled by a field that *looks* quantitative. Calibration compares
stated confidence against what the independent verifier actually concluded, and reports the gap.

**Current status: `NOT_MEASURED`.** No uncontaminated sample set of sufficient size exists yet.

## What it measures

For each confidence bucket: how many candidates were raised, how many the verifier confirmed, how
many it refuted, and how many never resolved. From the resolved ones it derives an observed rate and
compares it to what the label asserts.

| Label | Asserts |
|---|---:|
| `HIGH` | 0.90 |
| `MEDIUM` | 0.60 |
| `LOW` | 0.30 |
| `NOT_ASSESSED` | — |

Those probabilities are published **inside every record**, so a reader can disagree with the mapping
rather than guess it. `NOT_ASSESSED` is tracked but never scored: a finding that stated no
confidence made no prediction to be right or wrong about.

Two failure directions are named separately, because they cost different things:

- **Overconfident** — the observed rate falls materially below what the label asserts. These produce
  false accusations, which is the failure this project exists to prevent.
- **Underconfident** — the observed rate exceeds it. These produce real findings that were
  downgraded or discarded.

## What it refuses to do

**It will not report a number it has not earned.** Below `minimum_sample_size` resolved samples
(default 30), `measurement_status` is `NOT_MEASURED` and *every* metric renders as that literal
string — the headline figure and each per-bucket rate. Publishing a bucket rate while the headline
says `NOT_MEASURED` is how a number escapes its caveat and gets quoted a year later without one.

**The minimum is recorded in the record, not chosen at render time.** It cannot be lowered after
someone sees an unflattering result.

**Contamination disqualifies the whole record.** A session scoring findings it produced is measuring
its own memory. The record carries the reason in its first limitation rather than dropping the
samples quietly.

**Unresolved candidates never enter the rate.** A candidate whose verification was blocked by the
environment is not evidence that the confidence was right, and not evidence that it was wrong.
Folding them into the denominator would let an infrastructure failure read as a calibration result.
A bucket where everything is unresolved has no rate at all.

## Usage

```python
from sechelix_core.calibration import Contamination, calibrate, samples_from_report

record = calibrate(
    samples_from_report(report),
    contamination=Contamination(False, "NONE"),
    limitations=["Single project; measures agreement with this verifier, not ground truth."],
)
```

Samples are taken from each finding's **verification block**, not its status — the question is
whether the verifier agreed with the reviewer, so reading the reviewer's own conclusion would be
circular.

Records validate against [`schemas/calibration-v1.schema.json`](../../schemas/calibration-v1.schema.json)
via `validate_contract("calibration", record)`.

## The honest limit

Calibration measures agreement between stated confidence and **this verifier**. It is not accuracy
against ground truth. A perfectly calibrated reviewer paired with a bad verifier scores well and
means nothing.

That is why calibration is reported alongside the blind benchmark rather than instead of it, and why
`docs/research/evaluation-report.md` remains the place where correctness is discussed.

## Related

- [Blind evaluation packet](../../evals/blind-packet/README.md) — the uncontaminated measurement
- [Evaluation report](../research/evaluation-report.md) — why the benchmark is `NOT_MEASURED`
