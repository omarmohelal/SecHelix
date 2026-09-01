"""Confidence calibration: does stated confidence predict the verifier's verdict?

Every finding states a confidence. Nothing has ever checked whether that number
means anything. If candidates marked HIGH are verified 55% of the time, then HIGH
is decoration, and a reader who trusts it is being misled by a field that looks
quantitative.

This module compares stated confidence against what the independent verifier
actually concluded, and reports the gap.

Three rules keep it from becoming the exact thing this project refuses to ship.

**A calibration record is a claim about the reviewer**, so it obeys the same
evidence rules as a claim about code. Below a declared minimum sample size, every
metric renders as the literal string ``NOT_MEASURED``. It is never a number that
happens to be based on four samples.

**Contamination disqualifies the whole record, not individual samples.** A session
scoring findings it produced is measuring its own memory. The record carries the
reason rather than dropping the samples quietly.

**Unresolved candidates are counted separately and never folded into either
side.** A candidate whose verification was blocked is not evidence that the
confidence was right, and it is not evidence that it was wrong. Splitting them
into the denominator would let an environment failure look like a calibration
result.

The minimum sample size is declared *in the record* rather than chosen at render
time, so it cannot be lowered after seeing an unflattering number.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

NOT_MEASURED = "NOT_MEASURED"
MEASURED = "MEASURED"

VERIFIED = "VERIFIED"
REFUTED = {"FALSE_POSITIVE", "DUPLICATE_ROOT_CAUSE"}
UNRESOLVED = {"NOT_RUN", "LIKELY_BUT_UNPROVEN", "BLOCKED_BY_ENVIRONMENT"}

#: What each label is taken to assert. Published in the record so a reader can
#: argue with the mapping instead of guessing it. NOT_ASSESSED made no prediction,
#: so there is nothing to be right or wrong about.
STATED_PROBABILITY: dict[str, float | str] = {
    "HIGH": 0.90,
    "MEDIUM": 0.60,
    "LOW": 0.30,
    "NOT_ASSESSED": "NOT_APPLICABLE",
}

#: Below this many *resolved* samples a bucket's rate is noise.
DEFAULT_MINIMUM_SAMPLE_SIZE = 30

#: How far an observed rate may sit from the stated probability before the bucket
#: is called mis-calibrated. Wide on purpose: a narrow band would flag ordinary
#: variance as a defect.
TOLERANCE = 0.15


class CalibrationError(ValueError):
    """The samples cannot be turned into a calibration record."""


@dataclass(frozen=True)
class Sample:
    """One candidate, the confidence it was raised with, and how it resolved."""

    finding_id: str
    confidence: str
    outcome: str

    @property
    def resolved(self) -> bool:
        return self.outcome == VERIFIED or self.outcome in REFUTED


@dataclass
class Contamination:
    is_contaminated: bool
    reason: str
    excluded_sample_count: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "is_contaminated": self.is_contaminated,
            "reason": self.reason,
            "excluded_sample_count": self.excluded_sample_count,
        }


def samples_from_report(report: Mapping[str, Any]) -> list[Sample]:
    """Extract calibration samples from a canonical report.

    The confidence is read from the finding; the outcome is read from the
    *verification* block rather than the finding's own status, because the whole
    question is whether the verifier agreed with the reviewer.
    """
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise CalibrationError("report findings must be an array")

    samples = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        verification = finding.get("verification")
        if not isinstance(verification, Mapping):
            continue
        samples.append(Sample(
            finding_id=str(finding.get("finding_id", "")),
            confidence=str(finding.get("confidence", "NOT_ASSESSED")).upper(),
            outcome=str(verification.get("outcome", "NOT_RUN")).upper(),
        ))
    return samples


def _bucket(confidence: str, samples: Sequence[Sample], minimum: int) -> dict[str, Any]:
    verified = sum(1 for s in samples if s.outcome == VERIFIED)
    refuted = sum(1 for s in samples if s.outcome in REFUTED)
    unresolved = len(samples) - verified - refuted
    resolved = verified + refuted

    stated = STATED_PROBABILITY.get(confidence, "NOT_APPLICABLE")

    # A bucket below the threshold, or with nothing resolved, has no rate. Not a
    # zero — a zero is a measurement, and this is the absence of one.
    if resolved == 0 or resolved < minimum or stated == "NOT_APPLICABLE":
        rate: float | str = NOT_MEASURED
        gap: float | str = NOT_MEASURED
    else:
        rate = round(verified / resolved, 6)
        gap = round(rate - float(stated), 6)

    return {
        "confidence": confidence,
        "stated_probability": stated,
        "sample_size": len(samples),
        "verified": verified,
        "refuted": refuted,
        "unresolved": unresolved,
        "observed_rate": rate,
        "gap": gap,
    }


def calibrate(
    samples: Iterable[Sample],
    *,
    contamination: Contamination,
    minimum_sample_size: int = DEFAULT_MINIMUM_SAMPLE_SIZE,
    limitations: Sequence[str] = (),
    report_ids: Sequence[str] = (),
    sechelix_commit: str | None = None,
) -> dict[str, Any]:
    """Build a calibration record. Contaminated or thin input yields NOT_MEASURED."""
    if minimum_sample_size < 1:
        raise CalibrationError("minimum_sample_size must be at least 1")

    collected = list(samples)
    by_confidence: dict[str, list[Sample]] = {c: [] for c in STATED_PROBABILITY}
    for sample in collected:
        by_confidence.setdefault(sample.confidence, []).append(sample)

    buckets = [
        _bucket(confidence, by_confidence.get(confidence, []), minimum_sample_size)
        for confidence in STATED_PROBABILITY
    ]

    resolved_total = sum(b["verified"] + b["refuted"] for b in buckets)
    scored = [b for b in buckets if b["gap"] != NOT_MEASURED]

    # MEASURED requires both enough resolved samples and uncontaminated ones.
    # Either failure alone is enough to withhold every number.
    measured = (
        not contamination.is_contaminated
        and resolved_total >= minimum_sample_size
        and bool(scored)
    )

    if measured:
        weight = sum(b["verified"] + b["refuted"] for b in scored)
        error: float | str = round(
            sum(abs(b["gap"]) * (b["verified"] + b["refuted"]) for b in scored) / weight, 6
        )
        over = [b["confidence"] for b in scored if b["gap"] < -TOLERANCE]
        under = [b["confidence"] for b in scored if b["gap"] > TOLERANCE]
    else:
        error = NOT_MEASURED
        over, under = [], []
        # Withhold per-bucket numbers too. Publishing bucket rates while the
        # headline says NOT_MEASURED is how a number escapes its caveat.
        for bucket in buckets:
            bucket["observed_rate"] = NOT_MEASURED
            bucket["gap"] = NOT_MEASURED

    stated_limitations = list(limitations)
    if contamination.is_contaminated:
        stated_limitations.insert(
            0, f"Contaminated sample set: {contamination.reason}"
        )
    if resolved_total < minimum_sample_size:
        stated_limitations.append(
            f"Only {resolved_total} resolved sample(s); {minimum_sample_size} required "
            "before any rate is reported."
        )
    if not stated_limitations:
        stated_limitations.append(
            "Calibration measures agreement between stated confidence and this "
            "verifier, not correctness against ground truth."
        )

    record: dict[str, Any] = {
        "schema_version": "1.0",
        "measurement_status": MEASURED if measured else NOT_MEASURED,
        "sample_size": len(collected),
        "minimum_sample_size": minimum_sample_size,
        "buckets": buckets,
        "calibration_error": error,
        "overconfident_buckets": over,
        "underconfident_buckets": under,
        "contamination": contamination.as_dict(),
        "limitations": stated_limitations,
    }
    if report_ids or sechelix_commit:
        record["generated_from"] = {
            "report_ids": list(report_ids),
            **({"sechelix_commit": sechelix_commit} if sechelix_commit else {}),
        }
    return record


def render_markdown(record: Mapping[str, Any]) -> str:
    """Render a record for humans, withholding numbers the record withholds."""
    lines = ["# Confidence calibration", ""]
    if record["measurement_status"] != MEASURED:
        lines += [
            "**Status: `NOT_MEASURED`.**",
            "",
            "Not enough uncontaminated resolved samples exist to say whether stated "
            "confidence predicts anything. No rate is shown, because a rate computed "
            "from too few samples is a number that will be quoted long after its "
            "caveat is forgotten.",
            "",
        ]
    else:
        lines += [
            f"**Calibration error: {record['calibration_error']}** "
            f"across {record['sample_size']} sample(s).",
            "",
        ]

    lines += ["| Confidence | Stated | Samples | Verified | Refuted | Unresolved | Observed |",
              "|---|---:|---:|---:|---:|---:|---:|"]
    for bucket in record["buckets"]:
        lines.append(
            f"| {bucket['confidence']} | {bucket['stated_probability']} | "
            f"{bucket['sample_size']} | {bucket['verified']} | {bucket['refuted']} | "
            f"{bucket['unresolved']} | {bucket['observed_rate']} |"
        )

    lines += ["", "## Limitations", ""]
    lines += [f"- {item}" for item in record["limitations"]]
    return "\n".join(lines) + "\n"
