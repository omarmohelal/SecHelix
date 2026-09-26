#!/usr/bin/env python3
"""Measure bounded proof-classification stability across deterministic LOCAL load tiers.

This is not a production benchmark. It re-runs the complete paired dynamic proof
suite under synthetic, declared request latency and race-concurrency profiles so
SecHelix can detect whether its bounded proof primitives become flaky or
inconclusive when fixture timing changes.

The result remains a proof-primitive measurement. It does not measure discovery,
model reasoning, independent-verifier correctness, remediation, or release-gate
accuracy.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from evals.dynamic_proof_benchmark import run_dynamic_proof_benchmark


@dataclass(frozen=True)
class DynamicProfile:
    profile_id: str
    artificial_latency_ms: int
    race_concurrency: int


DEFAULT_PROFILES = (
    DynamicProfile("baseline", 0, 2),
    DynamicProfile("moderate", 20, 4),
    DynamicProfile("loaded", 60, 8),
)


def run_dynamic_profile_benchmark(
    *,
    sechelix_commit: str = "NOT_MEASURED",
    profiles: tuple[DynamicProfile, ...] = DEFAULT_PROFILES,
) -> dict[str, object]:
    if not profiles:
        raise ValueError("at least one dynamic profile is required")
    ids = [profile.profile_id for profile in profiles]
    if any(not item.strip() for item in ids) or len(ids) != len(set(ids)):
        raise ValueError("dynamic profile IDs must be unique non-empty strings")

    rows: list[dict[str, object]] = []
    all_correct = True
    all_covered = True
    for profile in profiles:
        result = run_dynamic_proof_benchmark(
            sechelix_commit=sechelix_commit,
            artificial_latency_ms=profile.artificial_latency_ms,
            race_concurrency=profile.race_concurrency,
        )
        metrics = result["metrics"]
        run = result["run"]
        correct = metrics["case_accuracy"] == 1.0
        covered = metrics["proof_class_coverage"] == 1.0
        all_correct = all_correct and correct
        all_covered = all_covered and covered
        rows.append(
            {
                "profile_id": profile.profile_id,
                "artificial_latency_ms": profile.artificial_latency_ms,
                "race_concurrency": profile.race_concurrency,
                "case_count": run["case_count"],
                "duration_ms": run["duration_ms"],
                "metrics": metrics,
                "coverage": result["coverage"],
                "correct": correct,
            }
        )

    return {
        "schema_version": "sechelix-dynamic-profile-benchmark/v1",
        "measurement_status": "MEASURED",
        "result_kind": "DYNAMIC_PROOF_PROFILE_BENCHMARK",
        "is_full_sechelix_workflow": False,
        "sechelix_commit": sechelix_commit,
        "profile_count": len(rows),
        "all_profiles_correct": all_correct,
        "all_profiles_cover_every_bounded_proof_class": all_covered,
        "profiles": rows,
        "limitations": [
            "Latency is deterministic synthetic fixture delay, not observed production network latency.",
            "Concurrency is bounded LOCAL request concurrency, not production traffic volume.",
            "Measures proof-classification stability only; candidate discovery and model reasoning are not exercised.",
            "Does not measure independent-verifier accuracy, remediation quality, or release-gate accuracy.",
            "A passing profile establishes stability only for these declared LOCAL fixture tiers.",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--sechelix-commit", default="NOT_MEASURED")
    args = parser.parse_args(argv)

    result = run_dynamic_profile_benchmark(sechelix_commit=args.sechelix_commit)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if (
        result["all_profiles_correct"]
        and result["all_profiles_cover_every_bounded_proof_class"]
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
