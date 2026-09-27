#!/usr/bin/env python3
"""Validate SecHelix evaluation fixture-tier claims.

The registry is deliberately conservative. A benchmark may only claim the
highest tier whose observable fixture properties are declared and validated.
This prevents a synthetic or loopback-only benchmark from being described as
production-like merely because it exercises dynamic code.

The validator does not run targets and does not score security correctness.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

SCHEMA_VERSION = "sechelix-fixture-tier-registry/v1"

TIER_ORDER = (
    "STATIC_PAIR",
    "LOCAL_PRIMITIVE",
    "REAL_BROWSER_INTEGRATION",
    "STATEFUL_APPLICATION",
    "COMPOSITE_APPLICATION",
)

ALLOWED_NETWORK_SCOPES = {"NONE", "LOOPBACK_ONLY"}
ALLOWED_STATUSES = {"MEASURED", "AVAILABLE", "PLANNED"}

REQUIREMENTS: dict[str, dict[str, Any]] = {
    "STATIC_PAIR": {
        "runtime_execution": False,
        "network_scope": "NONE",
    },
    "LOCAL_PRIMITIVE": {
        "runtime_execution": True,
        "network_scope": "LOOPBACK_ONLY",
        "deterministic_reset": True,
    },
    "REAL_BROWSER_INTEGRATION": {
        "runtime_execution": True,
        "network_scope": "LOOPBACK_ONLY",
        "real_browser": True,
        "deterministic_reset": True,
    },
    "STATEFUL_APPLICATION": {
        "runtime_execution": True,
        "network_scope": "LOOPBACK_ONLY",
        "durable_state": True,
        "multi_step_workflow": True,
        "deterministic_reset": True,
        "auth_personas_min": 2,
    },
    "COMPOSITE_APPLICATION": {
        "runtime_execution": True,
        "network_scope": "LOOPBACK_ONLY",
        "durable_state": True,
        "multi_step_workflow": True,
        "deterministic_reset": True,
        "auth_personas_min": 2,
        "service_count_min": 2,
        "async_boundary": True,
    },
}


class FixtureTierError(ValueError):
    """Registry or claim is malformed or overstates fixture realism."""


def _read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _nonempty_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FixtureTierError(f"{field} must be a non-empty string")
    return value.strip()


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FixtureTierError(f"{field} must be a non-negative integer")
    return value


def _properties(entry: Mapping[str, Any], field: str) -> dict[str, Any]:
    raw = entry.get("properties")
    if not isinstance(raw, Mapping):
        raise FixtureTierError(f"{field}.properties must be an object")
    props = dict(raw)

    if props.get("network_scope") not in ALLOWED_NETWORK_SCOPES:
        raise FixtureTierError(
            f"{field}.properties.network_scope must be one of "
            f"{sorted(ALLOWED_NETWORK_SCOPES)}"
        )

    for key in (
        "runtime_execution",
        "real_browser",
        "durable_state",
        "multi_step_workflow",
        "deterministic_reset",
        "async_boundary",
    ):
        if key in props and not isinstance(props[key], bool):
            raise FixtureTierError(f"{field}.properties.{key} must be boolean")

    for key in ("auth_personas", "service_count"):
        if key in props:
            props[key] = _nonnegative_int(props[key], f"{field}.properties.{key}")

    return props


def _require_tier_properties(
    *,
    tier: str,
    props: Mapping[str, Any],
    field: str,
) -> None:
    requirements = REQUIREMENTS[tier]
    for key, expected in requirements.items():
        if key.endswith("_min"):
            prop = key.removesuffix("_min")
            actual = props.get(prop, 0)
            if isinstance(actual, bool) or not isinstance(actual, int):
                raise FixtureTierError(f"{field}.properties.{prop} must be an integer")
            if actual < expected:
                raise FixtureTierError(
                    f"{field} claims {tier} but properties.{prop}={actual} "
                    f"is below required minimum {expected}"
                )
            continue
        actual = props.get(key)
        if actual != expected:
            raise FixtureTierError(
                f"{field} claims {tier} but properties.{key}={actual!r}; "
                f"required {expected!r}"
            )


def validate_registry(raw: Mapping[str, Any]) -> dict[str, Any]:
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise FixtureTierError(
            f"schema_version must be exactly {SCHEMA_VERSION!r}"
        )

    note = _nonempty_text(raw.get("scope_note"), "scope_note")
    lowered = note.lower()
    if "production" not in lowered or "not" not in lowered:
        raise FixtureTierError(
            "scope_note must explicitly state that registry tiers are not "
            "production-effectiveness claims"
        )

    entries = raw.get("benchmarks")
    if not isinstance(entries, list) or not entries:
        raise FixtureTierError("benchmarks must be a non-empty list")

    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []

    for index, item in enumerate(entries):
        field = f"benchmarks[{index}]"
        if not isinstance(item, Mapping):
            raise FixtureTierError(f"{field} must be an object")

        benchmark_id = _nonempty_text(item.get("benchmark_id"), f"{field}.benchmark_id")
        if benchmark_id in seen:
            raise FixtureTierError(f"duplicate benchmark_id: {benchmark_id}")
        seen.add(benchmark_id)

        runner = _nonempty_text(item.get("runner"), f"{field}.runner")
        if runner.startswith("/") or ".." in Path(runner).parts:
            raise FixtureTierError(f"{field}.runner must be a repository-relative path")

        tier = item.get("tier")
        if tier not in TIER_ORDER:
            raise FixtureTierError(
                f"{field}.tier must be one of {list(TIER_ORDER)}"
            )

        status = item.get("status")
        if status not in ALLOWED_STATUSES:
            raise FixtureTierError(
                f"{field}.status must be one of {sorted(ALLOWED_STATUSES)}"
            )

        props = _properties(item, field)
        _require_tier_properties(tier=tier, props=props, field=field)

        if tier in {"STATEFUL_APPLICATION", "COMPOSITE_APPLICATION"}:
            reset_strategy = _nonempty_text(
                item.get("reset_strategy"), f"{field}.reset_strategy"
            )
        else:
            reset_strategy = item.get("reset_strategy")
            if reset_strategy is not None:
                reset_strategy = _nonempty_text(
                    reset_strategy, f"{field}.reset_strategy"
                )

        limitations = item.get("limitations")
        if (
            not isinstance(limitations, list)
            or not limitations
            or not all(isinstance(value, str) and value.strip() for value in limitations)
        ):
            raise FixtureTierError(
                f"{field}.limitations must contain at least one explicit limitation"
            )

        normalized.append(
            {
                "benchmark_id": benchmark_id,
                "runner": runner,
                "tier": tier,
                "status": status,
                "properties": props,
                "reset_strategy": reset_strategy,
                "limitations": [value.strip() for value in limitations],
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "scope_note": note,
        "benchmarks": normalized,
    }


def summarize_registry(registry: Mapping[str, Any]) -> dict[str, Any]:
    normalized = validate_registry(registry)
    counts = {tier: 0 for tier in TIER_ORDER}
    measured = {tier: 0 for tier in TIER_ORDER}
    for entry in normalized["benchmarks"]:
        tier = entry["tier"]
        counts[tier] += 1
        if entry["status"] == "MEASURED":
            measured[tier] += 1

    highest_declared = max(
        (tier for tier in TIER_ORDER if counts[tier]),
        key=TIER_ORDER.index,
    )
    highest_measured_candidates = [tier for tier in TIER_ORDER if measured[tier]]
    highest_measured = (
        max(highest_measured_candidates, key=TIER_ORDER.index)
        if highest_measured_candidates
        else None
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "benchmark_count": len(normalized["benchmarks"]),
        "tier_counts": counts,
        "measured_tier_counts": measured,
        "highest_declared_tier": highest_declared,
        "highest_measured_tier": highest_measured,
        "production_effectiveness_established": False,
    }


def _cli() -> int:
    parser = argparse.ArgumentParser(
        description="Validate SecHelix benchmark fixture-tier claims"
    )
    parser.add_argument(
        "--registry",
        default="evals/fixture-tiers.json",
        help="fixture tier registry JSON",
    )
    parser.add_argument("--output", help="optional summary JSON output")
    args = parser.parse_args()

    registry = _read_json(args.registry)
    summary = summarize_registry(registry)
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
