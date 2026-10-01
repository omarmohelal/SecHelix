"""Blind model benchmark runner through Nexus.

This module never reads SecHelix fixture truth. It consumes a sealed cases packet,
runs each case in an isolated Nexus/SecHelix provider process, and freezes a
prediction packet that can only be scored later by evals/run_evals.py.

Running prediction and scoring in separate steps preserves the blind boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Callable

from .providers.base import ProviderError, ProviderResult
from .providers.nexus_cli import NexusCliExecutor


LABELS = frozenset({"VULNERABLE", "CLEAN"})
BENCHMARK_PROMPT = (
    "You are reviewing a single source file for security weaknesses. Decide whether "
    "the file contains an exploitable security weakness (VULNERABLE) or does not "
    "(CLEAN). Some files are written to look alarming while being protected by a "
    "real compensating control; some are written to look ordinary while being "
    "exploitable. Judge the actual behaviour, not the surface. Answer with exactly "
    "one label."
)


class ModelBenchmarkError(ValueError):
    """The sealed packet or model response cannot support a benchmark result."""


@dataclass(frozen=True)
class BlindCase:
    case_id: str
    family: str
    language: str
    filename: str
    source: str
    task: str

    def prompt(self) -> str:
        body = {
            "case_id": self.case_id,
            "family": self.family,
            "language": self.language,
            "filename": self.filename,
            "task": self.task,
            "source": self.source,
        }
        return BENCHMARK_PROMPT + "\n\nCase:\n" + json.dumps(
            body, sort_keys=True, ensure_ascii=False
        )


def load_blind_cases(path: str | Path) -> tuple[list[BlindCase], str]:
    source = Path(path)
    raw = source.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        packet = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ModelBenchmarkError(f"blind cases packet is invalid JSON: {exc}") from exc
    rows = packet.get("cases") if isinstance(packet, dict) else None
    if not isinstance(rows, list) or not rows:
        raise ModelBenchmarkError("blind cases packet must contain a non-empty cases array")

    cases: list[BlindCase] = []
    seen: set[str] = set()
    required = ("case_id", "family", "language", "filename", "source", "task")
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ModelBenchmarkError(f"cases[{index}] must be an object")
        missing = [key for key in required if not isinstance(row.get(key), str)]
        if missing:
            raise ModelBenchmarkError(
                f"cases[{index}] has missing/non-string fields: {', '.join(missing)}"
            )
        case_id = row["case_id"]
        if case_id in seen:
            raise ModelBenchmarkError(f"duplicate case_id: {case_id}")
        seen.add(case_id)
        cases.append(BlindCase(**{key: row[key] for key in required}))
    return cases, digest


def parse_label(text: str) -> str:
    cleaned = text.strip().upper()
    if cleaned in LABELS:
        return cleaned
    lines = [line.strip().upper() for line in text.splitlines() if line.strip()]
    exact = [line for line in lines if line in LABELS]
    if len(exact) == 1:
        return exact[0]
    raise ModelBenchmarkError(
        "model response must contain exactly one unambiguous VULNERABLE or CLEAN label"
    )


def run_nexus_benchmark(
    *,
    cases_path: str | Path,
    lane: str,
    sechelix_commit: str,
    fixture_suite_version: str,
    timeout_per_case: float = 300.0,
    executor_factory: Callable[[], NexusCliExecutor] | None = None,
) -> dict[str, Any]:
    if not lane.strip():
        raise ModelBenchmarkError("lane must be non-empty")
    if timeout_per_case <= 0:
        raise ModelBenchmarkError("timeout_per_case must be positive")

    cases, cases_sha256 = load_blind_cases(cases_path)
    make_executor = executor_factory or (
        lambda: NexusCliExecutor(lane=lane, role="security-engineer")
    )
    predictions: list[dict[str, str]] = []
    models: set[str] = set()
    providers: set[str] = set()
    input_tokens = 0
    output_tokens = 0
    have_input = have_output = False
    cost = 0.0
    have_cost = False

    started = time.monotonic()
    for case in cases:
        executor = make_executor()
        try:
            result: ProviderResult = executor.invoke(
                case.prompt(), timeout=timeout_per_case
            )
        except ProviderError as exc:
            raise ModelBenchmarkError(
                f"{case.case_id}: Nexus/model execution failed: {exc}"
            ) from exc
        label = parse_label(result.text)
        predictions.append(
            {
                "case_id": case.case_id,
                "predicted_label": label,
                "verification_status": "NOT_RUN",
            }
        )
        if result.model:
            models.add(result.model)
        if result.provider:
            providers.add(result.provider)
        if result.input_tokens is not None:
            input_tokens += result.input_tokens
            have_input = True
        if result.output_tokens is not None:
            output_tokens += result.output_tokens
            have_output = True
        if result.cost_usd is not None:
            cost += result.cost_usd
            have_cost = True

    elapsed = round(time.monotonic() - started, 3)
    return {
        "model": "+".join(sorted(models)) or lane,
        "provider": "+".join(sorted(providers)) or "Nexus",
        "runner": "SecHelix blind model benchmark via isolated Nexus review processes",
        "sechelix_commit": sechelix_commit,
        "cases_sha256": cases_sha256,
        "fixture_suite_version": fixture_suite_version,
        "agent_host": "Nexus",
        "execution_mode": "STATIC",
        "tools": [],
        "prompt_reference": "SecHelix BENCHMARK_PROMPT / blind label-only protocol",
        "time_seconds": elapsed,
        "input_tokens": input_tokens if have_input else "NOT_MEASURED",
        "output_tokens": output_tokens if have_output else "NOT_MEASURED",
        "cost": round(cost, 8) if have_cost else "NOT_MEASURED",
        "result_kind": "SECHELIX_MODEL_BENCHMARK_PREDICTIONS",
        "is_sechelix_result": True,
        "limitations": [
            "Prediction generation is blind and label-only; scoring must happen separately.",
            "verification_status is NOT_RUN for every case; this does not measure the full SecHelix verification/fix/retest workflow.",
            "One lane/run does not establish production effectiveness or variance.",
        ],
        "lane": lane,
        "case_count": len(predictions),
        "predictions": predictions,
    }


def write_prediction_packet(path: str | Path, packet: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(packet, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


__all__ = [
    "BENCHMARK_PROMPT",
    "BlindCase",
    "ModelBenchmarkError",
    "load_blind_cases",
    "parse_label",
    "run_nexus_benchmark",
    "write_prediction_packet",
]
