"""Provider-neutral reasoning executors.

The runner must never learn which vendor answered a node. Everything specific to
a provider lives behind :class:`ProviderExecutor`, and the evidence contracts
stay model-neutral -- a finding does not become more or less true because a
different model produced the candidate.

Two rules that are not negotiable for any implementation:

**Malformed output fails closed.** A provider that returns prose where a schema
was demanded, or JSON that does not validate, produces ``FAILED`` -- never a
best-effort parse. Half-understood model output silently becoming a finding is
the single worst failure mode available to a tool like this.

**Unmeasured is ``None``, never ``0``.** A host that does not report token counts
gets ``None``. Writing zero would make a budget report that understates spend and
a cost comparison that is quietly wrong.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

#: What every reasoning node must return. Deliberately small: a node reports
#: what it observed and where, and does not get to assert a verdict. Severity,
#: verification state and the release decision are computed from the evidence
#: contracts, not taken from a model's opinion.
NODE_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["candidates"],
    "properties": {
        "candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["claim", "location", "why"],
                "properties": {
                    "claim": {"type": "string", "minLength": 8},
                    "location": {"type": "string", "minLength": 1},
                    "why": {"type": "string", "minLength": 8},
                    "attacker_control": {"type": "string"},
                    "hypothesis_ids": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
        "notes": {"type": "string"},
        "examined": {"type": "array", "items": {"type": "string"}},
    },
}


class ProviderError(RuntimeError):
    """The provider could not be used, or returned something unusable."""


@dataclass
class ProviderResult:
    """One provider invocation, with its accounting."""

    text: str
    model: str | None = None
    provider: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None
    session_id: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class ProviderExecutor(Protocol):
    """What a provider adapter must offer."""

    name: str

    def invoke(self, prompt: str, *, timeout: float) -> ProviderResult:
        """Run one isolated request. No memory of any previous call."""
        ...


def extract_json(text: str) -> dict[str, Any]:
    """Pull one JSON object out of a model response.

    Models fence JSON, prefix it with a sentence, or both. This finds the first
    balanced object and parses it -- but it never *repairs*: a truncated or
    malformed object raises, because a guessed structure is indistinguishable
    from a real one once it reaches the evidence chain.
    """
    stripped = text.strip()
    fenced = re.search(r"```(?:json)?\s*(.+?)\s*```", stripped, re.DOTALL)
    if fenced:
        stripped = fenced.group(1).strip()

    start = stripped.find("{")
    if start == -1:
        raise ProviderError("no JSON object in provider response")

    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(stripped)):
        char = stripped[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(stripped[start : index + 1])
                except json.JSONDecodeError as exc:
                    raise ProviderError(f"provider response is not valid JSON: {exc}") from exc
    raise ProviderError("provider response contains an unterminated JSON object")


def validate_node_output(payload: Any) -> list[str]:
    """Check ``payload`` against :data:`NODE_OUTPUT_SCHEMA`.

    A tiny hand-rolled check rather than a dependency: the runner imports
    nothing outside the standard library, and the schema is small enough that a
    library would be more surface than it removes.
    """
    problems: list[str] = []
    if not isinstance(payload, dict):
        return [f"expected an object, got {type(payload).__name__}"]
    candidates = payload.get("candidates")
    if candidates is None:
        return ["missing required field 'candidates'"]
    if not isinstance(candidates, list):
        return [f"'candidates' must be a list, got {type(candidates).__name__}"]

    for index, candidate in enumerate(candidates):
        where = f"candidates[{index}]"
        if not isinstance(candidate, dict):
            problems.append(f"{where}: expected an object")
            continue
        for required in ("claim", "location", "why"):
            value = candidate.get(required)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"{where}.{required}: missing or empty")
        ids = candidate.get("hypothesis_ids", [])
        if ids is not None and not isinstance(ids, list):
            problems.append(f"{where}.hypothesis_ids: must be a list")
    return problems
