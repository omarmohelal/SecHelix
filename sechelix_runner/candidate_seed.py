"""Turn normalized scanner output into candidates for the independent verifier.

A scanner report, once normalized by an `adapters/` adapter, is a list of
`CANDIDATE`/`UNASSESSED` records. This module shapes each into the neutral
candidate the reasoner's verify node consumes: a claim, a location to look at,
and non-conclusive provenance (which tool, which rule). It deliberately drops
the tool's own severity/confidence -- the whole point of SecHelix is that a
scanner's verdict is a hypothesis, not a finding, so the independent verifier
reconstructs it from scratch.

This is the bridge that lets a Semgrep or OSV candidate go through the *same*
verifier as a model-hunted one, rather than being trusted because a scanner
emitted it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class SeedError(ValueError):
    """A seed file could not be read or contained no usable candidate."""


def _location_str(loc: Any) -> str:
    if isinstance(loc, str):
        return loc.strip()
    if isinstance(loc, dict):
        path = loc.get("path") or loc.get("file") or loc.get("uri") or ""
        line = loc.get("line") or loc.get("start_line") or loc.get("startLine")
        if path and line:
            return f"{path}:{line}"
        if path:
            return str(path)
    return ""


def _records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        rows: Any = payload
    elif isinstance(payload, dict):
        rows = payload.get("records")
        if rows is None and isinstance(payload.get("candidates"), list):
            rows = payload["candidates"]
    else:
        raise SeedError("seed input must be a JSON list or an adapter envelope with 'records'")
    if not isinstance(rows, list):
        raise SeedError("seed input has no 'records' list")
    return [r for r in rows if isinstance(r, dict)]


def candidate_from_record(record: dict[str, Any]) -> dict[str, Any]:
    """Map one normalized scanner record to a neutral verifier candidate.

    Keeps claim/location/why plus provenance; never carries the scanner's
    severity or confidence into the verifier's view.
    """
    claim = record.get("claim")
    if not isinstance(claim, str) or not claim.strip():
        raise SeedError("record missing a non-empty 'claim'")
    location = _location_str(record.get("location"))
    if not location:
        raise SeedError(f"record {claim.strip()!r} has no usable location")

    source = record.get("source")
    tool = source.get("tool") if isinstance(source, dict) else None
    rule_id = record.get("rule_id")
    observations = record.get("observations")

    why_parts: list[str] = []
    if isinstance(tool, str) and tool:
        why_parts.append(f"reported by {tool}")
    if isinstance(rule_id, str) and rule_id:
        why_parts.append(f"rule {rule_id}")
    if isinstance(observations, list) and observations and isinstance(observations[0], str):
        why_parts.append(observations[0])
    why = "; ".join(why_parts) or "external scanner candidate"

    candidate: dict[str, Any] = {"claim": claim.strip(), "location": location, "why": why}
    if isinstance(tool, str) and tool:
        candidate["scanner"] = tool
    if isinstance(rule_id, str) and rule_id:
        candidate["rule_id"] = rule_id
    # Deliberately NOT carried: the adapter's observation id. It is a digest of
    # the scanner's own report, not a registered SecHelix evidence id, so if it
    # reached the verifier's view the verifier could cite it -- and the binding
    # check correctly rejects a citation to evidence that is not in the
    # least-context view. A scanner candidate arrives with no reproduction
    # evidence; the verifier must treat it as UNPROVEN until SecHelix produces
    # real evidence, not inherit the scanner's own say-so as a citation.
    return candidate


def candidates_from_payload(payload: Any) -> list[dict[str, Any]]:
    candidates = [candidate_from_record(r) for r in _records(payload)]
    if not candidates:
        raise SeedError("seed input produced no candidates")
    return candidates


def load_seed_candidates(path: str | Path) -> list[dict[str, Any]]:
    """Read a normalized scanner report from disk and shape its candidates."""
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise SeedError(f"could not read seed file: {exc}") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SeedError(f"seed file is not valid JSON: {exc}") from exc
    return candidates_from_payload(payload)


__all__ = [
    "SeedError",
    "candidate_from_record",
    "candidates_from_payload",
    "load_seed_candidates",
]
