"""Shared normalization primitives for untrusted scanner observations."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping


CANDIDATE = "CANDIDATE"
UNASSESSED = "UNASSESSED"
SCHEMA_VERSION = "sechelix-evidence/v1"


class AdapterError(ValueError):
    """Raised when an input cannot be parsed without guessing."""


def _raw_bytes(payload: Any) -> bytes:
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        return payload.encode("utf-8")
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AdapterError("input is not JSON serializable") from exc


def payload_digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_raw_bytes(payload)).hexdigest()


def read_json(payload: Any) -> tuple[Any, str]:
    digest = payload_digest(payload)
    if isinstance(payload, (dict, list)):
        return payload, digest
    try:
        return json.loads(_raw_bytes(payload).decode("utf-8-sig")), digest
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError(f"invalid JSON input: {exc}") from exc


def read_json_lines(payload: Any) -> tuple[list[Mapping[str, Any]], str]:
    digest = payload_digest(payload)
    if isinstance(payload, list):
        rows = payload
    else:
        try:
            text = _raw_bytes(payload).decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise AdapterError("invalid UTF-8 JSONL input") from exc
        rows = []
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise AdapterError(f"invalid JSONL on line {number}: {exc}") from exc
    if not all(isinstance(row, Mapping) for row in rows):
        raise AdapterError("JSONL records must be objects")
    return list(rows), digest


def require_mapping(value: Any, context: str = "input") -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AdapterError(f"{context} must be a JSON object")
    return value


def require_list(value: Any, context: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise AdapterError(f"{context} must be a JSON array")
    return value


def text(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return fallback


def compact(values: Iterable[Any]) -> list[Any]:
    return [value for value in values if value not in (None, "", [], {})]


def location(
    path: Any = None,
    line: Any = None,
    column: Any = None,
    end_line: Any = None,
    uri: Any = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if path not in (None, ""):
        result["path"] = text(path)
    if uri not in (None, ""):
        result["uri"] = text(uri)
    for key, value in (("line", line), ("column", column), ("end_line", end_line)):
        if isinstance(value, int) and value >= 0:
            result[key] = value
    return result


def tool_signal(**values: Any) -> dict[str, Any]:
    """Keep scanner labels separate from SecHelix assessment fields."""
    result = {key: value for key, value in values.items() if value not in (None, "", [], {})}
    if result:
        result["trusted_for_assessment"] = False
    return result


def candidate(
    *,
    source: str,
    source_type: str,
    rule_id: Any,
    claim: Any,
    digest: str,
    source_version: Any = None,
    finding_location: Mapping[str, Any] | None = None,
    observations: Iterable[Any] = (),
    signal: Mapping[str, Any] | None = None,
    properties: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    rule = text(rule_id, "unknown")
    summary = text(claim, rule)
    loc = dict(finding_location or {})
    identity = json.dumps(
        [source, rule, loc, summary], sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "evidence_id": "obs:" + hashlib.sha256(identity).hexdigest()[:24],
        "source": {"tool": source, "type": source_type},
        "rule_id": rule,
        "claim": summary,
        "location": loc,
        "observations": [text(item) for item in observations if item not in (None, "")],
        "status": CANDIDATE,
        "assessment": UNASSESSED,
        "severity": UNASSESSED,
        "verification": UNASSESSED,
        "tool_signal": dict(signal or {}),
        "provenance": {"payload_digest": digest},
        "properties": dict(properties or {}),
    }
    if source_version not in (None, ""):
        result["source"]["version"] = text(source_version)
    return result


def strip_secrets(mapping: Mapping[str, Any], denied: Iterable[str]) -> dict[str, Any]:
    blocked = {key.casefold() for key in denied}
    return {key: value for key, value in mapping.items() if str(key).casefold() not in blocked}
