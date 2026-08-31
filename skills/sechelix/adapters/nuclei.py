"""Nuclei JSONL normalization with extracted values omitted."""

from __future__ import annotations

from typing import Any

from .base import candidate, location, read_json_lines, require_mapping, text, tool_signal


def parse(payload: Any) -> list[dict[str, Any]]:
    rows, digest = read_json_lines(payload)
    output: list[dict[str, Any]] = []
    for finding in rows:
        info = require_mapping(finding.get("info", {}), "Nuclei info")
        rule_id = finding.get("template-id") or finding.get("template") or "nuclei-template"
        claim = text(info.get("name"), text(rule_id))
        output.append(
            candidate(
                source="nuclei",
                source_type="bounded-template-observation",
                source_version=finding.get("nuclei-version"),
                rule_id=rule_id,
                claim=claim,
                digest=digest,
                finding_location=location(uri=finding.get("matched-at") or finding.get("host")),
                observations=[claim, "Extracted results and request/response bodies were omitted by the adapter."],
                signal=tool_signal(severity=info.get("severity"), type=finding.get("type"), matcher=finding.get("matcher-name")),
                properties={
                    "template_url": finding.get("template-url"),
                    "tags": info.get("tags", []),
                    "timestamp": finding.get("timestamp"),
                    "redacted": True,
                },
            )
        )
    return output
