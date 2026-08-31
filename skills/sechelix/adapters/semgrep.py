"""Semgrep JSON normalization."""

from __future__ import annotations

from typing import Any

from .base import candidate, location, read_json, require_list, require_mapping, text, tool_signal


def parse(payload: Any) -> list[dict[str, Any]]:
    document, digest = read_json(payload)
    root = require_mapping(document, "Semgrep input")
    normalized: list[dict[str, Any]] = []
    for result in require_list(root.get("results"), "Semgrep results"):
        finding = require_mapping(result, "Semgrep result")
        extra = require_mapping(finding.get("extra", {}), "Semgrep extra")
        start = require_mapping(finding.get("start", {}), "Semgrep start")
        end = require_mapping(finding.get("end", {}), "Semgrep end")
        message = text(extra.get("message"), text(finding.get("check_id"), "Semgrep result"))
        normalized.append(
            candidate(
                source="semgrep",
                source_type="static-analysis",
                source_version=root.get("version"),
                rule_id=finding.get("check_id"),
                claim=message,
                digest=digest,
                finding_location=location(
                    path=finding.get("path"),
                    line=start.get("line"),
                    column=start.get("col"),
                    end_line=end.get("line"),
                ),
                observations=[message],
                signal=tool_signal(
                    severity=extra.get("severity"),
                    confidence=require_mapping(extra.get("metadata", {}), "Semgrep metadata").get("confidence"),
                ),
                properties={"fingerprint": extra.get("fingerprint")},
            )
        )
    return normalized
