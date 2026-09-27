"""Bandit JSON normalization with scanner judgments kept untrusted."""

from __future__ import annotations

from typing import Any, Mapping

from .base import (
    AdapterError,
    candidate,
    location,
    read_json,
    require_list,
    require_mapping,
    tool_signal,
)


_SECRET_VALUE_RULES = frozenset({"B105", "B106", "B107"})


def _required_text(finding: Mapping[str, Any], key: str) -> str:
    value = finding.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AdapterError(f"Bandit finding {key} must be a non-empty string")
    return value


def _required_position(finding: Mapping[str, Any], key: str) -> int:
    value = finding.get(key)
    if type(value) is not int or value < 0:
        raise AdapterError(f"Bandit finding {key} must be a non-negative integer")
    return value


def parse(payload: Any) -> list[dict[str, Any]]:
    document, digest = read_json(payload)
    report = require_mapping(document, "Bandit input")
    if "results" not in report:
        raise AdapterError("Bandit input is missing results")

    findings = require_list(report["results"], "Bandit results")
    errors = require_list(report.get("errors"), "Bandit errors")
    if errors:
        raise AdapterError(
            "Bandit report contains scan errors; refusing to normalize incomplete evidence"
        )

    version = report.get("version") or report.get("bandit_version")
    output: list[dict[str, Any]] = []
    for item in findings:
        finding = require_mapping(item, "Bandit finding")
        test_id = _required_text(finding, "test_id")
        issue_text = _required_text(finding, "issue_text")
        filename = _required_text(finding, "filename")
        line_number = _required_position(finding, "line_number")
        col_offset = _required_position(finding, "col_offset")

        redacts_issue_text = test_id in _SECRET_VALUE_RULES
        claim = (
            f"Potential hardcoded secret reported by Bandit rule {test_id}"
            if redacts_issue_text
            else issue_text
        )
        observations = [
            "Matched source code was omitted by the adapter to avoid copying source or secrets."
        ]
        if redacts_issue_text:
            observations.append(
                "Bandit issue text was replaced because this rule may embed a hardcoded secret value."
            )

        output.append(
            candidate(
                source="bandit",
                source_type="static-analysis",
                source_version=version,
                rule_id=test_id,
                claim=claim,
                digest=digest,
                finding_location=location(
                    path=filename,
                    line=line_number,
                    column=col_offset,
                ),
                observations=observations,
                signal=tool_signal(
                    severity=finding.get("issue_severity"),
                    confidence=finding.get("issue_confidence"),
                ),
                properties={
                    "test_name": finding.get("test_name"),
                    "more_info": finding.get("more_info"),
                    "issue_cwe": finding.get("issue_cwe"),
                    "source_snippet_redacted": True,
                    "issue_text_redacted": redacts_issue_text,
                },
            )
        )
    return output
