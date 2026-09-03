"""Bandit JSON normalization.

Bandit severity/confidence remain untrusted tool signals. The adapter deliberately
omits the ``code`` field because source snippets can contain credentials, tokens,
or other sensitive literals that do not belong in normalized evidence.
"""

from __future__ import annotations

from typing import Any, Mapping

from .base import AdapterError, candidate, location, read_json, require_list, require_mapping, text, tool_signal


def _cwe(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, Any] = {}
    cwe_id = value.get("id")
    if isinstance(cwe_id, int) and cwe_id > 0:
        result["id"] = cwe_id
    link = value.get("link")
    if isinstance(link, str) and link.startswith("https://"):
        result["link"] = link
    return result


def _end_line(value: Any, fallback: Any) -> Any:
    if isinstance(value, list):
        lines = [item for item in value if isinstance(item, int) and item >= 0]
        if lines:
            return max(lines)
    return fallback


def parse(payload: Any) -> list[dict[str, Any]]:
    document, digest = read_json(payload)
    root = require_mapping(document, "Bandit input")
    if "results" not in root:
        raise AdapterError("Bandit input must contain a results array")
    findings = require_list(root.get("results"), "Bandit results")
    version = root.get("version") or root.get("bandit_version")

    output: list[dict[str, Any]] = []
    for item in findings:
        finding = require_mapping(item, "Bandit finding")
        rule_id = finding.get("test_id") or finding.get("test_name") or "bandit"
        issue_cwe = _cwe(finding.get("issue_cwe"))
        properties: dict[str, Any] = {}
        test_name = text(finding.get("test_name"))
        if test_name:
            properties["test_name"] = test_name
        more_info = text(finding.get("more_info"))
        if more_info:
            properties["more_info"] = more_info
        if issue_cwe:
            properties["issue_cwe"] = issue_cwe
        # Proves an intentional omission to downstream reviewers without copying
        # the source snippet itself into normalized evidence.
        if "code" in finding:
            properties["source_snippet_omitted"] = True

        output.append(
            candidate(
                source="bandit",
                source_type="static-analysis",
                source_version=version,
                rule_id=rule_id,
                claim=finding.get("issue_text") or f"Bandit candidate reported by {rule_id}",
                digest=digest,
                finding_location=location(
                    path=finding.get("filename"),
                    line=finding.get("line_number"),
                    column=finding.get("col_offset"),
                    end_line=_end_line(finding.get("line_range"), finding.get("line_number")),
                ),
                observations=[
                    value
                    for value in (
                        f"Bandit test name: {test_name}" if test_name else "",
                        "Bandit source snippet was intentionally omitted." if "code" in finding else "",
                    )
                    if value
                ],
                signal=tool_signal(
                    issue_severity=finding.get("issue_severity"),
                    issue_confidence=finding.get("issue_confidence"),
                ),
                properties=properties,
            )
        )
    return output
