"""Generic SARIF 2.x and CodeQL normalization."""

from __future__ import annotations

from typing import Any, Mapping

from .base import candidate, location, read_json, require_list, require_mapping, text, tool_signal


def _message(value: Any) -> str:
    if isinstance(value, Mapping):
        return text(value.get("text") or value.get("markdown"))
    return text(value)


def parse_sarif(payload: Any, source: str = "sarif") -> list[dict[str, Any]]:
    document, digest = read_json(payload)
    root = require_mapping(document, "SARIF input")
    runs = require_list(root.get("runs"), "SARIF runs")
    normalized: list[dict[str, Any]] = []
    for run in runs:
        run_map = require_mapping(run, "SARIF run")
        driver = require_mapping(
            require_mapping(run_map.get("tool"), "SARIF tool").get("driver"),
            "SARIF driver",
        )
        tool_name = source if source != "sarif" else text(driver.get("name"), "sarif")
        for result in require_list(run_map.get("results"), "SARIF results"):
            finding = require_mapping(result, "SARIF result")
            physical: Mapping[str, Any] = {}
            locations = require_list(finding.get("locations"), "SARIF result locations")
            if locations:
                physical = require_mapping(
                    require_mapping(locations[0], "SARIF location").get("physicalLocation", {}),
                    "SARIF physicalLocation",
                )
            artifact = require_mapping(physical.get("artifactLocation", {}), "SARIF artifactLocation")
            region = require_mapping(physical.get("region", {}), "SARIF region")
            message = _message(finding.get("message")) or text(finding.get("ruleId"), "SARIF result")
            rule = finding.get("rule") if isinstance(finding.get("rule"), Mapping) else {}
            normalized.append(
                candidate(
                    source=tool_name,
                    source_type="sarif",
                    source_version=driver.get("version") or driver.get("semanticVersion"),
                    rule_id=finding.get("ruleId") or rule.get("id"),
                    claim=message,
                    digest=digest,
                    finding_location=location(
                        path=artifact.get("uri"),
                        line=region.get("startLine"),
                        column=region.get("startColumn"),
                        end_line=region.get("endLine"),
                    ),
                    observations=[message],
                    signal=tool_signal(
                        level=finding.get("level"),
                        kind=finding.get("kind"),
                        rank=finding.get("rank"),
                    ),
                    properties={"fingerprints": finding.get("partialFingerprints", {})},
                )
            )
    return normalized


def parse_codeql(payload: Any) -> list[dict[str, Any]]:
    return parse_sarif(payload, source="codeql")
