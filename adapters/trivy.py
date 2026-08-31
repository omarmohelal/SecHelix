"""Trivy JSON normalization with secret material removed."""

from __future__ import annotations

from typing import Any, Mapping

from .base import candidate, location, read_json, require_list, require_mapping, text, tool_signal


def _vulnerabilities(result: Mapping[str, Any], digest: str) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    target = result.get("Target")
    for item in require_list(result.get("Vulnerabilities"), "Trivy vulnerabilities"):
        finding = require_mapping(item, "Trivy vulnerability")
        vuln_id = text(finding.get("VulnerabilityID"), "unknown")
        package = text(finding.get("PkgName"), "unknown package")
        output.append(
            candidate(
                source="trivy",
                source_type="dependency-analysis",
                rule_id=vuln_id,
                claim=f"{vuln_id} reported for {package}",
                digest=digest,
                finding_location=location(path=target),
                observations=[finding.get("Title"), finding.get("Description")],
                signal=tool_signal(severity=finding.get("Severity"), cvss=finding.get("CVSS")),
                properties={
                    "package": package,
                    "installed_version": finding.get("InstalledVersion"),
                    "fixed_version": finding.get("FixedVersion"),
                    "primary_url": finding.get("PrimaryURL"),
                },
            )
        )
    return output


def _misconfigurations(result: Mapping[str, Any], digest: str) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in require_list(result.get("Misconfigurations"), "Trivy misconfigurations"):
        finding = require_mapping(item, "Trivy misconfiguration")
        rule_id = finding.get("ID") or finding.get("AVDID")
        output.append(
            candidate(
                source="trivy",
                source_type="configuration-analysis",
                rule_id=rule_id,
                claim=finding.get("Title") or rule_id,
                digest=digest,
                finding_location=location(
                    path=result.get("Target"),
                    line=require_mapping(finding.get("CauseMetadata", {}), "Trivy cause metadata").get("StartLine"),
                ),
                observations=[finding.get("Message"), finding.get("Description")],
                signal=tool_signal(severity=finding.get("Severity"), status=finding.get("Status")),
                properties={"resolution": finding.get("Resolution"), "primary_url": finding.get("PrimaryURL")},
            )
        )
    return output


def _secrets(result: Mapping[str, Any], digest: str) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in require_list(result.get("Secrets"), "Trivy secrets"):
        finding = require_mapping(item, "Trivy secret")
        rule_id = finding.get("RuleID") or finding.get("Category") or "secret"
        output.append(
            candidate(
                source="trivy",
                source_type="secret-analysis",
                rule_id=rule_id,
                claim=finding.get("Title") or f"Potential secret reported by {rule_id}",
                digest=digest,
                finding_location=location(path=result.get("Target"), line=finding.get("StartLine"), end_line=finding.get("EndLine")),
                observations=["Potential secret material was redacted by the adapter."],
                signal=tool_signal(severity=finding.get("Severity"), category=finding.get("Category")),
                properties={"redacted": True},
            )
        )
    return output


def parse(payload: Any) -> list[dict[str, Any]]:
    document, digest = read_json(payload)
    root = require_mapping(document, "Trivy input")
    output: list[dict[str, Any]] = []
    for result in require_list(root.get("Results"), "Trivy Results"):
        result_map = require_mapping(result, "Trivy result")
        output.extend(_vulnerabilities(result_map, digest))
        output.extend(_misconfigurations(result_map, digest))
        output.extend(_secrets(result_map, digest))
    return output
