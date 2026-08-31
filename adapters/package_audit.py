"""npm and pnpm audit JSON normalization."""

from __future__ import annotations

from typing import Any, Mapping

from .base import candidate, location, read_json, require_mapping, text, tool_signal


def _modern(root: Mapping[str, Any], digest: str, manager: str) -> list[dict[str, Any]]:
    vulnerabilities = require_mapping(root.get("vulnerabilities", {}), f"{manager} vulnerabilities")
    output: list[dict[str, Any]] = []
    for package_name, raw in vulnerabilities.items():
        finding = require_mapping(raw, f"{manager} vulnerability")
        via = finding.get("via", [])
        via_items = via if isinstance(via, list) else [via]
        advisories = [item for item in via_items if isinstance(item, Mapping)]
        if not advisories:
            advisories = [finding]
        for advisory in advisories:
            rule_id = advisory.get("source") or advisory.get("url") or package_name
            title = advisory.get("title") or f"Audit advisory reported for {package_name}"
            nodes = finding.get("nodes") if isinstance(finding.get("nodes"), list) else []
            output.append(
                candidate(
                    source=manager,
                    source_type="dependency-analysis",
                    rule_id=rule_id,
                    claim=title,
                    digest=digest,
                    finding_location=location(path=nodes[0] if nodes else None),
                    observations=[title],
                    signal=tool_signal(severity=advisory.get("severity") or finding.get("severity"), cvss=advisory.get("cvss")),
                    properties={
                        "package": package_name,
                        "range": advisory.get("range") or finding.get("range"),
                        "url": advisory.get("url"),
                        "fix_available": finding.get("fixAvailable"),
                    },
                )
            )
    return output


def _legacy(root: Mapping[str, Any], digest: str, manager: str) -> list[dict[str, Any]]:
    advisories = require_mapping(root.get("advisories", {}), f"{manager} advisories")
    output: list[dict[str, Any]] = []
    for advisory_id, raw in advisories.items():
        advisory = require_mapping(raw, f"{manager} advisory")
        module = text(advisory.get("module_name"), "unknown package")
        output.append(
            candidate(
                source=manager,
                source_type="dependency-analysis",
                rule_id=advisory.get("github_advisory_id") or advisory_id,
                claim=advisory.get("title") or f"Audit advisory reported for {module}",
                digest=digest,
                finding_location=location(),
                observations=[advisory.get("overview"), advisory.get("recommendation")],
                signal=tool_signal(severity=advisory.get("severity"), cvss=advisory.get("cvss")),
                properties={"package": module, "vulnerable_versions": advisory.get("vulnerable_versions"), "url": advisory.get("url")},
            )
        )
    return output


def parse(payload: Any, manager: str = "npm-audit") -> list[dict[str, Any]]:
    document, digest = read_json(payload)
    root = require_mapping(document, f"{manager} input")
    if "vulnerabilities" in root:
        return _modern(root, digest, manager)
    if "advisories" in root:
        return _legacy(root, digest, manager)
    return []


def parse_npm(payload: Any) -> list[dict[str, Any]]:
    return parse(payload, "npm-audit")


def parse_pnpm(payload: Any) -> list[dict[str, Any]]:
    return parse(payload, "pnpm-audit")
