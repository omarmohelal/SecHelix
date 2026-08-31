"""OSV-Scanner JSON normalization."""

from __future__ import annotations

from typing import Any

from .base import candidate, location, read_json, require_list, require_mapping, text, tool_signal


def parse(payload: Any) -> list[dict[str, Any]]:
    document, digest = read_json(payload)
    root = require_mapping(document, "OSV input")
    normalized: list[dict[str, Any]] = []
    for result in require_list(root.get("results"), "OSV results"):
        result_map = require_mapping(result, "OSV result")
        source = require_mapping(result_map.get("source", {}), "OSV source")
        for package_result in require_list(result_map.get("packages"), "OSV packages"):
            package_map = require_mapping(package_result, "OSV package result")
            package = require_mapping(package_map.get("package", {}), "OSV package")
            package_name = text(package.get("name"), "unknown package")
            package_version = text(package.get("version"))
            for vulnerability in require_list(package_map.get("vulnerabilities"), "OSV vulnerabilities"):
                vuln = require_mapping(vulnerability, "OSV vulnerability")
                vuln_id = text(vuln.get("id"), "unknown")
                normalized.append(
                    candidate(
                        source="osv",
                        source_type="dependency-analysis",
                        rule_id=vuln_id,
                        claim=f"{vuln_id} reported for {package_name}",
                        digest=digest,
                        finding_location=location(path=source.get("path")),
                        observations=[vuln.get("summary"), vuln.get("details")],
                        signal=tool_signal(
                            severity=vuln.get("database_specific", {}).get("severity")
                            if isinstance(vuln.get("database_specific"), dict)
                            else None,
                            cvss=vuln.get("severity"),
                        ),
                        properties={
                            "package": package_name,
                            "version": package_version,
                            "aliases": vuln.get("aliases", []),
                            "modified": vuln.get("modified"),
                        },
                    )
                )
    return normalized
