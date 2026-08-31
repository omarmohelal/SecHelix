"""Gitleaks JSON normalization that never emits captured secret material."""

from __future__ import annotations

from typing import Any, Mapping

from .base import AdapterError, candidate, location, read_json, require_list, require_mapping, tool_signal


def parse(payload: Any) -> list[dict[str, Any]]:
    document, digest = read_json(payload)
    if isinstance(document, Mapping):
        findings = require_list(document.get("findings"), "Gitleaks findings")
        version = document.get("version")
    elif isinstance(document, list):
        findings = document
        version = None
    else:
        raise AdapterError("Gitleaks input must be an array or findings object")
    output: list[dict[str, Any]] = []
    for item in findings:
        finding = require_mapping(item, "Gitleaks finding")
        rule_id = finding.get("RuleID") or finding.get("Description") or "secret"
        output.append(
            candidate(
                source="gitleaks",
                source_type="secret-analysis",
                source_version=version,
                rule_id=rule_id,
                claim=finding.get("Description") or f"Potential secret reported by {rule_id}",
                digest=digest,
                finding_location=location(path=finding.get("File"), line=finding.get("StartLine"), column=finding.get("StartColumn")),
                observations=["Potential secret material was redacted by the adapter."],
                signal=tool_signal(tags=finding.get("Tags")),
                properties={
                    "commit": finding.get("Commit"),
                    "fingerprint": finding.get("Fingerprint"),
                    "redacted": True,
                },
            )
        )
    return output
