"""Opengrep JSON normalization.

Opengrep intentionally preserves Semgrep-compatible JSON result shapes, but it
is a distinct tool with its own version, engine behaviour and provenance.  The
adapter therefore does not alias the source name to ``semgrep``: evidence must
say which engine produced it so a later verifier can reproduce the signal.

As with every SecHelix adapter, an Opengrep result is a *candidate signal*, not
a vulnerability verdict.  Tool severity/confidence never promotes assessment.
"""

from __future__ import annotations

from typing import Any

from .base import candidate, location, read_json, require_list, require_mapping, text, tool_signal


def parse(payload: Any) -> list[dict[str, Any]]:
    document, digest = read_json(payload)
    root = require_mapping(document, "Opengrep input")
    normalized: list[dict[str, Any]] = []
    for result in require_list(root.get("results"), "Opengrep results"):
        finding = require_mapping(result, "Opengrep result")
        extra = require_mapping(finding.get("extra", {}), "Opengrep extra")
        start = require_mapping(finding.get("start", {}), "Opengrep start")
        end = require_mapping(finding.get("end", {}), "Opengrep end")
        metadata = require_mapping(extra.get("metadata", {}), "Opengrep metadata")
        message = text(extra.get("message"), text(finding.get("check_id"), "Opengrep result"))
        normalized.append(
            candidate(
                source="opengrep",
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
                    confidence=metadata.get("confidence"),
                ),
                properties={
                    "fingerprint": extra.get("fingerprint"),
                    "engine": "opengrep",
                    "taint_mode": metadata.get("mode") or metadata.get("analysis"),
                },
            )
        )
    return normalized
