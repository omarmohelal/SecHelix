"""Deterministic four-state applicability evaluation."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .contracts import validate_contract


ENGINE = "sechelix-deterministic-applicability-v1"


def _authorized(scope: dict[str, Any]) -> bool:
    return scope["authorization"]["confirmed"] and all(target["authorized"] for target in scope["in_scope"])


def evaluate_applicability(catalog: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    """Evaluate catalog hypotheses using only explicit scope and capability facts."""

    validate_contract("catalog", catalog)
    validate_contract("applicability-input", request)
    authorized = _authorized(request["scope"])
    capabilities = request["architecture"]["capabilities"]
    explicit_blocks = {item["hypothesis_id"]: item["reason"] for item in request.get("blocked_hypotheses", [])}
    catalog_ids = {item["id"] for item in catalog["hypotheses"]}
    unknown_blocks = sorted(set(explicit_blocks) - catalog_ids)
    if unknown_blocks:
        raise ValueError(f"blocked_hypotheses contains IDs outside the catalog: {', '.join(unknown_blocks)}")
    decisions: list[dict[str, Any]] = []
    for hypothesis in catalog["hypotheses"]:
        hypothesis_id = hypothesis["id"]
        tags = sorted(hypothesis["applicability"]["capability_tags"])
        states = {tag: capabilities.get(tag, {}).get("state", "UNDECLARED") for tag in tags}
        evidence_ids = sorted(
            {
                evidence_id
                for tag in tags
                for evidence_id in capabilities.get(tag, {}).get("evidence_ids", [])
            }
        )
        if not authorized:
            status, code = "BLOCKED", "SCOPE_NOT_AUTHORIZED"
            reason = "Scope authorization is not confirmed for every in-scope target."
        elif hypothesis_id in explicit_blocks:
            status, code = "BLOCKED", "EXPLICIT_BLOCK"
            reason = explicit_blocks[hypothesis_id]
        elif any(state == "PRESENT" for state in states.values()):
            status, code = "APPLICABLE", "CAPABILITY_PRESENT"
            present = [tag for tag, state in states.items() if state == "PRESENT"]
            reason = f"At least one required architecture capability is present: {', '.join(present)}."
        elif any(state == "BLOCKED" for state in states.values()):
            status, code = "BLOCKED", "CAPABILITY_BLOCKED"
            blocked = [tag for tag, state in states.items() if state == "BLOCKED"]
            reason = f"Architecture evidence is unavailable because capability review is blocked: {', '.join(blocked)}."
        elif states and all(state == "ABSENT" for state in states.values()):
            status, code = "NOT_APPLICABLE", "CAPABILITY_ABSENT"
            reason = f"All required architecture capabilities are explicitly absent: {', '.join(states)}."
        else:
            status, code = "UNKNOWN", "CAPABILITY_UNKNOWN"
            unresolved = [tag for tag, state in states.items() if state in {"UNKNOWN", "UNDECLARED"}]
            reason = f"Required architecture capability evidence is unresolved: {', '.join(unresolved)}."
        decisions.append(
            {
                "hypothesis_id": hypothesis_id,
                "status": status,
                "reason_code": code,
                "reason": reason,
                "capability_states": states,
                "evidence_ids": evidence_ids,
            }
        )
    counts = Counter(item["status"] for item in decisions)
    result = {
        "schema_version": "1.0",
        "catalog_version": catalog["schema_version"],
        "scope_id": request["scope"]["scope_id"],
        "engine": ENGINE,
        "authorized": authorized,
        "summary": {
            "APPLICABLE": counts["APPLICABLE"],
            "NOT_APPLICABLE": counts["NOT_APPLICABLE"],
            "UNKNOWN": counts["UNKNOWN"],
            "BLOCKED": counts["BLOCKED"],
            "TOTAL": len(decisions),
        },
        "decisions": decisions,
    }
    validate_contract("applicability-output", result)
    return result
