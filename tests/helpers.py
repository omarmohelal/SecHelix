"""Small valid artifact fixtures shared by core contract tests."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


def scope(*, confirmed: bool = True) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "scope_id": "SCOPE-DEMO",
        "project": "SecHelix fixture",
        "authorization": {
            "confirmed": confirmed,
            "basis": "OWNER" if confirmed else "UNCONFIRMED",
            "statement": "Owner-authorized review of a controlled local fixture." if confirmed else "Authorization has not been confirmed.",
            "authorized_by": "fixture-owner",
        },
        "mode": "LOCAL",
        "in_scope": [
            {
                "id": "TGT-APP",
                "type": "LOCAL_FIXTURE",
                "name": "fixture application",
                "locator": "./tests/fixtures/app",
                "environment": "LOCAL",
                "authorized": confirmed,
            }
        ],
        "out_of_scope": ["third-party systems"],
        "allowed_tools": ["stdlib test runner"],
        "stop_conditions": ["unexpected external side effect"],
    }


def applicability_input(*, confirmed: bool = True) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "scope": scope(confirmed=confirmed),
        "architecture": {
            "capabilities": {
                "authentication": {"state": "PRESENT", "reason": "Observed local authentication boundary.", "evidence_ids": ["EV-AUTH"]},
                "identity_lifecycle": {"state": "ABSENT", "reason": "Fixture has no recovery or provisioning."},
                "mfa": {"state": "ABSENT", "reason": "Fixture intentionally omits MFA."},
                "sessions": {"state": "ABSENT", "reason": "Fixture is stateless."},
                "cookies": {"state": "ABSENT", "reason": "No HTTP cookies are used."},
                "tokens": {"state": "ABSENT", "reason": "No bearer or refresh tokens are used."},
                "interpreters": {"state": "BLOCKED", "reason": "Generated parser source is unavailable."},
                "database_queries": {"state": "ABSENT", "reason": "Fixture has no database."},
                "templates": {"state": "ABSENT", "reason": "Fixture has no template engine."},
            },
            "evidence_ids": ["EV-AUTH"],
            "unknowns": ["Other catalog capabilities have not been mapped."],
        },
        "blocked_hypotheses": [
            {"hypothesis_id": "SHX-AUTH-L26", "reason": "The audit telemetry fixture is unavailable."}
        ],
    }


def attack_graph() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "graph_id": "GRAPH-DEMO",
        "scope_id": "SCOPE-DEMO",
        "title": "Local fixture attack surface",
        "nodes": [
            {"id": "N-API", "type": "ENTRYPOINT", "label": "API | ingress", "sensitivity": "PUBLIC", "evidence_ids": ["EV-GRAPH"]},
            {"id": "N-GUARD", "type": "CONTROL", "label": "Authorization \"guard\"", "sensitivity": "INTERNAL", "evidence_ids": ["EV-GRAPH"]},
            {"id": "N-DATA", "type": "STORE", "label": "Owned data", "sensitivity": "RESTRICTED", "evidence_ids": ["EV-GRAPH"]},
        ],
        "edges": [
            {"id": "E-01", "from": "N-API", "to": "N-GUARD", "type": "CALLS", "label": "request", "evidence_ids": ["EV-GRAPH"]},
            {"id": "E-02", "from": "N-GUARD", "to": "N-DATA", "type": "AUTHORIZES", "label": "owner check", "privileged": True, "evidence_ids": ["EV-GRAPH"]},
        ],
        "boundaries": [
            {"id": "B-APP", "label": "Application", "node_ids": ["N-GUARD", "N-DATA"], "evidence_ids": ["EV-GRAPH"]}
        ],
        "role_object_actions": [
            {
                "role": "member",
                "object": "owned record",
                "action": "read",
                "decision": "CONDITIONAL",
                "condition": "record.owner_id equals authenticated member",
                "enforcement_nodes": ["N-GUARD"],
                "evidence_ids": ["EV-GRAPH"],
            }
        ],
        "unknowns": ["Provider-side controls were not observed."],
    }


def evidence(evidence_id: str = "EV-OBS") -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "evidence_id": evidence_id,
        "kind": "VERIFICATION",
        "status": "CONFIRMED",
        "source": {
            "type": "TEST",
            "name": "controlled fixture",
            "version": "1",
            "collected_at": "2026-01-01T00:00:00Z",
            "provenance": "tests/helpers.py fixture",
        },
        "summary": "Synthetic evidence used to validate artifact contracts.",
        "environment": {"mode": "LOCAL", "scope_id": "SCOPE-DEMO", "target_id": "TGT-APP"},
        "artifacts": [
            {"name": "fixture.txt", "media_type": "text/plain", "sha256": "a" * 64, "locator": "tests/fixtures/fixture.txt"}
        ],
        "redactions": [],
        "related_hypothesis_ids": ["SHX-AUTH-L01"],
    }


def finding() -> dict[str, Any]:
    chain_link = {"established": True, "statement": "Established in the controlled fixture.", "evidence_ids": ["EV-OBS"]}
    return {
        "schema_version": "1.0",
        "finding_id": "SHX-F-DEMO",
        "title": "Controlled fixture verification record",
        "status": "VERIFIED",
        "severity": "HIGH",
        "confidence": "HIGH",
        "catalog_hypothesis_ids": ["SHX-AUTH-L01"],
        "affected_surface": ["local fixture"],
        "evidence_ids": ["EV-OBS", "EV-VERIFY"],
        "evidence_chain": {
            name: deepcopy(chain_link)
            for name in ("attacker_control", "reachability", "boundary_failure", "safe_reproduction", "impact", "preconditions", "root_cause")
        },
        "verification": {
            "independent": True,
            "verifier": "independent-fixture-verifier",
            "outcome": "VERIFIED",
            "evidence_ids": ["EV-VERIFY"],
            "refutation_attempt": "Checked the canonical guard and a safe negative-control fixture.",
        },
        "resolution": "OPEN",
    }


def report() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "report_id": "REPORT-DEMO",
        "scope_id": "SCOPE-DEMO",
        "mode": "LOCAL",
        "generated_at": "2026-01-01T00:00:00Z",
        "coverage": {
            "catalog_version": "2.2",
            "APPLICABLE": 1,
            "NOT_APPLICABLE": 0,
            "UNKNOWN": 544,
            "BLOCKED": 1,
            "TOTAL": 546,
        },
        "tools": [{"name": "unittest", "version": "stdlib", "purpose": "contract validation"}],
        "evidence": [evidence("EV-OBS"), evidence("EV-VERIFY")],
        "findings": [finding()],
        "rejected_false_positives": [],
        "blocked_checks": ["SHX-AUTH-L26"],
        "release_recommendation": "BLOCKED",
        "redaction_summary": [],
    }
