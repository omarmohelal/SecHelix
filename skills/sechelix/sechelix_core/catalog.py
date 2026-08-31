"""Canonical SecHelix catalog construction and frozen-ID helpers."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any


FAMILY_METADATA: dict[str, dict[str, Any]] = {
    "AUTH": {"tags": ["authentication", "identity_lifecycle", "mfa"], "priority": 5, "critical": True, "map": "OWASP-ASVS:V2", "ref": "https://owasp.org/www-project-application-security-verification-standard/"},
    "SESS": {"tags": ["sessions", "cookies", "tokens"], "priority": 5, "critical": True, "map": "OWASP-ASVS:V3", "ref": "https://owasp.org/www-project-application-security-verification-standard/"},
    "AUTHZ": {"tags": ["authorization", "multi_tenancy", "object_ownership"], "priority": 5, "critical": True, "map": "OWASP-ASVS:V4", "ref": "https://owasp.org/www-project-application-security-verification-standard/"},
    "INJ": {"tags": ["interpreters", "database_queries", "templates"], "priority": 5, "critical": True, "map": "OWASP-ASVS:V5", "ref": "https://owasp.org/www-project-application-security-verification-standard/"},
    "API": {"tags": ["http_api", "rpc", "webhooks"], "priority": 4, "critical": False, "map": "OWASP-ASVS:V13", "ref": "https://owasp.org/API-Security/"},
    "FILE": {"tags": ["file_uploads", "file_parsers", "object_storage"], "priority": 4, "critical": False, "map": "OWASP-ASVS:V12", "ref": "https://owasp.org/www-project-application-security-verification-standard/"},
    "SSRF": {"tags": ["url_fetching", "outbound_network", "callbacks"], "priority": 5, "critical": True, "map": "OWASP-ASVS:V5", "ref": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"},
    "WEB": {"tags": ["browser_client", "html_rendering", "cross_origin"], "priority": 4, "critical": False, "map": "OWASP-ASVS:V14", "ref": "https://owasp.org/www-project-application-security-verification-standard/"},
    "BIZ": {"tags": ["business_workflows", "entitlements", "state_transitions"], "priority": 5, "critical": True, "map": "OWASP-ASVS:V11", "ref": "https://owasp.org/www-project-application-security-verification-standard/"},
    "MONEY": {"tags": ["payments", "accounting", "payouts"], "priority": 5, "critical": True, "map": "OWASP-ASVS:V11", "ref": "https://owasp.org/www-project-application-security-verification-standard/"},
    "RACE": {"tags": ["concurrency", "retries", "idempotency"], "priority": 5, "critical": True, "map": "CWE-362", "ref": "https://cwe.mitre.org/data/definitions/362.html"},
    "DB": {"tags": ["database", "migrations", "database_policies"], "priority": 5, "critical": True, "map": "OWASP-ASVS:V5", "ref": "https://owasp.org/www-project-application-security-verification-standard/"},
    "CRYPTO": {"tags": ["cryptography", "secrets", "key_management"], "priority": 5, "critical": True, "map": "OWASP-ASVS:V6", "ref": "https://owasp.org/www-project-application-security-verification-standard/"},
    "SUPPLY": {"tags": ["dependencies", "package_install", "artifact_provenance"], "priority": 4, "critical": False, "map": "NIST-SSDF:PS.3", "ref": "https://csrc.nist.gov/Projects/ssdf"},
    "CI": {"tags": ["ci_cd", "build_automation", "release_artifacts"], "priority": 4, "critical": False, "map": "NIST-SSDF:PS.2", "ref": "https://csrc.nist.gov/Projects/ssdf"},
    "CLOUD": {"tags": ["cloud_resources", "iam", "network_configuration"], "priority": 4, "critical": False, "map": "CIS-CONTROLS:4", "ref": "https://www.cisecurity.org/controls"},
    "PRIV": {"tags": ["personal_data", "logging", "data_exports"], "priority": 4, "critical": False, "map": "OWASP-ASVS:V8", "ref": "https://owasp.org/www-project-application-security-verification-standard/"},
    "AI": {"tags": ["ai_models", "agents", "tool_protocols"], "priority": 4, "critical": False, "map": "OWASP-LLM:2025", "ref": "https://genai.owasp.org/llm-top-10/"},
    "OPS": {"tags": ["admin_operations", "support_workflows", "incident_response"], "priority": 4, "critical": False, "map": "NIST-CSF:2.0", "ref": "https://www.nist.gov/cyberframework"},
    "REL": {"tags": ["release_process", "feature_flags", "rollback"], "priority": 4, "critical": False, "map": "NIST-SSDF:PW.9", "ref": "https://csrc.nist.gov/Projects/ssdf"},
    "MAP": {"tags": ["entrypoints", "trust_boundaries", "external_integrations"], "priority": 3, "critical": False, "map": "OWASP-ASVS:V1", "ref": "https://owasp.org/www-project-application-security-verification-standard/"},
}


LENS_METADATA: dict[str, dict[str, Any]] = {
    "L01": {
        "requirements": ["The canonical guard definition and the invariant it is intended to enforce.", "Control-flow evidence for every path that can reach the protected sink."],
        "trap": "A guard missing on one function is not a bypass if every reachable caller enforces the same invariant canonically.",
        "guidance": "Compare path traces statically; if authorized, use an owned denied-case fixture against the canonical and suspected alternate path.",
    },
    "L02": {
        "requirements": ["Identity/tenant/owner type definitions, including nullable or anonymous states.", "Evidence of the effective decision made when identity resolution returns no subject."],
        "trap": "An anonymous path may be intentionally public; absence matters only when a protected decision consumes it.",
        "guidance": "Use a synthetic anonymous identity and an owned protected object; do not use another person's account or data.",
    },
    "L03": {
        "requirements": ["The error branches of each security-relevant lookup and their returned decision.", "A bounded failure observation or test double showing the downstream path on lookup error."],
        "trap": "A theoretically permissive branch is not reachable evidence if the lookup implementation cannot return that error state.",
        "guidance": "Prefer a local stub that returns a controlled error and assert that the operation refuses without external side effects.",
    },
    "L04": {
        "requirements": ["A route/RPC/worker inventory grouped by shared privileged sink or invariant.", "Guard traces for the primary path and every sibling or asynchronous path."],
        "trap": "Similar route names do not prove equivalent authority or access to the same protected object.",
        "guidance": "Exercise only owned fixtures through alternate paths after static sink matching; keep provider calls mocked.",
    },
    "L05": {
        "requirements": ["The server-side object ownership or tenancy model and canonical authorization decision.", "A two-identity trace showing how direct object identifiers are resolved and checked."],
        "trap": "Predictable or visible object identifiers alone are not an authorization failure.",
        "guidance": "Use two synthetic identities and their own objects; attempt only a reversible cross-fixture read or no-op mutation.",
    },
    "L06": {
        "requirements": ["Per-item authorization/invariant enforcement inside the bulk implementation.", "Transaction and partial-result behavior for a mixed-validity batch."],
        "trap": "Whole-batch rejection does not by itself demonstrate that every item received the intended check.",
        "guidance": "Use a tiny batch of owned synthetic objects with one deliberately invalid item and no real external effects.",
    },
    "L07": {
        "requirements": ["Query scoping, pagination, field selection, and response filtering for list/search/export paths.", "Role-separated observations over a synthetic corpus with known visibility."],
        "trap": "Hiding an item in the UI is not evidence that the server list endpoint enforces visibility.",
        "guidance": "Populate a minimal synthetic corpus for two test roles and compare identifiers and fields, not real customer records.",
    },
    "L08": {
        "requirements": ["A source-of-truth map for every security- or value-relevant field.", "The server/provider validation trace from client input to durable or external decision."],
        "trap": "Client-controlled fields are not a defect when the server independently derives or verifies the authoritative value.",
        "guidance": "Tamper only synthetic fixture values and assert server-side recomputation with provider integrations stubbed.",
    },
    "L09": {
        "requirements": ["Version, expiry, cache invalidation, or compare-and-set controls for mutable security state.", "A timeline showing the observed decision before and after the underlying state changes."],
        "trap": "The existence of a cache or preview is not evidence that stale data remains authoritative at commit time.",
        "guidance": "Change an owned fixture between preview and commit, then assert rejection or safe recomputation.",
    },
    "L10": {
        "requirements": ["Idempotency keys, uniqueness constraints, provider identifiers, and replay-window behavior.", "A repeated-request trace that correlates internal and external effects."],
        "trap": "Repeating a read-only or explicitly repeatable operation does not establish duplicate side effects.",
        "guidance": "Replay one identical local-fixture request with a mocked provider and count durable effects.",
    },
    "L11": {
        "requirements": ["Locking, isolation, compare-and-set, or uniqueness controls protecting the shared invariant.", "A synchronized trace demonstrating the possible interleaving and final durable state."],
        "trap": "Two concurrent code paths are not a race finding without a shared invariant and feasible overlap.",
        "guidance": "Use deterministic barriers in a disposable local store; avoid load against shared or production systems.",
    },
    "L12": {
        "requirements": ["Durable state boundaries around external effects, including outbox/inbox or recovery markers.", "Restart/reconciliation behavior for each crash point between effect and commit."],
        "trap": "An ordinary caught exception is not equivalent to process termination and restart.",
        "guidance": "Fault-inject only in a controlled fixture with fake providers, then restart and reconcile from durable state.",
    },
    "L13": {
        "requirements": ["Timeout classification, provider operation identifiers, and reconciliation logic.", "A late-success trace showing whether retry can distinguish unknown outcome from definitive failure."],
        "trap": "A timeout alone does not prove failure or duplication; the eventual provider outcome must be correlated.",
        "guidance": "Use a provider stub that completes after the caller times out and assert one reconciled effect.",
    },
    "L14": {
        "requirements": ["Transaction/compensation boundaries for multi-step operations.", "Response and persisted state when one controlled sub-operation fails."],
        "trap": "An intermediate partial write is not externally observable partial success if guaranteed compensation completes before response.",
        "guidance": "Fail one step in an owned multi-item fixture and verify both the returned status and final durable state.",
    },
    "L15": {
        "requirements": ["The authoritative transition table, including terminal states and privileged overrides.", "Enforcement evidence at every mutation path that can change the state."],
        "trap": "A documented administrative recovery transition is not an unauthorized reopening.",
        "guidance": "Attempt invalid transitions on synthetic state-machine records and assert no external side effect.",
    },
    "L16": {
        "requirements": ["Parsing, validation, defaulting, and coercion sites for the relevant value.", "Boundary-case observations for null, empty, non-finite, false, zero, and unknown values as applicable."],
        "trap": "A language coercion quirk is not relevant when the coerced value never reaches a security or integrity decision.",
        "guidance": "Use typed local fixtures for boundary values and assert explicit refusal or intentional defaults.",
    },
    "L17": {
        "requirements": ["Normalization/canonicalization rules at each parser, service, store, and provider boundary.", "Equivalent-input comparisons showing the value used for validation and the value used at the sink."],
        "trap": "Cosmetic representation differences are not bypasses when every layer compares the same canonical value.",
        "guidance": "Test a small equivalence set of inert strings locally; never use destructive payloads.",
    },
    "L18": {
        "requirements": ["Input provenance from initial storage through every later query, render, command, or tool-call sink.", "The escaping, parameterization, or allowlisting effective at the later-use context."],
        "trap": "Storing untrusted text is not a defect unless a later context interprets it unsafely.",
        "guidance": "Trace an inert sentinel through the full lifecycle; avoid live exploit strings and external commands.",
    },
    "L19": {
        "requirements": ["The same invariant stated for UI, API, worker, database, and provider layers that participate.", "A cross-layer trace identifying which layer owns the final decision."],
        "trap": "Different implementations are not inconsistent when a downstream canonical layer still enforces the invariant.",
        "guidance": "Use contract fixtures at adjacent boundaries and compare decisions without invoking real providers.",
    },
    "L20": {
        "requirements": ["A sensitive-data inventory mapped to response, log, trace, analytics, bundle, and error sinks.", "Redacted artifact samples proving the fields actually emitted and accessible to each audience."],
        "trap": "A sensitive-looking variable name is not exposure evidence without a reachable output and unauthorized audience.",
        "guidance": "Use synthetic canary values, never real secrets or PII, and preserve redacted proof only.",
    },
    "L21": {
        "requirements": ["Configuration schema, defaults, environment overlays, and deployment manifests.", "Effective configuration evidence for supported environments, including absent and legacy keys."],
        "trap": "An environment difference may be intentional and safe when validated by a fail-closed startup policy.",
        "guidance": "Exercise missing, shadow, and legacy flags in a local process or config parser; do not mutate shared environments.",
    },
    "L22": {
        "requirements": ["Ordered migration history and the expected schema/function version contract.", "A live or disposable schema snapshot compared with repository truth and deployment ordering."],
        "trap": "An unapplied migration in a development database is not release drift unless that environment is expected to be current.",
        "guidance": "Run upgrade/rollback checks only on disposable databases populated with synthetic state.",
    },
    "L23": {
        "requirements": ["Lockfiles, resolved sources, signatures/attestations, and allowed publisher or action policy.", "Build evidence showing the exact dependency or artifact selected from the declared source."],
        "trap": "A vulnerable dependency alert is not evidence of package substitution or provenance failure.",
        "guidance": "Use offline fixture manifests and verification commands; never publish test packages or alter a public namespace.",
    },
    "L24": {
        "requirements": ["Built-asset, origin, cookie, CSP, hydration, and runtime header evidence from the relevant environment.", "A browser/runtime trace connecting the observed behavior to the intended security control."],
        "trap": "A unit-test mismatch or console error is not a security failure without impact on the control.",
        "guidance": "Use a local browser fixture or authorized staging account with inert data and reduced side effects.",
    },
    "L25": {
        "requirements": ["Tool schemas, authority policy, context provenance, and operator/agent identity binding.", "A trace from untrusted content through model decision to the proposed or executed tool call."],
        "trap": "Model-generated text is not a tool-authorization failure when no privileged call is possible or executed.",
        "guidance": "Use fake tools and synthetic instructions; require confirmation and block real external actions.",
    },
    "L26": {
        "requirements": ["The actual operation outcome and the code that emits status, health, audit, or metrics.", "Correlated failure/success evidence showing whether observable claims match durable reality."],
        "trap": "A missing log is not the same as a false success claim; identify the consumer and asserted invariant.",
        "guidance": "Simulate a controlled local failure and assert returned status plus audit/metric output without exporting telemetry.",
    },
}


def expected_ids(families: list[dict[str, Any]], lenses: list[dict[str, Any]]) -> list[str]:
    """Return the canonical family-major, lens-minor hypothesis ID sequence."""

    return [f"SHX-{family['id']}-{lens['id']}" for family in families for lens in lenses]


def enrich_source(source: dict[str, Any]) -> dict[str, Any]:
    """Upgrade the original cross-product source metadata without changing IDs."""

    catalog = deepcopy(source)
    for family in catalog["families"]:
        metadata = FAMILY_METADATA[family["id"]]
        family.update(
            capability_tags=metadata["tags"],
            priority=metadata["priority"],
            integrity_critical=metadata["critical"],
            mappings=[metadata["map"]],
            references=[metadata["ref"]],
        )
    for lens in catalog["lenses"]:
        metadata = LENS_METADATA[lens["id"]]
        lens.update(
            evidence_requirements=metadata["requirements"],
            false_positive_traps=[metadata["trap"]],
            safe_test_guidance=metadata["guidance"],
        )
    return catalog


def build_catalog(source: dict[str, Any]) -> dict[str, Any]:
    """Materialize all explicit hypotheses from enriched canonical metadata."""

    catalog = enrich_source(source)
    hypotheses: list[dict[str, Any]] = []
    for family in catalog["families"]:
        for lens in catalog["lenses"]:
            hypotheses.append(
                {
                    "id": f"SHX-{family['id']}-{lens['id']}",
                    "family_id": family["id"],
                    "lens_id": lens["id"],
                    "title": f"{family['name']} — {lens['name']}",
                    "hypothesis": (
                        f"Review whether {family['focus']} exhibits the {lens['name']} condition. "
                        f"Question to resolve: {lens['question']}"
                    ),
                    "claim_status": "HYPOTHESIS",
                    "applicability": {
                        "capability_tags": family["capability_tags"],
                        "rule": "ANY_CAPABILITY_PRESENT",
                    },
                    "evidence_requirements": lens["evidence_requirements"],
                    "false_positive_traps": lens["false_positive_traps"],
                    "safe_test_guidance": lens["safe_test_guidance"],
                    "priority": family["priority"],
                    "integrity_critical": family["integrity_critical"],
                    "mappings": family["mappings"],
                    "references": family["references"],
                }
            )
    return {
        "schema_version": "2.2",
        "project": "SecHelix",
        "representation": "explicit_hypotheses",
        "description": (
            "21 security families × 26 verification lenses = 546 explicit, stable hypothesis records. "
            "Records are review questions selected by architecture applicability, never vulnerability or exploit claims."
        ),
        "families": catalog["families"],
        "lenses": catalog["lenses"],
        "hypotheses": hypotheses,
        "hypothesis_count": len(hypotheses),
        "selection_rule": (
            "Evaluate every record with the deterministic four-state applicability engine before review; "
            "missing evidence is UNKNOWN and only explicit absence is NOT_APPLICABLE."
        ),
        "claim_policy": (
            "Every catalog record is an unverified hypothesis. Findings require an evidence chain and, for High/Critical, independent verification."
        ),
    }


def load_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def stable_json(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
