"""Canonical schema and semantic validation for SecHelix artifacts."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .catalog import expected_ids
from .schema_validation import validate_schema


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = {
    "scope": "scope-v1.schema.json",
    "catalog": "catalog-v2.schema.json",
    "applicability-input": "applicability-input-v1.schema.json",
    "applicability-output": "applicability-output-v1.schema.json",
    "attack-surface": "attack-surface-v1.schema.json",
    "evidence": "evidence-v1.schema.json",
    "finding": "finding-v1.schema.json",
    "report": "report-v1.schema.json",
    "extension-manifest": "extension-manifest-v1.schema.json",
    "extension-registry": "extension-registry-v1.schema.json",
}


class ContractValidationError(ValueError):
    """Raised when an artifact fails its structural or semantic contract."""

    def __init__(self, contract: str, errors: list[str]):
        self.contract = contract
        self.errors = errors
        super().__init__(f"{contract} validation failed:\n" + "\n".join(f"- {error}" for error in errors))


def load_json(path: str | Path) -> Any:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def validate_contract(
    contract: str,
    data: Any,
    *,
    require_authorization: bool = False,
    manifest_path: str | Path | None = None,
) -> None:
    """Validate a named artifact; return normally only when all checks pass."""

    if contract not in SCHEMAS:
        raise KeyError(f"unknown contract {contract!r}; choose from {sorted(SCHEMAS)}")
    errors = validate_schema(data, ROOT / "schemas" / SCHEMAS[contract])
    if not errors:
        semantic = globals().get(f"_validate_{contract.replace('-', '_')}")
        if semantic:
            semantic(data, errors, require_authorization=require_authorization, manifest_path=manifest_path)
    if errors:
        raise ContractValidationError(contract, errors)


def _duplicates(values: list[str]) -> list[str]:
    return sorted(value for value, count in Counter(values).items() if count > 1)


def _validate_scope(data: dict[str, Any], errors: list[str], **options: Any) -> None:
    authorization = data["authorization"]
    confirmed = authorization["confirmed"]
    if confirmed and authorization["basis"] == "UNCONFIRMED":
        errors.append("$.authorization: confirmed authorization cannot use UNCONFIRMED basis")
    if not confirmed and authorization["basis"] != "UNCONFIRMED":
        errors.append("$.authorization: unconfirmed authorization must use UNCONFIRMED basis")
    target_ids = [target["id"] for target in data["in_scope"]]
    for duplicate in _duplicates(target_ids):
        errors.append(f"$.in_scope: duplicate target id {duplicate!r}")
    if options.get("require_authorization"):
        if not confirmed:
            errors.append("$.authorization.confirmed: explicit authorization is required")
        unauthorized = [target["id"] for target in data["in_scope"] if not target["authorized"]]
        if unauthorized:
            errors.append(f"$.in_scope: targets are not authorized: {', '.join(unauthorized)}")
        if data["mode"] == "PRODUCTION_SAFE" and not data.get("production_restrictions"):
            errors.append("$.production_restrictions: PRODUCTION_SAFE mode requires explicit restrictions")


def _validate_catalog(data: dict[str, Any], errors: list[str], **options: Any) -> None:
    families = data["families"]
    lenses = data["lenses"]
    hypotheses = data["hypotheses"]
    family_ids = [item["id"] for item in families]
    lens_ids = [item["id"] for item in lenses]
    hypothesis_ids = [item["id"] for item in hypotheses]
    for label, values in (("family", family_ids), ("lens", lens_ids), ("hypothesis", hypothesis_ids)):
        for duplicate in _duplicates(values):
            errors.append(f"$.{label}s: duplicate {label} id {duplicate!r}")
    expected = expected_ids(families, lenses)
    if hypothesis_ids != expected:
        missing = sorted(set(expected) - set(hypothesis_ids))
        extra = sorted(set(hypothesis_ids) - set(expected))
        errors.append(f"$.hypotheses: sequence is not the canonical 21×26 cross-product; missing={missing[:5]}, extra={extra[:5]}")
    if data["hypothesis_count"] != len(hypotheses):
        errors.append("$.hypothesis_count: does not equal the explicit hypothesis array length")
    family_by_id = {item["id"]: item for item in families}
    lens_by_id = {item["id"]: item for item in lenses}
    for family_index, family in enumerate(families):
        for reference_index, reference in enumerate(family["references"]):
            parsed = urlsplit(reference)
            if parsed.scheme != "https" or not parsed.netloc:
                errors.append(
                    f"$.families[{family_index}].references[{reference_index}]: expected an absolute HTTPS reference"
                )
    for index, hypothesis in enumerate(hypotheses):
        family = family_by_id.get(hypothesis["family_id"])
        lens = lens_by_id.get(hypothesis["lens_id"])
        if not family or not lens:
            errors.append(f"$.hypotheses[{index}]: family or lens reference does not exist")
            continue
        expected_id = f"SHX-{family['id']}-{lens['id']}"
        if hypothesis["id"] != expected_id:
            errors.append(f"$.hypotheses[{index}].id: expected {expected_id!r}")
        inherited = {
            "applicability.capability_tags": (hypothesis["applicability"]["capability_tags"], family["capability_tags"]),
            "priority": (hypothesis["priority"], family["priority"]),
            "integrity_critical": (hypothesis["integrity_critical"], family["integrity_critical"]),
            "mappings": (hypothesis["mappings"], family["mappings"]),
            "references": (hypothesis["references"], family["references"]),
            "evidence_requirements": (hypothesis["evidence_requirements"], lens["evidence_requirements"]),
            "false_positive_traps": (hypothesis["false_positive_traps"], lens["false_positive_traps"]),
            "safe_test_guidance": (hypothesis["safe_test_guidance"], lens["safe_test_guidance"]),
        }
        for field, (actual, expected_value) in inherited.items():
            if actual != expected_value:
                errors.append(f"$.hypotheses[{index}].{field}: does not match canonical family/lens metadata")
    manifest_path = Path(options.get("manifest_path") or ROOT / "catalog" / "hypothesis-ids.txt")
    if manifest_path.exists():
        manifest_ids = [line.strip() for line in manifest_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if manifest_ids != hypothesis_ids:
            errors.append(f"$.hypotheses: IDs differ from frozen manifest {manifest_path}")


def _validate_applicability_input(data: dict[str, Any], errors: list[str], **_: Any) -> None:
    _validate_scope(data["scope"], errors, require_authorization=False)
    blocked = [item["hypothesis_id"] for item in data.get("blocked_hypotheses", [])]
    for duplicate in _duplicates(blocked):
        errors.append(f"$.blocked_hypotheses: duplicate hypothesis id {duplicate!r}")


def _validate_applicability_output(data: dict[str, Any], errors: list[str], **_: Any) -> None:
    ids = [item["hypothesis_id"] for item in data["decisions"]]
    for duplicate in _duplicates(ids):
        errors.append(f"$.decisions: duplicate hypothesis id {duplicate!r}")
    actual = Counter(item["status"] for item in data["decisions"])
    for status in ("APPLICABLE", "NOT_APPLICABLE", "UNKNOWN", "BLOCKED"):
        if data["summary"][status] != actual[status]:
            errors.append(f"$.summary.{status}: expected {actual[status]}")
    if data["summary"]["TOTAL"] != len(data["decisions"]):
        errors.append("$.summary.TOTAL: does not equal decision count")
    if sum(data["summary"][status] for status in ("APPLICABLE", "NOT_APPLICABLE", "UNKNOWN", "BLOCKED")) != data["summary"]["TOTAL"]:
        errors.append("$.summary: state counts do not sum to TOTAL")


def _validate_attack_surface(data: dict[str, Any], errors: list[str], **_: Any) -> None:
    node_ids = [node["id"] for node in data["nodes"]]
    node_set = set(node_ids)
    for label, values in (("node", node_ids), ("edge", [edge["id"] for edge in data["edges"]]), ("boundary", [item["id"] for item in data["boundaries"]])):
        for duplicate in _duplicates(values):
            errors.append(f"$.{label}s: duplicate {label} id {duplicate!r}")
    for index, edge in enumerate(data["edges"]):
        for endpoint in ("from", "to"):
            if edge[endpoint] not in node_set:
                errors.append(f"$.edges[{index}].{endpoint}: unknown node {edge[endpoint]!r}")
    membership: Counter[str] = Counter()
    for index, boundary in enumerate(data["boundaries"]):
        for node_id in boundary["node_ids"]:
            membership[node_id] += 1
            if node_id not in node_set:
                errors.append(f"$.boundaries[{index}].node_ids: unknown node {node_id!r}")
    for node_id, count in sorted(membership.items()):
        if count > 1:
            errors.append(f"$.boundaries: node {node_id!r} belongs to more than one boundary")
    for index, entry in enumerate(data["role_object_actions"]):
        for node_id in entry["enforcement_nodes"]:
            if node_id not in node_set:
                errors.append(f"$.role_object_actions[{index}].enforcement_nodes: unknown node {node_id!r}")
        if entry["decision"] == "CONDITIONAL" and not entry.get("condition"):
            errors.append(f"$.role_object_actions[{index}].condition: CONDITIONAL decision requires a condition")


def _validate_finding(data: dict[str, Any], errors: list[str], **_: Any) -> None:
    evidence_ids = set(data["evidence_ids"])
    for name, link in data["evidence_chain"].items():
        unknown = sorted(set(link["evidence_ids"]) - evidence_ids)
        if unknown:
            errors.append(f"$.evidence_chain.{name}.evidence_ids: not declared on finding: {unknown}")
        if data["status"] == "VERIFIED" and not link["established"]:
            errors.append(f"$.evidence_chain.{name}.established: VERIFIED finding requires a complete evidence chain")
        if link["established"] and not link["evidence_ids"]:
            errors.append(f"$.evidence_chain.{name}.evidence_ids: an established link requires evidence")
    verification = data["verification"]
    verification_unknown = sorted(set(verification["evidence_ids"]) - evidence_ids)
    if verification_unknown:
        errors.append(f"$.verification.evidence_ids: not declared on finding: {verification_unknown}")
    if data["status"] == "VERIFIED" and verification["outcome"] != "VERIFIED":
        errors.append("$.verification.outcome: VERIFIED finding requires VERIFIED verification outcome")
    if data["severity"] in {"HIGH", "CRITICAL"} and data["status"] == "VERIFIED":
        if not verification["independent"] or not verification.get("verifier"):
            errors.append("$.verification: verified High/Critical finding requires a named independent verifier")
        if not verification["evidence_ids"]:
            errors.append("$.verification.evidence_ids: verified High/Critical finding requires verification evidence")
    outcome_statuses = {"FALSE_POSITIVE", "LIKELY_BUT_UNPROVEN", "DUPLICATE_ROOT_CAUSE", "BLOCKED_BY_ENVIRONMENT"}
    if data["status"] in outcome_statuses and verification["outcome"] not in {data["status"], "NOT_RUN"}:
        errors.append("$.verification.outcome: contradicts finding status")


def _validate_report(data: dict[str, Any], errors: list[str], **_: Any) -> None:
    coverage = data["coverage"]
    if sum(coverage[state] for state in ("APPLICABLE", "NOT_APPLICABLE", "UNKNOWN", "BLOCKED")) != coverage["TOTAL"]:
        errors.append("$.coverage: state counts do not sum to TOTAL")
    if len(data["blocked_checks"]) != coverage["BLOCKED"]:
        errors.append("$.blocked_checks: count does not match coverage.BLOCKED")
    evidence_ids = [item["evidence_id"] for item in data["evidence"]]
    finding_ids = [item["finding_id"] for item in data["findings"]]
    for label, values in (("evidence", evidence_ids), ("finding", finding_ids)):
        for duplicate in _duplicates(values):
            errors.append(f"$.{label}: duplicate {label} id {duplicate!r}")
    evidence_set = set(evidence_ids)
    for index, finding in enumerate(data["findings"]):
        finding_errors: list[str] = []
        _validate_finding(finding, finding_errors)
        errors.extend(f"$.findings[{index}]{error[1:]}" if error.startswith("$") else error for error in finding_errors)
        unknown = sorted(set(finding["evidence_ids"]) - evidence_set)
        if unknown:
            errors.append(f"$.findings[{index}].evidence_ids: report is missing referenced evidence {unknown}")


def _validate_extension_manifest(data: dict[str, Any], errors: list[str], **_: Any) -> None:
    """Enforce invariants that a contributor must not be able to self-promote around."""

    if data["lifecycle"] != "COMMUNITY":
        errors.append("$.lifecycle: submitted manifests must start in COMMUNITY")
    entrypoints = data["entrypoints"]
    for index, entrypoint in enumerate(entrypoints):
        path = Path(entrypoint)
        if path.is_absolute() or ".." in path.parts:
            errors.append(f"$.entrypoints[{index}]: must be a repository-relative path without '..'")
    fixtures = data["tests"]["fixtures"]
    for index, fixture in enumerate(fixtures):
        path = Path(fixture)
        if path.is_absolute() or ".." in path.parts:
            errors.append(f"$.tests.fixtures[{index}]: must be a repository-relative path without '..'")


def _validate_extension_registry(data: dict[str, Any], errors: list[str], **_: Any) -> None:
    ids = [item["id"] for item in data["extensions"]]
    for duplicate in _duplicates(ids):
        errors.append(f"$.extensions: duplicate extension id {duplicate!r}")
    for index, item in enumerate(data["extensions"]):
        if not item["manifest"].startswith("extensions/community/"):
            errors.append(f"$.extensions[{index}].manifest: must live under extensions/community/")
        review = item.get("review")
        if item["lifecycle"] in {"INCUBATING", "OFFICIAL"} and not review:
            errors.append(f"$.extensions[{index}].review: promoted extensions require a maintainer review record")
