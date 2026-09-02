"""Canonical schema and semantic validation for SecHelix artifacts."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .catalog import expected_ids
from .knowledge import expected_research_confidence
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
    "source-registry": "source-registry-v1.schema.json",
    "knowledge-graph": "knowledge-graph-v1.schema.json",
    "calibration": "calibration-v1.schema.json",
    "policy-pack": "policy-pack-v1.schema.json",
    "lesson-card": "lesson-card-v1.schema.json",
    "research-packet": "research-packet-v1.schema.json",
    "gold-check-pack": "gold-check-pack-v1.schema.json",
    "runtime-trace": "runtime-trace-v1.schema.json",
    "dependency-exploitability": "dependency-exploitability-v1.schema.json",
    "secret-lifecycle": "secret-lifecycle-v1.schema.json",
    "mcp-graph": "mcp-graph-v1.schema.json",
    "ai-bom": "ai-bom-v1.schema.json",
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


#: Links that cannot honestly stand on their own, and what each one presupposes.
#:
#: The evidence chain is a lattice, not a sequence: most links are independent and
#: a finding is allowed to establish them in any order, or not at all. Three
#: implications are not optional, because asserting the consequent while denying
#: the antecedent describes something that cannot happen:
#:
#: ``impact`` asserts harm was demonstrated, which is only meaningful if an
#: attacker can both influence the input and reach the code — otherwise what was
#: demonstrated is a conditional, and a conditional belongs in ``statement`` with
#: ``established`` false. ``safe_reproduction`` asserts the path was actually
#: walked, which cannot be true of a path that was never shown to be reachable.
#:
#: Deliberately absent: ``boundary_failure`` does NOT presuppose ``reachability``.
#: A missing authorization check is a real, statically-establishable fact about a
#: handler nobody has yet shown is reachable, and demanding reachability first
#: would suppress true findings. Nothing else is inferred.
_CHAIN_PREREQUISITES: dict[str, tuple[str, ...]] = {
    "impact": ("attacker_control", "reachability"),
    "safe_reproduction": ("reachability",),
}


def _validate_finding(data: dict[str, Any], errors: list[str], **_: Any) -> None:
    evidence_ids = set(data["evidence_ids"])
    chain = data["evidence_chain"]
    for name, link in chain.items():
        unknown = sorted(set(link["evidence_ids"]) - evidence_ids)
        if unknown:
            errors.append(f"$.evidence_chain.{name}.evidence_ids: not declared on finding: {unknown}")
        if data["status"] == "VERIFIED" and not link["established"]:
            errors.append(f"$.evidence_chain.{name}.established: VERIFIED finding requires a complete evidence chain")
        if link["established"] and not link["evidence_ids"]:
            errors.append(f"$.evidence_chain.{name}.evidence_ids: an established link requires evidence")
    for name, prerequisites in _CHAIN_PREREQUISITES.items():
        if not chain[name]["established"]:
            continue
        missing = [required for required in prerequisites if not chain[required]["established"]]
        if missing:
            errors.append(
                f"$.evidence_chain.{name}.established: cannot be established while "
                f"{', '.join(missing)} is not — observation is not attacker capability"
            )
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


def _validate_gold_check_pack(data: dict[str, Any], errors: list[str], **_: Any) -> None:
    """Keep reusable packs tied to canonical provenance and honest calibration."""

    source_ids = set(_knowledge_source_index())
    unknown_sources = sorted(set(data["sources"]["source_ids"]) - source_ids)
    if unknown_sources:
        errors.append(f"$.sources.source_ids: unknown source IDs: {unknown_sources}")

    catalog = load_json(ROOT / "catalog" / "checks.json")
    hypothesis_ids = {item["id"] for item in catalog["hypotheses"]}
    unknown_hypotheses = sorted(set(data["sources"]["catalog_hypothesis_ids"]) - hypothesis_ids)
    if unknown_hypotheses:
        errors.append(f"$.sources.catalog_hypothesis_ids: unknown hypothesis IDs: {unknown_hypotheses}")

    # The evaluation corpus is deliberately not part of the portable skill bundle, so a
    # pack's fixture references can only be cross-checked where that corpus is present.
    # Treating its absence as a violation would fail every pack inside an installed skill.
    fixtures_dir = ROOT / "evals" / "fixtures"
    if fixtures_dir.is_dir():
        fixture_ids: set[str] = set()
        for path in sorted(fixtures_dir.glob("*.json")):
            fixture = load_json(path)
            if isinstance(fixture, dict) and isinstance(fixture.get("id"), str):
                fixture_ids.add(fixture["id"])
        unknown_fixtures = sorted(set(data["regression"]["fixture_ids"]) - fixture_ids)
        if unknown_fixtures:
            errors.append(f"$.regression.fixture_ids: unknown fixture IDs: {unknown_fixtures}")

    calibration = data["calibration"]
    if calibration["measurement_status"] == "NOT_MEASURED" and calibration["sample_size"] != 0:
        errors.append("$.calibration.sample_size: NOT_MEASURED requires a zero sample size")
    if calibration["measurement_status"] == "MEASURED" and calibration["sample_size"] == 0:
        errors.append("$.calibration.sample_size: MEASURED requires a non-zero sample size")


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


def _knowledge_source_index() -> dict[str, dict[str, Any]]:
    registry = load_json(ROOT / "knowledge" / "source-registry.json")
    return {source["id"]: source for source in registry["sources"]}


def _knowledge_node_ids() -> set[str]:
    graph = load_json(ROOT / "knowledge" / "graph" / "relationships.json")
    return {node["id"] for node in graph["nodes"]}


def _validate_source_registry(data: dict[str, Any], errors: list[str], **_: Any) -> None:
    if data["policy"]["trust_order"] != ["S", "A", "B", "C", "R"]:
        errors.append("$.policy.trust_order: expected canonical S, A, B, C, R order")
    ids = [source["id"] for source in data["sources"]]
    for duplicate in _duplicates(ids):
        errors.append(f"$.sources: duplicate source id {duplicate!r}")
    for index, source in enumerate(data["sources"]):
        for field in ("canonical_url", "terms_url"):
            parsed = urlsplit(source[field])
            if parsed.scheme != "https" or not parsed.netloc:
                errors.append(f"$.sources[{index}].{field}: expected an absolute HTTPS URL")
        uses = source["allowed_uses"]
        if source["access_mode"] == "HUMAN_ONLY" or source["trust_tier"] == "R":
            forbidden = [name for name, allowed in uses.items() if name != "human_reference" and allowed]
            if forbidden:
                errors.append(f"$.sources[{index}].allowed_uses: restricted source permits {forbidden}")
            if not uses["human_reference"]:
                errors.append(f"$.sources[{index}].allowed_uses.human_reference: HUMAN_ONLY source must allow manual reference")
        license_data = source["license"]
        if license_data["per_artifact_review"] and (uses["full_text_storage"] or uses["embeddings"]):
            errors.append(f"$.sources[{index}].allowed_uses: per-artifact review forbids full text and embeddings by default")
        if (uses["full_text_storage"] or uses["embeddings"] or uses["model_training"]) and license_data["status"] != "VERIFIED":
            errors.append(f"$.sources[{index}].allowed_uses: sensitive reuse requires a VERIFIED license")
        if source["source_class"] == "CURRICULUM" and (uses["model_training"] or uses["model_evaluation"]):
            errors.append(f"$.sources[{index}].allowed_uses: curriculum sources cannot train or evaluate models by default")


def _validate_knowledge_graph(data: dict[str, Any], errors: list[str], **_: Any) -> None:
    source_ids = set(_knowledge_source_index())
    node_ids = [node["id"] for node in data["nodes"]]
    node_set = set(node_ids)
    for label, values in (("node", node_ids), ("edge", [edge["id"] for edge in data["edges"]])):
        for duplicate in _duplicates(values):
            errors.append(f"$.{label}s: duplicate {label} id {duplicate!r}")
    for index, node in enumerate(data["nodes"]):
        if node["provenance"] == "EXTERNAL" and not node["source_ids"]:
            errors.append(f"$.nodes[{index}].source_ids: external node requires provenance")
        unknown = sorted(set(node["source_ids"]) - source_ids)
        if unknown:
            errors.append(f"$.nodes[{index}].source_ids: unknown source IDs {unknown}")
    for index, edge in enumerate(data["edges"]):
        for endpoint in ("from", "to"):
            if edge[endpoint] not in node_set:
                errors.append(f"$.edges[{index}].{endpoint}: unknown node {edge[endpoint]!r}")
        unknown = sorted(set(edge["source_ids"]) - source_ids)
        if unknown:
            errors.append(f"$.edges[{index}].source_ids: unknown source IDs {unknown}")


def _validate_lesson_card(data: dict[str, Any], errors: list[str], **_: Any) -> None:
    sources = _knowledge_source_index()
    unknown_sources = sorted(set(data["source_ids"]) - set(sources))
    if unknown_sources:
        errors.append(f"$.source_ids: unknown source IDs {unknown_sources}")
    restricted = sorted(
        source_id for source_id in data["source_ids"]
        if source_id in sources and sources[source_id]["access_mode"] == "HUMAN_ONLY"
    )
    if restricted:
        errors.append(f"$.source_ids: lesson cards cannot ingest HUMAN_ONLY sources {restricted}")
    unknown_nodes = sorted(set(data["mapping_node_ids"]) - _knowledge_node_ids())
    if unknown_nodes:
        errors.append(f"$.mapping_node_ids: unknown graph nodes {unknown_nodes}")


def _validate_research_packet(data: dict[str, Any], errors: list[str], **_: Any) -> None:
    sources = _knowledge_source_index()
    for index, reference in enumerate(data["sources"]):
        source = sources.get(reference["source_id"])
        if not source:
            errors.append(f"$.sources[{index}].source_id: unknown source ID {reference['source_id']!r}")
            continue
        if source["access_mode"] == "HUMAN_ONLY" or not source["allowed_uses"]["normalized_facts"]:
            errors.append(f"$.sources[{index}].source_id: source cannot be used in an automated research packet")
        if reference["official_advisory"] and source["source_class"] != "OFFICIAL_ADVISORY":
            errors.append(f"$.sources[{index}].official_advisory: registry does not classify this source as an official advisory")
    for field, state in (("code_evidence", "present"), ("safe_reproduction", "performed")):
        if data[field][state] and not data[field]["evidence_refs"]:
            errors.append(f"$.{field}.evidence_refs: declared proof requires at least one evidence reference")
        if not data[field][state] and data[field]["evidence_refs"]:
            errors.append(f"$.{field}.evidence_refs: references contradict the false proof flag")
    expected = expected_research_confidence(data, {"sources": list(sources.values())})
    if data["confidence"] != expected:
        errors.append(f"$.confidence: expected deterministic state {expected!r}")
