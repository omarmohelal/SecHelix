import json
import unittest
from copy import deepcopy
from pathlib import Path

from sechelix_core.contracts import ContractValidationError, validate_contract
from sechelix_core.variant_hunter import VariantSearchError, classify_variant, search_variants


ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = ROOT / "gold-packs" / "SEC-AUTHZ-IDOR-001" / "pack.json"


def seed() -> dict[str, str]:
    return {
        "finding_id": "SHX-AUTHZ-L02-DEMO",
        "invariant": "subject-scoped-object-access",
        "boundary": "object-authorization",
        "action": "read",
        "actor": "seller",
        "object": "listing",
        "identity_state": "missing",
        "enforcement_layer": "repository",
        "sink_kind": "list-query",
        "framework": "generic-data-access",
    }


def candidate(candidate_id: str = "candidate-a") -> dict[str, str]:
    return {
        "candidate_id": candidate_id,
        "invariant": "subject-scoped-object-access",
        "boundary": "object-authorization",
        "action": "read",
        "actor": "seller",
        "object": "listing",
        "identity_state": "missing",
        "enforcement_layer": "repository",
        "sink_kind": "list-query",
        "framework": "generic-data-access",
        "reachability": "REACHABLE",
        "control_state": "MISSING",
    }


class GoldPackTests(unittest.TestCase):
    def test_reference_pack_satisfies_contract(self) -> None:
        pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))
        validate_contract("gold-check-pack", pack)

    def test_pack_cannot_disable_independent_verification(self) -> None:
        pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))
        pack["verification"]["independent_required"] = False
        with self.assertRaises(ContractValidationError):
            validate_contract("gold-check-pack", pack)

    def test_pack_rejects_unknown_provenance(self) -> None:
        pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))
        pack["sources"]["source_ids"].append("unknown-source")
        with self.assertRaises(ContractValidationError):
            validate_contract("gold-check-pack", pack)


class VariantHunterTests(unittest.TestCase):
    def test_exact_signature_remains_hypothesis(self) -> None:
        result = classify_variant(seed(), candidate())
        self.assertEqual(result["classification"], "EXACT")
        self.assertEqual(result["claim_status"], "HYPOTHESIS")

    def test_changed_dimension_is_variant_not_verified_finding(self) -> None:
        sibling = candidate()
        sibling["framework"] = "django"
        result = classify_variant(seed(), sibling)
        self.assertEqual(result["classification"], "VARIANT")
        self.assertEqual(result["changed_dimensions"], ["framework"])
        self.assertEqual(result["claim_status"], "HYPOTHESIS")

    def test_compensating_control_refutes_candidate(self) -> None:
        protected = candidate()
        protected["control_state"] = "ENFORCED"
        result = classify_variant(seed(), protected)
        self.assertEqual(result["classification"], "REFUTED")
        self.assertIn("COMPENSATING_CONTROL_ENFORCED", result["reason_codes"])

    def test_missing_evidence_is_blocked(self) -> None:
        unknown = candidate()
        unknown["reachability"] = "UNKNOWN"
        self.assertEqual(classify_variant(seed(), unknown)["classification"], "BLOCKED")

    def test_results_have_stable_priority_and_identity_order(self) -> None:
        exact = candidate("z-exact")
        variant = candidate("a-variant")
        variant["object"] = "invoice"
        refuted = candidate("a-refuted")
        refuted["reachability"] = "UNREACHABLE"
        results = search_variants(seed(), [refuted, variant, exact])
        self.assertEqual([item["classification"] for item in results], ["EXACT", "VARIANT", "REFUTED"])

    def test_incomplete_signature_is_rejected(self) -> None:
        incomplete = deepcopy(candidate())
        incomplete.pop("invariant")
        with self.assertRaises(VariantSearchError):
            classify_variant(seed(), incomplete)


if __name__ == "__main__":
    unittest.main()
