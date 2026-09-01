from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from scripts.validate_knowledge import validate
from sechelix_core.contracts import ContractValidationError, validate_contract
from sechelix_core.knowledge import expected_research_confidence, load_source_registry, stale_source_ids


ROOT = Path(__file__).resolve().parents[1]


def packet() -> dict:
    return json.loads((ROOT / "examples" / "research-packet.example.json").read_text(encoding="utf-8"))


class KnowledgeEngineTests(unittest.TestCase):
    def test_checked_in_knowledge_artifacts_validate(self) -> None:
        self.assertEqual(validate(), [])

    def test_restricted_curricula_are_human_only(self) -> None:
        registry = load_source_registry()
        restricted = [source for source in registry["sources"] if source["trust_tier"] == "R"]
        self.assertGreaterEqual(len(restricted), 3)
        for source in restricted:
            self.assertEqual(source["access_mode"], "HUMAN_ONLY")
            self.assertTrue(source["allowed_uses"]["human_reference"])
            self.assertFalse(any(
                allowed for name, allowed in source["allowed_uses"].items()
                if name != "human_reference"
            ))

    def test_two_independent_sources_are_supported(self) -> None:
        artifact = packet()
        artifact["sources"] = [
            {
                "source_id": "nvd",
                "url": "https://nvd.nist.gov/developers/vulnerabilities",
                "retrieved_at": "2026-09-01T00:00:00Z",
                "relation": "SUPPORTS",
                "official_advisory": False,
                "exact_version_match": True
            },
            {
                "source_id": "osv",
                "url": "https://osv.dev/",
                "retrieved_at": "2026-09-01T00:00:00Z",
                "relation": "SUPPORTS",
                "official_advisory": False,
                "exact_version_match": True
            }
        ]
        artifact["confidence"] = "SUPPORTED"
        self.assertEqual(expected_research_confidence(artifact), "SUPPORTED")
        validate_contract("research-packet", artifact)

    def test_official_advisory_with_exact_version_is_high_confidence(self) -> None:
        artifact = packet()
        artifact["sources"] = [{
            "source_id": "cisa-kev",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "retrieved_at": "2026-09-01T00:00:00Z",
            "relation": "SUPPORTS",
            "official_advisory": True,
            "exact_version_match": True
        }]
        artifact["confidence"] = "HIGH_CONFIDENCE"
        self.assertEqual(expected_research_confidence(artifact), "HIGH_CONFIDENCE")
        validate_contract("research-packet", artifact)

    def test_code_evidence_and_safe_reproduction_confirm(self) -> None:
        artifact = packet()
        artifact["code_evidence"] = {"present": True, "evidence_refs": ["EV-CODE-001"]}
        artifact["safe_reproduction"] = {"performed": True, "evidence_refs": ["EV-REPRO-001"]}
        artifact["confidence"] = "CONFIRMED"
        self.assertEqual(expected_research_confidence(artifact), "CONFIRMED")
        validate_contract("research-packet", artifact)

    def test_wrong_confidence_is_rejected(self) -> None:
        artifact = packet()
        artifact["confidence"] = "CONFIRMED"
        with self.assertRaises(ContractValidationError):
            validate_contract("research-packet", artifact)

    def test_graph_rejects_dangling_endpoint(self) -> None:
        graph = json.loads((ROOT / "knowledge" / "graph" / "relationships.json").read_text(encoding="utf-8"))
        graph = deepcopy(graph)
        graph["edges"][0]["to"] = "CWE-DOES-NOT-EXIST"
        with self.assertRaises(ContractValidationError):
            validate_contract("knowledge-graph", graph)

    def test_freshness_budget_identifies_due_sources(self) -> None:
        due = stale_source_ids(now=datetime(2027, 1, 1, tzinfo=timezone.utc))
        self.assertIn("cisa-kev", due)
        self.assertIn("portswigger-web-security-academy", due)


if __name__ == "__main__":
    unittest.main()
