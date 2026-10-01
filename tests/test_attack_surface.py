from copy import deepcopy
import unittest

from sechelix_core.attack_surface import (
    AttackSurfaceDiffError,
    diff_attack_surfaces,
    render_mermaid,
    validate_attack_surface,
)
from sechelix_core.contracts import ContractValidationError
from tests.helpers import attack_graph


class AttackSurfaceTests(unittest.TestCase):
    def test_graph_validates_and_mermaid_is_stable_and_escaped(self) -> None:
        graph = attack_graph()
        validate_attack_surface(graph)
        first = render_mermaid(graph)
        self.assertEqual(first, render_mermaid(graph))
        self.assertIn("API &#124; ingress", first)
        self.assertIn("Authorization &quot;guard&quot;", first)
        self.assertNotIn("N-API", first)

    def test_dangling_edge_is_rejected(self) -> None:
        graph = deepcopy(attack_graph())
        graph["edges"][0]["to"] = "N-MISSING"
        with self.assertRaises(ContractValidationError):
            validate_attack_surface(graph)

    def test_node_cannot_belong_to_multiple_boundaries(self) -> None:
        graph = deepcopy(attack_graph())
        graph["boundaries"].append(
            {"id": "B-DATA", "label": "Data", "node_ids": ["N-DATA"], "evidence_ids": ["EV-GRAPH"]}
        )
        with self.assertRaises(ContractValidationError):
            validate_attack_surface(graph)

    def test_attack_surface_diff_creates_hypotheses_for_new_structure(self) -> None:
        before = attack_graph()
        after = deepcopy(before)
        after["graph_id"] = "GRAPH-DEMO-2"
        after["nodes"].append(
            {
                "id": "N-WEBHOOK",
                "type": "ENTRYPOINT",
                "label": "Webhook receiver",
                "sensitivity": "PUBLIC",
                "evidence_ids": ["EV-WEBHOOK"],
            }
        )
        result = diff_attack_surfaces(before, after)
        self.assertTrue(result["changed"])
        self.assertEqual(result["material_change_count"], 1)
        self.assertEqual(result["sections"]["nodes"]["added"][0]["id"], "N-WEBHOOK")
        seeds = result["new_hypotheses"]
        self.assertEqual(len(seeds), 1)
        self.assertEqual(seeds[0]["status"], "NEW_HYPOTHESIS")
        self.assertEqual(seeds[0]["element_type"], "NODES")
        self.assertIn("not vulnerability evidence", seeds[0]["evidence_required"])

    def test_evidence_reference_churn_does_not_manufacture_new_surface(self) -> None:
        before = attack_graph()
        after = deepcopy(before)
        after["graph_id"] = "GRAPH-DEMO-2"
        after["nodes"][0]["evidence_ids"] = ["EV-REFRESHED"]
        after["edges"][0]["evidence_ids"] = ["EV-REFRESHED"]
        result = diff_attack_surfaces(before, after)
        self.assertFalse(result["changed"])
        self.assertEqual(result["material_change_count"], 0)
        self.assertEqual(result["new_hypotheses"], [])

    def test_authorization_matrix_change_becomes_hypothesis_not_finding(self) -> None:
        before = attack_graph()
        after = deepcopy(before)
        after["graph_id"] = "GRAPH-DEMO-2"
        after["role_object_actions"][0]["decision"] = "ALLOW"
        after["role_object_actions"][0].pop("condition")
        result = diff_attack_surfaces(before, after)
        seeds = result["new_hypotheses"]
        self.assertEqual(len(seeds), 1)
        self.assertEqual(seeds[0]["element_type"], "ROLE_OBJECT_ACTIONS")
        self.assertEqual(seeds[0]["change"], "CHANGED")
        self.assertNotIn("VERIFIED", seeds[0].values())

    def test_new_unknown_is_security_work_not_a_clean_result(self) -> None:
        before = attack_graph()
        after = deepcopy(before)
        after["graph_id"] = "GRAPH-DEMO-2"
        after["unknowns"].append("Webhook signing policy has not been mapped.")
        result = diff_attack_surfaces(before, after)
        self.assertEqual(result["unknowns"]["added"], ["Webhook signing policy has not been mapped."])
        self.assertEqual(result["new_hypotheses"][0]["element_type"], "UNKNOWN")

    def test_different_scope_ids_cannot_be_compared(self) -> None:
        before = attack_graph()
        after = deepcopy(before)
        after["scope_id"] = "SCOPE-OTHER"
        with self.assertRaisesRegex(AttackSurfaceDiffError, "share scope_id"):
            diff_attack_surfaces(before, after)

    def test_diff_is_deterministic(self) -> None:
        before = attack_graph()
        after = deepcopy(before)
        after["graph_id"] = "GRAPH-DEMO-2"
        after["nodes"][0]["label"] = "Public API ingress"
        self.assertEqual(
            diff_attack_surfaces(before, after),
            diff_attack_surfaces(before, after),
        )


if __name__ == "__main__":
    unittest.main()
