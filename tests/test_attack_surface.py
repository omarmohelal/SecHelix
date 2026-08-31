from copy import deepcopy
import unittest

from sechelix_core.attack_surface import render_mermaid, validate_attack_surface
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


if __name__ == "__main__":
    unittest.main()
