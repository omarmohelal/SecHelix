import unittest

from sechelix_runner.graph import GraphError, GraphNode, ReasonerGraph
from sechelix_runner.roles import NodeRole


def _pipeline() -> ReasonerGraph:
    return ReasonerGraph(
        [
            GraphNode("gate", NodeRole.RELEASE_GATE, ("verify",), mandatory=True),
            GraphNode("verify", NodeRole.INDEPENDENT_VERIFIER, ("authz", "bl"), mandatory=True),
            GraphNode("authz", NodeRole.AUTHORIZATION, ("map",)),
            GraphNode("bl", NodeRole.BUSINESS_LOGIC, ("map",)),
            GraphNode("map", NodeRole.MAPPER, (), mandatory=True),
        ]
    )


class GraphConstructionTests(unittest.TestCase):
    def test_rejects_two_node_cycle_and_names_the_path(self) -> None:
        with self.assertRaises(GraphError) as caught:
            ReasonerGraph(
                [
                    GraphNode("a", NodeRole.MAPPER, ("b",)),
                    GraphNode("b", NodeRole.MAPPER, ("a",)),
                ]
            )
        self.assertIn("cycle", str(caught.exception))
        self.assertIn("->", str(caught.exception))

    def test_rejects_longer_cycle(self) -> None:
        with self.assertRaises(GraphError):
            ReasonerGraph(
                [
                    GraphNode("a", NodeRole.MAPPER, ("c",)),
                    GraphNode("b", NodeRole.MAPPER, ("a",)),
                    GraphNode("c", NodeRole.MAPPER, ("b",)),
                ]
            )

    def test_rejects_self_dependency(self) -> None:
        with self.assertRaises(GraphError):
            ReasonerGraph([GraphNode("a", NodeRole.MAPPER, ("a",))])

    def test_rejects_unknown_dependency(self) -> None:
        with self.assertRaises(GraphError):
            ReasonerGraph([GraphNode("a", NodeRole.MAPPER, ("ghost",))])

    def test_rejects_duplicate_node_id(self) -> None:
        with self.assertRaises(GraphError):
            ReasonerGraph(
                [GraphNode("a", NodeRole.MAPPER), GraphNode("a", NodeRole.AUTHORIZATION)]
            )


class GraphOrderingTests(unittest.TestCase):
    def test_dependencies_precede_dependents(self) -> None:
        order = _pipeline().topological_order()
        self.assertLess(order.index("map"), order.index("authz"))
        self.assertLess(order.index("authz"), order.index("verify"))
        self.assertLess(order.index("verify"), order.index("gate"))

    def test_order_is_deterministic_across_constructions(self) -> None:
        """Ties broken on node_id, so the order is a property of the graph."""
        expected = _pipeline().topological_order()
        for _ in range(25):
            self.assertEqual(ReasonerGraph(_pipeline().nodes).topological_order(), expected)

    def test_sibling_ties_break_on_node_id(self) -> None:
        graph = ReasonerGraph(
            [
                GraphNode("root", NodeRole.MAPPER),
                GraphNode("zeta", NodeRole.AUTHORIZATION, ("root",)),
                GraphNode("alpha", NodeRole.BUSINESS_LOGIC, ("root",)),
            ]
        )
        self.assertEqual(graph.topological_order(), ["root", "alpha", "zeta"])


class GraphQueryTests(unittest.TestCase):
    def test_mandatory_nodes_are_reported(self) -> None:
        self.assertEqual(_pipeline().mandatory_node_ids, ["gate", "map", "verify"])

    def test_descendants_are_transitive(self) -> None:
        self.assertEqual(
            sorted(_pipeline().descendants("map")), ["authz", "bl", "gate", "verify"]
        )

    def test_leaf_has_no_descendants(self) -> None:
        self.assertEqual(_pipeline().descendants("gate"), set())

    def test_ready_nodes_requires_all_dependencies_satisfied(self) -> None:
        graph = _pipeline()
        self.assertEqual(graph.ready_nodes(set(), set()), ["map"])
        self.assertNotIn("verify", graph.ready_nodes({"map", "authz"}, {"map", "authz"}))

    def test_blocked_by_names_the_missing_dependency(self) -> None:
        self.assertEqual(_pipeline().blocked_by("verify", {"authz"}), ["bl"])


if __name__ == "__main__":
    unittest.main()
