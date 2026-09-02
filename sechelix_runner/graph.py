"""The reasoner graph.

A run is a directed acyclic graph of nodes. Which nodes exist is decided by
applicability against the target, not by a fixed pipeline -- a repository with no
web surface has no ``BROWSER`` node, and that absence is a recorded routing
decision rather than a silently empty stage.

Two properties this module is responsible for.

**Determinism.** The same graph must produce the same execution order on every
machine and every replay. A topological sort alone does not give that: whenever
several nodes are simultaneously ready, the order depends on set iteration.
:meth:`ReasonerGraph.topological_order` breaks every tie on ``node_id`` so the
order is a property of the graph rather than of the interpreter.

**Refusal to run a graph that cannot be trusted.** A cycle, a dependency on a
node that does not exist, or a duplicate id are all rejected before anything
executes, with the offending path named. A cycle discovered halfway through a
run has already spent budget.
"""

from __future__ import annotations

from dataclasses import dataclass

from .roles import NodeRole


class GraphError(ValueError):
    """The graph is not executable. Raised before any node runs."""


@dataclass(frozen=True)
class GraphNode:
    """One planned unit of work.

    ``mandatory`` is the field the release gate cares about. A mandatory node
    that does not reach a satisfied state means the run cannot make a clean
    claim, however good the findings from the other lanes were.
    """

    node_id: str
    role: NodeRole
    depends_on: tuple[str, ...] = ()
    mandatory: bool = False
    node_version: str = "1.0.0"
    #: Why this node is in the graph, copied into the routing log.
    reason: str = ""


class ReasonerGraph:
    """A validated set of nodes and their dependencies."""

    def __init__(self, nodes: list[GraphNode]) -> None:
        self._nodes: dict[str, GraphNode] = {}
        for node in nodes:
            if node.node_id in self._nodes:
                raise GraphError(f"duplicate node id: {node.node_id!r}")
            self._nodes[node.node_id] = node
        self._validate_dependencies()
        self._reject_cycles()

    # -- construction checks -------------------------------------------------

    def _validate_dependencies(self) -> None:
        for node in self._nodes.values():
            for parent in node.depends_on:
                if parent == node.node_id:
                    raise GraphError(f"node {node.node_id!r} depends on itself")
                if parent not in self._nodes:
                    raise GraphError(
                        f"node {node.node_id!r} depends on unknown node {parent!r}"
                    )

    def _reject_cycles(self) -> None:
        """Depth-first three-colour search, reporting the cycle it found.

        A bare "graph has a cycle" is not actionable on a graph with twenty
        nodes, so the offending path is reconstructed and named.
        """
        white, grey, black = 0, 1, 2
        colour = {node_id: white for node_id in self._nodes}
        stack: list[str] = []

        def visit(node_id: str) -> None:
            colour[node_id] = grey
            stack.append(node_id)
            for parent in sorted(self._nodes[node_id].depends_on):
                if colour[parent] == grey:
                    cycle = stack[stack.index(parent) :] + [parent]
                    raise GraphError("dependency cycle: " + " -> ".join(cycle))
                if colour[parent] == white:
                    visit(parent)
            stack.pop()
            colour[node_id] = black

        for node_id in sorted(self._nodes):
            if colour[node_id] == white:
                visit(node_id)

    # -- reading -------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, node_id: object) -> bool:
        return node_id in self._nodes

    def __getitem__(self, node_id: str) -> GraphNode:
        return self._nodes[node_id]

    @property
    def node_ids(self) -> list[str]:
        return sorted(self._nodes)

    @property
    def nodes(self) -> list[GraphNode]:
        return [self._nodes[node_id] for node_id in self.node_ids]

    @property
    def mandatory_node_ids(self) -> list[str]:
        return sorted(n.node_id for n in self._nodes.values() if n.mandatory)

    def _dependents(self) -> dict[str, list[str]]:
        dependents: dict[str, list[str]] = {node_id: [] for node_id in self._nodes}
        for node in self._nodes.values():
            for parent in node.depends_on:
                dependents[parent].append(node.node_id)
        return dependents

    def topological_order(self) -> list[str]:
        """A deterministic execution order: dependencies before dependents.

        Ties are broken on ``node_id`` so the order is reproducible across
        processes and platforms.
        """
        indegree = {
            node_id: len(set(self._nodes[node_id].depends_on)) for node_id in self._nodes
        }
        dependents = self._dependents()

        ready = sorted(n for n, d in indegree.items() if d == 0)
        order: list[str] = []
        while ready:
            node_id = ready.pop(0)
            order.append(node_id)
            for child in sorted(dependents[node_id]):
                indegree[child] -= 1
                if indegree[child] == 0:
                    ready.append(child)
            ready.sort()

        if len(order) != len(self._nodes):
            raise GraphError("graph is not acyclic")
        return order

    def ready_nodes(self, satisfied: set[str], done: set[str]) -> list[str]:
        """Nodes whose dependencies are all satisfied and which have not run.

        ``satisfied`` and ``done`` are separate arguments because they answer
        different questions: a node that FAILED is done but not satisfied, and
        its dependents must not run on evidence that was never produced.
        """
        return sorted(
            node_id
            for node_id, node in self._nodes.items()
            if node_id not in done and set(node.depends_on) <= satisfied
        )

    def blocked_by(self, node_id: str, satisfied: set[str]) -> list[str]:
        """Which dependencies of ``node_id`` are not satisfied."""
        return sorted(set(self._nodes[node_id].depends_on) - satisfied)

    def descendants(self, node_id: str) -> set[str]:
        """Every node downstream of ``node_id``.

        Used when a node does not deliver: everything that needed its evidence
        is transitively BLOCKED, and each one still gets its own record.
        """
        dependents = self._dependents()
        seen: set[str] = set()
        stack = list(dependents[node_id])
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack.extend(dependents[current])
        return seen
