"""The authority graph of an agent: who can reach what, through which server.

An agent with tools is a deputy holding somebody's credentials and deciding what
to do with them by reading text. Reviewing one by reading its prompt is reviewing
the wrong artifact. The reviewable artifact is the graph:

``Agent -> MCP Server -> Tool / Resource / Prompt -> Permission -> Data -> External System``

Everything interesting is a property of that graph. Excessive authority is a tool
in the run that the task never needed. A confused deputy is a path from something
a stranger can write to something the operator's credential can do. Exfiltration
is a path from data to a destination somebody else observes. None of those are
visible in a prompt, and all of them are visible in edges.

Four rules.

**Every detection is a HYPOTHESIS, and says so in its own record.** This graph is
assembled from *declarations* — config files, tool manifests, code that registers
handlers. A declared edge is not a demonstrated call. Runtime reachability is
recorded as ``UNPROVEN`` on every finding, and each one carries what evidence
would establish it and what evidence would refute it, so the next step is a task
rather than an argument.

**A declared control never silences a detection, and MCP annotations least of
all.** The MCP specification is explicit that ``readOnlyHint``,
``destructiveHint``, ``idempotentHint`` and ``openWorldHint`` are hints, are not
guaranteed to reflect actual behaviour, and that clients "should never make
critical tool-use decisions based on annotations received from untrusted servers".
A privilege tier read off an annotation is a tier the *server* defines. So
annotations are recorded on the detection and are never consulted to produce one.
The only thing an annotation can do here is *raise* a hypothesis — when a server
claims ``readOnlyHint`` for a tool the operator declared with a write permission,
the disagreement is itself worth reporting. Operator-declared controls are treated
the same way: recorded as ``declared_controls``, never as a refutation, because a
declaration is what this module reads and it cannot check itself.

**Tool identity is (server, name, definition).** A bare name is not an identity in
a host that merges several servers into one namespace, and an approval keyed on a
name survives a definition change it should not have survived.

**No severity is assigned here.** Severity is a judgement about impact in a
deployment, and this module has a declaration file. It emits paths and the
evidence that would settle them; the severity vocabulary lives in the finding
contract, downstream, where a verifier has been.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

SCHEMA_VERSION = "1.0"

HYPOTHESIS = "HYPOTHESIS"
DECLARATION = "DECLARATION"
UNPROVEN = "UNPROVEN"

#: Node kinds in the authority graph.
AGENT = "AGENT"
MCP_SERVER = "MCP_SERVER"
TOOL = "TOOL"
RESOURCE = "RESOURCE"
PROMPT = "PROMPT"
PERMISSION = "PERMISSION"
DATA = "DATA"
EXTERNAL_SYSTEM = "EXTERNAL_SYSTEM"
INPUT_SOURCE = "INPUT_SOURCE"
SECRET_REFERENCE = "SECRET_REFERENCE"

NODE_KINDS = (
    AGENT, MCP_SERVER, TOOL, RESOURCE, PROMPT,
    PERMISSION, DATA, EXTERNAL_SYSTEM, INPUT_SOURCE, SECRET_REFERENCE,
)

#: What a permission lets a tool do.
ACTIONS = ("READ", "WRITE", "DELETE", "EXECUTE", "NETWORK", "SPAWN_AGENT")

#: Actions that change state. A read-only *return value* says nothing about this:
#: a tool whose arguments reach a network destination writes to that destination.
WRITE_ACTIONS = frozenset({"WRITE", "DELETE", "EXECUTE", "SPAWN_AGENT"})

#: Actions with no bounded recovery path, absent an explicit override.
IRREVERSIBLE_ACTIONS = frozenset({"DELETE", "EXECUTE", "SPAWN_AGENT"})

#: Credential the tool call executes with.
CREDENTIAL_SCOPES = ("RUN_PRINCIPAL", "AMBIENT", "UNKNOWN")

TRUST_LEVELS = ("OPERATOR", "UNTRUSTED", "UNKNOWN")
SENSITIVITIES = ("PUBLIC", "INTERNAL", "RESTRICTED", "UNKNOWN")
YES_NO_UNKNOWN = ("YES", "NO", "UNKNOWN")

#: Where the host renders server-supplied text.
DESCRIPTION_CHANNELS = ("INSTRUCTION", "DATA", "UNKNOWN")

#: Confirmation quality for an irreversible action, in the host's own words.
CONFIRMATIONS = ("NONE", "IN_BAND", "OUT_OF_BAND_BOUND", "UNKNOWN")

FLOW_KINDS = ("ARGUMENT", "RESULT", "CONTEXT")

#: Annotation keys defined by the MCP specification. Listed so the record can
#: state exactly what it carried and refused to act on.
ANNOTATION_HINT_KEYS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")

#: Instruction-shaped phrasings in server-supplied text. A description exists to
#: tell the model when to call a tool, so it is instruction text by construction;
#: these are the phrasings that try to steer the *rest* of the run. Deliberately
#: a small, readable list — this is a hypothesis generator, not a filter, and a
#: benign description can match. The absence of a match refutes nothing.
_POISONING_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("override", re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|earlier|above)\b")),
    ("mandatory_call", re.compile(r"(?i)\b(?:always|must|you\s+must)\s+call\b")),
    ("ordering", re.compile(r"(?i)\bbefore\s+(?:using|calling)\s+any\s+other\b")),
    ("secrecy", re.compile(r"(?i)\b(?:do\s+not|don't|never)\s+(?:tell|mention|reveal|show)\b")),
    ("data_pull", re.compile(r"(?i)\bpass\s+the\s+(?:contents|output|result)\b")),
    ("channel_marker", re.compile(r"(?i)<\s*(?:important|system|instructions?)\s*>")),
    ("role_claim", re.compile(r"(?i)\b(?:system|developer)\s*(?:prompt|message)\s*[:=]")),
)


class McpGraphError(ValueError):
    """The declared graph is internally inconsistent."""


# ---------------------------------------------------------------------------
# Declared entities
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Agent:
    agent_id: str
    name: str
    purpose: str = ""
    server_ids: tuple[str, ...] = ()
    #: Actions the task actually needs. Empty means nobody wrote it down, which is
    #: itself the finding: authority the run never bounded.
    required_actions: tuple[str, ...] = ()
    #: Whether the dispatcher narrows authority when third-party content is in
    #: context. Recorded as declared; never treated as demonstrated.
    provenance_control: str = "UNKNOWN"


@dataclass(frozen=True)
class Server:
    server_id: str
    name: str
    transport: str = "UNKNOWN"
    operator_controlled: str = "UNKNOWN"
    #: Where the host renders this server's descriptions and annotations.
    description_channel: str = "UNKNOWN"


@dataclass(frozen=True)
class Tool:
    tool_id: str
    server_id: str
    name: str
    description: str = ""
    permission_ids: tuple[str, ...] = ()
    #: External systems this tool's arguments or effects reach.
    reaches: tuple[str, ...] = ()
    confirmation: str = "UNKNOWN"
    #: Server-supplied hints. Recorded in the output, consulted by nothing that
    #: decides whether a detection fires. See the module docstring.
    annotations: Mapping[str, Any] = field(default_factory=dict)

    @property
    def identity(self) -> tuple[str, str]:
        """(server, name). A bare name is not an identity in a merged namespace."""
        return (self.server_id, self.name)


@dataclass(frozen=True)
class Resource:
    resource_id: str
    server_id: str
    name: str
    description: str = ""
    data_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Prompt:
    prompt_id: str
    server_id: str
    name: str
    description: str = ""


@dataclass(frozen=True)
class Permission:
    permission_id: str
    action: str
    label: str = ""
    data_id: str = ""
    credential_scope: str = "UNKNOWN"
    #: Override the default reversibility of the action when the deployment knows
    #: better. ``None`` means "use the action's default".
    irreversible: bool | None = None

    @property
    def is_write(self) -> bool:
        return self.action in WRITE_ACTIONS

    @property
    def is_irreversible(self) -> bool:
        if self.irreversible is not None:
            return self.irreversible
        return self.action in IRREVERSIBLE_ACTIONS


@dataclass(frozen=True)
class DataStore:
    data_id: str
    name: str
    sensitivity: str = "UNKNOWN"


@dataclass(frozen=True)
class ExternalSystem:
    system_id: str
    name: str
    operator_controlled: str = "UNKNOWN"


@dataclass(frozen=True)
class InputSource:
    source_id: str
    name: str
    trust: str = "UNKNOWN"


@dataclass(frozen=True)
class SecretRef:
    secret_id: str
    name: str
    location: str = ""


@dataclass(frozen=True)
class Flow:
    flow_id: str
    source: str
    target: str
    kind: str = "CONTEXT"
    note: str = ""


# ---------------------------------------------------------------------------
# The graph
# ---------------------------------------------------------------------------


class PermissionGraph:
    """Declared agent authority, assembled into something that can be walked."""

    def __init__(self, graph_id: str) -> None:
        self.graph_id = graph_id
        self.agents: dict[str, Agent] = {}
        self.servers: dict[str, Server] = {}
        self.tools: dict[str, Tool] = {}
        self.resources: dict[str, Resource] = {}
        self.prompts: dict[str, Prompt] = {}
        self.permissions: dict[str, Permission] = {}
        self.data: dict[str, DataStore] = {}
        self.external: dict[str, ExternalSystem] = {}
        self.inputs: dict[str, InputSource] = {}
        self.secrets: dict[str, SecretRef] = {}
        self.flows: list[Flow] = []
        self._ids: dict[str, str] = {}

    # -- construction ---------------------------------------------------------

    def _claim(self, node_id: str, kind: str) -> str:
        if not node_id:
            raise McpGraphError("every node needs an id")
        if node_id in self._ids:
            raise McpGraphError(
                f"id {node_id!r} is already used by a {self._ids[node_id]} node; ids are "
                "the only thing edges refer to and must be unique across kinds"
            )
        self._ids[node_id] = kind
        return node_id

    def add_agent(self, agent: Agent) -> Agent:
        self._claim(agent.agent_id, AGENT)
        self.agents[agent.agent_id] = agent
        return agent

    def add_server(self, server: Server) -> Server:
        self._claim(server.server_id, MCP_SERVER)
        self.servers[server.server_id] = server
        return server

    def add_tool(self, tool: Tool) -> Tool:
        self._claim(tool.tool_id, TOOL)
        self.tools[tool.tool_id] = tool
        return tool

    def add_resource(self, resource: Resource) -> Resource:
        self._claim(resource.resource_id, RESOURCE)
        self.resources[resource.resource_id] = resource
        return resource

    def add_prompt(self, prompt: Prompt) -> Prompt:
        self._claim(prompt.prompt_id, PROMPT)
        self.prompts[prompt.prompt_id] = prompt
        return prompt

    def add_permission(self, permission: Permission) -> Permission:
        if permission.action not in ACTIONS:
            raise McpGraphError(
                f"unknown action {permission.action!r}; choose from {list(ACTIONS)}"
            )
        self._claim(permission.permission_id, PERMISSION)
        self.permissions[permission.permission_id] = permission
        return permission

    def add_data(self, store: DataStore) -> DataStore:
        self._claim(store.data_id, DATA)
        self.data[store.data_id] = store
        return store

    def add_external(self, system: ExternalSystem) -> ExternalSystem:
        self._claim(system.system_id, EXTERNAL_SYSTEM)
        self.external[system.system_id] = system
        return system

    def add_input_source(self, source: InputSource) -> InputSource:
        if source.trust not in TRUST_LEVELS:
            raise McpGraphError(f"unknown trust level {source.trust!r}")
        self._claim(source.source_id, INPUT_SOURCE)
        self.inputs[source.source_id] = source
        return source

    def add_secret(self, secret: SecretRef) -> SecretRef:
        self._claim(secret.secret_id, SECRET_REFERENCE)
        self.secrets[secret.secret_id] = secret
        return secret

    def add_flow(self, flow: Flow) -> Flow:
        if flow.kind not in FLOW_KINDS:
            raise McpGraphError(f"unknown flow kind {flow.kind!r}")
        for endpoint in (flow.source, flow.target):
            if endpoint not in self._ids:
                raise McpGraphError(f"flow {flow.flow_id!r} refers to unknown node {endpoint!r}")
        self.flows.append(flow)
        return flow

    # -- derived views --------------------------------------------------------

    def kind_of(self, node_id: str) -> str:
        return self._ids.get(node_id, "UNKNOWN")

    def tools_for_agent(self, agent: Agent) -> list[Tool]:
        """Every tool reachable through the servers this agent connects to."""
        servers = set(agent.server_ids)
        return [t for t in self.tools.values() if t.server_id in servers]

    def permissions_for_tool(self, tool: Tool) -> list[Permission]:
        return [self.permissions[p] for p in tool.permission_ids if p in self.permissions]

    def agents_for_tool(self, tool: Tool) -> list[Agent]:
        return [a for a in self.agents.values() if tool.server_id in a.server_ids]

    def _adjacency(self) -> dict[str, list[tuple[str, str]]]:
        """Directed edges a value can travel along, as (target, edge label)."""
        edges: dict[str, list[tuple[str, str]]] = {node: [] for node in self._ids}
        for tool in self.tools.values():
            for permission in self.permissions_for_tool(tool):
                if permission.data_id and permission.data_id in self.data:
                    if permission.action == "READ":
                        edges[permission.data_id].append((tool.tool_id, "READ_BY"))
                    else:
                        edges[tool.tool_id].append((permission.data_id, permission.action))
            for system_id in tool.reaches:
                if system_id in self.external:
                    edges[tool.tool_id].append((system_id, "REACHES"))
        for flow in self.flows:
            edges[flow.source].append((flow.target, flow.kind))
        return edges

    def _paths_to(
        self,
        start: str,
        predicate,
        *,
        limit: int = 64,
    ) -> list[list[str]]:
        """Breadth-first search for simple paths from ``start`` to matching nodes."""
        edges = self._adjacency()
        found: list[list[str]] = []
        queue: list[list[str]] = [[start]]
        while queue and len(found) < limit:
            path = queue.pop(0)
            for target, _label in edges.get(path[-1], ()):
                if target in path:
                    continue
                extended = path + [target]
                if predicate(target):
                    found.append(extended)
                    continue
                queue.append(extended)
        return found


# ---------------------------------------------------------------------------
# Export forms
# ---------------------------------------------------------------------------


def to_graph(graph: PermissionGraph) -> dict[str, Any]:
    """Nodes and edges, in the shape a renderer or another tool can consume."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    def node(node_id: str, kind: str, label: str, **attributes: Any) -> None:
        nodes.append({"id": node_id, "kind": kind, "label": label,
                      "attributes": {k: v for k, v in attributes.items()}})

    def edge(source: str, target: str, kind: str, label: str = "") -> None:
        edges.append({"id": f"E-{len(edges) + 1:04d}", "from": source, "to": target,
                      "kind": kind, "label": label})

    for agent in graph.agents.values():
        node(agent.agent_id, AGENT, agent.name,
             purpose=agent.purpose,
             required_actions=list(agent.required_actions),
             provenance_control=agent.provenance_control)
        for server_id in agent.server_ids:
            if server_id in graph.servers:
                edge(agent.agent_id, server_id, "CONNECTS_TO")

    for server in graph.servers.values():
        node(server.server_id, MCP_SERVER, server.name,
             transport=server.transport,
             operator_controlled=server.operator_controlled,
             description_channel=server.description_channel)

    for tool in graph.tools.values():
        node(tool.tool_id, TOOL, tool.name,
             server_id=tool.server_id,
             confirmation=tool.confirmation,
             server_supplied_hints=dict(tool.annotations))
        if tool.server_id in graph.servers:
            edge(tool.server_id, tool.tool_id, "EXPOSES")
        for permission_id in tool.permission_ids:
            if permission_id in graph.permissions:
                edge(tool.tool_id, permission_id, "GRANTED")
        for system_id in tool.reaches:
            if system_id in graph.external:
                edge(tool.tool_id, system_id, "REACHES")

    for resource in graph.resources.values():
        node(resource.resource_id, RESOURCE, resource.name, server_id=resource.server_id)
        if resource.server_id in graph.servers:
            edge(resource.server_id, resource.resource_id, "EXPOSES")
        for data_id in resource.data_ids:
            if data_id in graph.data:
                edge(resource.resource_id, data_id, "EXPOSES_DATA")

    for prompt in graph.prompts.values():
        node(prompt.prompt_id, PROMPT, prompt.name, server_id=prompt.server_id)
        if prompt.server_id in graph.servers:
            edge(prompt.server_id, prompt.prompt_id, "EXPOSES")

    for permission in graph.permissions.values():
        node(permission.permission_id, PERMISSION, permission.label or permission.action,
             action=permission.action,
             credential_scope=permission.credential_scope,
             write=permission.is_write,
             irreversible=permission.is_irreversible)
        if permission.data_id and permission.data_id in graph.data:
            edge(permission.permission_id, permission.data_id, "ACTS_ON", permission.action)

    for store in graph.data.values():
        node(store.data_id, DATA, store.name, sensitivity=store.sensitivity)

    for system in graph.external.values():
        node(system.system_id, EXTERNAL_SYSTEM, system.name,
             operator_controlled=system.operator_controlled)

    for source in graph.inputs.values():
        node(source.source_id, INPUT_SOURCE, source.name, trust=source.trust)

    for secret in graph.secrets.values():
        node(secret.secret_id, SECRET_REFERENCE, secret.name, location=secret.location)

    for flow in graph.flows:
        edge(flow.source, flow.target, f"FLOWS_{flow.kind}", flow.note)

    return {"nodes": nodes, "edges": edges}


_MERMAID_UNSAFE = re.compile(r'["\n\r]')


def to_mermaid(graph_form: Mapping[str, Any]) -> str:
    """Render nodes and edges as a Mermaid flowchart.

    Ids are rewritten to ``N0…Nn`` because a declared node id can contain
    characters Mermaid reads as syntax, and a diagram that silently fails to parse
    is worse than no diagram.
    """
    alias = {node["id"]: f"N{index}" for index, node in enumerate(graph_form.get("nodes", []))}
    lines = ["flowchart LR"]
    for node in graph_form.get("nodes", []):
        label = _MERMAID_UNSAFE.sub(" ", f"{node['kind']}: {node['label']}")
        lines.append(f'    {alias[node["id"]]}["{label}"]')
    for edge in graph_form.get("edges", []):
        source, target = alias.get(edge["from"]), alias.get(edge["to"])
        if not source or not target:
            continue
        label = _MERMAID_UNSAFE.sub(" ", edge.get("label") or edge["kind"])
        lines.append(f'    {source} -->|"{label}"| {target}')
    return "\n".join(lines) + "\n"


def to_permission_matrix(graph: PermissionGraph) -> dict[str, Any]:
    """One row per (agent, tool); one column per declared permission."""
    columns = sorted(graph.permissions)
    rows: list[dict[str, Any]] = []
    for agent in sorted(graph.agents.values(), key=lambda a: a.agent_id):
        for tool in sorted(graph.tools_for_agent(agent), key=lambda t: t.tool_id):
            granted = {p.permission_id: p for p in graph.permissions_for_tool(tool)}
            rows.append({
                "agent_id": agent.agent_id,
                "server_id": tool.server_id,
                "tool_id": tool.tool_id,
                "tool_name": tool.name,
                "cells": [granted[c].action if c in granted else "NONE" for c in columns],
                "write": any(p.is_write for p in granted.values()),
                "irreversible": any(p.is_irreversible for p in granted.values()),
                "credential_scopes": sorted({p.credential_scope for p in granted.values()}) or ["UNKNOWN"],
                "confirmation": tool.confirmation,
            })
    return {"columns": columns, "rows": rows}


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def _hints(tool: Tool) -> dict[str, Any]:
    """The server's own claims about a tool, for the record only."""
    return {key: tool.annotations[key] for key in ANNOTATION_HINT_KEYS if key in tool.annotations}


class _Detections:
    """Accumulator that stamps the invariant fields on every entry."""

    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def add(
        self,
        kind: str,
        *,
        statement: str,
        node_ids: Sequence[str],
        path: Sequence[str] = (),
        evidence_required: Sequence[str] = (),
        refuted_if: Sequence[str] = (),
        declared_controls: Sequence[str] = (),
        server_supplied_hints: Mapping[str, Any] | None = None,
    ) -> None:
        self.items.append({
            "detection_id": f"MCP-H-{len(self.items) + 1:04d}",
            "kind": kind,
            # Not a severity, not a confidence, and not a finding. The graph came
            # from declarations, so the honest status is the same for all of them.
            "status": HYPOTHESIS,
            "basis": DECLARATION,
            "runtime_reachability": UNPROVEN,
            "node_ids": list(node_ids),
            "path": list(path),
            "statement": statement,
            "evidence_required": list(evidence_required),
            "refuted_if": list(refuted_if),
            "declared_controls": list(declared_controls),
            "server_supplied_hints": dict(server_supplied_hints or {}),
        })


def detect(graph: PermissionGraph) -> list[dict[str, Any]]:
    """Every hypothesis the declared graph supports. Nothing here is a finding."""
    out = _Detections()
    _detect_excessive_authority(graph, out)
    _detect_unsafe_write(graph, out)
    _detect_confused_deputy(graph, out)
    _detect_argument_injection(graph, out)
    _detect_secret_propagation(graph, out)
    _detect_description_poisoning(graph, out)
    _detect_server_text_channel(graph, out)
    _detect_cross_tool_exfiltration(graph, out)
    _detect_annotation_contradiction(graph, out)
    return out.items


def _detect_excessive_authority(graph: PermissionGraph, out: _Detections) -> None:
    for agent in sorted(graph.agents.values(), key=lambda a: a.agent_id):
        required = set(agent.required_actions)
        for tool in sorted(graph.tools_for_agent(agent), key=lambda t: t.tool_id):
            for permission in graph.permissions_for_tool(tool):
                if not permission.is_write and permission.action != "NETWORK":
                    continue
                if required and permission.action in required:
                    continue
                if required:
                    statement = (
                        f"{agent.name} reaches {tool.name} on {tool.server_id}, which is granted "
                        f"{permission.action}. The agent declares it requires "
                        f"{sorted(required)}, so this authority is surplus to the task."
                    )
                else:
                    statement = (
                        f"{agent.name} reaches {tool.name} on {tool.server_id}, which is granted "
                        f"{permission.action}. The agent declares no required action set, so "
                        "nothing bounds the run's authority to the task it was given."
                    )
                out.add(
                    "EXCESSIVE_AUTHORITY",
                    statement=statement,
                    node_ids=[agent.agent_id, tool.tool_id, permission.permission_id],
                    path=[agent.agent_id, tool.server_id, tool.tool_id, permission.permission_id],
                    evidence_required=[
                        "The dispatcher's reachable tool set for one real run, from the call log "
                        "rather than the configuration.",
                        "The credential the tool executes with, read at the tool rather than "
                        "inferred from the manifest.",
                    ],
                    refuted_if=[
                        "A per-run allowlist enforced in the dispatcher against the resolved tool "
                        "identity (server, name, definition digest) excludes this tool.",
                        "The permission is scoped to the run principal and the principal already "
                        "holds it independently of the agent.",
                    ],
                    declared_controls=[f"credential_scope={permission.credential_scope}"],
                    server_supplied_hints=_hints(tool),
                )


def _detect_unsafe_write(graph: PermissionGraph, out: _Detections) -> None:
    for tool in sorted(graph.tools.values(), key=lambda t: t.tool_id):
        irreversible = [p for p in graph.permissions_for_tool(tool) if p.is_irreversible]
        if not irreversible or tool.confirmation == "OUT_OF_BAND_BOUND":
            continue
        out.add(
            "UNSAFE_WRITE_CAPABILITY",
            statement=(
                f"{tool.name} on {tool.server_id} holds "
                f"{sorted(p.action for p in irreversible)} with confirmation "
                f"{tool.confirmation!r}. An irreversible action with no confirmation bound to "
                "the canonicalised arguments is reachable by whatever the model decides to emit."
            ),
            node_ids=[tool.tool_id, *(p.permission_id for p in irreversible)],
            evidence_required=[
                "The executor's signature: whether it runs a stored approved proposal or the "
                "model's current step.",
                "Whether the confirmation travels a channel the run can write to.",
            ],
            refuted_if=[
                "Approval is bound to a digest of the canonicalised action, consumed on use, and "
                "the executor runs the stored proposal.",
                "The tool's own authorization refuses the action for the run principal, shown at "
                "the tool.",
            ],
            declared_controls=[f"confirmation={tool.confirmation}"],
            server_supplied_hints=_hints(tool),
        )


def _detect_confused_deputy(graph: PermissionGraph, out: _Detections) -> None:
    privileged = {
        tool.tool_id
        for tool in graph.tools.values()
        if any(p.is_write for p in graph.permissions_for_tool(tool))
    }
    for source in sorted(graph.inputs.values(), key=lambda s: s.source_id):
        if source.trust == "OPERATOR":
            continue
        for path in graph._paths_to(source.source_id, lambda n: n in privileged):
            tool = graph.tools[path[-1]]
            agents = graph.agents_for_tool(tool)
            controls = sorted({f"provenance_control={a.provenance_control}" for a in agents})
            trust_note = (
                "is third-party writable" if source.trust == "UNTRUSTED"
                else "has no recorded set of writers, so it cannot be assumed operator-only"
            )
            out.add(
                "CONFUSED_DEPUTY",
                statement=(
                    f"{source.name} {trust_note}, and a declared path carries it to {tool.name} "
                    f"on {tool.server_id}, which holds a state-changing permission. The privilege "
                    "comes from the operator and the instruction from somewhere else."
                ),
                node_ids=[source.source_id, tool.tool_id],
                path=path,
                evidence_required=[
                    "The assembled context for one run, with every segment annotated by who can "
                    "write it.",
                    "A call log across repeated runs, not a transcript: a narration is not an "
                    "invocation.",
                ],
                refuted_if=[
                    "Content origin reaches the dispatcher and the dispatcher narrows authority "
                    "for a step reached from third-party content.",
                    "The only writers of this source are principals already entitled to instruct "
                    "the agent, shown from the write path.",
                    "The tool's effect is within what the run principal already holds.",
                ],
                declared_controls=controls,
                server_supplied_hints=_hints(tool),
            )


def _detect_argument_injection(graph: PermissionGraph, out: _Detections) -> None:
    for flow in graph.flows:
        if flow.kind != "ARGUMENT" or graph.kind_of(flow.target) != TOOL:
            continue
        source_kind = graph.kind_of(flow.source)
        if source_kind == INPUT_SOURCE and graph.inputs[flow.source].trust == "OPERATOR":
            continue
        if source_kind not in (INPUT_SOURCE, DATA, TOOL, RESOURCE):
            continue
        tool = graph.tools[flow.target]
        destinations = [s for s in tool.reaches if s in graph.external]
        out.add(
            "TOOL_ARGUMENT_INJECTION",
            statement=(
                f"Content from {flow.source} is declared to reach an argument of {tool.name} on "
                f"{tool.server_id}"
                + (
                    f", whose arguments reach {sorted(destinations)}. The argument is the payload: "
                    "classifying a tool as safe by what it returns ignores where its arguments go."
                    if destinations else
                    ". Whether that argument is interpreted depends on the tool's own sink, which "
                    "this graph does not describe."
                )
            ),
            node_ids=[flow.source, tool.tool_id, *destinations],
            path=[flow.source, tool.tool_id, *destinations],
            evidence_required=[
                "The tool implementation's handling of this argument at its sink.",
                "Whether the argument value is validated against a closed set before the call.",
            ],
            refuted_if=[
                "The argument is constrained to a closed set — an enum or an id pattern — so free "
                "text never arrives.",
                "The sink applies a structural control: bound parameters, fixed argv with operands "
                "after --, contextual encoding, or an identifier-to-destination mapping.",
            ],
            server_supplied_hints=_hints(tool),
        )


def _detect_secret_propagation(graph: PermissionGraph, out: _Detections) -> None:
    for secret in sorted(graph.secrets.values(), key=lambda s: s.secret_id):
        for path in graph._paths_to(secret.secret_id, lambda n: graph.kind_of(n) == TOOL):
            tool = graph.tools[path[-1]]
            destinations = [s for s in tool.reaches if s in graph.external]
            out.add(
                "SECRET_PROPAGATION",
                statement=(
                    f"{secret.name} is declared to reach {tool.name} on {tool.server_id}"
                    + (f", whose arguments reach {sorted(destinations)}." if destinations
                       else ". A credential in a tool argument is a credential in that tool's logs, "
                            "error strings and upstream requests.")
                ),
                node_ids=[secret.secret_id, tool.tool_id, *destinations],
                path=path,
                evidence_required=[
                    "Where the tool writes its arguments: request bodies, logs, error messages.",
                    "Whether the credential is present in the model's context at all, or only "
                    "inside the tool process.",
                ],
                refuted_if=[
                    "The credential lives in the tool process and is never rendered into the "
                    "model's input or an argument.",
                    "The destination is operator-controlled and the credential is already scoped "
                    "to it.",
                ],
                server_supplied_hints=_hints(tool),
            )


def _poisoning_hits(text: str) -> list[str]:
    return sorted({name for name, pattern in _POISONING_PATTERNS if pattern.search(text or "")})


def _detect_description_poisoning(graph: PermissionGraph, out: _Detections) -> None:
    described: list[tuple[str, str, str, str]] = []
    for tool in graph.tools.values():
        described.append((tool.tool_id, tool.server_id, tool.name, tool.description))
    for resource in graph.resources.values():
        described.append((resource.resource_id, resource.server_id, resource.name, resource.description))
    for prompt in graph.prompts.values():
        described.append((prompt.prompt_id, prompt.server_id, prompt.name, prompt.description))

    for node_id, server_id, name, description in sorted(described):
        hits = _poisoning_hits(description)
        if not hits:
            continue
        server = graph.servers.get(server_id)
        control = server.operator_controlled if server else "UNKNOWN"
        out.add(
            "TOOL_DESCRIPTION_POISONING",
            statement=(
                f"The description of {name} on {server_id} contains instruction-shaped text "
                f"({', '.join(hits)}). Descriptions are model-facing text supplied by the server; "
                f"this server's operator control is {control!r}."
            ),
            node_ids=[node_id, server_id] if server else [node_id],
            evidence_required=[
                "Where the host renders this description in the assembled context.",
                "Who can change the description after the operator reviewed it, and whether any "
                "approval is bound to the definition rather than the name.",
            ],
            refuted_if=[
                "Server-supplied text is rendered into the untrusted data channel with a "
                "provenance label and never into an operator segment.",
                "The description is pinned by digest and a change invalidates the approval.",
            ],
            declared_controls=[f"operator_controlled={control}"],
        )


def _detect_server_text_channel(graph: PermissionGraph, out: _Detections) -> None:
    for server in sorted(graph.servers.values(), key=lambda s: s.server_id):
        if server.description_channel != "INSTRUCTION":
            continue
        if server.operator_controlled == "YES":
            continue
        out.add(
            "SERVER_TEXT_IN_INSTRUCTION_CHANNEL",
            statement=(
                f"{server.name} supplies descriptions and annotations that the host renders into "
                f"the instruction channel, and its operator control is "
                f"{server.operator_controlled!r}. That is a third party with write access to the "
                "operator's channel, independent of what any individual description says today."
            ),
            node_ids=[server.server_id],
            evidence_required=[
                "The serialized request to the model, showing which field the server's text "
                "occupies.",
                "Whether the host handles notifications/tools/list_changed and whether prior "
                "approvals survive a definition change.",
            ],
            refuted_if=[
                "The host renders server text as labelled untrusted data.",
                "The server is operator-controlled, pinned by digest, and its text goes through "
                "the same review as code.",
            ],
            declared_controls=[
                f"operator_controlled={server.operator_controlled}",
                f"transport={server.transport}",
            ],
        )


def _detect_cross_tool_exfiltration(graph: PermissionGraph, out: _Detections) -> None:
    leaky = {
        system.system_id
        for system in graph.external.values()
        if system.operator_controlled != "YES"
    }
    for store in sorted(graph.data.values(), key=lambda d: d.data_id):
        if store.sensitivity == "PUBLIC":
            continue
        for path in graph._paths_to(store.data_id, lambda n: n in leaky):
            tools = [n for n in path if graph.kind_of(n) == TOOL]
            if len(tools) < 2:
                continue
            out.add(
                "CROSS_TOOL_EXFILTRATION",
                statement=(
                    f"{store.name} (sensitivity {store.sensitivity}) is declared to reach "
                    f"{graph.external[path[-1]].name} through "
                    f"{' then '.join(graph.tools[t].name for t in tools)}. No single tool in that "
                    "chain both reads the data and reaches the destination, which is why a "
                    "per-tool review does not see it."
                ),
                node_ids=[store.data_id, *tools, path[-1]],
                path=path,
                evidence_required=[
                    "That each hop actually occurs at runtime, from a call log across repeated "
                    "runs.",
                    "What sensitive material is genuinely in context during the run.",
                ],
                refuted_if=[
                    "A destination allowlist that model output cannot widen applies to the "
                    "network-reaching tool.",
                    "Retrieval or the first tool filters by the caller's identity, so the data "
                    "never enters the chain.",
                ],
            )


def _detect_annotation_contradiction(graph: PermissionGraph, out: _Detections) -> None:
    """The one place annotations are read — and only to raise, never to lower.

    A server claiming ``readOnlyHint`` for a tool the operator declared with a
    write permission is two parties disagreeing about what the tool does. The
    disagreement is reportable. What it must never do is resolve in the server's
    favour, which is why nothing else in this module reads these keys.
    """
    for tool in sorted(graph.tools.values(), key=lambda t: t.tool_id):
        hints = _hints(tool)
        if not hints:
            continue
        write = [p for p in graph.permissions_for_tool(tool) if p.is_write]
        irreversible = [p for p in graph.permissions_for_tool(tool) if p.is_irreversible]
        contradictions = []
        if hints.get("readOnlyHint") is True and write:
            contradictions.append(
                f"readOnlyHint is true but the operator declared "
                f"{sorted(p.action for p in write)}"
            )
        if hints.get("destructiveHint") is False and irreversible:
            contradictions.append(
                f"destructiveHint is false but the operator declared "
                f"{sorted(p.action for p in irreversible)}"
            )
        if not contradictions:
            continue
        out.add(
            "ANNOTATION_CONTRADICTS_DECLARATION",
            statement=(
                f"For {tool.name} on {tool.server_id}: {'; '.join(contradictions)}. The MCP "
                "specification states annotations are hints and are not guaranteed to reflect "
                "actual behaviour. This is recorded as a disagreement to investigate; it does not "
                "lower any other detection on this tool."
            ),
            node_ids=[tool.tool_id],
            evidence_required=[
                "The tool implementation, to settle which of the two claims is true.",
                "Whether any host-side authorization decision reads these annotation keys.",
            ],
            refuted_if=[
                "The operator's permission declaration is wrong and the tool genuinely performs no "
                "state change, shown from the implementation.",
            ],
            server_supplied_hints=hints,
        )


# ---------------------------------------------------------------------------
# Record
# ---------------------------------------------------------------------------


def analyze(graph: PermissionGraph) -> dict[str, Any]:
    """Build the full record: graph, matrix, and every hypothesis, with caveats."""
    graph_form = to_graph(graph)
    return {
        "schema_version": SCHEMA_VERSION,
        "graph_id": graph.graph_id,
        "basis": DECLARATION,
        "graph": graph_form,
        "mermaid": to_mermaid(graph_form),
        "permission_matrix": to_permission_matrix(graph),
        "detections": detect(graph),
        "notes": [
            "Every entry in detections is a HYPOTHESIS. The graph was assembled from "
            "declarations — configuration, manifests, registration code — and a declared edge is "
            "not a demonstrated call.",
            "This module assigns no severity. Severity is a judgement about impact in a "
            "deployment; it belongs to a finding, after a verifier has been.",
            "MCP tool annotations are recorded and are never consulted to decide whether a "
            "detection fires. The specification states they are hints, are not guaranteed to "
            "reflect behaviour, and that clients should never make critical tool-use decisions "
            "based on annotations from untrusted servers.",
            "Tool identity here is (server, name). A host that merges several servers into one "
            "flat namespace has a collision rule, and that rule becomes an access control by "
            "accident.",
        ],
        "limitations": [
            "Absence of a detection is not evidence of absence. Anything the declarations omit — "
            "a tool registered at runtime, a server connected by a user, a sink inside a tool "
            "implementation — is invisible here.",
            "The description-poisoning patterns are a small readable list, not a filter. A benign "
            "description can match and a hostile one can avoid every pattern.",
            "Declared controls are recorded, never treated as demonstrated. Closing a hypothesis "
            "requires the evidence named on it.",
            "Path search is bounded. A graph dense enough to exceed the bound reports the paths it "
            "found and not the ones it stopped looking for, so a long detection list is a reason "
            "to re-run against a narrowed subgraph rather than to assume the list is complete.",
        ],
    }
