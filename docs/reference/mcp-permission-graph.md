# MCP / agent permission graph

Reviewing an agent by reading its prompt is reviewing the wrong artifact.

The reviewable artifact is the graph:

```
Agent → MCP Server → Tool / Resource / Prompt → Permission → Data → External System
```

Everything interesting is a property of that graph. Excessive authority is a tool in the run that the
task never needed. A confused deputy is a path from something a stranger can write to something the
operator's credential can do. Exfiltration is a path from data to a destination somebody else
observes. None of those are visible in a prompt, and all of them are visible in edges.

## What it looks for

| Kind | The shape it names |
|---|---|
| `EXCESSIVE_AUTHORITY` | A tool reachable by the agent holds an action outside the agent's declared requirement — or the agent declares no requirement at all, so nothing bounds the run |
| `UNSAFE_WRITE_CAPABILITY` | An irreversible action with no confirmation bound to the canonicalised arguments |
| `CONFUSED_DEPUTY` | A declared path from third-party-writable content to a tool holding a state-changing permission |
| `TOOL_ARGUMENT_INJECTION` | Untrusted content reaching a tool argument — the argument is the payload, whatever the return value is |
| `SECRET_PROPAGATION` | A credential reference reaching a tool argument, and from there that tool's logs, errors and upstream requests |
| `TOOL_DESCRIPTION_POISONING` | Instruction-shaped text in server-supplied model-facing text |
| `SERVER_TEXT_IN_INSTRUCTION_CHANNEL` | A server that is not operator-controlled supplying text the host renders as instructions |
| `CROSS_TOOL_EXFILTRATION` | Sensitive data reaching an outside system through two or more tools, so no single tool's review sees it |
| `ANNOTATION_CONTRADICTS_DECLARATION` | The server's hint and the operator's permission declaration disagree about what a tool does |

## Exports

`to_graph()` returns nodes and edges. `to_mermaid()` renders those as a flowchart — node ids are
rewritten to `N0…Nn` because a declared id can contain characters Mermaid reads as syntax, and a
diagram that silently fails to parse is worse than no diagram.

`to_permission_matrix()` returns one row per (agent, tool) and one column per declared permission,
with `NONE` in ungranted cells. Each row also carries whether the tool is write-capable, whether it
is irreversible, which credential scopes it executes with, and its confirmation quality — the four
things that decide blast radius and that a matrix of names alone hides.

## What it refuses to do

**It refuses to call anything a finding.** Every detection carries `status: HYPOTHESIS`,
`basis: DECLARATION`, and `runtime_reachability: UNPROVEN`. The graph is assembled from configuration
files, tool manifests, and code that registers handlers. A declared edge is not a demonstrated call,
and no amount of structure in a config file makes it one. Each detection instead carries
`evidence_required` — what would establish it at runtime — and `refuted_if` — what would close it —
so the next step is a task rather than an argument.

**It refuses to let an MCP annotation lower anything.** The specification defines `readOnlyHint`,
`destructiveHint`, `idempotentHint` and `openWorldHint`, states they are hints, states they are not
guaranteed to be a faithful representation of actual tool behaviour, and states that clients should
never make critical tool-use decisions based on annotations received from untrusted servers. An
authorization tier read off an annotation is a tier the *server* defines.

So annotations are recorded on every detection they touch and consulted by nothing that decides
whether one fires. The test suite asserts this over every combination of the four hints: the
detections are identical in all of them. The one thing an annotation may do is *raise* a hypothesis —
a server claiming `readOnlyHint` for a tool the operator declared with a write permission is two
parties disagreeing, and the disagreement is reportable. It resolves in neither party's favour here.

**It refuses to treat an operator's own declared control as a refutation either.** A declared
provenance-aware dispatcher, a declared confirmation, a declared credential scope — each is recorded
in `declared_controls` and closes nothing. This module reads declarations; it cannot check them. The
one exception is stated as a rule rather than an inference: a confirmation declared as
`OUT_OF_BAND_BOUND` withholds `UNSAFE_WRITE_CAPABILITY`, because that value asserts the specific
properties the detection is about, and the detection would otherwise fire on every well-built system.

**It refuses to assign severity.** Severity is a judgement about impact in a deployment, and this
module has a configuration file. There is no `severity` and no `confidence` property anywhere in the
contract, so one cannot be added by a caller and read back as though the analysis produced it. That
vocabulary lives in the finding contract, downstream, after a verifier has been.

**It refuses to treat a bare tool name as an identity.** Tool identity here is `(server, name)`. A
host that merges several servers into one flat namespace has a collision rule, and that rule becomes
an access control by accident: an allowlist entry approved when `search_docs` belonged to the vetted
server now points at whatever claims the name.

## Usage

```python
from sechelix_core.mcp_graph import Agent, PermissionGraph, Permission, Server, Tool, analyze

graph = PermissionGraph("GRAPH-1")
graph.add_server(Server("S-docs", "community docs server", operator_controlled="NO",
                        description_channel="INSTRUCTION"))
graph.add_agent(Agent("A-1", "support agent", server_ids=("S-docs",),
                      required_actions=("READ",)))
graph.add_permission(Permission("P-net", "NETWORK", credential_scope="AMBIENT"))
graph.add_tool(Tool("T-search", "S-docs", "search_docs", permission_ids=("P-net",)))

record = analyze(graph)
record["mermaid"]             # the flowchart
record["permission_matrix"]   # rows and columns
record["detections"]          # hypotheses, each with what would settle it
```

Records validate against
[`schemas/mcp-graph-v1.schema.json`](../../schemas/mcp-graph-v1.schema.json) via
`validate_contract("mcp-graph", record)`.

## The honest limit

Absence of a detection is not evidence of absence. Anything the declarations omit is invisible here:
a tool registered at runtime, a server a developer connected locally, a sink inside a tool
implementation, a namespace merge whose collision rule lives in the host rather than the config.

The description-poisoning patterns are a small readable list, not a filter. A benign description can
match one and a hostile one can avoid all of them — the mechanism, and why filtering is not a
boundary, is set out in [AI, agent, and MCP security](ai-agent-security.md).

Protocol statements here are pinned to the same MCP revision as that document. Re-check the
specification rather than this file when the answer matters.

## Related

- [AI, agent, and MCP security](ai-agent-security.md) — the mechanisms, and what refutes each one
- [AI security inventory](ai-bom.md) — the asset list a graph is drawn over
- [Attack surface and authorization graph](authorization-graph.md) — the same modelling applied to a conventional application
