# AI security inventory (AI-BOM)

You cannot review the authority of a system whose parts you have not listed.

Dependency manifests do not list them. A model pulled by mutable tag, a skill file that is control
rather than content, an MCP server installed by name from a public index, a vector store restored
from a shared snapshot, a memory store shared across tenants — none of these appear in a lockfile,
and all of them sit on a privileged execution path.

An AI-BOM is that list, with two properties on every entry that decide whether the list is useful or
actively misleading.

## What it inventories

`MODEL`, `PROVIDER`, `AGENT`, `SKILL`, `MCP_SERVER`, `TOOL`, `RAG_STORE`, `DATASET`, `MEMORY_STORE`,
`EXTERNAL_API`, `PERMISSION`, `SECRET_REFERENCE`, `NETWORK_DESTINATION`.

Assets connect through `USES`, `EXPOSES`, `READS`, `WRITES`, `REACHES`, `AUTHENTICATES_WITH` and
`DERIVED_FROM`, so the inventory is the substrate a permission graph is drawn over rather than a flat
table.

## The two properties

**Trust boundary** — `INTERNAL`, `THIRD_PARTY`, `PUBLIC`, or `UNKNOWN`.

**Provenance** — `DECLARED` (a file says it exists) or `OBSERVED` (something watched it and left
evidence).

Both default to the answer that admits ignorance, and both are enforced rather than encouraged.

## What it refuses to do

**It refuses to infer `INTERNAL`.** This is the failure that matters. "Internal" is the comfortable
default, and defaulting to it is how a third-party inference endpoint, a community MCP server and a
crawled corpus end up inside the boundary and stop being reviewed.

So an asset whose boundary was not established is `UNKNOWN`, and `UNKNOWN` is the default value.
`classify_boundary` returns `INTERNAL` only for an explicit `YES` *and* a stated basis; every other
input — `NO`, `UNKNOWN`, an empty string, "maybe" — returns `THIRD_PARTY` or `UNKNOWN`. There is no
argument that turns "we did not check" into "inside the boundary". Any boundary other than `UNKNOWN`
requires a written basis, which is the point at which somebody notices they do not have one.

Unresolved boundaries are published as their own list, `unknown_boundary_asset_ids`, so they read as
an outstanding question rather than a table cell nobody scrolled to. The rendered report says, in
those words, that until they are resolved those assets should be reviewed as though they were
outside.

**It refuses to present a declared asset as observed.** `DECLARED` and `OBSERVED` answer different
questions: a config file listing four MCP servers tells you nothing about the fifth one a developer
connected locally. They are counted apart in the summary, published as separate id lists, and
labelled per row in the rendered table. `OBSERVED` without an evidence id is refused at construction
rather than accepted and quietly downgraded — something observed it or nothing did.

**It refuses to hold a secret value.** A secret is inventoried by reference: the variable it is read
from, the vault path, the field name. A reference whose name or locator matches a credential pattern
is refused at entry, because the usual way a value reaches an inventory is somebody pasting it into
the name field. Home-directory paths are deliberately *not* treated as credentials — a local server
legitimately lives under one, and refusing that would make the honest locator unrecordable.

Everything exported also passes through the redaction in [`proof_bundle`](proof-bundles.md), and the
BOM records how many values that touched. That is the second line, not the first.

## Usage

```python
from sechelix_core.ai_inventory import Asset, Inventory, classify_boundary, to_ai_bom

inventory = Inventory("BOM-1", subject="support agent service")
boundary, basis = classify_boundary("NO")
inventory.add(Asset(asset_id="AS-model", kind="MODEL", name="hosted chat model",
                    boundary=boundary, boundary_basis=basis, locator="config/model.yaml"))
inventory.add_secret_reference("AS-token", "SUPPORT_API_TOKEN", read_from="environment variable")
inventory.link("AS-model", "AS-token", "AUTHENTICATES_WITH")

bom = to_ai_bom(inventory)
bom["unknown_boundary_asset_ids"]   # the real to-do list
bom["declared_only_asset_ids"]      # what nothing has observed running
```

Records validate against [`schemas/ai-bom-v1.schema.json`](../../schemas/ai-bom-v1.schema.json) via
`validate_contract("ai-bom", bom)`.

## The honest limit

An inventory is a lower bound. It lists what the declarations and the observations reached; anything
registered at runtime, connected locally, or pulled by a mutable tag can be absent without leaving a
gap that is visible in the output. Completeness is the one property a BOM cannot assert about itself,
and this one does not try — it states the bound instead, in its own `limitations`.

Nothing here discovers assets. The module is a contract and a set of refusals; populating it is the
reviewer's work, and an empty BOM validates perfectly while telling you nothing.

## Related

- [MCP / agent permission graph](mcp-permission-graph.md) — what the inventory is drawn into
- [AI, agent, and MCP security](ai-agent-security.md) — why each asset class is on a privileged path
- [Proof bundles](proof-bundles.md) — where the redaction comes from
