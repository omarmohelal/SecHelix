# Tooling installation report

Date: 2026-08-31  
Host: Windows, Claude Code 2.1.240, Node 22.23.2, pnpm 11.19.0  
Skills CLI: 1.5.23  
shadcn CLI: 4.19.1

This report distinguishes installation, discovery, documentation/component lookup, live MCP connectivity, and credential/license blockers. An exit code of zero is not treated as proof by itself.

## Summary

| Tool | Requested action | Result |
|---|---|---|
| shadcn Skill | Install for Claude Code and Codex | **PASS** |
| shadcn MCP | Inspect existing configuration and prove live queries | **PASS — already installed** |
| COSS Skill | Install for Claude Code and Codex | **PASS** |
| Preline MCP Skill | Install skill files only | **PASS** |
| Preline Theme Generator Skill | Install for Claude Code and Codex | **PASS** |
| Preline hosted MCP | Do not install without real API key/Pro access | **BLOCKED_BY_CREDENTIAL** |
| Magic UI MCP | Install official server and prove Claude Code connectivity/querying | **PASS** |
| Aceternity | Use shadcn registry in the private site later; no standalone MCP | **REFERENCE / NOT YET CONFIGURED** |
| React Bits Pro | Do not access without paid entitlement/key | **BLOCKED_BY_LICENSE** |

## shadcn Agent Skill

Command used:

```powershell
pnpm dlx skills@latest add shadcn/ui --skill shadcn --global --agent claude-code codex --yes
```

Installed source revision: `shadcn/ui@63c1308d112b6b1205d86244a156cca1abef5087`.

Files/config changed:

- `C:\Users\hgjk\.agents\skills\shadcn\` — universal Skill files.
- `C:\Users\hgjk\.claude\skills\shadcn` — junction to the universal Skill for Claude Code.

Proof:

- `npx skills@latest list -g --json` returned `name: shadcn`, the installed path, and source `shadcn/ui`.
- `SKILL.md` exists with valid `name` and `description` frontmatter.
- Discovery query: searched the installed Skill for `components.json` and registry workflow rules; results describe existing-component discovery and alias checks.
- Documentation query: searched `rules/forms.md` for field/accessibility/validation guidance; the Skill requires `FieldGroup`/`Field` composition and validation states.
- Result: **PASS**. The Skill will be visible to newly started agent turns/sessions.

Rollback:

```powershell
npx skills@latest remove shadcn --global --yes
```

## shadcn MCP

The MCP was already present before VNext installation work. It was inspected rather than reinitialized, avoiding duplicate configuration.

Observed configuration:

```text
Scope: User
Command: npx shadcn@latest mcp
Status: Connected
```

Versions:

- shadcn CLI: 4.19.1.
- MCP handshake server version: 1.0.0.

Connectivity and query proof:

1. `claude mcp list` reported `shadcn ... Connected`.
2. MCP `tools/list` returned registry tools including `view_items_in_registries`, `get_item_examples_from_registries`, and `get_audit_checklist`.
3. Discovery/component query: `view_items_in_registries(["@shadcn/button"])` returned the Button registry item and its `radix-ui` dependency.
4. Documentation/example query: `get_item_examples_from_registries({ registries: ["@shadcn"], query: "button demo" })` returned accessible Button examples, including `aria-label` on icon-only controls.

Result: **PASS**.

Rollback (only if the previously existing server is intentionally removed):

```powershell
claude mcp remove shadcn -s user
```

## COSS Agent Skill

Command used:

```powershell
pnpm dlx skills@latest add cosscom/coss --skill coss --global --agent claude-code codex --yes
```

Installed source revision: `cosscom/coss@758e6535ae0143dce8c85f12e33eebf60b6b2ecb`.

Files/config changed:

- `C:\Users\hgjk\.agents\skills\coss\`.
- `C:\Users\hgjk\.claude\skills\coss` junction.

Proof:

- Global Skills discovery returned `coss` with source `cosscom/coss`.
- `SKILL.md` exists with MIT licensing metadata and explicit Tailwind 4/Base UI compatibility.
- Discovery query: `references/component-registry.md` returned the Command and other indexed primitives.
- Component/docs query: `references/primitives/dialog.md` returned modal focus guidance, AlertDialog selection rules, and the official `@coss/dialog` add command.
- Result: **PASS**.

Architecture decision: keep COSS reference-only unless a specific Base UI component is materially better. Do not bulk-add a second primitive implementation.

Rollback:

```powershell
npx skills@latest remove coss --global --yes
```

## Preline Agent Skills

Command used:

```powershell
npx --yes skills@latest add htmlstreamofficial/preline --skill preline-mcp preline-theme-generator --global --agent claude-code codex --yes
```

Installed source revision: `htmlstreamofficial/preline@05ca59998db345cfede649b00093032409b37f25`.

Files/config changed:

- `C:\Users\hgjk\.agents\skills\preline-mcp\`.
- `C:\Users\hgjk\.agents\skills\preline-theme-generator\`.
- Matching Claude Code junctions under `C:\Users\hgjk\.claude\skills\`.

Proof for `preline-mcp` Skill:

- Global Skills discovery returned the expected name/source/path.
- `SKILL.md`, catalog map, composite-layout guidance, and six-tool MCP reference exist.
- Discovery query: the catalog map returned marketing, hero, navigation, sidebar, tabs, pricing, and conversion categories.
- Component/docs query: the MCP reference documents `components_list` and `single_component`, requires exact IDs, and warns against loading the full 300k+ character catalog without a section.
- Result: **PASS for Skill files**.

Proof for `preline-theme-generator` Skill:

- Global Skills discovery returned the expected name/source/path.
- Bundled workflow, token reference, palette guidance, validation checklist, examples, and local generator scripts exist.
- Discovery/docs query: token reference returned light/dark selectors, primary ramps, navigation focus states, and inverse foreground semantics.
- Result: **PASS for Skill files**.

Hosted MCP result: **BLOCKED_BY_CREDENTIAL**. No token was requested, invented, printed, or written. Public docs/Skill files remain usable.

Rollback:

```powershell
npx skills@latest remove preline-mcp preline-theme-generator --global --yes
```

## Magic UI MCP

Official installer command used:

```powershell
npx --yes @magicuidesign/cli@latest install claude
```

The official installer updated the Claude Desktop MCP configuration at:

```text
C:\Users\hgjk\AppData\Roaming\Claude\claude_desktop_config.json
```

It created the `@magicuidesign/mcp` server entry, but that did not prove Claude Code visibility. The documented Claude Code CLI was therefore used with the required native-Windows wrapper:

```powershell
claude mcp add magicuidesign-mcp --scope user -- cmd /c npx -y @magicuidesign/mcp@latest
```

Additional file changed:

```text
C:\Users\hgjk\.claude.json
```

Version and connectivity:

- MCP handshake reported `Magic UI MCP` version 1.0.4.
- `claude mcp list` reported `magicuidesign-mcp ... Connected`.
- `claude mcp get magicuidesign-mcp` confirmed user scope, stdio transport, and the official package.

Query proof:

1. MCP `tools/list` returned `listRegistryItems`, `searchRegistryItems`, and `getRegistryItem`.
2. Discovery query: `searchRegistryItems({ query: "border beam", kind: "component", limit: 3 })` returned Border Beam, Animated Beam, and Shine Border.
3. Component/docs query: `getRegistryItem({ name: "border-beam", includeSource: false, includeExamples: true, includeRelated: true })` returned its purpose, `motion` dependency, registry URL, official shadcn add command, related examples, and usage examples.

Result: **PASS**.

Rollback:

```powershell
claude mcp remove magicuidesign-mcp -s user
```

For Claude Desktop, back up `claude_desktop_config.json`, remove only the `@magicuidesign/mcp` property under `mcpServers`, and restart Claude Desktop. Do not delete unrelated MCP entries.

## Not installed by design

| Tool | Reason | Future proof required |
|---|---|---|
| Aceternity standalone MCP | No official standalone MCP exists | Configure official registry through shadcn in private site's `components.json` |
| Radix Theme/runtime replacement | Existing canonical primitive layer is sufficient | Architecture decision and conflict review |
| Tremor runtime | Current Raw patterns can be adapted selectively | Exact component dependency/license review |
| HyperUI package/MCP | No official integration exists | Reference snippets only |
| Mantine runtime/Skills/MCP | Useful as LLM documentation; runtime is not selected | Architecture decision; experimental-MCP review |
| Preline hosted MCP | API key/Pro entitlement unavailable | Real credential stored outside source, then live server queries |
| React Bits Pro | Paid entitlement/key unavailable | Verified developer seat, private registry config, redistribution review |
| Magic UI Skill | The user explicitly requested MCP only | Separate adoption decision |

