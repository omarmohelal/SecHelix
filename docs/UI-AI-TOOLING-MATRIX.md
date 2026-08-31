# UI and AI tooling matrix

Verified against current first-party documentation on 2026-08-31. No tool is adopted merely because an installer exits successfully. Installation proof, discovery queries, versions, changed files, blockers, and rollback steps belong in `docs/TOOLING-INSTALL-REPORT.md`.

Public SecHelix has no JavaScript package manager, `components.json`, or frontend runtime. UI tools are for the separate private/local VNext site unless explicitly described as an agent-development tool.

| Source | Official Skill? | Official MCP? | Registry/CLI? | License/access | Installed at audit? | Useful for SecHelix? | Decision | Reason |
|---|---|---|---|---|---|---|---|---|
| [shadcn/ui](https://ui.shadcn.com/docs/skills) | Yes | [Yes](https://ui.shadcn.com/docs/mcp) | `shadcn@latest`; public and namespaced registries | MIT; public | MCP already connected; Skill absent | Yes | **ADOPT** | Canonical composition/registry layer. Preserve SecHelix tokens and choose one primitive implementation per component. New projects now default to Base UI; pin Radix only when the architecture requires it. |
| [Magic UI](https://magicui.design/docs/mcp) | Yes, newly available | Yes, `@magicuidesign/mcp` | Magic CLI plus shadcn-compatible registry | MIT for public repo/MCP; Pro is paid and redistribution-restricted | No | Yes, selectively | **ADOPT MCP ONLY** | The brief explicitly requests the MCP only. Use blur, border beam, counters, and micro-motion sparingly with reduced-motion support; do not use Pro without verified access. |
| [Aceternity UI](https://ui.aceternity.com/docs/cli) | No official Skill found | No standalone official MCP | Official `@aceternity` registry through shadcn | Free and paid catalog; custom license limits source/stock redistribution | No | Selectively | **ADOPT REGISTRY / REFERENCE** | Use the existing shadcn MCP/CLI, never a similarly named third-party MCP. Inspect each component, dependency, and access label before use. |
| [Radix UI](https://www.radix-ui.com/primitives/docs/overview/getting-started) | No | No | npm packages only | MIT; public | Indirectly available through existing UI tooling | Yes | **REFERENCE** | Accessibility and interaction-behavior reference. Do not globally add Radix Themes CSS or create a second primitive layer. |
| [Tremor](https://www.tremor.so/docs/getting-started/installation) | No | No | Tremor Raw copy/paste; legacy npm track is separate | Apache-2.0 for Raw; Blocks are MIT | No | Yes, for metrics | **REFERENCE** | Adapt only exact chart/KPI patterns needed for benchmarks and coverage. Do not assume legacy `@tremor/react` is the current architecture. |
| [HyperUI](https://github.com/markmead/hyperui) | No distributable HyperUI Skill | No | Copy/paste patterns | MIT; public | No | Modestly | **REFERENCE** | Useful for compact Tailwind forms/cards/CTA structure. No installation and no second design system. |
| [COSS UI](https://coss.com/ui/docs/skills) | Yes | No official MCP | shadcn-compatible `@coss/*` registry | `apps/ui` MIT carve-out; wider monorepo defaults to AGPL | No | Yes, as reference | **ADOPT SKILL / REFERENCE** | Evaluate Base UI composition, command, dialog, and form patterns. Do not bulk-add COSS primitives beside the canonical layer. |
| [Mantine](https://mantine.dev/guides/llms/) | Yes, three focused Skills | Yes, experimental `@mantine/mcp-server` | npm runtime; official `llms.txt` and `llms-full.txt` | MIT; public; experimental MCP needs no token | No | Yes, as documentation | **REFERENCE** | Use LLM-friendly docs for AppShell, combobox, modal/drawer, focus, empty-state, and API ergonomics. Runtime adoption is not justified. |
| [Preline](https://preline.co/docs/agent-skills.html) | Yes | [Yes](https://preline.co/docs/mcp.html), hosted | npm plus Skills CLI | Skill/public docs available; MCP requires API key and Pro; Pro is proprietary | No | Yes | **ADOPT SKILLS; MCP BLOCKED_BY_CREDENTIAL** | Use public blocks/docs for marketing, docs, product, support, pricing, and FAQ patterns. Never fabricate or commit an API key. |
| [React Bits](https://github.com/DavidHDev/react-bits) | No supported free Skill path; Pro registry has a Skill | No current free MCP path; Pro uses shadcn MCP | Free `@react-bits` registry; paid authenticated Pro registries | Free MIT + Commons Clause restrictions; Pro requires paid license/key and forbids public redistribution | No | Yes, selectively | **ADOPT SELECTED FREE / PRO BLOCKED_BY_LICENSE** | Use restrained free effects only in the private site after license review. Never install unofficial MCP packages or copy Pro source without entitlement. |

## Verified installation and discovery commands

### shadcn/ui

```bash
pnpm dlx skills add shadcn/ui
pnpm dlx shadcn@latest mcp init --client claude
```

Claude Code proof: `/mcp`, followed by one registry discovery query and one component documentation query. The existing shadcn MCP already reports connected; the initializer must not be rerun unless configuration inspection proves it is necessary.

### Magic UI

Current first-party Claude installer:

```bash
npx @magicuidesign/cli@latest install claude
```

Manual first-party payload if the installer does not surface in Claude Code:

```bash
claude mcp add magicuidesign-mcp --scope project -- cmd /c npx -y @magicuidesign/mcp@latest
```

Magic's docs label the client “Claude” without documenting the exact config scope. Therefore the post-install `/mcp`/`claude mcp list` proof is mandatory.

### Aceternity registry

Add only to the private site's `components.json`:

```json
{
  "registries": {
    "@aceternity": "https://ui.aceternity.com/registry/{name}.json"
  }
}
```

Then prove discovery without adding a component:

```bash
npx shadcn@latest list @aceternity
npx shadcn@latest search @aceternity -q "card"
```

### COSS UI

```bash
pnpm dlx skills add cosscom/coss
```

Do not run `shadcn init @coss/style` or bulk-add `@coss/ui` to the site after shadcn becomes canonical.

### Mantine reference surface

```text
https://mantine.dev/llms.txt
https://mantine.dev/llms-full.txt
```

The official Skills and experimental MCP are available, but are intentionally not installed because SecHelix is not adopting the Mantine runtime.

### Preline

```bash
npx skills add htmlstreamofficial/preline
```

The hosted MCP remains `BLOCKED_BY_CREDENTIAL` until a real API key/Pro entitlement is provided. A project-scoped literal bearer token is forbidden because it would write the credential into source configuration.

### React Bits free

Use only exact, reviewed components after the private site exists, for example:

```bash
npx shadcn@latest add @react-bits/BlurText-TS-TW
```

Pro registries require `REACTBITS_LICENSE_KEY` and a valid developer license. No Pro command may run until entitlement is verified.

## Explicit rejections and blockers

| Item | Result | Rationale |
|---|---|---|
| Unofficial Aceternity MCP packages | `REJECT` | Official integration is the shadcn registry/MCP. |
| HyperUI Skill/MCP | `NOT_AVAILABLE_OFFICIAL` | Public library is copy/paste reference material. |
| COSS MCP | `NOT_AVAILABLE_OFFICIAL` | First-party Skill exists; no first-party MCP is documented. |
| Tremor Skill/MCP | `NOT_AVAILABLE_OFFICIAL` | Use current Raw documentation/source selectively. |
| Mantine runtime | `NOT_ADOPTED_ARCHITECTURALLY` | Documentation is useful; a full second runtime/component system is not. |
| Mantine MCP | `AVAILABLE_OFFICIAL_EXPERIMENTAL` | Not needed for the chosen architecture. |
| Preline MCP without key | `BLOCKED_BY_CREDENTIAL` | Never invent or persist a token. |
| React Bits free MCP/Skill | `NO_CURRENT_OFFICIAL_INSTALL_PATH` | A historical announcement is not a current supported installation path. |
| React Bits Pro | `BLOCKED_BY_LICENSE` | Paid entitlement and private key configuration have not been proven. |
| Magic UI Pro | `BLOCKED_BY_LICENSE` | Public MCP is sufficient; paid source is unnecessary and redistribution-limited. |

## Alpha.2 design decisions from the ten-source review

The private site applies ideas, not bulk component imports:

| Source | Alpha.2 influence | Implementation choice |
|---|---|---|
| shadcn/ui | composable accessible primitives | Kept the existing Radix-based Button, Dialog, Input, Sheet, Tabs, Badge, and Accordion layer; added no parallel runtime. |
| Magic UI | restrained border beam and code/file presentation | Reused the existing CSS border beam only on the evidence workbench; added a static manifest/code surface with reduced-motion coverage. |
| Aceternity | asymmetric bento storytelling | Composed the Extension Forge as an unequal manifest/pipeline grid rather than importing a paid block. |
| Radix UI | focus, keyboard, dialog, and tab behavior | Workbench states use tab semantics; command navigation uses the existing accessible Dialog/Input primitives. |
| Tremor | honest KPI and benchmark presentation | Preserved `NOT_MEASURED` metrics and compact status bands instead of decorative charts or invented trends. |
| HyperUI | concise CTA and step layouts | Tightened contribution actions and the five-stage lifecycle into scan-friendly sections. |
| COSS | command palette ergonomics | Added a searchable keyboard-opened navigation dialog with grouped product/contributor destinations. |
| Mantine | Spotlight and AppShell information architecture | Added global `⌘/Ctrl+K` and `/` navigation without adopting the Mantine runtime. |
| Preline | stepper and documentation patterns | Built the proposal → contract → proof → review → promotion pipeline and a dedicated contributor route. |
| React Bits | selective visual energy | Kept motion to bounded beam/status transitions; rejected shader, cursor, and perpetual background effects for performance and clarity. |
