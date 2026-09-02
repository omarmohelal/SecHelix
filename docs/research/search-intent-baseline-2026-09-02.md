# Search intent baseline — 2026-09-02

Two things live here: what Google Search Console actually reports today, and the intent map the
site is being organised around. They are deliberately in the same file, because the second was
built **without** the first and that fact has to travel with it.

## 1. Search Console — the honest answer is "no data"

Property: `sc-domain:sechelix.com`, read from the owner's authenticated Search Console on
2026-09-02.

| Field | Value |
|---|---|
| Date range requested | 3 months (the longest offered on this property) |
| Date range with data | **2026-08-31 → 2026-08-31** — one day |
| Total clicks | **0** |
| Total impressions | **0** |
| Average CTR | 0% |
| Average position | 0 |
| Top queries table | **No data** |

There is no branded group and no non-branded group, because there are **no queries at all**. The
property was created on 2026-09-01 and Search Console is still in its initial processing window; the
Overview and Indexing reports both still read *"Processing data, please check again in a day or so."*

**Generative AI / AI features report:** not available on this property. The Performance view offers
Search type Web only; no AI Mode, AI Overviews or "AI features" breakdown is present to inspect.

### What this means for the work that follows

The plan asked to prioritise genuine impressions over guessed keywords. There are no genuine
impressions to prioritise. So the intent map below is **derived from what SecHelix actually does**,
cross-checked against the pages that already exist — not from observed demand, and not from a
keyword tool. It is a hypothesis about intent, and it is labelled as one.

Re-run this audit once Search Console has 28 days of data. If the real queries disagree with the map,
the real queries win.

## 2. Intent map

Six clusters. Every one maps to a page that already exists or to the single new pillar. **No page is
created per keyword**, and no cluster gets a page of its own just because it has a name.

### A — AppSec agent (product category)

`appsec agent` · `application security agent` · `application security AI agent` · `AI appsec agent` ·
`security audit agent` · `security review agent` · `code security agent`

→ **[`/appsec-agent`](https://sechelix.com/appsec-agent)** — new. This is the only page added for a
cluster, because there was previously no generic product-category entry point at all: every existing
page answered a narrower task. It is also the hub that links out to every cluster below.

### B — AI coding security

`AI generated code security` · `AI code security audit` · `secure AI generated code` ·
`vibe coding security` · `AI coding security review` · `AI code vulnerability review`

→ **`/ai-generated-code-security`** (exists) · deeper treatment in
**`/research/how-to-secure-ai-generated-code`**.

### C — Agent host security

`Claude Code security audit` · `Claude Code AppSec` · `Claude security skill` ·
`Codex security audit` · `Codex AppSec agent` · `GitHub Copilot security review`

→ **`/claude-code-security-skill`** · **`/codex-security-skill`** · **`/copilot-security-skill`**
(all exist). One page per host, not per query.

### D — MCP and agent security

`MCP security audit` · `MCP server security` · `MCP authorization audit` · `agent tool security` ·
`AI agent permission audit` · `tool authority security` · `prompt injection MCP`

→ **`/mcp-security-audit`** (exists). `prompt injection MCP` and `tool authority` are both already
covered in that page's body; neither earns its own route.

### E — Application logic

`BOLA IDOR audit` · `authorization security audit` · `tenant isolation testing` ·
`business logic security` · `payment logic security` · `race condition security` ·
`idempotency security testing`

→ **`/authorization-bola-idor`** (BOLA, IDOR, tenant isolation) ·
**`/business-logic-security`** (payments, races, idempotency). Both exist.

### F — Proof and remediation

`security regression testing` · `verify vulnerability fix` · `false positive security review` ·
`security finding verification`

→ **`/security-regression-testing`** (exists) · **`/benchmarks`** for what has and has not been
measured · **`/research/why-an-appsec-agent-should-try-to-disprove-its-own-findings`** for the
false-positive argument.

### Deliberately unmapped

`zero-trust repository audit` keeps its own page (**`/zero-trust-repository-audit`**) because
`UNTRUSTED_REPO` mode is a real distinct capability, not a keyword variant.

## 3. Rules this map is held to

- One page per **task**, never one page per query string.
- A page earns its place by answering the question better than its own metadata does.
- No hidden keyword blocks, no boilerplate shared across pages, no doorway pages.
- Nothing in this map licenses a performance claim. The blind label suite is measured; the full
  SecHelix workflow is `NOT_MEASURED`, and every page repeats that boundary rather than eliding it.
