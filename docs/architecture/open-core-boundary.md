# Open core and the future Cloud boundary

**Nothing in this document is built.** It is a boundary decided in advance, so that later commercial
pressure meets a line that already exists rather than one drawn under pressure.

## The rule

**The local security engine is never paywalled.**

Everything needed to run a complete audit on your own machine — the skill, the catalog, the
specialist roles, the schemas, the adapters, the report renderer, the release gate, the Gold Packs,
the local Workbench — stays Apache-2.0 and stays complete. Not a trial, not a reduced ruleset, not a
findings cap.

This is not generosity. A security tool that withholds checks behind a plan is a tool whose output
you cannot reason about: a clean report might mean the code is fine or might mean the rule was in a
tier you did not buy. The whole premise of this project is that a report means something specific,
and a paywalled engine breaks that before any other argument starts.

## What could reasonably be commercial

The distinction that holds up: **the engine is free, hosting other people's state is not.**

Running an audit locally costs the user their own compute. Storing their evidence, scheduling their
runs, holding their organization graph, and being liable for their data are all real ongoing costs
that scale with usage, and charging for them does not make the local tool weaker.

| Tier | Contents | Why it is not the engine |
|---|---|---|
| **Core** (free, open) | Local skill, local audits, reports, Gold Packs, local Workbench, policy packs, all analysis modules | This is the product. It is complete. |
| **Pro** | Hosted audit history, scheduled audits, GitHub PR bot, private evidence storage, managed policy packs, cloud dashboard | Persistence and scheduling — infrastructure, not analysis |
| **Team** | Multi-repo organization graph, shared campaigns, RBAC, Slack/Jira integration, shared risk acceptance, team analytics | Coordination between people, which only exists when there are people |
| **Enterprise** | SSO/SAML/SCIM, private or VPC runner, self-hosted control plane, retention and residency controls, audit logs, custom policy packs, compliance evidence, SLA | Procurement and compliance requirements, not security capability |

Read the table by asking one question of each row: *does removing this make the local audit find
fewer things?* If yes, it belongs in Core. Nothing above passes that test.

## Lines that must not be crossed

**No telemetry from the open-source skill.** It must never transmit repository content, findings,
file paths or usage data. A security tool that phones home is a supply-chain risk wearing a product
label, and the audience most likely to adopt this is the audience least likely to forgive it.

**No degraded local results to make Cloud look better.** If a check exists, it runs locally.

**No account required to use Core.** No sign-up wall, no key, no online activation.

**Evidence stays the user's.** Hosted storage is a convenience the user opts into, and export is
never behind a plan. A proof bundle they cannot take with them is a proof bundle that belongs to us.

**Nothing sold before it exists.** No "coming soon" pricing, no waitlist implying a launch date, no
counter of how many people already signed up.

## Architecture consequence

Cloud must be a **consumer of Core's artifacts, not a fork of Core's engine.**

Everything Cloud would offer is downstream of things already contracted: a report validates against
`report-v1`, a policy decision against `policy-pack-v1`, a bundle carries its own manifest and
digest. Cloud stores, schedules, and displays those artifacts. It does not re-implement the analysis
that produced them.

The practical test: if the hosted service disappeared tomorrow, every user should still be able to
run the same audits and read the same reports with nothing missing. If that ever stops being true,
the boundary has moved.

That constraint is also what keeps Core honest — a Cloud that cannot add analysis has no incentive to
weaken the analysis it does not own.

## Status

- Billing: **not implemented**, and deliberately not designed yet.
- Hosted service: **does not exist**.
- Waitlist: a signal of interest only. It promises nothing and dates nothing.

## Related

- [`LICENSE`](../../LICENSE) — Apache-2.0
- [Policy packs](../reference/policy-packs.md) — the contract Cloud would consume
- [Proof bundles](../reference/proof-bundles.md) — the export that must never be gated
