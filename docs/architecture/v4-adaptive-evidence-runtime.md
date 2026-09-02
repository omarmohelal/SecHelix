# V4 — Adaptive Evidence Runtime (plan)

**Status: PLANNED. Not built, not released, not measured.**

This is a design record, not a description of shipped software. Every section below states which of
three states it is in, and nothing here licenses a capability claim on any public surface until it
moves to `BUILT` and carries a test.

- `BUILT` — code exists, tested, in `main`.
- `SPECIFIED` — the contract and acceptance test are decided; no code.
- `OPEN` — the design question is not settled.

Grounding evidence for every gap is in
[`../research/competitive-architecture-2026-09.md`](../research/competitive-architecture-2026-09.md),
which was written from cloned source at pinned commits.

## 0. What is actually built today

| Item | State | Evidence |
|---|---|---|
| Evidence-chain implication invariant | **BUILT** | `_CHAIN_PREREQUISITES` in `sechelix_core/contracts.py`; 5 tests in `tests/test_contracts.py`; suite 821 passed / 392 subtests |
| Competitive architecture audit | **BUILT** | `docs/research/competitive-architecture-2026-09.md` |
| Everything else in this document | `SPECIFIED` or `OPEN` | — |

One capability shipped in this pass. It is small, and it closed a hole that had been asserted in
prose and never enforced: a finding could claim `impact` was established while `attacker_control`
was not. That is worth more than a longer list of half-built subsystems.

## 1. The shape, and the one rule that constrains it

```
SecHelix Skill  (portable, unchanged, works with none of the below installed)
      │
      └── Runner  (OPTIONAL package)
            ├── Reasoner DAG
            ├── Evidence Graph        ← existing evidence-v1 contracts
            ├── Verifier Quorum       ← existing quorum.py, unchanged
            ├── Remediation           ← existing remediation.py
            └── Release Gate          ← fail-closed, existing semantics
```

**The rule: the runner is optional and stays optional.** The portable skill must keep cold-installing
and running with no runner, no Python package, and no container. This is not a preference — it is
what makes SecHelix usable inside Claude Code, Codex and Copilot at all, and the cold-install test is
the guard. Any change that makes the runner load-bearing for the skill has broken the product.

## 2. Staging

Ordered by dependency, not by appeal. Each stage is independently shippable and independently
useless to claim until measured.

### Stage 1 — Runner skeleton + DAG telemetry `SPECIFIED`

Node contract, per-node records, deterministic replay. No adaptivity, no sandbox, no network.

Every node records: node id, role, model/provider, input evidence ids, output evidence ids,
start/end, duration, tokens, cost, status, failure, scope, commit, redacted context digest.
Persisted as evidence records under the existing lineage, not a parallel log.

**Acceptance:** a recorded run replays to an identical finding set and identical telemetry.

### Stage 2 — Budget governor `SPECIFIED`

`max_cost_usd`, `max_duration_seconds`, `max_hunters`, `max_verifiers`, `max_runtime_requests`,
`max_browser_actions`, `max_concurrency`. Estimate before, track during, degrade or stop at
threshold.

**The invariant sec-af does not need and SecHelix does:** budget exhaustion terminates the run as
`INCOMPLETE`. It may never skip a required verification and return `PASS`.

**Acceptance:** a test that starves the budget mid-verification and asserts the gate returns
`INCOMPLETE`. If that test does not exist, the budget governor does not ship.

### Stage 3 — Context views `SPECIFIED`

Each node declares the evidence ids it needs; the runner supplies exactly those, projected from
`attack_surface.py`, `authz_graph.py`, `dependency_graph.py`, `mcp_graph.py`.

**Acceptance:** token delta per node published **with** any recall regression it causes. A context
saving that loses findings is a loss and gets reported as one.

### Stage 4 — Coverage ledger `SPECIFIED`

Bind each audit to canonical repo + origin + commit + branch. Track routes, entrypoints, sinks,
trust boundaries, state machines, hypotheses, files/symbols, runtime paths as
`new / changed / reused / not_revisited / never_covered / stale`.

`never_covered` is the state competitors do not report and the reason to build this.

**Acceptance:** run twice on one target; run 2 names run 1's blind spots. Separately, measure
SecHelix's own single-run vs multi-run recall on the eval suite — cloudflare states that its best
single run finds roughly half of what multiple runs find, and SecHelix should know its own number
rather than borrow theirs.

### Stage 5 — Sandbox + proof builder `SPECIFIED`, network posture `SPECIFIED`

Deny-all egress by default. Explicit target allowlist. No sudo. No offensive toolchain. A **local**
callback listener — never a public out-of-band service. Artifacts stay in the run workspace.
`STATIC` remains the default mode; dynamic work is `LOCAL`/`STAGING` unless explicitly approved.

Smallest safe verification plan per class: IDOR → two identities, one object; XSS → controlled
browser execution; SSRF → allowlisted local callback; race → deterministic concurrent test; webhook
→ signature + replay. Never escalate to destructive exploitation.

**Preserved invariant:** runtime observation alone cannot override missing attacker control. This is
now enforced in the contract as of this pass, so the proof builder inherits it rather than having to
re-implement it.

**Acceptance:** egress to a non-allowlisted host fails; `runtime_trace.py`'s import-time capability
self-check still fails the build if network reach is introduced where it is forbidden; each proof
class confirms its vulnerable fixture and declines its compensated one.

### Stage 6 — Adaptive orchestration `OPEN`

Signals: finding density, refutation rate, critical architecture signal, coverage gap, budget state,
unknown applicability, runtime contradiction, repeated root cause, dependency reachability, tool
failure. Every adaptation emits a decision record — trigger, signal, value, threshold, action, cost
delta. No silent routing.

**Why this is `OPEN` and last.** The audit found that **no reference project implements it.**
sec-af's strategy selection is one-shot boolean gating off recon output; cloudflare adapts across
runs, not within one. This is net-new engineering with no prior art to study, which makes it the
highest-risk item in V4 and the worst candidate to build first.

**Acceptance:** ships behind a flag, static path stays the default, and it must beat static on
recall-per-dollar on the eval suite. If it does not, it does not become the default — and that
result gets published either way.

### Stage 7 — CLI, API, protocol packs, native pack, compliance mapping `SPECIFIED`

Sequenced after the runner because each is a surface over it. Compliance states are
`EVIDENCED / PARTIAL / NOT_EVIDENCED / NOT_APPLICABLE / UNKNOWN`; the word "compliant" is never
emitted, and an unmapped control resolves to `UNKNOWN` rather than to a model's guess.

Every protocol pack requires vulnerable / clean / compensated fixtures before it counts as built.
The native lane is applicability-gated and must not run on projects with no native surface.

## 3. The Arena, and why it is not simply "run all four"

`OPEN` — blocked on design, not effort.

The brief asks to compare SecHelix, SEC-AF, Cloudflare and Strix on identical targets. The audit
found a problem with doing that on one leaderboard:

**Strix's published benchmark is XBEN** — 104 web-security CTF challenges, black-box, 96% solve rate
at v0.4.0, ~19 minutes and ~$3.37 per challenge. That is a *success-rate* metric on deliberately
vulnerable targets with **no false-positive term at all**, because a CTF challenge has no clean cases
to wrongly flag.

**SecHelix's suite is 38 paired vulnerable/clean cases** where the clean half is the entire point —
precision 0.950, FP rejection 0.947.

An agent that flags everything scores *unchanged* on XBEN and catastrophically on SecHelix's suite.
Running each tool on the other's benchmark measures the thing it never claimed. A single combined
number would be misleading in whichever direction it pointed.

**Design decision: two boards, identical targets, both published.**

1. **Exploit-success board** — can the tool demonstrate the vulnerability? Strix's design is
   favoured here and SecHelix will likely lose, because SecHelix deliberately declines destructive
   exploitation.
2. **Discrimination board** — precision, FP rate, FP rejection on paired cases. SecHelix's design is
   favoured here.

Each board declares model, budget, wall-clock and cost. Targets are authorized local/isolated only.
Cases are frozen before any competitor output is seen — **no tuning after observing results.**

## 4. What may not be said

Until the Arena exists in the two-board form above, **no comparative claim is licensed**, including
implicit ones. Specifically not:

- that SecHelix is better than SEC-AF, Cloudflare, Strix, or any other tool;
- that having more capabilities in a matrix means producing better audits — capability presence is
  not capability quality;
- that the blind label figure (0.950) describes the full SecHelix workflow. It does not. The blind
  label suite is `MEASURED`; the full workflow is `NOT_MEASURED`; the comparison is unmeasured
  entirely.

The competitive audit establishes what each project's source contains and where SecHelix has
nothing. That is a map of work, not a scoreboard.
