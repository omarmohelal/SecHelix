# Competitive architecture audit — 2026-09

What five reference projects actually implement, read from their source, and where SecHelix has a
real gap rather than a naming difference.

Nothing here is taken from a README claim. Every row cites a path in a cloned tree at a pinned
commit. Where a project's marketing and its code disagree, the code wins and the disagreement is
recorded.

## 0. What was studied

| Project | Commit | Licence | Language | Size | Kind |
|---|---|---|---|---|---|
| `Agent-Field/sec-af` | `47d57d76ea17` | Apache-2.0 | Go (port of a Python original) | 715 files | Audit **node/service** |
| `cloudflare/security-audit-skill` | `8bac42001ddd` | MIT | Markdown + one CommonJS validator | 13 files | Agent **skill** |
| `usestrix/strix` v1.6.1 | `f1e24fe3f2a5` | Apache-2.0 | Python | 503 files | Autonomous **pentest agent** |
| `sam-cre/Security_Audit_Skill` | `eace89cbb152` | **NONE** | Markdown + shell | 63 files | Agent **skill** |
| `AlCalzone/security-audit-skill` | `db4ac7cedf8b` | MIT | Markdown | 8 files | Agent **skill** |

### Licence handling, decided before anything was read in detail

- **`sam-cre/Security_Audit_Skill` has no `LICENSE` file.** Absent a licence grant, default
  copyright applies and there is **no permission to copy, adapt or redistribute any of its
  expression**. It is treated as *behaviour-observable, expression-forbidden*: we may note that it
  parallelises above a file-count threshold; we may not reuse its wording, its file layout, or its
  thresholds as written. Every row sourced from it below is a **description of behaviour**, and its
  clean-room plan derives the design from SecHelix's own contracts instead.
- Apache-2.0 and MIT permit reuse with attribution. Even so, **no competitor source is vendored into
  SecHelix.** The plans below are specifications written against SecHelix's existing schemas, not
  ports. Where an idea is genuinely theirs, this document is the attribution.

### One correction to the premise

The previous discovery baseline recorded that Gemini described SEC-AF as a "multi-reasoner DAG with
an adversarial prover". That description is **substantially accurate** — `go/internal/phases` really
does build a tracked DAG, and `internal/agents/prove` really is a separate refutation agent. Gemini
was right about this project even though it was wrong about several others it named in the same
answers. The architecture below is read from the tree, not from that summary.

---

## 1. Capability matrix

Gap is scored against **SecHelix `3.4.0-alpha.2` as it exists**, not against its roadmap.

### 1.1 Execution runtime

| Field | Value |
|---|---|
| **Competitor** | `sec-af`; `strix` |
| **Source** | `sec-af: go/internal/orch/run.go` (678 lines), `go/internal/phases/phases.go`; `strix: strix/core/runner.py`, `strix/core/execution.py` |
| **What it does** | sec-af drives an audit as code: `recon_phase → hunt_phase → prove_phase → remediation_phase`, each sub-agent reached through `router.call(...)` so the control plane records a **child execution**. Hunters run under a semaphore of `max(1, min(max_concurrent_hunters, N))`; provers under a semaphore of 3. strix runs an agent loop over a tool set inside a container session. |
| **SecHelix today** | **No runtime at all.** `sechelix_core/` is a library of pure-Python contract and correlation helpers; there is no `pyproject.toml`, no console script, no executor. Orchestration is performed by the host agent reading `SKILL.md`. |
| **Gap** | **REAL** — the single largest one. |
| **Licence** | Apache-2.0 both. |
| **Clean-room plan** | Build `sechelix-runner` as an **optional** package that imports the existing `sechelix_core` contracts and executes nodes against them. It must not become a prerequisite: the portable skill keeps working with no runner installed, and the cold-install test stays as the guard. Do **not** port sec-af's phase names — SecHelix's node list is longer and already named in `agents/`. |
| **Measurement** | Cold-install test still passes with the runner absent; a run driven by the runner and a run driven by the skill produce the same finding set on the same fixture. |

### 1.2 Structural role isolation

| Field | Value |
|---|---|
| **Competitor** | `sec-af` |
| **Source** | `go/internal/phases/doc.go` — every sub-agent is `app.Call` with the same target name and kwargs, *never* a direct Go function call, because a direct call "would collapse the DAG". |
| **What it does** | Role separation is enforced by the call boundary: a hunter is a different tracked execution from a prover, not a different paragraph in one prompt. |
| **SecHelix today** | **Partial, and stronger where it exists.** `sechelix_core/quorum.py` already enforces blindness *structurally*: a vote cannot be recorded once the tally is visible, sealed votes are unreadable until every expected voter has submitted, and `DISAGREEMENT` is a terminal outcome that cannot be resolved by majority. That is a stricter independence property than sec-af's prove phase, which has no quorum. But outside quorum, the 17 specialists are prompt-level roles in one context. |
| **Gap** | **PARTIAL** |
| **Licence** | Apache-2.0. |
| **Clean-room plan** | Extend the existing quorum guarantee outward: the runner gives each node its own process/context and its own evidence view, so "independent verifier" is a boundary rather than an instruction. **Do not rebuild quorum** — it is already the better design; wire the runner into it. |
| **Measurement** | A role-isolation test that fails if a node can read another node's un-sealed output. |

### 1.3 Per-node telemetry (cost, tokens, duration)

| Field | Value |
|---|---|
| **Competitor** | `sec-af`; `strix` |
| **Source** | `sec-af: go/internal/orch/budget.go` (`TotalCostUSD`, `CostBreakdown`, `AgentInvocations`, all mutex-guarded); `strix/llm/context_budget.py` (per-model token budgets resolved from LiteLLM metadata) |
| **What it does** | Cost and invocation counts accumulate per phase and are readable only through guarded accessors, so a partial read during a running phase is impossible. |
| **SecHelix today** | Nothing. No execution means no telemetry. |
| **Gap** | **REAL** |
| **Licence** | Apache-2.0 both. |
| **Clean-room plan** | Node records: id, role, model/provider, input+output evidence ids, start/end, duration, tokens, cost, status, failure, scope, commit, redacted context digest. Persist as evidence records under the existing `evidence-v1.schema.json` lineage rather than a new parallel log. |
| **Measurement** | Replay a recorded run and assert the telemetry reproduces exactly. |

### 1.4 Budget governor

| Field | Value |
|---|---|
| **Competitor** | `sec-af` |
| **Source** | `go/internal/orch/budget.go` — `BudgetExhaustedError`; `checkTimeBudget` (strictly `>`); `checkCostBudget` (`>=`, both total and per-phase); `phaseBudgetLimit` splits `max_cost_usd` by `recon/hunt/prove` percentage weights. |
| **What it does** | A real fail-closed budget with **per-phase allowances**, not just a global ceiling. The strict-vs-inclusive comparison asymmetry is deliberate and documented. |
| **SecHelix today** | Nothing. |
| **Gap** | **REAL** |
| **Licence** | Apache-2.0. |
| **Clean-room plan** | `max_cost_usd`, `max_duration_seconds`, `max_hunters`, `max_verifiers`, `max_runtime_requests`, `max_browser_actions`, `max_concurrency`. Estimate before, track during, degrade or stop at threshold. **The SecHelix-specific rule sec-af does not need:** exhausting the budget must terminate as `INCOMPLETE` — it may never skip a required verification and then return `PASS`. That is a release-gate invariant, not a budget feature. |
| **Measurement** | A test that starves the budget mid-verification and asserts the gate returns `INCOMPLETE`, never `PASS`. |

### 1.5 Adaptive orchestration

| Field | Value |
|---|---|
| **Competitor** | `sec-af` — and this is the row where the marketing and the code diverge. |
| **Source** | `go/internal/orch/strategies.go: DefaultStrategies(recon)` |
| **What it does** | Selects hunter strategies **once**, from recon output, by boolean gating: `crypto_usage` non-empty → add crypto; `dependencies.direct_count > 0` → add supply-chain; `architecture.api_surface` non-empty → add API-security; depth `standard`/`thorough` → add business-logic; depth `thorough` + language match → add language-specific. |
| **Honest reading** | This is **static conditional selection at run start**, not continuous feedback. There is no re-planning from refutation rate, finding density, or coverage gaps mid-run. `cloudflare` gets closer to adaptivity but does it *across* runs, not within one. |
| **SecHelix today** | Applicability resolution (`APPLICABLE / NOT_APPLICABLE / UNKNOWN / BLOCKED`) is comparable one-shot gating, and arguably better because `UNKNOWN` is explicit. |
| **Gap** | **REAL — but net-new, not catch-up.** No reference implementation exists to study. |
| **Licence** | Apache-2.0. |
| **Clean-room plan** | Signals: finding density, refutation rate, critical architecture signal, coverage gap, budget state, unknown applicability, runtime contradiction, repeated root cause, dependency reachability, tool failure. Every adaptation emits a decision record — trigger, signal value, threshold, action, cost delta. **No silent routing.** Because nobody has built this, it carries the most delivery risk in V4 and should ship behind a flag with the static path as default. |
| **Measurement** | Adaptation decisions are replayable and each is attributable to a signal crossing a stated threshold. Compare adaptive vs static on the same fixtures: if adaptive does not beat static on recall-per-dollar, it does not ship on by default. |

### 1.6 Per-specialist context views

| Field | Value |
|---|---|
| **Competitor** | `sec-af`; `strix` |
| **Source** | `sec-af: go/internal/recontext/context.go` (826 lines) — `prune_recon_for_strategy` returns a pruned recon dict per hunt strategy; `*_hints_for_context` render strategy-specific prompt strings. `strix/llm/compaction.py`, `strix/llm/context_budget.py`. |
| **What it does** | A crypto hunter never receives the full recon narrative — it receives the crypto projection of it. Golden-tested byte-for-byte because the strings reach the model. |
| **SecHelix today** | Nothing structural. The skill is read whole. |
| **Gap** | **REAL** |
| **Licence** | Apache-2.0 both. |
| **Clean-room plan** | Derive views from SecHelix's existing artefacts, which are richer inputs than sec-af's recon dict: `attack_surface.py`, `authz_graph.py`, `dependency_graph.py`, `mcp_graph.py`. Each node declares the evidence ids it needs; the runner supplies exactly those. |
| **Measurement** | Token delta per node, full-context vs view. Publish the saving **and** any recall regression it causes — a context saving that loses findings is a loss. |

### 1.7 Dynamic sandbox

| Field | Value |
|---|---|
| **Competitor** | `strix` (only). `sec-af` has **none** — its Dockerfile deploys the audit node itself, not a target sandbox. |
| **Source** | `containers/Dockerfile`; `strix/runtime/docker_client.py` (`_sandbox_network`, `_apply_sandbox_network`); `strix/runtime/caido_*.py`; `strix/tools/{agent_browser,proxy,shell}` |
| **What it does** | A Kali Linux container with **passwordless sudo**, an offensive toolchain built in (`httpx`, `katana`, `vulnx`, `gospider`, `interactsh-client`, `govulncheck`), a Caido HTTP proxy, and a browser tool. |
| **Critical finding** | **The network is not deny-by-default.** `_sandbox_network()` attaches an *optional named* Docker network; when unset the container gets the default bridge and full egress. And `interactsh` — referenced from the system prompt and the SSRF/RCE/XXE/deserialisation skills — is an **out-of-band callback to a public internet service**. |
| **SecHelix today** | Deliberately nothing, and `sechelix_core/runtime_trace.py` enforces that structurally: `traffic_capabilities()` inspects the module's own namespace for anything that could put bytes on a wire or start a process, and **import fails** if one is ever added. |
| **Gap** | **PARTIAL, and mostly by choice.** |
| **Licence** | Apache-2.0. |
| **Clean-room plan** | Build a SecHelix sandbox that is the **inverse** of strix's: deny-all egress by default, explicit target allowlist, no sudo, no offensive toolchain, and a **local** callback listener instead of a public OOB service. Keep `runtime_trace.py`'s import-time capability check intact and add the same check to the sandbox boundary. |
| **Measurement** | A confinement test that asserts egress to a non-allowlisted host fails, and that the capability self-check still fails the build if network reach is introduced into a module forbidden to have it. |

### 1.8 Active proof building

| Field | Value |
|---|---|
| **Competitor** | `strix`; `cloudflare` |
| **Source** | `strix/skills/vulnerabilities/{ssrf,rce,xxe,insecure_deserialization}.md`; `cloudflare .../SKILL.md` — "Only report what you can exploit… Send this request, get this result", and the instruction to extract suspect code into a **minimal standalone harness** and test the hypothesis in isolation. |
| **What it does** | strix exploits to a flag. cloudflare stops short of that and instead builds a minimal harness, then explicitly marks anything needing infrastructure it lacks as "requires deployment testing" rather than confirmed. |
| **SecHelix today** | `proof_bundle.py` and `runtime_trace.py` exist and can *correlate* an observation with a static claim, but nothing *produces* the observation. |
| **Gap** | **REAL** (for producing evidence), **NONE** (for recording and correlating it). |
| **Licence** | Apache-2.0 / MIT. |
| **Clean-room plan** | Follow cloudflare's posture, not strix's: smallest safe verification plan per class — IDOR → two identities against one object; XSS → controlled browser execution; SSRF → **allowlisted local** callback; race → deterministic concurrent test; webhook → signature + replay. Never escalate to destructive exploitation. Preserve the existing rule that **runtime observation alone cannot override missing attacker control** — an observed request is not proof of an attacker's ability to make it. |
| **Measurement** | Per class, a paired fixture where the proof builder must confirm the vulnerable case and must decline the compensated case. |

### 1.9 Cross-run coverage memory

| Field | Value |
|---|---|
| **Competitor** | `cloudflare`; `sam-cre` (behaviour only — unlicensed) |
| **Source** | `cloudflare .../SKILL.md` "Coverage and prior runs"; `sam-cre .../references/differential-audit-protocol.md` |
| **What it does** | cloudflare reads prior runs' `findings.json` before hunting: skip known findings, **weight this run toward what prior runs under-explored**, and resolve prior disagreements. It states plainly that "the best single run finds roughly half the total vulnerabilities across multiple runs". sam-cre keys a differential re-audit off a prior state directory plus git history. |
| **SecHelix today** | `diff_review.py` / `pr_review.py` / `patch_mode.py` handle *code* deltas. Nothing tracks *audit coverage* across runs. A second SecHelix audit does not know where the first one did not look. |
| **Gap** | **REAL** |
| **Licence** | MIT (cloudflare) / **none** (sam-cre — behaviour only, no expression reuse). |
| **Clean-room plan** | Bind every audit to a stable target identity (canonical repo, origin, commit, branch) and track routes, entrypoints, sinks, trust boundaries, state machines, hypotheses, files/symbols, runtime paths — each as `new / changed / reused / not_revisited / never_covered / stale`. `never_covered` is the honest one and the one competitors do not report. |
| **Measurement** | Run twice on the same target; assert run 2 reports run 1's blind spots. Adopt cloudflare's humility as a measurable claim rather than a slogan: measure SecHelix's own single-run vs multi-run recall on the eval suite and publish it whatever it says. |

### 1.10 Deterministic output validation

| Field | Value |
|---|---|
| **Competitor** | `cloudflare` |
| **Source** | `skills/security-audit/validate-findings.cjs` (201 lines) + `report-schema.json` |
| **What it does** | A schema validator with a **structural evidence-chain invariant**: `trace[0].kind` must be `entrypoint`, the last must be `sink`, and every element between must be `propagation`. A finding whose trace does not run entrypoint→propagation→sink fails, independent of any model's opinion. |
| **SecHelix today** | Stronger than first assumed, and the first draft of this row was wrong. `contracts.py:_validate_finding` **already** enforced that every chain link's `evidence_ids` are declared on the finding, that a `VERIFIED` finding has every link established, and that an established link carries at least one evidence id. SecHelix's chain is also *named* (`attacker_control`, `reachability`, `boundary_failure`, `safe_reproduction`, `impact`, `preconditions`, `root_cause`) rather than positional, so cloudflare's `entrypoint → propagation → sink` rule does not transfer literally. |
| **What was genuinely missing** | **Implication between links.** A probe against the real validator showed a non-`VERIFIED` finding could declare `impact` and `safe_reproduction` **established while `attacker_control` was not** — precisely the failure `runtime_trace.py` promises in prose ("runtime observation alone cannot override missing attacker control") but nothing enforced. A control probe confirmed the finding: "nothing established" is legal, so the acceptance was specific to the implication, not blanket permissiveness. |
| **Gap** | **PARTIAL → now CLOSED.** |
| **Licence** | MIT (idea only; nothing copied — the SecHelix rule is semantic, not positional). |
| **What shipped** | `_CHAIN_PREREQUISITES` in `sechelix_core/contracts.py`: `impact` requires `attacker_control` **and** `reachability`; `safe_reproduction` requires `reachability`. Deliberately conservative — `boundary_failure` does **not** require `reachability`, because a missing authorization check is a real statically-establishable fact about a handler nobody has traced yet, and demanding reachability first would suppress true findings. |
| **Measurement** | Five tests in `tests/test_contracts.py`: three rejection cases, one acceptance-once-prerequisites-hold, and one that asserts partial findings are **not** suppressed. Suite: 821 passed, 392 subtests, no regression. |

### 1.11 Compliance mapping

| Field | Value |
|---|---|
| **Competitor** | `sec-af`; `sam-cre` (behaviour only) |
| **Source** | `sec-af: go/internal/compliance/mapping.go` (604 lines) + `table_gen.go`; `_DEFAULT_FRAMEWORKS = OWASP, PCI-DSS, SOC2, HIPAA, ISO27001` |
| **What it does** | A static **CWE → framework-control table**, plus an **AI fallback** (`GetComplianceMappingsHybrid`) that asks a model to invent a mapping for CWEs the table does not cover, swallowing errors to an empty result. |
| **Honest reading** | The static table is sound. The AI fallback is a hallucination surface pointed directly at a compliance artefact, and there is no evidence-state vocabulary — a mapping either exists or does not. |
| **SecHelix today** | Nothing. |
| **Gap** | **REAL** for the mapping; the *design* gap runs the other way. |
| **Licence** | Apache-2.0 / none. |
| **Clean-room plan** | Map **verified evidence** (not CWE labels) to ASVS, OWASP API, PCI DSS, SOC 2, ISO 27001, NIST SSDF, with states `EVIDENCED / PARTIAL / NOT_EVIDENCED / NOT_APPLICABLE / UNKNOWN`. Never emit "compliant". **Reject the AI fallback:** an unmapped CWE resolves to `UNKNOWN`, which is information; a guessed control is a liability. |
| **Measurement** | Every state transition traceable to an evidence id. A control with no evidence must render `NOT_EVIDENCED`, never blank. |

### 1.12 Sink-inventory-first method

| Field | Value |
|---|---|
| **Competitor** | `AlCalzone` |
| **Source** | `skills/security-audit/SKILL.md` — "enumerate every sink → *then* judge each one. Inventory first is the whole point"; `references/always-flag.md` |
| **What it does** | Two-phase spine: inventory every dangerous sink regardless of current belief about hostility, *then* disqualify. Plus an **always-flag** set (e.g. the `pickle`/`dill` load family) so dangerous on sight that the trace-to-boundary requirement is **waived**. |
| **SecHelix today** | `attack_surface.py` maps trust boundaries and `applicability.py` gates hypotheses — closer to "select applicable checks" than "enumerate every sink then disqualify". |
| **Gap** | **PARTIAL** |
| **Licence** | MIT. |
| **Design tension worth recording** | `always-flag` is in direct tension with SecHelix's evidence-first contract: it reports without a traced attacker path. AlCalzone is not wrong — for `pickle.loads` the base rate justifies it — but adopting it wholesale would break the property SecHelix is built on. |
| **Clean-room plan** | Adopt the inventory-first ordering. Adopt always-flag **only** as a distinct severity-bearing state that is explicitly *not* `VERIFIED` — e.g. an unconditional-sink finding that reports the sink honestly while recording that attacker control was never established. |
| **Measurement** | Recall delta on the eval suite from inventory-first ordering; false-positive delta from any always-flag lane, measured separately. |

### 1.13 Parallelisation thresholds

| Field | Value |
|---|---|
| **Competitor** | `sam-cre` (**unlicensed — behaviour only**) |
| **Source** | `skill/security-audit/references/multi-agent-strategy.md` |
| **What it does** | Declines to parallelise unless the target is large or polyglot or genuinely decoupled, on the stated grounds that coordination overhead outweighs the gain on small monolithic targets. |
| **SecHelix today** | No orchestration, so no policy. |
| **Gap** | **PARTIAL** (becomes relevant only once the runner exists). |
| **Licence** | **None — no expression may be reused.** The idea "don't fan out on small targets" is not copyrightable; their thresholds as written are their expression and are not adopted. |
| **Clean-room plan** | Derive SecHelix's own fan-out policy from its **own** measured data once the runner can measure it. Do not import a threshold nobody has validated. |
| **Measurement** | Cost/latency vs recall at several fan-out widths on the eval suite; pick thresholds from that curve. |

### 1.14 Published benchmark

| Field | Value |
|---|---|
| **Competitor** | `strix` |
| **Source** | `benchmarks/README.md` |
| **What it does** | XBEN (XBOW's 104 web-security CTF challenges), black-box: **96%** (100/104) at v0.4.0 — 100% level 1, 96% level 2, 75% level 3 — **~19 min average solve, ~$337 total for 100 challenges**. Full data in a separate `usestrix/benchmarks` repo. |
| **SecHelix today** | One blind label-only evaluation: precision 0.950, detection recall 1.000, FP rate 0.053, FP rejection 0.947 (TP 38 · FP 2 · TN 36 · FN 0), with the full workflow still `NOT_MEASURED`. |
| **Gap** | **REAL for public comparability**, and the honest reading is uncomfortable in both directions: strix publishes cost and time per challenge, which SecHelix does not; SecHelix publishes false-positive rejection, which strix does not. |
| **Licence** | Apache-2.0. |
| **The problem with a head-to-head, stated plainly** | **XBEN and the SecHelix blind suite measure different things and are not interchangeable.** XBEN asks "did the agent capture the flag" — a recall/success metric on exploitable, deliberately-vulnerable targets, with no false-positive term at all, because a CTF challenge has no clean cases to wrongly flag. The SecHelix suite is 38 *paired* vulnerable/clean cases where the entire point is the clean half. An agent that flags everything scores 0% worse on XBEN and catastrophically worse on SecHelix's suite. Running SecHelix on XBEN would measure the thing SecHelix is worst suited to; running strix on the paired suite would measure the thing strix never claimed. |
| **Clean-room plan** | Build the Arena, but **not** as a single leaderboard. Two boards on identical targets: an exploit-success board (where strix's design is favoured) and a precision/FP-rejection board (where SecHelix's is), each declaring model, budget, time and cost. Publish both, including the one SecHelix loses. |
| **Measurement** | This *is* the measurement. Nothing about relative quality may be stated until it exists — see §3. |

---

## 2. Gap summary

| Capability | Gap | Notes |
|---|---|---|
| Execution runtime | **REAL** | Largest. Everything else depends on it. |
| Budget governor | **REAL** | Reference design exists; add the `INCOMPLETE` invariant. |
| Per-node telemetry | **REAL** | Straightforward once the runner exists. |
| Context views | **REAL** | Reference design exists; SecHelix's inputs are richer. |
| Coverage ledger | **REAL** | Nobody does the full version; cloudflare does the useful half. |
| Compliance mapping | **REAL** | Reject the competitor's AI fallback. |
| Adaptive orchestration | **REAL** | **Net-new. No reference implementation anywhere.** Highest risk. |
| Arena benchmark | **REAL** | Blocked on design, not effort — see §1.14. |
| Role isolation | PARTIAL | Quorum already exceeds sec-af; extend outward. |
| Dynamic sandbox | PARTIAL | Mostly a deliberate absence. Must invert strix's network posture. |
| Active proof building | PARTIAL | Recording exists; production does not. |
| Evidence-chain implication | **CLOSED** | Found by probe, fixed and tested in this pass. |
| Sink-inventory-first | PARTIAL | Adopt ordering; quarantine always-flag. |
| Parallelisation policy | PARTIAL | Derive our own thresholds; do not import theirs. |
| Verifier quorum | **NONE** | SecHelix's sealed blind vote with terminal `DISAGREEMENT` is stronger than any competitor's. |
| Variant hunting | **NONE** | `variant_hunter.py` + `variant_rules.py`. |
| Root-cause campaigns | **NONE** | `campaigns.py`. |
| Proof bundles | **NONE** | `proof_bundle.py`. |
| Applicability states | **NONE** | `APPLICABLE/NOT_APPLICABLE/UNKNOWN/BLOCKED` — no competitor has `UNKNOWN`. |
| Untrusted-repo mode | **NONE** | `untrusted_repo.py`. No competitor treats repo content as non-instructional. |
| Scanner adapters | **NONE** | 13 adapters vs sec-af's 0 and cloudflare's 0. |

## 3. Things to deliberately reject

1. **strix's sandbox posture.** Kali + passwordless sudo + offensive toolchain + default-bridge egress + public OOB callbacks is a pentest environment. Adopting it would contradict SecHelix's deny-default requirement and its authorised-systems-only safety model.
2. **`interactsh` or any public out-of-band callback service.** The proof builder gets a local, allowlisted listener or it does not get one.
3. **sec-af's AI compliance fallback.** A model guessing a control mapping, with errors swallowed to empty, is a hallucination pointed at a compliance artefact. Unmapped resolves to `UNKNOWN`.
4. **AlCalzone's `always-flag` as a verified finding.** Adopt it only as an explicitly-not-verified state.
5. **sam-cre's thresholds as written.** Unlicensed expression, and unvalidated numbers.
6. **Any "better than X" claim.** Not licensed by anything in this document — see §1.14.
7. **Rebuilding verifier quorum, variant hunting, campaigns or proof bundles.** SecHelix already has them and, on quorum, has the stronger design.

## 4. What this document does not establish

It does not show that SecHelix is better or worse than any project studied. It shows what each
project's source contains and where SecHelix has nothing. Capability presence is not capability
quality, and none of these tools have been run against each other on a common target.

The blind label suite remains `MEASURED`; the full SecHelix workflow remains `NOT_MEASURED`; and
the relative comparison remains **unmeasured entirely** until the Arena in §1.14 exists in the
two-board form described there.
