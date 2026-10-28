# SecHelix Engineering Baseline

**Status date:** 2026-10-29
**Checkout under test:** `C:\Users\hgjk\Documents\SecHelix` (Windows working tree), branch `main`, clean.
**Runtime used for verification:** WSL Ubuntu-24.04, Python 3.12.3, run against the Windows tree via `/mnt/c/...`.
A separate `~/SecHelix` checkout also exists inside WSL; it was **not** used for these results.

This document is Phase 0 of the engineering brief: establish a *verified* baseline before editing.
Every status below is backed by a command that was actually run. Claims that could not be
executed here (live dynamic runs, external targets) are marked **UNVERIFIED** rather than assumed.

---

## 1. Executive summary

The foundation is **healthy, not broken.** The full dev suite and every CI validator pass on a
clean checkout. The project is an **Agent-Skill-first, evidence-first** system (canonical
`skills/sechelix/SKILL.md`, optional stdlib-only Python runtime) whose differentiator is an
**independent verifier that tries to disprove each candidate** and returns `INCOMPLETE` rather
than a false `PASS`.

Several assumptions in the engineering brief do **not** match this repository and must be
resolved before building against them (Section 5). Most importantly: there is **no embedded
Strix engine**, and **none** of the brief's named LLM providers (OpenRouter, the `wasmjsvm.com`
gateway, an in-engine Nexus/FCC router) exist in the code.

## 2. Verified evidence

| Check | Command | Result |
|---|---|---|
| CI validators (×6) | `scripts/validate_{catalog,skill,distribution,extensions,knowledge,gold_packs}.py` | **6/6 OK** |
| Dev test suite | `pytest -q` | **1724 passed, 810 subtests passed, 0 failed** (115.7s) |
| Editable install | `pip install -e .` | **OK** |
| CLI health | `sechelix doctor` | **OK** — `core_contracts True`, network `DENY` default, redaction enabled |
| Pentest CLI | `sechelix-pentest --help` | **OK** — subcommands: `plan init contract run run-config promotion-checkpoint bundle static-scan tool-scan crawl` |

`doctor` also reports: reasoning executors `{claude-code: False, gemini-cli: True}` in this env;
Docker 29.8.1 and git present; default reasoning executor is `NullExecutor` (opt-in by `--executor`).

## 3. Architecture as it actually is

Seven layers (per `ARCHITECTURE.md`): agent/model adapters → canonical `SKILL.md` → knowledge
resolution → coverage model (21 families × 26 lenses = 546 slots) → Gold Packs + Variant Hunter
→ evidence adapters → verification + release gate.

- **`sechelix_core/`** — the contracts and engines: `catalog`, `contracts`, `authz_graph`,
  `dependency_graph`, `runtime_trace`, `secret_lifecycle`, `diff_review`, `pr_review`,
  `ai_inventory`, `mcp_graph`, `quorum`, `proof_bundle`, `variant_hunter`, `policy_packs`.
- **`sechelix_runner/`** — optional execution runtime: `cli`, `mcp_server`, `runner`, `budget`,
  `coverage`, `sandbox`, `report`, `proof_exec`, plus `providers/` and `pentest/`.
- **`sechelix_runner/providers/`** — provider-neutral reasoning (`base.ProviderExecutor`,
  fail-closed schema validation, unmeasured tokens = `None`) with concrete `claude_code.py`,
  `gemini_cli.py`, and `reasoning.py`.
- **`sechelix_runner/pentest/`** — the **native** live-web foundation: `scope` (deny-by-default,
  enforced outside the model), `browser`, `http_evidence`, `discovery`, `engagement`,
  `full_workflow`, `api_client`, `checkpoint`, `remediation_graph`, `reproduction`.
- Dynamic backend is **home-grown**, not Strix.

## 4. Capability matrix

Legend: **WORKING** (verified here) · **PARTIAL** (code + unit tests, real-target run unverified)
· **UNVERIFIED** (present, not exercised here) · **MISSING** (not in repo).

| Capability | Status | Evidence / note |
|---|---|---|
| Canonical skill + adapter mirrors | WORKING | `validate_skill` OK; `.claude` / `.agents` mirrors present |
| Coverage model (21×26) | WORKING | `validate_catalog` OK; invariant test enforces 546 |
| Gold Packs + Variant Hunter | WORKING | `validate_gold_packs` OK; unit tests green |
| Knowledge resolution + rights | WORKING | `validate_knowledge` OK |
| Evidence-first verification | WORKING (unit) | `quorum`, `proof_bundle`, `pentest_verification` tests green; verifier fail-closed |
| Code / static review | WORKING (unit) | `diff_review`, `pr_review`, `authz_graph`, `dependency_graph`, `runtime_trace` tests green |
| Secrets lifecycle | WORKING (unit) | `secret_lifecycle` tests green; redaction on in `doctor` |
| AI / MCP security | WORKING (unit) | `ai_inventory`, `mcp_graph` tests green |
| MCP server interface | UNVERIFIED | `mcp_server.py` present; not smoke-tested live |
| Web dynamic pentest | PARTIAL | rich `pentest/` + tests; live authorized run not executed here (needs Playwright + target) |
| API security testing | PARTIAL | `pentest/api_client`, `static-scan`; live run unverified |
| Business-logic testing | PARTIAL | `authz_graph`, `attack_chains`, `runtime_trace`; fixtures exist, live unverified |
| Supply chain / SBOM | PARTIAL | `generate_sbom`, `generate_security_runtime_sbom`, secret checks present |
| Scope enforcement (deny-by-default) | PARTIAL | enforced in CLI + code; no live scope-escape test run here |
| Resume / cancel / checkpoint | UNVERIFIED | `pentest/checkpoint.py` + `promotion-checkpoint` cmd present; not exercised end-to-end |
| Provider abstraction | WORKING | `ProviderExecutor` fail-closed, model-neutral |
| claude-code executor | PARTIAL | present; `available=False` in this env |
| gemini-cli executor | WORKING | present; `available=True` in this env |
| **External scanners** (Semgrep, CodeQL, Gitleaks, Trivy, OSV, ZAP, Nuclei, opengrep, npm/pnpm-audit, playwright, safety) | WORKING | `adapters/` has 12 stdlib normalizers → one `CANDIDATE`/`UNASSESSED` envelope (`sechelix-evidence/v1`); tool severity kept as `trusted_for_assessment:false`; 20 adapter tests pass; `python -m adapters.cli <tool> <report>` |
| **OpenRouter provider** (brief Provider A) | WORKING (live-verified 2026-10-29) | `providers/openrouter.py`; chat/tools/streaming/JSON/errors all pass on `qwen/qwen3.8-27b` — see SECHELIX-PROVIDERS.md |
| **wasm/DeepSeek gateway** (brief Provider B) | MISSING | no `wasmjsvm`/`deepseek-v4`/`SECHELIX_WASM_API_KEY` anywhere |
| **In-engine Nexus/FCC router** (brief Provider C) | MISSING | Nexus exists only as external MCP tooling, not wired into the runner |
| **Embedded Strix engine** | MISSING | no submodule/vendor; `strix` appears only in docs + one sandbox comment |

## 5. Brief ↔ repository mismatches (resolve before building)

1. **No broken foundation to "repair."** Phase 1's premise (broken install, failing tests,
   broken imports/entrypoints) does not hold for this checkout — suite and validators are green.
2. **No embedded Strix.** Phases 2/3/8 assume Strix is the primary dynamic backend. It is not
   present; the native `pentest/` subsystem is. Benchmarking "vs. Strix" would require installing
   upstream Strix separately as an external comparator, not an embedded engine.
3. **Named LLM providers are absent.** Phase 4 Providers A (OpenRouter), B (wasm gateway), and
   C (Nexus/FCC routing) are all MISSING in code. The existing provider model is CLI-agent-based
   (`claude-code`, `gemini-cli`). Adding HTTP providers is net-new work, not integration.
4. **Referenced docs don't exist yet:** `docs/engineering/*` (this file is the first),
   `docs/full-install.md`. The brief cites them as if present.
5. **Two checkouts.** `~/SecHelix` (WSL) and this Windows tree are separate working copies.
   Pick one canonical tree for the work to avoid divergence.

## 6. Honest open questions for the owner

- Which of the net-new items (OpenRouter provider, wasm gateway, external-scanner adapters,
  Strix-as-comparator) are actually wanted, versus artifacts of a generic brief?
- Target checkout: this Windows tree, or `~/SecHelix` in WSL?
- Highest-priority working vertical slice to build first (Section 7 is a candidate ordering).

## 7. Recommended first vertical slice (proposal, not yet done)

Given the foundation is green, the highest-value grounded work is **one real end-to-end
evidence-backed run**, not a rewrite:

1. Add the **OpenRouter provider** behind the existing `ProviderExecutor` (fail-closed, token
   accounting, redaction) — it's the one provider with a stable public contract.
2. Wire one **external scanner adapter** (OSV-Scanner or Gitleaks: cheap, deterministic, SARIF)
   as normalized *candidate* evidence that still passes through the independent verifier.
3. Prove a single **STATIC** assessment end-to-end on the `examples/expense-api` fixture with a
   real reasoning executor, producing a verified finding + a refuted candidate + a release gate.

Each step is independently testable and preserves every existing contract and safety boundary.

---

## 8. Addendum — verified work (2026-10-29, same day)

Two corrections and one real milestone, from executing against the live system.

**Correction A — external scanners are not MISSING.** `adapters/` already ships
12 standard-library normalizers (semgrep, opengrep, codeql/sarif, osv, trivy,
gitleaks, npm-audit, pnpm-audit, playwright, zap, nuclei, safety). Every record
is emitted as `CANDIDATE`/`UNASSESSED` under `sechelix-evidence/v1`, with the
tool's own severity retained only as `tool_signal.trusted_for_assessment:false`;
`adapters/safety.py` builds bounded scope-aware commands but never executes them.
20 adapter tests pass. The matrix row and Section 5 item 3 are corrected
accordingly. The first draft under-inspected `adapters/`.

**Correction B — OpenRouter is now WORKING, live-verified.** Provider built and
probed against `qwen/qwen3.8-27b`: chat, token+cost accounting, tool calling,
streaming, JSON mode, and error shapes all pass (see `SECHELIX-PROVIDERS.md`).

**Milestone — first live end-to-end assessment.** `sechelix audit
examples/expense-api --executor openrouter` ran the real reasoner graph on the
live model: `map` + `architecture` + release `gate` nodes executed, the
independent `verify` node was correctly **skipped** ("no candidates to verify"),
nothing blocked or failed, spend **$0.0042** against a $0.75 cap. A second run at
`--depth standard` behaved identically ($0.0022).

**Why no candidates (verified in code).** `_default_graph` is **applicability-
gated, not depth-gated**: a reasoning lane is added only when its required
world-context exists (`ROLE_CONTEXT[role]["required"]`). On the expense-api world
only the `architecture` lane qualified; the hunter lanes' required inputs were
absent, so they never ran — which is why `--depth quick` and `--depth standard`
produced the same 4-node route. Depth affects world breadth, not the node set.
The `sechelix audit` CLI is therefore a thin orchestration demo; deep per-family
hunting lives in the pentest workflow and the SKILL-driven flow with a richer
world. `examples/expense-api/prove.py` drives the known cross-tenant bug directly.

**Slice done — scanner candidates reach the independent verifier.** Added
`--seed-candidates FILE` to `sechelix audit` (`sechelix_runner/candidate_seed.py`,
14 unit tests). It maps normalized `adapters.cli` output into neutral verifier
candidates — claim, location, non-conclusive provenance (tool + rule) — and
**drops the scanner's severity/confidence** so the verifier reconstructs the
claim rather than trusting it. Proven live: seeding an OSV `CRITICAL`
(`GHSA-DEMO-0001` against a non-existent `package-lock.json`) into
`examples/expense-api` made the `verify` node applicable and it **ran on the
scanner candidate** ("every candidate is independently verified", spend $0.012).

**Resolved — structured output makes the verifier work end to end.** The first
seeded run ended `INCOMPLETE`: via the plain-prompt path neither qwen3.8-27b nor
gpt-4o-mini produced the strict verifier schema (one dropped the bound
`candidate_ref`, the other omitted `refutation_attempt`). The fix was **structured
output**: the HTTP providers now send `response_format: json_schema` built from a
`strictify()` of the node's own schema (`NODE_OUTPUT_SCHEMA` /
`VERIFIER_OUTPUT_SCHEMA`), proven first in isolation — qwen then echoed
`candidate_ref` verbatim and passed the real `validate_verifier_output` with zero
problems.

A second bug surfaced and was fixed in the seed mapper: it carried the adapter's
observation id into the candidate, the verifier cited it, and the binding check
correctly rejected a citation to evidence not in the least-context view. The id
is now dropped (a scanner candidate arrives with no reproduction evidence).

**Milestone — full differentiator loop, live.** `sechelix audit
examples/expense-api --executor openrouter --seed-candidates osv_norm.json` now
runs green: `map` → `architecture` → **`verify` SUCCEEDED** → **`gate`
SUCCEEDED**, "all mandatory nodes satisfied". The independent verifier classified
the scanner's `CRITICAL` as **`LIKELY_BUT_UNPROVEN` with empty `evidence_ids`** —
it refused to promote a scanner's say-so to `VERIFIED` without independent
evidence. Scanner candidate → independent verifier → evidence-based verdict →
release gate, end to end on a live model, is proven.
