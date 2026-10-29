# SecHelix readiness assessment — 2026-10-29

An honest, evidence-grounded answer to "what genuinely works, what is incomplete,
and what needs fixing", produced by reading the code and running the environment
(not by trusting the docs). Written against the mission brief's phases. Every
claim cites code (`file:line`) or an observed run; anything unverified is marked.

## Environment preflight (observed this session)

Tooling on the WSL Ubuntu-24.04 runner (`./.venv` Python 3.12.3):

| Tool | State |
|---|---|
| Docker engine | **UP** (29.8.1) |
| Node / npx | present (v22.23.2 / 10.8.2) |
| Semgrep, Gitleaks, Trivy, OSV-Scanner, CodeQL | **all MISSING** |
| Ollama | **MISSING** |

Consequence: the static-scanner adapters that exist in code **cannot actually run
here** until the binaries are installed, and the "local free model" path (Ollama)
is not available on this machine. This is an install gap, not a code gap.

## What is genuinely operational (verified)

- **Deterministic autodiscovery** (`sechelix_runner/pentest/autodiscovery/`) — the
  real end-to-end loop, proven this session on `examples/expense-api` with live
  HTTP: discover the cross-tenant BOLA unseeded → independently verify (CONFIRMED,
  HTTP 200) → **synthesize** the scoped-query fix from source → verify REFUTED
  (HTTP 404) → tenancy regression green. Tests: `test_discovery_engine` (6),
  `test_fix_synthesis` (9), `test_remediation_flow` (8). Zero model spend.
- **Independent verification is real and separated** — `autodiscovery/verifier.py`
  re-derives attacker/owner from fresh listings; scanner candidates re-enter the
  *same* verifier (`candidate_seed.py`), and the reasoning graph has a stripped
  `INDEPENDENT_VERIFIER` view (`providers/__init__.py:17`).
- **Strix adapter** — compatibility-gated (`require_compatible`,
  `strix_adapter.py:772`), scope-bounded (`TargetScope` is the authority), with
  **fail-closed bounded-egress containment** wired in (`firewalled_strix_sandbox`,
  entered at `strix_adapter.py:~940`; refuses the result if containment is
  unproven) and a coverage out-of-scope check (`coverage_out_of_scope_hosts:469`).
- **NEW this session — Strix guidance briefing** (`strix_briefing.py`): the
  deterministic inventory is injected as an advisory `--instruction` attack-surface
  map (endpoints, object model, ranked hypothesis *classes*, identity labels),
  deliberately carrying **no finding** — a unit test proves an answer-bearing
  report still yields a briefing with no confirmed object id and no verdict word,
  and that it cannot widen `--target`. Tests: `test_strix_briefing` (14).
- **Provider routing + accounting** — pluggable `ProviderExecutor`s
  (`claude-code`, `gemini-cli`, `openrouter`, `wasm-gateway`, `nexus`). OpenRouter
  is **live-verified** (chat, tool-calling, streaming, JSON mode, cost accounting —
  `SECHELIX-PROVIDERS.md`). **Per-run budget enforcement is real**
  (`budget.py` `BudgetGovernor.reserve/settle`, wired in `runner.py:464/478/722`).
- **Reporting** — SARIF 2.1.0, HTML, Markdown, JSON all render for real
  (`report.py:42/144/208/241`), with honest "incomplete" banners on partial
  coverage.
- **Static scanner adapters** — Semgrep, Gitleaks, Trivy are really invoked via
  `subprocess` and normalized to the common candidate shape
  (`static_tools.py:38/80/88/121/133`); results stay `CANDIDATE_ONLY`.

## Incomplete / needs fixing (prioritized)

1. **OSV-Scanner and CodeQL are parse-only** — adapters normalize a pre-existing
   report (`adapters/registry.py:17,19`) but nothing spawns the binary. The
   "5 scanners" story is really **3 invoked + 2 parse-only**. (Also: neither binary
   is installed here.)
2. **No cross-provider fallback** — one executor is selected per run
   (`pentest_service.py:210`); model-level fallback/preflight exists only on the
   FCC/Strix lane (`strix_adapter.py:151,276`), not the main reasoning providers.
   The brief's "provider fallback with approval" is unbuilt for that path.
3. **Budget can under-count** when a provider returns no `usage` block — cost is
   `None` and reservations settle against 0 actual (`base.py:15-17`,
   `runner.py:722`). A ceiling on a non-reporting provider is not a hard stop.
4. **`integrations/strix-compat.json` is decorative** — version gating uses the
   hardcoded `STRIX_TESTED_VERSION`/`..._COMMIT` constants (`strix_adapter.py:49-50`),
   not the JSON. The file can silently drift from the code's real pins.
5. **"Taint / trust-boundary" review is LLM-reasoning, not a deterministic engine**
   — the `INJECTION_DATAFLOW` role (`roles.py:22`) depends on provider quality;
   only the autodiscovery BOLA class is truly deterministic.
6. **wasm-gateway unverified** (no key) and **Ollama not a first-class provider**
   (string-referenced only). FCC loopback mode is built (`nexus-strix-security-mesh.md`).

## Cannot be completed in THIS environment (needs you)

- **Install the scanners** to run Phase-2A for real: `semgrep`, `gitleaks`,
  `trivy`, `osv-scanner` (and CodeQL where licensing permits). None are present.
- **Provider keys** are not exported in the non-interactive shell; a live
  reasoning/Strix run needs `SECHELIX_OPENROUTER_API_KEY` (or an FCC endpoint) and
  **spends money** — gated behind an explicit budget, not run unattended here.
- **GamingOps and The Nexus audits (Phase 5)** need their repos located and their
  identities/authorization confirmed; active testing only against isolated
  authorized environments, never production, never real transactions. Not started.

## Test evidence (this session)

- Targeted suites run green: autodiscovery discovery (6), fix synthesis (9),
  remediation loop (8), Strix briefing + adapter (50). 
- A full-tree `unittest discover` run was executed; note a pre-existing
  module-name collision surfaces one loader `ERROR` in discovery
  (`unittest.loader._FailedTest`) independent of these changes — the affected
  module imports cleanly on its own. Full-suite pass/fail is tracked separately.

## Honest bottom line

SecHelix is **substantially real** — an evidence-first architecture that is mostly
implemented, with a genuinely working deterministic discover→verify→fix→retest
core and a scope-bounded, contained Strix adapter. The gaps are specific and
nameable (two parse-only scanners, no main-path provider fallback, a budget
under-count edge, a decorative compat file), not structural. The largest barriers
to the brief's "end-to-end on a real target" acceptance are **operational, not
architectural**: scanners aren't installed, provider keys aren't present, and a
live LLM-guided Strix run costs money and must be explicitly budgeted.
