# SecHelix production-readiness tracker

A durable, honest status for the "real pentest engine" effort so work can
resume without relying on chat memory. Status legend:

- **DONE** — implemented and verified in this checkout / CI.
- **PARTIAL** — some pieces work and are verified; others are not.
- **BLOCKED** — cannot proceed without a named prerequisite.
- **NOT STARTED** — not yet begun in this effort.
- **UNVERIFIED** — code exists but no real run proves it here.

A passing unit-test suite is **not** acceptance. Acceptance requires an observed
finding, a reproduction, independent verification, and retest evidence.

## Milestones

| # | Area | Status | Notes |
|---|------|--------|-------|
| 1 | CI runner security | **DONE** | Fork-PR approval set to `all_external_contributors`; posture in `SECHELIX-RUNNER-SECURITY.md`. No secrets/publishing on the runner. |
| 2 | Strix end-to-end (find/fix/retest) | **PARTIAL** | Engine runs for real via the FCC streaming path (67 streamed LLM calls, full recon + threat model + subagents). SecHelix fail-closes on timeout/partial and on scope escape. Deterministic find/fix/retest on expense-API proven with real HTTP evidence. Sandbox network isolation (`SECHELIX_STRIX_ISOLATE_NETWORK=1`) is now a **fail-closed, bounded-egress** boundary, hardened and proven: keeps Strix on its default network (Caido bootstraps normally), pauses the sandbox on detection, installs a **default-DROP** policy from inside its netns via a **pinned prebuilt** iptables sidecar (accept loopback + DNS + established + the single target port; drop everything else — other ports, siblings, **and the public internet**), then **unpauses and verifies from inside the sandbox** before the run is accepted; any failure aborts the run. Per-run ownership (baseline snapshot + atomic claim registry + startup reaper) means a scan never touches another scan's container. Live proof from a contained OpenRouter run: target reachable (200), gateway `:8082` + dead `:9999` + internet `1.1.1.1` all dropped, Caido up *despite the pause*, adapter accepted the run (`SCAN_EXIT=0`), coverage in scope, zero sandboxes/sidecars/claims left. 25 unit tests. See `STRIX-E2E-FINDINGS.md §A`. **Throughput gap closed** (faster model completes in budget). Remaining: Strix itself didn't surface the BOLA — the discovery gap (`gpt-4o-mini` guessed wrong endpoints). |
| 3 | Discovery gap (auto candidate generation) | **PARTIAL** | A deterministic-first discovery engine (`sechelix_runner/pentest/autodiscovery/`) now **discovers the expense-API BOLA unseeded** and refutes the SQL decoy, with real HTTP evidence. Given only the base URL, four tenant/role-labelled test identities, and the documented `GET /api/receipts` route, it builds a normalized endpoint inventory (infers the REST item endpoint, the resource id, and the `org_id` tenant field from observed responses), generates coverage-ranked hypotheses, and executes a cross-tenant IDOR matrix: it harvests the ids each identity may legitimately see, then tries them under another identity — the org-2 approver's own list reveals receipt 201, which the org-1 approver then reads (HTTP 200, `org_id=2`). It never receives the answer (a guard test asserts the source hardcodes neither the id nor seed data). CONFIRMED BOLA + REFUTED BFLA + REFUTED SQLi, 6 benchmark tests. Covers acceptance **C** and **D** on the fixture. **Not yet**: multi-framework route extraction (only documented-route + REST-inference so far), write/state-changing endpoints, and feeding the inventory to Strix as guidance. See `DISCOVERY-ENGINE.md`. |
| 4 | Providers | **PARTIAL** | OpenRouter: live-verified. Local reasoning gateway via the FCC path (`openai/...` Responses, SSE-first): **LIVE-VERIFIED** — streaming transport proven end-to-end through Strix. Nexus: untested. Remote wasm gateway (`deepseek-v4.1-flash`): still **LIVE_UNVERIFIED** (no confirmed key). |
| 5 | Code-review pipeline | **PARTIAL** | Scanner adapters exist and normalize evidence; no end-to-end benchmarked review proven here. |
| 6 | CLI / MCP experience | **PARTIAL** | Commands exist; a full unstitched assessment flow is not yet audited/verified. |
| 7 | Reliability + benchmark suite | **PARTIAL** | Unit coverage exists. Scope-escape is **detected and unit-tested** (coverage-record guard, validated against the real run) and **prevented** by the fail-closed bounded-egress isolation (proven live, Caido intact, verified-or-abort, concurrency-safe — see M2 / `STRIX-E2E-FINDINGS.md §A`). Injection, provider-switch, and SecHelix-vs-Strix benchmarks not measured. |
| 8 | security-runtime CI | **UNBLOCKED, not wired** | Docker is now available in WSL, so the container build can run; it must stay trusted-only (Docker socket = host root) and is not yet routed. |
| 9 | Acceptance scenarios A–F | **PARTIAL** | **C -> D -> E now stitched as one SecHelix-driven flow** (`autodiscovery.run_remediation`): discovery finds the expense-API BOLA unseeded; an *independent* verifier reproduces it on the vulnerable copy (CONFIRMED, HTTP 200), the reference fix is applied to an isolated copy, the verifier re-runs (REFUTED, HTTP 404), and the tenancy regression suite goes green — all from throwaway copies, real HTTP evidence (`test_remediation_flow.py`). The fix is now produced **two ways**, both held to the same before/after regression: the target's reference `fix.patch`, **and** a patch **synthesized deterministically from source** (`fix_synth.py`, `run_remediation(synthesize=True)`) — it localizes the unscoped lookup, binds the caller's `org_id` from the in-scope principal, or abstains; the synthesized-fix loop proves before-CONFIRMED / after-REFUTED / suite-green with the reference patch playing no part (`test_fix_synthesis.py` + the synthesized-loop tests). Dynamic-pentest via Strix (B): engine runs for real but Strix itself has not completed a bounded discovery; feeding the inventory to Strix is pending. |

## Next action

Milestone 2 completion. The engine runs for real, is **network-contained**
(egress firewall, Caido intact — proven live), and **completes in budget** on a
faster model. Both earlier blockers are resolved:

1. ~~**Throughput / model latency.**~~ **Solved.** On a faster model (OpenRouter
   `openai/gpt-4o-mini`, ~1 s/call) a contained run **completes within budget**;
   the slow local gateway timed out at 45 turns / 2000s. `STRIX-E2E-FINDINGS.md` §B.
2. ~~**Containment breaks Caido / is not a real boundary.**~~ **Solved and
   hardened.** The containment is now a fail-closed, bounded-egress boundary
   (default-DROP; drops the public internet too, not just sibling ports),
   proven-or-abort via in-sandbox verification, with a pinned prebuilt helper
   image and per-run ownership so concurrent scans can't interfere. Live proof:
   target reachable, gateway `:8082` + dead `:9999` + internet `1.1.1.1` all
   dropped, Caido bootstraps despite the pause, adapter accepts the run, clean
   teardown. `STRIX-E2E-FINDINGS.md` §A.

**Remaining — the discovery gap (next priority).** Strix completed a contained
run but did not drive the agent to the BOLA endpoint (`gpt-4o-mini` guessed
wrong paths). Closing this needs a deterministic-first discovery system (route
and attack-surface inventory feeding a coverage-aware hypothesis planner), not
merely a bigger model. Tracked as milestone 3 (discovery gap) and the vNext
plan; this is where engineering continues after the M0 containment hardening.

Do not upgrade the pinned engine unless compatibility tests justify it.
