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
| 2 | Strix end-to-end (find/fix/retest) | **PARTIAL** | Engine runs for real via the FCC streaming path (67 streamed LLM calls, full recon + threat model + subagents). SecHelix fail-closes on timeout/partial and now on scope escape. Deterministic find/fix/retest on expense-API proven with real HTTP evidence. Sandbox network isolation (`SECHELIX_STRIX_ISOLATE_NETWORK=1`: internal net + target-only proxy) **blocks siblings as proven** (unreachable at socket and direct-curl layers) but **is not yet assessment-ready**: the `--internal` topology also severs the host→sandbox path Strix needs to drive Caido, so its HTTP proxy fails to bootstrap and a contained run assesses nothing — needs a topology fix (egress firewall, not blanket `--internal`). **Throughput gap closed:** on a faster model (OpenRouter `gpt-4o-mini`, ~1 s/call) the run completes in budget; the slow local model timed out. BOLA still not surfaced by Strix itself (blocked by the Caido limitation under isolation). See `STRIX-E2E-FINDINGS.md`. |
| 3 | Discovery gap (auto candidate generation) | **NOT STARTED** | Live `audit` on the expense-API fixture ran mapping/architecture but produced no candidates without scanner seeding. Applicability graph needs work. |
| 4 | Providers | **PARTIAL** | OpenRouter: live-verified. Local reasoning gateway via the FCC path (`openai/...` Responses, SSE-first): **LIVE-VERIFIED** — streaming transport proven end-to-end through Strix. Nexus: untested. Remote wasm gateway (`deepseek-v4.1-flash`): still **LIVE_UNVERIFIED** (no confirmed key). |
| 5 | Code-review pipeline | **PARTIAL** | Scanner adapters exist and normalize evidence; no end-to-end benchmarked review proven here. |
| 6 | CLI / MCP experience | **PARTIAL** | Commands exist; a full unstitched assessment flow is not yet audited/verified. |
| 7 | Reliability + benchmark suite | **PARTIAL** | Unit coverage exists. Scope-escape is now **detected and unit-tested** (coverage-record guard, validated against the real run) and **network-blocked** by isolation (proven), though that isolation is not yet assessment-ready (breaks Caido — see M2 / `STRIX-E2E-FINDINGS.md`). Injection, provider-switch, and SecHelix-vs-Strix benchmarks not measured. |
| 8 | security-runtime CI | **UNBLOCKED, not wired** | Docker is now available in WSL, so the container build can run; it must stay trusted-only (Docker socket = host root) and is not yet routed. |
| 9 | Acceptance scenarios A–F | **PARTIAL** | Fix-and-retest (C): real evidence recorded (expense-API BOLA, HTTP 200 leak -> patch -> HTTP 404, 8/8 tests). Dynamic-pentest (B): engine runs for real but did not complete a bounded discovery; others unverified. |

## Next action

Milestone 2 completion. The engine runs for real; two things (down from the
original list) block calling the live Strix discovery loop acceptance-complete,
now cleanly separated:

1. ~~**Throughput / model latency.**~~ **Solved.** On a faster model (OpenRouter
   `openai/gpt-4o-mini`, ~1 s/call) a contained run **completes within budget**
   (`run_status: completed`); the slow local gateway timed out at 45 turns /
   2000s. Wiring in `STRIX-E2E-FINDINGS.md` §B.
2. **Containment breaks Caido (now the blocker).** The `--internal` network
   blocks siblings as proven, but it also severs the host→sandbox control path
   Strix uses to drive **Caido** (its HTTP-intercept proxy on port 48080), so
   Caido fails to bootstrap and the agent assesses nothing — a contained run
   completes having found nothing *for this reason*, not latency. Needs a
   topology that blocks only sandbox→other-host-services while leaving
   host→sandbox:48080 and sandbox→target intact (egress firewall via the
   sandbox's `NET_ADMIN` cap, not a blanket `--internal` network). Until then,
   confirm "Strix itself finds the BOLA" with a fast model and **isolation off**.
   See `STRIX-E2E-FINDINGS.md` §A "Known limitation".

Do not upgrade the pinned engine unless compatibility tests justify it.
