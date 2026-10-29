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
| 2 | Strix end-to-end (find/fix/retest) | **PARTIAL** | Engine runs for real via the FCC streaming path (67 streamed LLM calls, full recon + threat model + subagents). SecHelix fail-closes on timeout/partial and now on scope escape. Deterministic find/fix/retest on expense-API proven with real HTTP evidence. Sandbox network isolation (`SECHELIX_STRIX_ISOLATE_NETWORK=1`) now **shipped and proven working**: keeps Strix on its default network (Caido bootstraps normally) and firewalls the sandbox's egress from inside its netns via an `iptables` sidecar — accept the target port, drop every other host-gateway port. Live proof from inside a running contained OpenRouter sandbox: target reachable (200), real `:8082` gateway + `:8070` blocked (timeout), Caido up, run completed in budget, clean teardown. (The earlier `--internal` topology blocked siblings but broke Caido; replaced.) **Throughput gap closed** too (faster model completes in budget). Remaining: Strix itself didn't surface the BOLA — a model-capability item (`gpt-4o-mini` guessed wrong endpoints). See `STRIX-E2E-FINDINGS.md`. |
| 3 | Discovery gap (auto candidate generation) | **NOT STARTED** | Live `audit` on the expense-API fixture ran mapping/architecture but produced no candidates without scanner seeding. Applicability graph needs work. |
| 4 | Providers | **PARTIAL** | OpenRouter: live-verified. Local reasoning gateway via the FCC path (`openai/...` Responses, SSE-first): **LIVE-VERIFIED** — streaming transport proven end-to-end through Strix. Nexus: untested. Remote wasm gateway (`deepseek-v4.1-flash`): still **LIVE_UNVERIFIED** (no confirmed key). |
| 5 | Code-review pipeline | **PARTIAL** | Scanner adapters exist and normalize evidence; no end-to-end benchmarked review proven here. |
| 6 | CLI / MCP experience | **PARTIAL** | Commands exist; a full unstitched assessment flow is not yet audited/verified. |
| 7 | Reliability + benchmark suite | **PARTIAL** | Unit coverage exists. Scope-escape is now **detected and unit-tested** (coverage-record guard, validated against the real run) and **prevented** by the egress-firewall isolation (proven live, Caido intact — see M2 / `STRIX-E2E-FINDINGS.md`). Injection, provider-switch, and SecHelix-vs-Strix benchmarks not measured. |
| 8 | security-runtime CI | **UNBLOCKED, not wired** | Docker is now available in WSL, so the container build can run; it must stay trusted-only (Docker socket = host root) and is not yet routed. |
| 9 | Acceptance scenarios A–F | **PARTIAL** | Fix-and-retest (C): real evidence recorded (expense-API BOLA, HTTP 200 leak -> patch -> HTTP 404, 8/8 tests). Dynamic-pentest (B): engine runs for real but did not complete a bounded discovery; others unverified. |

## Next action

Milestone 2 completion. The engine runs for real, is **network-contained**
(egress firewall, Caido intact — proven live), and **completes in budget** on a
faster model. Both earlier blockers are resolved:

1. ~~**Throughput / model latency.**~~ **Solved.** On a faster model (OpenRouter
   `openai/gpt-4o-mini`, ~1 s/call) a contained run **completes within budget**;
   the slow local gateway timed out at 45 turns / 2000s. `STRIX-E2E-FINDINGS.md` §B.
2. ~~**Containment breaks Caido.**~~ **Solved.** Replaced the `--internal`
   network with a default-network + in-netns `iptables` egress firewall sidecar.
   Live proof: inside a running contained sandbox the target is reachable while
   the real `:8082` gateway and `:8070` are blocked, Caido bootstraps, the run
   completes, teardown is clean. `STRIX-E2E-FINDINGS.md` §A.

Remaining to call the live discovery loop acceptance-complete: a reasoning model
strong enough to drive the agent to the BOLA endpoint (`gpt-4o-mini` completed
but guessed wrong paths). That is a model choice, not an engine/containment gap.

Do not upgrade the pinned engine unless compatibility tests justify it.
