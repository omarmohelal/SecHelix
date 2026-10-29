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
| 2 | Strix end-to-end (find/fix/retest) | **PARTIAL** | Engine runs for real via the FCC streaming path (67 streamed LLM calls, full recon + threat model + subagents). SecHelix fail-closes on timeout/partial and now on scope escape. Deterministic find/fix/retest on expense-API proven with real HTTP evidence. Sandbox network isolation now **shipped and empirically proven** (`SECHELIX_STRIX_ISOLATE_NETWORK=1`: internal net + target-only proxy; siblings unreachable at socket and direct-curl layers). **Remaining gap:** a live Strix discovery run did not complete within budget (model latency) so it did not itself surface the BOLA. See `STRIX-E2E-FINDINGS.md`. |
| 3 | Discovery gap (auto candidate generation) | **NOT STARTED** | Live `audit` on the expense-API fixture ran mapping/architecture but produced no candidates without scanner seeding. Applicability graph needs work. |
| 4 | Providers | **PARTIAL** | OpenRouter: live-verified. Local reasoning gateway via the FCC path (`openai/...` Responses, SSE-first): **LIVE-VERIFIED** — streaming transport proven end-to-end through Strix. Nexus: untested. Remote wasm gateway (`deepseek-v4.1-flash`): still **LIVE_UNVERIFIED** (no confirmed key). |
| 5 | Code-review pipeline | **PARTIAL** | Scanner adapters exist and normalize evidence; no end-to-end benchmarked review proven here. |
| 6 | CLI / MCP experience | **PARTIAL** | Commands exist; a full unstitched assessment flow is not yet audited/verified. |
| 7 | Reliability + benchmark suite | **PARTIAL** | Unit coverage exists. Scope-escape is now **detected and unit-tested** (coverage-record guard, validated against the real run) *and prevented* (network isolation, proof in `STRIX-E2E-FINDINGS.md`). Injection, provider-switch, and SecHelix-vs-Strix benchmarks not measured. |
| 8 | security-runtime CI | **UNBLOCKED, not wired** | Docker is now available in WSL, so the container build can run; it must stay trusted-only (Docker socket = host root) and is not yet routed. |
| 9 | Acceptance scenarios A–F | **PARTIAL** | Fix-and-retest (C): real evidence recorded (expense-API BOLA, HTTP 200 leak -> patch -> HTTP 404, 8/8 tests). Dynamic-pentest (B): engine runs for real but did not complete a bounded discovery; others unverified. |

## Next action

Milestone 2 completion. The engine runs for real and is now network-contained;
one thing blocks calling the live Strix discovery loop acceptance-complete:

1. ~~**Network isolation.**~~ **Done.** `SECHELIX_STRIX_ISOLATE_NETWORK=1` puts
   the sandbox on a per-run `--internal` Docker network with a single dual-homed
   proxy to the authorized target (the LLM reasoning is host-side, so nothing
   else needs to be reachable). Proven from inside the real sandbox image:
   target reachable via the proxy, every host loopback service unreachable at
   both the raw-socket and direct-curl layers. The coverage-record guard remains
   as defense-in-depth. See `STRIX-E2E-FINDINGS.md`.
2. **Budget/latency (remaining).** At the current gateway model's latency a
   quick scan did not finish in 13 min / 25 turns. Either raise the
   wall-clock/turn budget on a contained run or use a faster model, then confirm
   Strix itself surfaces the expense-API BOLA.

Do not upgrade the pinned engine unless compatibility tests justify it.
