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
| 2 | Strix end-to-end (find/fix/retest) | **NOT STARTED** | Docker now reachable in WSL (daemon up); next: materialize pinned Strix, run a real local assessment through SecHelix against a disposable vulnerable app. |
| 3 | Discovery gap (auto candidate generation) | **NOT STARTED** | Live `audit` on the expense-API fixture ran mapping/architecture but produced no candidates without scanner seeding. Applicability graph needs work. |
| 4 | Providers | **PARTIAL** | OpenRouter: live-verified. wasm gateway (`deepseek-v4.1-flash`): **LIVE_UNVERIFIED** (no confirmed key). Nexus/FCC tool-calling + budget: untested. |
| 5 | Code-review pipeline | **PARTIAL** | Scanner adapters exist and normalize evidence; no end-to-end benchmarked review proven here. |
| 6 | CLI / MCP experience | **PARTIAL** | Commands exist; a full unstitched assessment flow is not yet audited/verified. |
| 7 | Reliability + benchmark suite | **PARTIAL** | Unit coverage exists; scope-escape, injection, provider-switch, and SecHelix-vs-Strix benchmarks not measured. |
| 8 | security-runtime CI | **UNBLOCKED, not wired** | Docker is now available in WSL, so the container build can run; it must stay trusted-only (Docker socket = host root) and is not yet routed. |
| 9 | Acceptance scenarios A–F | **UNVERIFIED** | None of static-review, dynamic-pentest, fix-and-retest, provider-reliability, CI, or fresh-install have a recorded real run yet. |

## Next action

Milestone 2: prove the complete local **Strix -> SecHelix** finding / fix /
retest loop against a disposable intentionally vulnerable web app, with real
request/response or runtime evidence, independent verification, and a retest.
Verify Docker connectivity and the pinned Strix contract first; do not upgrade
the pinned engine unless compatibility tests justify it.
