# V5 implementation plan — safe dynamic AppSec

This is the single canonical V5 implementation plan. It preserves SecHelix's
evidence-first architecture: **CANDIDATE → independent verifier tries to
DISPROVE → VERIFIED only with evidence → root-cause fix → regression → retest**.

## Research baseline

Architecture/pattern research was performed against the current
`usestrix/strix` plus `KeygraphHQ/shannon`, `Tashima-Tarsh/Pentagi`,
`GreyDGL/PentestGPT`, and the archived `aliasrobotics/cai`. Research is
pattern-level only. No third-party source is copied. Strix is Apache-2.0;
Shannon/PentAGI/PentestGPT licensing must be checked at the exact revision before
any reuse; CAI contains proprietary/research-only additions and is therefore
reference-only.

The useful patterns are isolated runtimes, browser + proxy observation,
specialized agents, explicit PoC validation, persistent run artifacts,
multi-provider execution, and operator-visible progress. SecHelix keeps a
stricter difference: a finder cannot verify its own finding and target authority
is a hard boundary outside model control.

## Gap analysis and convergence order

| Capability | Current baseline | V5 convergence |
|---|---|---|
| Evidence-first verification | Shipped | Preserve; independent verifier remains mandatory |
| Scope boundary | Policy gateway shipped for LOCAL/STAGING browser/API/static execution | Keep every new executor behind the same gateway |
| Browser/auth/personas | Browser/API authority, persona matrix, declared authz probes and bounded LOCAL CSRF proof shipped | Add explicit Playwright XSS execution + session rotation/revocation fixtures and richer state capture |
| HTTP/API | Policy-gated request runner + same-origin redirect enforcement + secret-minimized exchange evidence + anonymous safe replay executor shipped | Add authenticated CSRF/XSS/session replay fixtures and richer proxy evidence |
| External scanners | Semgrep, curated JWT/session scout, Gitleaks and Trivy run through the gateway | Finish dependency audit/runtime image pinning and measured scanner contribution |
| Sandbox | Docker policy/executor exists | Build dedicated V5 image with pinned security tools |
| Tool gateway | Shipped and consumed by browser/API/static execution | Extend only through named capabilities; never add a generic shell |
| Business logic | Specialist graph exists | Add idempotency/race/payment/webhook/state-machine fixtures |
| Multi-agent graph | Live graph exists | Converge names on V5 specialist graph; verifier stays separate |
| Evidence store | Run/engagement artifacts + exact scanner dedupe shipped | Add conservative correlation hints, then canonical finding evidence envelope/root-cause grouping |
| Fix/retest | Methodology exists | Executable fix command + original-proof replay |
| CI | Static Action/SARIF shipped | PR_SECURITY + scheduled STAGING_PENTEST |
| Evaluation | Protocol + CVE/blind suites | Dynamic vulnerable/decoy benchmark and cost/time metrics |
| Cost control | Budgets/routing exist | Provider tiers, repository-map cache, per-run token/cost ledger |
| UX | CLI + live pentest CLI exist | Unify audit/pentest/fix/replay/report/coverage and TUI status |

## Spec Kit flow

**Specify:** V5 is an authorized AppSec platform, not an internet scanner.
Dynamic execution requires explicit target scope and auditable authority.

**Clarify:** CAPTCHA bypass is out of scope. Use staging/test bypass, saved
authenticated state, or a human checkpoint. Production remains non-destructive
and must not inherit STAGING authority implicitly.

**Plan:** land focused PRs in dependency order: gateway → sandbox/tool image →
static/supply-chain adapters → HTTP/proxy → authenticated browser fixtures →
business-logic runner → evidence/dedupe → fix/retest → CI modes → benchmarks →
cost routing → unified UX.

**Tasks:** every PR adds negative tests proving scope escape, secret leakage,
destructive defaults, or finder-self-verification cannot occur.

**Analyze:** compare measured benchmark deltas, not feature counts. A scanner
signal remains CANDIDATE/UNASSESSED until SecHelix verification.

**Implement:** prefer thin adapters around reviewed tools. Never add a generic
agent-facing shell. Keep raw credentials out of persisted evidence.

**Converge:** remove superseded V5 TODOs rather than creating parallel plans;
update this file and the public capability matrix as slices become measured.

## Current slice acceptance criteria

Scanner evidence now has two deliberately different noise controls:

1. exact normalized duplicate observations are collapsed while preserving a
   duplicate count; and
2. separate observations may be **correlated** only when they share an exact
   source location plus an explicit catalog hypothesis, CWE mapping, or exact
   normalized claim.

Correlation never removes the original evidence, never invents a root cause,
never becomes `VERIFIED`, and never treats two tools as independent verifiers.
The output exists to reduce repeated navigation/reasoning while preserving
provenance.

Current focused slice: remediation/retest now has an executable `sechelix fix-check` surface over the existing scratch-workspace runner. It runs only named, policy-gated tests in the network-disabled sandbox, consumes explicit differential-review and independent-verification evidence, refuses the caller's current working tree, and can reach `READY_FOR_REVIEW` only when every canonical remediation stage passed. It never applies the patch.\n\nCurrent focused slice: the HTTP/API client now has a secret-minimized exchange recorder behind the existing policy/scope controls. It persists method, redacted URL, status, content type, header names, body sizes and auth-context labels, never header values/cookies/bodies. Replayability is marked only for read-only exchanges that can be reconstructed without secret or query data.

Current focused slice: safely reconstructible anonymous GET/HEAD/OPTIONS exchanges can now be replayed through the normal TargetScope, InteractionPolicy, gateway and redirect controls. Persisted replayability is revalidated rather than trusted, and any authentication context, body, sensitive header or redacted query forces a fresh operator-authorized request.\n\nCurrent focused slice: session revocation now has a fixed-shape LOCAL proof using a fresh operator-supplied fixture session plus an explicit local revocation hook. It records a successful protected-read control, revokes that exact fixture session, then replays the same session. Continued access is VULNERABLE_BEHAVIOR evidence; denial is SECURE_BEHAVIOR; a broken control or revocation hook is INCONCLUSIVE. Session headers remain ephemeral and never enter the artifact.\n\nNext focused slice: add explicit Playwright-backed LOCAL XSS marker execution with the same scope/policy/evidence boundaries; then extend authenticated session rotation/revocation coverage beyond the deterministic fixture path.


## CSRF proof execution

SecHelix now has a fixed-shape LOCAL-only CSRF proof class. It requires both an
authenticated fixture session and fixture write authority. The proof sends one
same-origin control and one otherwise identical form-compatible request with a
fixed foreign Origin, using only a loopback target covered by the active network
grant. Session headers are ephemeral inputs and never appear in the proof
artifact.

The result is deliberately narrow: accepting the foreign-origin request is
VULNERABLE_BEHAVIOR evidence, denying it while the control succeeds is
SECURE_BEHAVIOR evidence, and an unusable control is INCONCLUSIVE. The proof
does not promote a finding; independent verification still establishes attacker
control, reachability and the broken boundary.


## Session revocation proof execution

SecHelix now has a fixed-shape LOCAL-only session revocation proof. It requires
both an authenticated fixture session and explicit fixture-session revocation
authority. The operator supplies a deterministic local revocation hook; SecHelix
does not invent a logout/reset endpoint or persist the session material.

The proof first establishes that the protected read works, invokes the local
revocation hook, then replays the exact same session against the same resource.
If the replay is denied, the result is SECURE_BEHAVIOR. If it still reaches the
protected resource, the result is VULNERABLE_BEHAVIOR evidence for stale
authority or incomplete revocation propagation. A failed control or revocation
hook is INCONCLUSIVE. Independent verification is still required before a
finding can become VERIFIED.

