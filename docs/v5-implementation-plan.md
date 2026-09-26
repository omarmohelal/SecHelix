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
| HTTP/API | Policy-gated request runner + same-origin redirect enforcement + secret-minimized exchange evidence + anonymous safe replay + cookie metadata + fresh authenticated-flow correlation + value-free response-security projection shipped | Add browser/proxy parity and richer correlation without persisting credential values |
| External scanners | Semgrep, curated JWT/session scout, Gitleaks and Trivy run through the gateway | Finish dependency audit/runtime image pinning and measured scanner contribution |
| Sandbox | Docker policy/executor exists | Build dedicated V5 image with pinned security tools |
| Tool gateway | Shipped and consumed by browser/API/static execution | Extend only through named capabilities; never add a generic shell |
| Business logic | Race/idempotency, stateful webhook replay, one-step forbidden state-transition, bounded payment duplicate-effect, multi-step prerequisite workflow, and cross-entity money-flow proofs shipped | Expand multi-party settlement/refund fixtures and broader workflow invariants |
| Multi-agent graph | Live graph exists | Converge names on V5 specialist graph; verifier stays separate |
| Evidence store | Run/engagement artifacts + exact scanner dedupe shipped | Add conservative correlation hints, then canonical finding evidence envelope/root-cause grouping |
| Fix/retest | Methodology exists | Executable fix command + original-proof replay |
| CI | Static Action/SARIF shipped | PR_SECURITY + scheduled STAGING_PENTEST |
| Evaluation | Protocol + CVE/blind suites + deterministic paired dynamic proof benchmark + evidence-backed Arena assessment packet builder shipped | Expand auth/session/browser dynamic pairs, then measure full workflow cost/time and verifier/gate metrics |
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

Current focused slice: safely reconstructible anonymous GET/HEAD/OPTIONS exchanges can now be replayed through the normal TargetScope, InteractionPolicy, gateway and redirect controls. Persisted replayability is revalidated rather than trusted, and any authentication context, body, sensitive header or redacted query forces a fresh operator-authorized request.\n\nCurrent focused slice: session revocation now has a fixed-shape LOCAL proof using a fresh operator-supplied fixture session plus an explicit local revocation hook. It records a successful protected-read control, revokes that exact fixture session, then replays the same session. Continued access is VULNERABLE_BEHAVIOR evidence; denial is SECURE_BEHAVIOR; a broken control or revocation hook is INCONCLUSIVE. Session headers remain ephemeral and never enter the artifact.\n\nCurrent focused slice: XSS now has an explicit Playwright-backed LOCAL marker proof. The payload is fixed by SecHelix, query-encoded, and limited to writing one deterministic window marker. Target scope is exact-loopback, browser requests pass through the policy gateway and read-only interaction policy, and the proof requires a declared sink selector so non-execution without sink reachability remains INCONCLUSIVE rather than a false clean result.\n\nCurrent focused slice: HTTP evidence now extracts security-relevant Set-Cookie attributes in memory while discarding cookie names and values. Evidence can record Secure, HttpOnly, SameSite class, Partitioned, root Path, Domain scoping, __Host-/__Secure- prefix class, deletion Max-Age and Expires presence. Multiple Set-Cookie headers are preserved as separate attribute observations; legacy evidence without this optional field remains readable. These are transport observations only and do not self-promote into session findings.\n\nCurrent focused slice: webhook proof can now accept an operator-supplied local state readback. A valid signed control must establish the declared single-application invariant; unsigned, invalid-signature and replay requests are then checked for additional state changes. HTTP acceptance alone remains inconclusive when no state readback exists. Only state digests enter evidence notes.\n\nCurrent focused slice: business-logic testing now includes a fixed-shape LOCAL state-transition proof. The operator declares the expected start state, the state that should remain safe, and one forbidden target state; SecHelix issues exactly one bounded POST and uses an operator-supplied local readback to decide whether that forbidden edge was reached. Starting-state mismatch or an unexpected intermediate state is INCONCLUSIVE, and only state digests enter evidence. A 2xx no-op is SECURE only for the declared transition invariant; it is not a global authorization or validation verdict.\n\nNext focused slice: expand paired dynamic coverage to auth/session/browser proof classes, then add full-workflow cost/time telemetry and verifier/gate measurement runs.


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



## XSS browser proof execution

SecHelix now has a bounded LOCAL browser proof for reflected XSS candidates. It
does not expose an arbitrary JavaScript execution API. The proof owns one fixed
benign payload that writes a deterministic string marker to a fixed window
property. The caller provides only the LOCAL URL template and the sink selector.

The target must be literal loopback and covered by the active network policy.
The browser receives an exact TargetScope plus PolicyToolGateway and read-only
InteractionPolicy; out-of-scope subresources are blocked. If the fixed marker
executes, the proof records VULNERABLE_BEHAVIOR. If the marker reaches the
declared sink only as inert text, it records SECURE_BEHAVIOR. If neither can be
established, the result remains INCONCLUSIVE. Raw rendered text and the injected
payload are not persisted in the proof artifact.


## Secret-free cookie security evidence

Authenticated HTTP analysis needs more than a boolean that a Set-Cookie header
was present, but storing cookie names or values would turn SecHelix evidence into
credential material. The HTTP recorder therefore parses Set-Cookie values only
in memory and persists a fixed security-attribute projection:

- Secure and HttpOnly;
- SameSite category;
- Partitioned;
- root Path and Domain scoping;
- whether the cookie used __Host- or __Secure- prefix semantics;
- Max-Age deletion and Expires presence.

Cookie names and values never enter the artifact. The metadata is evidence for a
session specialist, not a vulnerability verdict: preference cookies can
legitimately differ from authentication cookies, so independent context and
verification remain required.


## Stateful webhook replay proof

Webhook status codes are not enough to prove replay impact: an idempotent
endpoint may legitimately return 2xx for a repeated delivery. SecHelix can now
accept a LOCAL fixture state callback plus the expected single-application
state.

The proof establishes the valid signed control first, then sends unsigned,
incorrectly signed and replayed deliveries. The raw fixture state never enters
the artifact. SecHelix records only digests and classifies additional
side-effects after the valid control as VULNERABLE_BEHAVIOR evidence. If
unsigned/invalid deliveries are rejected and state remains at the supplied
single-application invariant through replay, the bounded replay check records
SECURE_BEHAVIOR. A bad-signature delivery that returns an accepted status but
produces no observed state change remains INCONCLUSIVE rather than being called
secure. Without readback, the existing conservative status-only behavior remains
unchanged and an accepted replay stays INCONCLUSIVE.


## Forbidden state-transition proof

SecHelix now has a bounded LOCAL proof for a single operator-declared business
workflow edge. It requires explicit fixture write authority and a deterministic
state readback. The operator supplies three invariants: the expected starting
state, the safe post-attempt state, and one forbidden target state.

The executor refuses to run if the fixture does not begin in the declared start
state. It then issues exactly one POST through the existing literal-loopback
network policy and reads state again. Reaching the forbidden state is
VULNERABLE_BEHAVIOR evidence; remaining in the declared safe state is
SECURE_BEHAVIOR for that bounded transition only; any other state is
INCONCLUSIVE. Raw workflow state and request credentials are not persisted —
only state digests and secret-minimized HTTP observations enter the proof
artifact. Independent verification is still required before finding promotion.


## Payment invariant proof

SecHelix now has a fixed-shape LOCAL proof for one operator-declared financial
effect. The fixture exposes an integer balance or liability readback in minor
units and the exact expected delta for one legitimate charge or refund.

The executor records the starting state, issues one bounded POST, and refuses to
continue if that control did not produce the declared single-operation delta.
Only after the control is proven does SecHelix replay the exact same request
once. If replay produces no additional financial effect, the bounded invariant
is SECURE_BEHAVIOR. If replay applies the same declared delta again, the result
is VULNERABLE_BEHAVIOR evidence for duplicate charge/refund behavior. Any other
financial movement is INCONCLUSIVE rather than guessed.

The primitive is direction-agnostic, so both charges and refunds are represented
as signed integer deltas. Raw balances, request bodies, authorization headers and
idempotency keys are never persisted in the proof artifact; state appears only
as digests. The proof requires explicit fixture write authority and financial
readback authority, remains LOCAL-only, and never promotes a finding without the
independent verifier.


## Fresh authenticated flow correlation

SecHelix can now join a freshly verified persona/browser context to
secret-minimized HTTP exchange evidence without persisting reusable credential
material. Correlation is exact and observation-only: the persisted
`authentication_context` label is not trusted by itself.

A row is produced only when all of these conditions hold:

- the persona login was positively verified in the current live world;
- the HTTP record names that exact `persona:<profile>` context;
- HTTP method matches;
- scheme, authority and path match;
- the ordered query parameter names match after independently redacted values
  are normalized away.

The correlation carries the persona name/role, browser and HTTP status,
evidence sequence references, and an explicit statement that no credential
material was persisted. It is always non-replayable from evidence and requires a
fresh session for further authenticated execution. Failed logins, stale context
labels, and mismatched surfaces do not correlate.

This is context for authentication/authorization/API/runtime specialists, not a
security verdict and not independent verification.


## Multi-step workflow prerequisite proof

SecHelix now has a bounded LOCAL proof for one operator-declared prerequisite in
a multi-step business workflow. The operator provides a deterministic start,
intermediate and final state, plus a local fixture reset hook and the state that
must remain after a denied shortcut.

The executor first proves the legitimate control path: step one must establish
the declared intermediate state and step two must establish the final state.
Only after that control succeeds does SecHelix invoke the operator-controlled
local reset hook and verify the fixture returned to the exact start state. It
then executes step two directly, without step one.

If the shortcut reaches the final state, the result is
VULNERABLE_BEHAVIOR evidence for prerequisite bypass. If the shortcut is denied
or accepted as a harmless no-op while the declared safe bypass state remains,
the bounded invariant is SECURE_BEHAVIOR. Broken controls, failed resets and
unexpected intermediate states remain INCONCLUSIVE.

The proof requires explicit fixture write, state-readback and reset authority.
It uses at most three mutation requests, remains LOCAL-only, persists only state
digests plus secret-minimized HTTP observations, and never promotes a finding
without independent verification.


## Rich HTTP response-security evidence

The bounded API transport recorder now persists a richer response projection
without storing response-header values, request-header values, bodies, cookies,
tokens or reusable credential material.

For each recorded exchange SecHelix can retain:

- elapsed request/response time in milliseconds;
- same-origin redirect count after every hop was re-authorized;
- a SHA-256 digest of the bounded response sample already read by the client;
- CORS allow-origin classification only: absent, wildcard, null,
  exact-request-origin, or other;
- allow-credentials and Vary: Origin presence;
- cache-control classes such as public/private/no-store/no-cache and whether a
  shared max-age directive exists;
- security-header presence/projection for CSP, frame-ancestors, X-Frame-Options,
  nosniff, HSTS, Referrer-Policy, Permissions-Policy, COOP, COEP and CORP.

Raw values such as allowed origins, HSTS ages, CSP directives, request origins,
cache ages and policy strings are intentionally discarded after in-memory
classification. The evidence remains observational: header presence or absence
does not automatically become a vulnerability verdict.

Legacy HTTP evidence without these optional fields remains loadable. Replay
authority is unchanged and still re-validates the original read-only,
anonymous, body-free and non-redacted invariants rather than trusting the
persisted replay flag.


## Dynamic proof primitive benchmark

SecHelix now has a deterministic LOCAL benchmark for five paired dynamic proof
families: one-step state transitions, duplicate payment/refund effects,
cross-entity money-flow idempotency, settlement/partial-refund lifecycle
idempotency, and multi-step workflow prerequisite enforcement. Every family has
one intentionally vulnerable fixture and one clean sibling.

The benchmark records expected and observed proof behavior, request count and
elapsed time per case, then reports aggregate case accuracy,
vulnerable-behavior recall, clean-behavior rejection rate and inconclusive rate.
It uses literal loopback only, no model, no external scanner, no credentials and
no finding promotion.

The result kind is explicitly `DYNAMIC_PROOF_PRIMITIVE_BENCHMARK` and
`is_full_sechelix_workflow=false`. It must not be used to claim end-to-end
SecHelix precision/recall, verifier accuracy, remediation quality or
release-gate accuracy. Those remain separate full-workflow measurements.


## Cross-entity money-flow invariant proof

SecHelix now has a bounded LOCAL proof for a single multi-entity financial
operation. The operator declares the exact expected delta vector across two to
eight named fixture entities and may also declare explicit forbidden vectors
for known misrouting or missing-counter-entry outcomes.

The executor snapshots every declared balance in integer minor units, performs
one bounded mutation, and computes the observed per-entity delta vector. If the
first mutation matches a declared forbidden vector, SecHelix records
VULNERABLE_BEHAVIOR evidence. If it matches neither the expected vector nor a
declared forbidden vector, the result remains INCONCLUSIVE.

Only after the expected first-operation vector is established does SecHelix
replay the exact request once. A zero replay vector is SECURE_BEHAVIOR for the
declared idempotency invariant; replaying the expected vector again, or reaching
an explicitly forbidden vector, is VULNERABLE_BEHAVIOR evidence.

Entity labels must remain stable throughout the proof. Raw balances, vectors,
request bodies and credential/header values never enter serialized evidence;
only digests and secret-minimized HTTP observations are persisted. The proof is
LOCAL-only, requires explicit fixture write and financial-readback authority,
and never promotes its own finding.


## Evidence-backed Arena workflow assessment

Arena full-workflow scoring now refuses naked per-case workflow booleans. Every
applicable judgment for applicability, verification, false-positive refutation,
root cause, regression proof, and release gate must include an evidence record
with a basis, stable references, and an artifact SHA-256 digest.

This closes a separate measurement weakness from evaluator independence: an
independent evaluator still must be attributable, but now the evaluator's own
case-level judgments are also attributable to concrete evidence. The harness
still cannot prove that an external artifact is truthful; it can prove that a
publishable score is bound to named, digest-stable evidence rather than an
unsupported assertion.

The full SecHelix workflow remains NOT_MEASURED until an uncontaminated,
independent evaluator completes the protocol. This slice strengthens the path to
that measurement; it does not manufacture the measurement itself.


## Settlement and partial-refund sequence proof

SecHelix now has a bounded LOCAL proof for one multi-party financial lifecycle:
an initial settlement followed by a refund. The operator declares the exact
cross-entity delta vector for each operation over the same stable set of
financial entities.

The executor proves the settlement control first, then replays that exact request
once and requires zero additional movement. Only after settlement idempotency is
established does it execute the declared refund, verify the exact refund vector,
and replay the refund once.

A repeated settlement or refund that applies the same declared money movement
again is VULNERABLE_BEHAVIOR evidence. A settlement/refund lifecycle in which
both first operations match their declared vectors and both exact replays produce
zero movement is SECURE_BEHAVIOR for this bounded invariant. Any unexpected
vector remains INCONCLUSIVE instead of being guessed.

This supports partial refunds naturally: the refund vector can reverse only a
declared fraction of worker/platform/provider/customer balances. The proof uses
2-8 entities, at most four LOCAL mutation requests, integer minor units only,
and explicit fixture write plus financial-readback authority. Raw balances,
headers, bodies and idempotency keys never enter the proof artifact.


The settlement/refund benchmark pair specifically proves that a valid settlement
is applied exactly once, then exercises a partial refund and checks that the
refund itself is also exactly-once. The vulnerable sibling keeps settlement
idempotent but applies the refund vector again on replay, so the pair measures
the refund-replay branch rather than merely rediscovering duplicate settlement.


## Arena assessment packet builder

SecHelix now includes a fail-closed helper for independent evaluators producing
full-workflow Arena assessments. The helper accepts explicit evaluator judgments
for every workflow field and binds each scored boolean to one or more local
artifacts.

Artifact files are read only to compute SHA-256 digests. The assessment output
contains stable evaluator-supplied references plus a canonical bundle digest; it
does not copy artifact bytes or absolute/local paths into the packet. Artifact
paths must remain under an explicit base directory, and missing files, path
escapes, duplicate refs, missing workflow fields, short bases, or evidence-free
booleans are rejected before Arena finalization.

`NOT_APPLICABLE` judgments remain evidence-free by design. The builder never
decides whether a participant is correct, never establishes evaluator
independence, and never changes Arena's contamination/blindness gates. Its
purpose is to make verifier, regression-proof and release-gate assessments
reproducibly attributable without turning self-authored assertions into a
measurement.
