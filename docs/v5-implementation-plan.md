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
| HTTP/API | Policy-gated request runner + same-origin redirect enforcement + secret-minimized exchange evidence + anonymous safe replay + cookie metadata + fresh authenticated-flow correlation + shared browser/direct-HTTP response-security projection + observational parity comparison shipped | Add deeper proxy provenance without persisting credential values |
| External scanners | Semgrep, curated JWT/session scout, Gitleaks and Trivy run through the gateway; isolated scanner ablations are measurable; Gitleaks/Trivy release archives and the Semgrep/pip-audit Python graph are SHA-256 hash locked | Keep scanner/runtime provenance current and publish image provenance |
| Sandbox | Docker policy/executor + dedicated V5 security runtime exist; base image is digest-pinned, Python dependencies install with `--require-hashes`, the final stage excludes download tooling, CI emits a lock-derived CycloneDX runtime SBOM evidence bundle, and manual-main publication can push an immutable GHCR digest with SLSA provenance + SBOM attestations | Keep publication explicit, immutable and fail-closed; never infer published provenance from local CI evidence |
| Tool gateway | Shipped and consumed by browser/API/static execution | Extend only through named capabilities; never add a generic shell |
| Business logic | Race/idempotency, stateful webhook replay, one-step forbidden state-transition, bounded payment duplicate-effect, multi-step prerequisite workflow, and cross-entity money-flow proofs shipped | Expand multi-party settlement/refund fixtures and broader workflow invariants |
| Multi-agent graph | Live graph exists | Converge names on V5 specialist graph; verifier stays separate |
| Evidence store | Run/engagement artifacts + exact scanner dedupe shipped | Add conservative correlation hints, then canonical finding evidence envelope/root-cause grouping |
| Fix/retest | Methodology exists | Executable fix command + original-proof replay |
| CI | Static Action/SARIF shipped | PR_SECURITY + scheduled STAGING_PENTEST |
| Evaluation | Protocol + CVE/blind suites + paired LOCAL benchmark covering every bounded proof class + real-browser XSS/session integrations + evidence-backed Arena assessment/batch/prediction-freeze builders shipped | Complete an uncontaminated independent full-workflow run, then extend production-like fixture tiers |
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

Current focused slice: safely reconstructible anonymous GET/HEAD/OPTIONS exchanges can now be replayed through the normal TargetScope, InteractionPolicy, gateway and redirect controls. Persisted replayability is revalidated rather than trusted, and any authentication context, body, sensitive header or redacted query forces a fresh operator-authorized request.\n\nCurrent focused slice: session revocation now has a fixed-shape LOCAL proof using a fresh operator-supplied fixture session plus an explicit local revocation hook. It records a successful protected-read control, revokes that exact fixture session, then replays the same session. Continued access is VULNERABLE_BEHAVIOR evidence; denial is SECURE_BEHAVIOR; a broken control or revocation hook is INCONCLUSIVE. Session headers remain ephemeral and never enter the artifact.\n\nCurrent focused slice: XSS now has an explicit Playwright-backed LOCAL marker proof. The payload is fixed by SecHelix, query-encoded, and limited to writing one deterministic window marker. Target scope is exact-loopback, browser requests pass through the policy gateway and read-only interaction policy, and the proof requires a declared sink selector so non-execution without sink reachability remains INCONCLUSIVE rather than a false clean result.\n\nCurrent focused slice: HTTP evidence now extracts security-relevant Set-Cookie attributes in memory while discarding cookie names and values. Evidence can record Secure, HttpOnly, SameSite class, Partitioned, root Path, Domain scoping, __Host-/__Secure- prefix class, deletion Max-Age and Expires presence. Multiple Set-Cookie headers are preserved as separate attribute observations; legacy evidence without this optional field remains readable. These are transport observations only and do not self-promote into session findings.\n\nCurrent focused slice: webhook proof can now accept an operator-supplied local state readback. A valid signed control must establish the declared single-application invariant; unsigned, invalid-signature and replay requests are then checked for additional state changes. HTTP acceptance alone remains inconclusive when no state readback exists. Only state digests enter evidence notes.\n\nCurrent focused slice: business-logic testing now includes a fixed-shape LOCAL state-transition proof. The operator declares the expected start state, the state that should remain safe, and one forbidden target state; SecHelix issues exactly one bounded POST and uses an operator-supplied local readback to decide whether that forbidden edge was reached. Starting-state mismatch or an unexpected intermediate state is INCONCLUSIVE, and only state digests enter evidence. A 2xx no-op is SECURE only for the declared transition invariant; it is not a global authorization or validation verdict.\n\nCurrent focused slice: Arena publication is now freeze-bound. Finalization requires the exact prediction-freeze artifact, validates the generated blindness schema and reveal ordering, checks prediction/freeze digest continuity, and proves that the freeze names the same prepared packet and participant. A hand-authored blindness JSON can no longer make a full-workflow record publishable on booleans and digest-shaped strings alone.

Current focused slice: published runtime image provenance is now explicit and fail-closed. The security-runtime workflow keeps normal push/PR runs verify-only; a manual workflow dispatch on `main` with `publish=true` is the only path that can publish. It pushes one immutable GHCR tag bound to the commit SHA, then generates both SLSA build-provenance and CycloneDX SBOM attestations against the exact pushed digest. Publication permissions exist only on that gated job, and no mutable `latest` tag is written.\n\nCurrent focused slice: benchmark fixture realism now has a conservative, machine-validated tier registry. Static pairs, bounded LOCAL primitives and real-browser integrations are distinguished from planned stateful/composite LOCAL application tiers. Higher-tier claims fail closed unless durable state, multi-step workflow, deterministic reset, persona count, service count and asynchronous-boundary requirements are explicitly satisfied. Tier depth never establishes production effectiveness or substitutes for independent Arena measurement.\n\nCurrent focused slice: the first deterministic `STATEFUL_APPLICATION` fixture is now executable. It is literal-loopback only, uses SQLite durable state, three distinct fixture personas, a multi-step request → approve → settle refund workflow, role/prerequisite enforcement, and deterministic reset. Its self-test measures fixture integrity only and explicitly does not establish SecHelix discovery/verifier/remediation/release-gate accuracy or production effectiveness.

Current focused slice: the first deterministic `COMPOSITE_APPLICATION` fixture is now executable as two distinct literal-loopback services over shared durable SQLite state. The workflow service produces a refund-settlement outbox event and a separate ledger-worker service consumes it exactly once, creating an explicit asynchronous boundary with deterministic reset. Its self-test measures only fixture topology/invariants; it does not establish SecHelix or production effectiveness.

Current focused slice: independent-verifier output is now a typed, fail-closed handoff rather than another hunter-style candidate list. Every neutralized candidate receives a deterministic SHA-256 candidate_ref and must be assessed exactly once. The verifier cannot change the bound claim/location, cannot invent evidence references outside its least-context view, and VERIFIED requires stable supporting evidence. These assessments are promoted only as verifier_assessments; they never auto-promote into canonical finding-v1 records, severity, remediation, or a release decision.

Next focused slice: materialize canonical finding-v1 records from typed verifier assessments only when all required evidence-chain and report fields are independently available, then add REMEDIATOR and PATCH_VERIFIER to the full-workflow graph and bind the stateful/composite fixtures through remediation, regression proof and the canonical release gate. Only after that path is complete should the freeze-bound independent Arena run measure the end-to-end workflow. Complete-packet cost/time aggregation, runtime provenance, fixture-tier validation, and deterministic stateful/composite LOCAL fixtures are shipped; synthetic latency/concurrency and fixture self-tests remain non-production measurements.


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




## Auth/session/browser dynamic pairs

The deterministic LOCAL dynamic proof benchmark now includes four additional
vulnerable/clean pairs beyond the existing business-logic and payment families:

- authorization IDOR: foreign identity receives the owner's object versus an
  explicit denial;
- CSRF: a cross-origin form-compatible authenticated request is accepted versus
  an Origin-enforcing fixture;
- session revocation: the same revoked session continues to reach a protected
  resource versus immediate denial after the operator-controlled revocation
  hook;
- XSS marker classification: the fixed benign marker executes versus reaches
  the declared sink only as inert text.

These remain proof-primitive measurements, not full SecHelix workflow scores.
The IDOR, CSRF and session pairs exercise the literal-loopback HTTP executor.
The XSS pair intentionally uses a deterministic browser fixture adapter so CI can
measure proof classification without claiming Playwright/browser-engine
compatibility. Real browser-engine compatibility stays a separate integration
benchmark.

The benchmark therefore grows from 10 to 18 benchmark executions spanning nine
paired proof families while preserving the existing result kind,
`DYNAMIC_PROOF_PRIMITIVE_BENCHMARK`, and
`is_full_sechelix_workflow=false`.

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


## Arena run telemetry

SecHelix now has a deterministic adapter from a completed `RunResult.to_dict()`
artifact to Arena run metadata. It records wall-clock elapsed time, node status
counts, provider/model sets, aggregate input/output tokens and cost only when
those fields are complete, and the actual independent-verifier and release-gate
node records.

Missing telemetry is represented as `NOT_MEASURED`, never silently summed from
only the nodes that happened to report it and never coerced to zero. Blocked and
skipped nodes that did not execute provider work are excluded from token/cost
completeness denominators. Failed or incomplete executed nodes still count: if
their operational telemetry is missing, the aggregate remains unmeasured.

The adapter also SHA-256 binds the generated metadata to the source run artifact.
These are operational measurements only. Verifier and release-gate correctness
still requires a blinded, independent, evidence-backed Arena assessment; the
telemetry adapter cannot turn a self-assessed run into a measured workflow
result.


## Arena workspace evidence index

Full-workflow assessment can now bind itself to an intact persisted SecHelix run
workspace rather than to loose copied snippets. The Arena workspace helper first
verifies the run's `manifest.json`; changed, missing, or newly injected files
cause a hard failure.

For an intact run it emits SHA-256 identities for `run.json`, `graph.json`,
`replay/outcomes.json`, and the manifest itself. It also maps graph roles to
digest-only records for independent verifier, release gate, remediator and patch
verifier outputs, preserving status, evidence IDs and operational telemetry
without copying output bodies into the index.

This closes an attribution gap in upcoming verifier/gate measurement runs: an
independent evaluator can cite a stable evidence index and the original redacted
workspace while Arena still decides measurement eligibility separately.
Workspace integrity is not correctness, and this helper does not score or
promote any finding.


## Real-browser XSS integration benchmark

SecHelix now has a separate optional benchmark for the actual
`SafeAuthorizedBrowser` / Playwright Chromium path used by the bounded XSS
proof. A literal-loopback server exposes one reflected executable sink and one
HTML-escaped inert sink; the same fixed SecHelix marker proof must distinguish
both.

The integration harness is deliberately fail-closed about infrastructure.
Missing Playwright or Chromium yields `BLOCKED_BY_ENVIRONMENT`, not a false
clean result and not a fabricated measurement. A measured result requires both
the vulnerable and clean browser-engine cases to match their declared behavior.

This benchmark is intentionally separate from the deterministic 9-family proof
primitive suite: CI can keep the primitive classification suite stable while an
operator with the optional web runtime can measure real browser compatibility.
It still does not measure discovery, independent verification, remediation or
release-gate correctness.


## Real-browser session integration benchmark

SecHelix now has a second optional real-browser integration benchmark focused on
imported authenticated sessions and browser-context isolation. A literal-loopback
fixture exposes one protected selector. One fresh browser context receives a
valid ephemeral fixture cookie and must verify the protected surface; a separate
context receives an invalid cookie and must not verify it.

The browser contexts use the normal `TargetScope`, `InteractionPolicy`,
`PolicyToolGateway`, `ResolvedAccess` and `SessionProbe` path. Session
values never enter the benchmark artifact. Missing Playwright or Chromium is
reported as `BLOCKED_BY_ENVIRONMENT`, never interpreted as a clean session
result.

This measures session import/isolation and positive/negative protected-surface
verification only. It does not replace the bounded session-revocation proof and
does not claim full-workflow SecHelix accuracy.


## Real-browser session revocation integration

The optional real-browser session benchmark now covers both imported-session
isolation and server-side revocation using the actual
`SafeAuthorizedBrowser` / Playwright Chromium path when the environment
provides it.

Two new literal-loopback cases reuse the same browser context before and after a
deterministic operator-controlled revocation event:

- the intentionally vulnerable fixture continues to authorize the exact same
  session after revocation;
- the clean fixture re-checks server-side session state and denies the same
  browser session immediately after revocation.

The benchmark records only booleans, challenge class, elapsed time and case
identity. Cookie values remain execution-only inputs and never enter the result
artifact. Missing Playwright/Chromium is `BLOCKED_BY_ENVIRONMENT`, never
misreported as a clean security result.

This is still an integration benchmark for a bounded browser/session primitive,
not end-to-end SecHelix verifier or release-gate accuracy.


## Secret-free redirect trace evidence

Authorized API evidence now retains the shape of same-origin redirect chains
without persisting redirect query values or credential material. Each hop records
only the 3xx status, source and destination methods, and independently redacted
source/destination URLs.

The API redirect handler still re-authorizes every hop through scope,
interaction policy and the tool gateway before following it. Cross-origin
credential forwarding remains blocked. The evidence recorder validates that the
declared redirect count exactly matches the supplied hop sequence and refuses
non-3xx hop records.

This makes method-changing redirects such as POST -> GET visible to later
analysis while preserving the existing evidence boundary: query values, header
values, cookies and bodies are not stored. Redirect traces are observations, not
security verdicts.


## Complete bounded proof-class benchmark coverage

The deterministic LOCAL dynamic benchmark now has paired vulnerable/clean
fixtures for every bounded proof class implemented by `LocalProofExecutor`.
The benchmark adds race/idempotency, webhook signature/replay, path traversal
and SSRF callback pairs to the existing authorization, browser/session,
business-logic and money-flow families.

Each case records the actual proof class emitted by the executor. The result
contains an explicit covered-class list, missing-class list and
`proof_class_coverage` metric; CI expects coverage to remain 1.0 as new proof
classes are added. This prevents feature growth from silently outrunning the
dynamic measurement suite.

The result remains a proof-primitive benchmark, not a full SecHelix workflow
score. It does not inherit claims about candidate discovery, model reasoning,
independent verification, remediation or release-gate accuracy.


## Arena full-packet batch handoff

SecHelix now has a fail-closed bridge from individual manifest-verified run
workspaces to one complete independent-assessor handoff for an Arena blind
packet.

`evals/arena_batch.py` consumes a PREPARED Arena manifest plus an explicit
case-to-run map. Every opaque prepared case ID must be represented exactly once.
Each case is converted through the existing Arena run-telemetry adapter and
manifest-verified workspace evidence index, so the batch inherits the same hard
requirements for run identity, graph/scope/commit binding, independent-verifier
evidence and release-gate evidence.

The batch refuses:

- missing or extra cases;
- duplicate case IDs or reused run IDs;
- run/workspace identity mismatches;
- manifest drift in any case;
- absolute paths or paths escaping the evaluator-selected base directory;
- any case that is not individually READY_FOR_INDEPENDENT_ASSESSMENT.

The handoff contains per-case measurement bundles and canonical digests, but no
workflow correctness score, no blind truth and no copied verifier/gate output
bodies. Its top-level measurement status remains `NOT_MEASURED`. The next
required step is still an uncontaminated independent evaluator producing
evidence-backed workflow judgments under Arena's blindness and independence
rules.


## Dynamic latency/concurrency profile benchmark

SecHelix now measures whether every bounded proof class keeps the same
vulnerable/clean classification under three declared LOCAL timing/load profiles.
The existing deterministic proof benchmark is parameterized by synthetic server
latency and bounded race concurrency without changing its default baseline.

The default matrix is:

- baseline: 0 ms fixture latency, race concurrency 2;
- moderate: 20 ms fixture latency, race concurrency 4;
- loaded: 60 ms fixture latency, race concurrency 8.

Each tier re-runs the complete paired proof-class suite and records case
accuracy, vulnerable-behavior recall, clean-behavior rejection, inconclusive
rate, proof-class coverage and total duration. CI can therefore catch a proof
primitive that becomes flaky or ambiguous only after timing/concurrency changes.

These profiles are deliberately synthetic and literal-loopback only. They are
not measurements of production latency, production throughput, real user load,
infrastructure queues or external network behavior, and they do not measure
candidate discovery, model reasoning, independent-verifier correctness,
remediation quality or release-gate accuracy.


## Manifest-verified Arena batch assessor binding

SecHelix now has a fail-closed assessor phase for complete Arena batch handoffs.
The assessor still supplies the correctness judgments; SecHelix does not infer or
self-grade them.

The new batch-assessment builder requires the assessment spec to bind both the
exact batch handoff digest and blind-packet digest, covers every opaque CASE-
identifier exactly once, and permits scored judgments to cite only files already
listed in that case's manifest-verified workspace artifact map.

Every cited local file is re-hashed at assessment-build time and must exactly
match the digest recorded in the case measurement bundle. The emitted assessment
contains only stable case/workspace references and a canonical artifact-bundle
digest; local paths and artifact contents are discarded. NOT_APPLICABLE remains
evidence-free rather than fabricating support.

The output is Arena-finalize compatible but does not establish evaluator
independence, reveal ground truth, or assign correctness. Those remain explicit
external protocol requirements.


## Controlled scanner contribution ablation

SecHelix now has an executable paired ablation for scanner contribution over the
blind vulnerable/clean fixture suite. The control arm must explicitly disable
scanners and the treatment arm must explicitly declare the scanner source(s).

The comparator fails closed unless both arms match on the same ablation run ID,
model, provider, host, execution mode, prompt reference, blind case digest and
fixture-suite version. Both complete prediction packets are scored by the same
canonical evaluator before deltas are calculated.

The result reports changes in precision, detection recall, verified precision,
false-positive rate, false-positive rejection rate, and operational time/token/
cost fields when both arms actually measured those values. It also reports only
aggregate changed-case counts: vulnerable detections gained/lost and clean false
positives removed/introduced. Per-case ground truth is not emitted.

A multi-scanner treatment is explicitly bundle-level. SecHelix does not assign
individual-tool causal credit without isolating that scanner in its own
treatment arm. This measurement is label-suite scanner contribution only; it
does not inherit independent-verifier, remediation, release-gate or production
effectiveness claims from Arena.


## Isolated scanner ablation matrix

SecHelix now has a controlled composition layer for scanner attribution. A
matrix starts from one scanner-disabled blind control and compares it with one
treatment arm per scanner. Every treatment must enable exactly one unique
scanner and still pass the canonical pair-ablation checks for model, provider,
host, execution mode, prompt, blind case digest, fixture-suite version, run ID
and declared scanner provenance.

This closes the attribution gap left by bundle-level ablations: a scanner gets
its own delta row only when it was the sole scanner changed in that treatment
arm. Multi-scanner treatments and duplicate scanner arms fail closed.

The matrix does not emit per-case truth or raw scanner output. Time, token and
cost totals are complete only when every arm measured the underlying value;
missing telemetry remains `NOT_MEASURED`. Aggregate changed-case counts sum
separate counterfactual arms and are explicitly not unique production findings.

The next measurement step is repeated-trial aggregation across separately
matched matrices plus broader full-workflow cost/time coverage.


## Repeated isolated scanner trials

SecHelix now persists the matched comparison conditions in each isolated scanner
matrix and can aggregate multiple independently executed matrices. Trial run IDs
must be unique, while model, provider, agent host, execution mode, prompt
reference, blind case digest, fixture-suite version and scanner set must match
exactly.

For each isolated scanner the aggregator reports mean, minimum and maximum
metric deltas across trials. Operational time/token/cost spread is complete only
when every trial measured the value; missing measurements remain
`NOT_MEASURED`. Changed-case totals and means are descriptive
counterfactual-run summaries, not unique findings.

The aggregator deliberately does not compute p-values, confidence intervals or
production-effectiveness claims. Repetition reduces dependence on one run but
does not change the scope of the authored blind fixture suite.

Published runtime image provenance/attestation is now gated behind an explicit manual-main publication path. The next correctness focus is an uncontaminated independently assessed full-workflow Arena run. Complete-packet cost/time aggregation, Python transitive artifact locking, CI runtime SBOM evidence, and exact-digest publication attestations are shipped.


## Security runtime provenance pinning

The dedicated V5 security runtime now removes two mutable/broken build paths from
the scanner sandbox.

The Python base image is pinned by OCI index digest rather than tag alone. The
runtime uses a multi-stage build: network/download tooling exists only in the
builder stage, while the final non-root image receives the prepared virtual
environment plus the verified scanner binaries.

Gitleaks and Trivy release archives are now pinned by per-architecture SHA-256
for amd64 and arm64 and are verified before extraction. Trivy was moved from the
older 0.66.0 artifact path to 0.74.0 because the old release asset path is no
longer a reliable build input. The Trivy architecture mapping is explicit
(`Linux-64bit` / `Linux-ARM64`) rather than assuming Go architecture labels
match the upstream archive names.

`containers/security-runtime/runtime-lock.json` is the human/audit provenance
record. The runtime manifest exposes whether a tool is artifact-hash pinned or
only exact-version pinned, and tests fail if the Dockerfile, lock and manifest
drift.

Semgrep and pip-audit now share a generated Python 3.12 lock containing exact
versions plus SHA-256 hashes for every resolved transitive distribution,
including pip itself. The Docker builder installs only from that lock with
`pip --require-hashes`; direct roots remain separately declared in
`python-tools.in`, and runtime tests fail if their versions drift from the
manifest/provenance record.

The Python lock is an artifact-integrity boundary, not a claim that every wheel
for every platform has been executed. The security-runtime CI currently proves
the digest-pinned Linux amd64 image build and network-disabled smoke path; binary
Gitleaks/Trivy archives retain explicit amd64/arm64 hashes. Published
multi-architecture image provenance, attestations and release SBOM verification
remain separate work rather than being implied by the repository lock.



## Published security runtime image provenance and attestations

The security-runtime workflow now separates **verification** from **publication**.
Pull requests and ordinary pushes still build, smoke-test and emit short-lived
local evidence only. Publishing is possible only through a manual
`workflow_dispatch` on `main` with the boolean `publish=true`.

The publication job runs only after the normal build-and-smoke job succeeds. It
has the narrowly required package/OIDC/attestation permissions; those permissions
are not granted to the verification job. The image is pushed to GHCR under an
immutable `sha-<commit>` tag and no mutable `latest` tag is created.

The pushed OCI digest is the attestation subject. SecHelix creates two signed
GitHub/Sigstore-backed attestations for that exact digest:

- SLSA build provenance generated from the publication workflow; and
- the deterministic CycloneDX runtime SBOM generated from the repository's
  pinned provenance inputs.

Both attestations are pushed to the registry and associated with the repository.
This closes the previous gap between local CI evidence and a published image
without pretending that every normal CI build is published or attested. A local
image ID, repository lock, or uploaded CI artifact alone still does **not**
establish published-image provenance.

## Complete-packet Arena operational summary

The manifest-verified Arena batch handoff now aggregates operational telemetry
across the complete blind packet instead of requiring an evaluator to sum
individual case bundles manually.

The packet records summed/mean/min/max per-case elapsed time, input/output
tokens and cost with explicit measured/applicable case counts. A single missing
applicable token or cost measurement makes that packet metric `NOT_MEASURED`
rather than silently summing the remaining cases; when no case executed
applicable provider work the metric is `NOT_APPLICABLE`.

Timing keeps two different quantities separate. `case_elapsed_seconds.total`
is the sum of each run's own wall time, while
`observed_packet_span_seconds` is earliest case start to latest case finish.
Concurrent case execution can therefore produce a packet span smaller than the
summed case time without being mistaken for inconsistent telemetry.

The summary also carries observed agent-host/provider/model labels. It remains
operational-only: top-level Arena correctness stays `NOT_MEASURED` until an
uncontaminated independent assessor completes the evidence-backed workflow
assessment.


## Security runtime SBOM evidence

The dedicated V5 security-runtime workflow now emits a deterministic CycloneDX
1.5 inventory from repository-controlled provenance rather than querying a
registry or vulnerability service at build time.

The generator binds the digest-pinned Python base image, every exact Python
package/version plus its hash set from `python-tools.lock`, and the per-architecture
Gitleaks/Trivy release-asset hashes from `runtime-lock.json`. The SBOM records
SHA-256 digests of both provenance inputs and explicitly marks published image
provenance as `NOT_MEASURED`.

After the digest-pinned Docker build and network-disabled smoke test, CI records
the local image ID and a sorted `pip freeze --all` inventory alongside the SBOM
and its SHA-256. The evidence bundle is uploaded as a short-lived GitHub Actions
artifact for review. Tests fail closed on malformed/unhashed Python entries,
missing base-image digest binding, duplicate component identities, or missing
binary per-architecture provenance.

This is build evidence, not registry publication. No image is pushed and no
signature/attestation for a published digest is claimed by this slice.


## Arena prediction freeze and truth-order binding

SecHelix now has a fail-closed protocol helper for freezing the complete Arena
prediction batch before blind truth is revealed.

`evals/arena_freeze.py freeze` consumes the PREPARED Arena manifest and the
complete manifest-verified batch handoff. It revalidates the handoff digest,
every case bundle digest, packet identity, participant identity and exact opaque
case set. The resulting prediction digest is derived only from each case ID, run
ID and manifest-verified bundle digest; ground truth is neither read nor emitted.

A second `blindness` step accepts that exact freeze plus an independently
obtained ground-truth digest and declared truth-reveal time. The reveal time must
be strictly later than the prediction freeze. The generated blindness record
carries the frozen prediction digest directly into Arena finalization.

This strengthens auditability but deliberately does not manufacture
independence. Timestamps, contamination state and evaluator-independence remain
externally attributable facts, and Arena's existing independent-assessor
attestation/publication blockers still apply. A freeze record therefore remains
`NOT_MEASURED` and never scores correctness on its own.

The next correctness milestone is an uncontaminated external/independent Arena
run that uses this freeze chain and evidence-backed batch assessment to measure
verifier, false-positive refutation, root-cause, regression-proof and release
gate accuracy without self-certification.


## Browser / HTTP response-security parity

Browser network evidence and direct HTTP evidence now use the same fixed
value-free response-security projection. Playwright response/request headers are
consumed only in memory and immediately reduced to transport classes such as
CORS class, cache directives, CSP/frame-ancestor presence, X-Frame-Options,
nosniff, HSTS, referrer/permissions policy and cross-origin isolation headers.

No raw header value is retained on `NetworkEvent`. If Playwright cannot expose
the headers for a response, browser evidence stores `None` rather than
misrepresenting an unmeasured projection as "all protections absent".

Grouped browser exchanges carry the projection into canonical runtime
observations, which gives authentication/API specialists browser/direct-HTTP
parity without exposing Authorization, Cookie, CSP text, HSTS max-age, origins
or other potentially sensitive header values. This is transport observation
only and cannot promote a finding without the normal independent verifier.


## Browser / direct-HTTP security parity correlation

Fresh authenticated-flow correlations now compare the browser and direct-HTTP
value-free response-security projections when both were measured for the same
persona, method and normalized surface.

The correlation emits only `MATCH`, `DIFF`, or `NOT_MEASURED`, the fixed
projection field names that differ, and whether each path was measured. It never
copies raw header values and never turns a transport mismatch into a finding. A
browser/CDN/proxy path can legitimately differ from a direct request, so parity
remains `OBSERVATION` context for specialists and the independent verifier.

Browser header-capture failure stays `NOT_MEASURED` rather than being silently
interpreted as every security header being absent.


## Value-free proxy/cache provenance

SecHelix now derives a fixed proxy/cache provenance projection from both direct
HTTP and browser execution paths. Raw intermediary header values are consumed
only transiently and are never written into artifacts.

The persisted projection is intentionally coarse. It records:

- whether a Via chain was observed and a bounded hop-count hint;
- whether Age was present and whether it was positive;
- a coarse cache outcome class such as hit, miss, bypass, stale/revalidated or
  other;
- only allowlisted forwarding request-header names;
- only fixed intermediary marker classes derived from response-header names.

It does not store Via contents, client/proxy IPs, cache node names, request IDs,
CDN trace IDs, Authorization/Cookie values, or arbitrary header values.

Fresh authenticated-flow correlation now compares this value-free provenance
between browser and direct-HTTP evidence. Results are only MATCH, DIFF or
NOT_MEASURED with differing fixed field names. A difference is contextual
evidence that paths may differ; it is never a vulnerability verdict and cannot
promote a finding.
