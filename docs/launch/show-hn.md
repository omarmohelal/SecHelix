# Show HN draft

> **DRAFT — requires human review before publishing. Do not post automatically.**

---

## Title options (all under 80 chars)

1. `Show HN: SecHelix – an AppSec agent skill that tries to refute its own findings` (78)
2. `Show HN: SecHelix – it talked itself out of the XSS it wanted to report` (70)
3. `Show HN: An AppSec workflow where the interesting output was a refutation` (72)
4. `Show HN: SecHelix – evidence-first security review for coding agents` (67)
5. `Show HN: Security findings are claims; this tries to verify them first` (69)

Recommended: option 2 leads with the refutation, which is the actual story. Option 1 is the safer
neutral phrasing if the moderators dislike the narrative framing.

---

## Body

I have been working on SecHelix, an open-source (Apache-2.0) Agent Skill and methodology for
application security review. The premise is a boring one: a security finding is a claim, and a
claim needs to survive an attempt to disprove it before it gets reported as a vulnerability.

The clearest thing I can show is not a scary bug. It is a run where the tool talked itself out of
the finding it wanted to report.

### The run

Authorized self-audit of a private repo I own (`omarmohelal/gamingops-store`), 2026-09-01. A
display-only storefront: ~600 lines of TypeScript/TSX across 19 source files, Next.js 16.2.7.
Modes STATIC + LOCAL. Agent host was Claude Code. **Zero scanners enabled** — this was code reading
plus local runtime observation. Nothing outside 127.0.0.1 was contacted.

The funnel:

```
1 external data source, 3 public routes, 0 authenticated actions
  -> 41 of 546 hypotheses applicable
  -> 3 candidates
  -> 1 verified, 2 refuted
  -> 1 fix + 1 hardening
  -> 10 regression assertions
  -> release decision: PASS after remediation
```

### The refutation

Remote store-config values (`hero.ctaHref`, `footerLinks[].href`, `socials.*`, a listing `image`)
flowed into `href`/`src` attributes with only `.trim()` applied. That is exactly the shape a scanner
or a confident reviewer files as HIGH-severity XSS.

Verification refuted it two ways.

First, a local mock config API served `javascript:alert(document.domain)`. The rendered document
contained:

```
href="javascript:throw new Error('React has blocked a javascript: URL as a security precaution.')"
```

React 19 neutralizes `javascript:` URLs before they reach the document. No script execution is
achievable through that path.

Second, attacker control was never established. The config source is the operator's own workspace
API, not an internet-reachable input.

Recorded outcome: `FALSE_POSITIVE`, with the refutation reason retained in the report. A scheme
allowlist was still added at the trust boundary, and the report labels it **HARDENING**, not a
vulnerability fix. Depending on a renderer internal for URL safety is fragile, but fragile is not
the same as exploitable, and the report says so.

A second candidate — a suspected PII leak in a buyer-name masking helper — was rejected after every
code path was traced and returned a masked value.

### The finding that survived

`SHX-F-GOS-HEADERS-001`, MEDIUM, clickjacking / UI redress. `next.config.ts` had only an `images`
block. The production build emitted no CSP, no `X-Frame-Options`, no `X-Content-Type-Options`, no
`Referrer-Policy`, no HSTS, no `Permissions-Policy`, and advertised `X-Powered-By: Next.js`. A local
probe page on a separate origin embedded the storefront and the whole UI rendered, including the
Sign in entry point.

Severity was deliberately held at MEDIUM. The realistic outcome is phishing amplification and brand
abuse, not account takeover, because the app performs no authenticated state-changing actions. I
would rather under-sell a real finding than inflate it.

Fix: a catch-all `headers()` rule with CSP `frame-ancestors 'none'`, `X-Frame-Options: DENY`,
nosniff, referrer policy, `Permissions-Policy`, HSTS, COOP, and `poweredByHeader: false`. Retest, in
the browser's own words:

```
Framing 'http://localhost:3009/' violates the following Content Security Policy
directive: "frame-ancestors 'none'". The request has been blocked.
```

### The part I nearly got wrong

The first retest appeared to **fail**. Headers still missing, hostile URL still in the DOM. The
cause was a stale Next.js prerender cache plus a still-running server bound to the old port. Only a
clean rebuild proved the fix.

I recorded that because it is exactly the kind of detail that silently converts a real fix into a
false claim of remediation. A green typecheck is not proof that a built application is fixed.

### What it actually is, structurally

- 546 structured security hypotheses = exactly 21 families x 26 verification lenses
- 17 model-neutral specialist role profiles, including an independent verifier
- 22 JSON Schema Draft 2020-12 contracts
- 18 Gold Check Packs
- 38 paired eval fixtures = 76 cases across 10 families
- Knowledge graph: 76 nodes, 100 edges, 11 lesson cards
- Four applicability outcomes: `APPLICABLE` / `NOT_APPLICABLE` / `UNKNOWN` / `BLOCKED`. Missing
  evidence is never treated as absence.
- Release gate returns `PASS` / `PASS_WITH_KNOWN_RISK` / `BLOCKED` / fail-closed `INCOMPLETE`.

Repo: https://github.com/omarmohelal/SecHelix
Install: `npx skills@latest add omarmohelal/SecHelix --skill sechelix`
Release 3.0.0-alpha.4 (alpha). Apache-2.0.

---

## What this does not do yet

- **Benchmarks are NOT_MEASURED.** The documented blocker is `CONTAMINATED_EVALUATOR`: the fixture
  suite was expanded on 2026-09-01 by the same assistant session that would have acted as the
  evaluated model, so that session knew fixtures it had written itself. Scoring it would
  measure recall of authored answers, not security-review capability. Unblocking requires a run by a
  model/session that did not author the fixtures, using blind exported cases.
- There is a harness baseline at `evals/results/baseline-keyword-v1.json`, and it is **explicitly
  not a SecHelix score** (`is_sechelix_result: false`). It is a naive regex keyword matcher run
  against the fixtures to prove the scoring harness works and that the fixtures cannot be solved by
  pattern matching. It scored precision 0.511 / recall 0.632 on a balanced 38/38 split — chance level.
  That is a statement about **fixture difficulty**, not about SecHelix performance.
- The case study is **one** small ~600 LOC app with no authentication and no server-side state. It
  measures nothing about general performance.
- The verified finding was **MEDIUM**, not a dramatic critical. Clickjacking on a display-only
  storefront.
- **No public third-party trophy-case entries exist yet.** The trophy case requires a public project
  and a public advisory, issue, or fix reference. It is currently empty on purpose.
- The target repo is **private**, so the case study is not independently reproducible by a reader.
  It is a self-audit by the owner, not peer-reviewed or externally validated.
- It is **alpha** software (3.0.0-alpha.4). Interfaces and contracts can still change.

---

## Pre-answers to the comments I expect

**"So it's a prompt?"**
Partly, and I would rather say so than pretend otherwise. The instruction layer is prompt-shaped —
it has to be, because the execution host is a coding agent. What is not prompt-shaped: 546 stable
hypothesis IDs in a validated catalog, 22 JSON Schema contracts that reports must validate against,
a release-gate policy that fails closed on `INCOMPLETE`, scanner/SARIF adapters, and paired
vulnerable/clean fixtures with a scoring harness. The value claim is the evidence standard and the
schemas that make a report checkable, not the wording.

**"Where are the benchmarks?"**
Not measured, and the blocker is documented rather than hidden. See above:
`CONTAMINATED_EVALUATOR`. I could have run the eval and posted a number. The number would have
measured whether a session could recall fixtures it wrote. I would rather ship `NOT_MEASURED` than
ship a score I do not believe. If you want to unblock it, a run by a model/session that did not
author the fixtures, on blind exported cases, is the thing that would do it.

**"n=1 case study."**
Correct, and the write-up says so in its own limitations section. One ~600 LOC app, no auth, no
server-side state, and the repo is private so you cannot re-run it. I am not presenting it as
evidence of accuracy. I am presenting it as a worked example of the process — specifically of the
process rejecting its own most attractive finding. If it had found a critical RCE I would trust it
less, not more.

**"Isn't the header finding trivial? Any scanner catches missing CSP."**
Yes. That is somewhat the point: the boring finding was the real one and the exciting finding was
not. A scanner would also have flagged the `javascript:` URL flow, and that flag would have been
wrong. The differentiator being claimed is what happens to the second one, not the first.

**"LLMs hallucinate vulnerabilities; why would this be different?"**
It assumes that too. That is why important candidates go to a verifier whose job is to disprove
them, why missing evidence maps to `UNKNOWN` or `BLOCKED` instead of `NOT_APPLICABLE`, and why the
gate can return fail-closed `INCOMPLETE`. It does not eliminate hallucination; it tries to make an
unproven claim expensive to promote into a report. Whether it succeeds at scale is exactly the thing
that is `NOT_MEASURED`.

**"Why would I let an agent run a security tool on my code?"**
Only run it on systems you own or are explicitly authorized to test. Modes are bounded: `STATIC`
sends no dynamic traffic, `LOCAL` stays local. The case study run contacted nothing outside
127.0.0.1 and enabled no scanners at all.

**"Two models agreeing is not independent verification."**
Agreed, and the docs say that explicitly. Refutation is a different job from detection, and model
reputation is not evidence. That framing is a design constraint, not a solved problem.

Happy to take criticism on the evidence standard itself — that is the part I most want stress-tested
before anyone relies on it.
