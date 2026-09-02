# Reddit drafts

> **DRAFT — requires human review before publishing. Do not post automatically.**

---

**Before posting — a human must check, per subreddit:**

- current self-promotion rules and any account-age / karma / ratio requirements;
- required post flair (r/netsec in particular enforces flair and is hostile to tool marketing);
- whether a project-announcement post is permitted at all, or whether only a technical write-up
  with the tool as incidental context is acceptable;
- that the linked case study is reachable and that no private-repo content leaks in the link.

Two variants follow. Do not cross-post them verbatim; the tone difference is deliberate.

---

# Variant A — r/netsec

**Suggested title:**

`Refuting a high-severity XSS candidate: React 19 neutralizes javascript: URLs before they reach the DOM`

Alternate, if a tool-name title is permitted:

`SecHelix case study: 3 candidates, 1 verified MEDIUM, 2 refuted — including the one that looked like HIGH XSS`

**Suggested flair:** `tools` or `article` — human must confirm the current flair list.

---

## Body

Short write-up of an authorized owner self-audit, posted mainly for the refutation mechanism rather
than the finding.

**Setup.** Private repo, owner self-audit, 2026-09-01. Display-only Next.js 16.2.7 storefront,
~600 LOC TypeScript/TSX across 19 source files. STATIC + LOCAL modes only, agent host Claude Code,
**zero scanners enabled** — code reading plus local runtime observation. Nothing outside 127.0.0.1
was contacted.

**The candidate that looked bad.** Remote store-config values (`hero.ctaHref`, `footerLinks[].href`,
`socials.*`, a listing `image`) flow into `href`/`src` with only `.trim()` applied. That is the
canonical shape of a HIGH-severity XSS report — taint from a remote source into a URL sink with no
scheme validation.

**Refutation, part 1 — the sink is not a sink here.** A local mock config API served
`javascript:alert(document.domain)`. The rendered document contained:

```
href="javascript:throw new Error('React has blocked a javascript: URL as a security precaution.')"
```

React 19 rewrites `javascript:` URLs before they reach the document. No script execution is
achievable through that path.

**Refutation, part 2 — attacker control was never established.** The config source is the operator's
own workspace API, not an internet-reachable input. Taint analysis that starts at "remote fetch"
and stops there gets this wrong; the question is who can write the value, not where it is read from.

Recorded outcome: `FALSE_POSITIVE`, refutation reason retained in the report.

A scheme allowlist was still added at the trust boundary — relying on a renderer internal for URL
safety is fragile — but the report labels that **HARDENING**, not a vulnerability fix. That
distinction is the whole point of writing it down.

Second refuted candidate: suspected PII leak in a buyer-name masking helper, rejected after every
code path was traced and returned a masked value.

**What actually survived.** `SHX-F-GOS-HEADERS-001`, **MEDIUM**, clickjacking / UI redress.
`next.config.ts` had only an `images` block; the production build emitted no CSP, no
`X-Frame-Options`, no `X-Content-Type-Options`, no `Referrer-Policy`, no HSTS, no
`Permissions-Policy`, and advertised `X-Powered-By: Next.js`. A local probe page on a separate origin
embedded the storefront and the full UI rendered including the Sign in entry point.

Held at MEDIUM deliberately: phishing amplification and brand abuse, not account takeover, because
the app performs no authenticated state-changing actions.

Fix was a catch-all `headers()` rule (CSP `frame-ancestors 'none'`, `X-Frame-Options: DENY`,
nosniff, referrer policy, `Permissions-Policy`, HSTS, COOP, `poweredByHeader: false`). Retest:

```
Framing 'http://localhost:3009/' violates the following Content Security Policy
directive: "frame-ancestors 'none'". The request has been blocked.
```

**Process detail worth stealing.** The first retest appeared to fail — headers still missing, hostile
URL still in the DOM. Cause: stale Next.js prerender cache plus a still-running server bound to the
old port. Only a clean rebuild proved the fix. Recorded because that is the failure mode that
silently converts a real fix into a false claim of remediation.

**Funnel for the whole run:** 1 external data source, 3 public routes, 0 authenticated actions ->
41 of 546 hypotheses applicable -> 3 candidates -> 1 verified, 2 refuted -> 1 fix + 1 hardening ->
10 regression assertions -> release decision PASS after remediation.

Framework is Apache-2.0: https://github.com/omarmohelal/SecHelix (546 hypotheses = 21 families x 26
lenses, 19 JSON Schema Draft 2020-12 contracts, four applicability outcomes
`APPLICABLE`/`NOT_APPLICABLE`/`UNKNOWN`/`BLOCKED` where missing evidence is never treated as absence).

## What this does not do yet

- Benchmarks are **NOT_MEASURED**. Blocker is `CONTAMINATED_EVALUATOR`: the fixture suite was
  expanded on 2026-09-01 by the same assistant session that would have been the evaluated model, so
  it knew fixtures it had written itself. Scoring that measures recall of authored answers, not
  capability. Unblocking needs a run by a model/session that did not author the fixtures, on blind
  exported cases.
- `evals/results/baseline-keyword-v1.json` is **not** a SecHelix score (`is_sechelix_result: false`).
  It is a naive regex keyword matcher run to prove the harness works and that the fixtures resist
  pattern matching: precision 0.511 / recall 0.632 on a balanced 38/38 split, i.e. chance. That is a
  fixture-difficulty statement, not a performance claim.
- n=1, ~600 LOC, no auth, no server-side state. Measures nothing about general performance.
- The verified finding was MEDIUM. Not a critical.
- No public third-party trophy-case entries exist yet; the trophy case requires a public project and
  a public fix/advisory reference and is deliberately empty.
- Target repo is private, so this is not independently reproducible by you. Owner self-audit, not
  peer-reviewed or externally validated.
- Alpha software (3.0.0-alpha.4).

---
---

# Variant B — r/AppSec

**Suggested title:**

`We built a review process that has to refute its own findings — here's the run where it killed the exciting one`

Alternate:

`Triage cost, false-positive fatigue, and a HIGH-looking XSS that wasn't: an evidence-first review walkthrough`

**Suggested flair:** human must check the current r/AppSec flair list and self-promo policy before
posting.

---

## Body

Most of the cost in AppSec is not detection. It is triage. Every unverified HIGH costs an engineer's
afternoon, and after enough of them the team stops reading the queue at all. That is the failure mode
I care about, and it is why the interesting output of a security run is sometimes the finding that
got killed.

Here is a full worked run where exactly that happened.

### Scope

Authorized owner self-audit of a private repo, 2026-09-01. Display-only storefront, Next.js 16.2.7,
~600 LOC TypeScript/TSX across 19 source files. STATIC + LOCAL only, agent host Claude Code,
**zero scanners enabled** — code reading plus local runtime observation. Nothing outside 127.0.0.1
was contacted.

```
1 external data source, 3 public routes, 0 authenticated actions
  -> 41 of 546 hypotheses applicable
  -> 3 candidates
  -> 1 verified, 2 refuted
  -> 1 fix + 1 hardening
  -> 10 regression assertions
  -> release decision PASS after remediation
```

Note the second line. 41 of 546 hypotheses were considered applicable. The other 505 were not
sprayed at the target and then triaged away — applicability was decided from architecture evidence
first, using four outcomes: `APPLICABLE`, `NOT_APPLICABLE`, `UNKNOWN`, `BLOCKED`. Missing evidence
maps to `UNKNOWN`, never silently to `NOT_APPLICABLE`. That is the difference between a queue you
can trust and a queue you learn to ignore.

### The candidate that would have burned a day

Remote store-config values (`hero.ctaHref`, `footerLinks[].href`, `socials.*`, a listing `image`)
flowed into `href`/`src` attributes with only `.trim()` applied. Remote source, URL sink, no scheme
validation. If that lands in your queue as HIGH XSS, nobody on the team blinks. Somebody schedules
a fix, somebody writes a Jira ticket, and if you are unlucky somebody writes a customer-facing
disclosure.

Verification killed it two ways.

**One — the sink neutralizes it.** A local mock config API served
`javascript:alert(document.domain)`, and the rendered document contained:

```
href="javascript:throw new Error('React has blocked a javascript: URL as a security precaution.')"
```

React 19 neutralizes `javascript:` URLs before they reach the document. No script execution is
achievable via that path.

**Two — attacker control was never established.** The config source is the operator's own workspace
API, not an internet-reachable input. If nobody hostile can write the value, there is no
vulnerability to write up, however bad the dataflow looks on a diagram.

Recorded outcome: `FALSE_POSITIVE`, with the refutation reason retained so the next reviewer does
not re-raise it in six months. That retained reason is, in practice, the highest-leverage artifact in
the whole report — it is what stops a refuted candidate from becoming a recurring triage tax.

A scheme allowlist was still added at the trust boundary as defence in depth, because depending on a
renderer internal for URL safety is fragile. The report labels it **HARDENING**, not a vulnerability
fix. Two different words, two different meanings, and conflating them is how remediation metrics get
quietly corrupted.

Second refuted candidate: suspected PII leak in a buyer-name masking helper, rejected after tracing
every code path returned a masked value.

### What survived, and why it stayed MEDIUM

`SHX-F-GOS-HEADERS-001`, clickjacking / UI redress. `next.config.ts` had only an `images` block. The
production build emitted no CSP, no `X-Frame-Options`, no `X-Content-Type-Options`, no
`Referrer-Policy`, no HSTS, no `Permissions-Policy`, and advertised `X-Powered-By: Next.js`. A local
probe page on a separate origin embedded the storefront and the whole UI rendered, Sign in entry
point included.

Severity was held at **MEDIUM** on purpose. The realistic outcome is phishing amplification and brand
abuse, not account takeover, because the app performs no authenticated state-changing actions.
Severity inflation is the other half of false-positive fatigue: a queue full of HIGHs that are really
MEDIUMs trains people to discount HIGHs.

Fix: catch-all `headers()` rule with CSP `frame-ancestors 'none'`, `X-Frame-Options: DENY`, nosniff,
referrer policy, `Permissions-Policy`, HSTS, COOP, and `poweredByHeader: false`. Retest evidence, in
the browser's own words:

```
Framing 'http://localhost:3009/' violates the following Content Security Policy
directive: "frame-ancestors 'none'". The request has been blocked.
```

Then 10 regression assertions so the fix cannot silently regress on the next config refactor.

### The SDLC lesson buried in the retest

The **first** retest appeared to fail. Headers still missing, hostile URL still in the DOM. The cause
was a stale Next.js prerender cache plus a still-running server bound to the old port. Only a clean
rebuild proved the fix.

Think about which direction that error runs in your own pipeline. A stale artifact that makes a fixed
thing look broken costs you an hour of confusion. A stale artifact that makes a broken thing look
fixed closes a ticket, passes a gate, and ships. Same root cause, opposite consequences. That is why
retest environment provenance belongs in the evidence, not in someone's memory.

### The framework

Apache-2.0, https://github.com/omarmohelal/SecHelix, install with
`npx skills@latest add omarmohelal/SecHelix --skill sechelix`. Structurally: 546 hypotheses = 21
families x 26 lenses; 17 model-neutral specialist role profiles including an independent verifier;
19 JSON Schema Draft 2020-12 contracts; 18 Gold Check Packs; 38 paired eval fixtures = 76 cases across
10 families; knowledge graph of 76 nodes, 100 edges, 11 lesson cards. Release gate returns `PASS`,
`PASS_WITH_KNOWN_RISK`, `BLOCKED`, or fail-closed `INCOMPLETE`.

The design position is one sentence: **security findings are claims, and a claim gets verified before
it gets to accuse anyone.**

## What this does not do yet

- Benchmarks are **NOT_MEASURED**, and the blocker is written down rather than glossed:
  `CONTAMINATED_EVALUATOR`. The fixture suite was expanded on 2026-09-01 by the same assistant
  session that would have acted as the evaluated model, giving it prior knowledge of fixtures it had
  written itself. Scoring that would measure recall of authored answers, not security-review capability.
  Unblocking requires a run by a model/session that did not author the fixtures, using blind exported
  cases.
- There is a harness baseline at `evals/results/baseline-keyword-v1.json` that is **explicitly not a
  SecHelix score** (`is_sechelix_result: false`). It is a naive regex keyword matcher, run only to
  prove the scoring harness works and that the fixtures cannot be solved by pattern matching. It hit
  precision 0.511 / recall 0.632 on a balanced 38/38 split — chance level. Read that as a statement
  about fixture difficulty, not about how SecHelix performs.
- This case study is **one** small ~600 LOC app with no authentication and no server-side state. It
  tells you nothing about performance on a real service with roles, tenancy, money, and state
  machines.
- The verified finding was **MEDIUM**, not a dramatic critical.
- **No public third-party trophy-case entries exist yet.** The trophy case requires a public project
  and a public advisory, issue, or fix reference, and is deliberately empty rather than padded.
- The target repo is **private**, so you cannot independently reproduce this run. It is an owner
  self-audit, not peer-reviewed and not externally validated.
- It is **alpha** (3.0.0-alpha.4). Treat contracts and interfaces as still moving.

Happy to argue about the evidence standard — attacker control, reachability, boundary failure, safe
reproduction, impact, preconditions, root cause, fix, regression proof. If your triage process
already enforces something stronger, I would genuinely like to hear what it is.
