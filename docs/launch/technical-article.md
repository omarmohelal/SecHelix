# The most useful thing my security review did was withdraw a finding

> **DRAFT — requires human review before publishing. Do not post automatically.**

*Target: dev.to / personal blog. Roughly 1,780 words.*

---

There is a moment in every security review where you have found something, and you want it to be
real. The dataflow is clean, the sink is ugly, the severity picks itself. Writing it up feels like
winning.

That moment is the most dangerous point in the whole process, because nothing downstream is built to
catch you. Nobody audits a HIGH for being too generous.

Here is a run where the tool talked itself out of exactly that finding, and what the surrounding
machinery had to look like for that to happen.

## The setup

Authorized owner self-audit of a private repository I own, on 2026-09-01. A display-only storefront:
roughly 600 lines of TypeScript and TSX across 19 source files, Next.js 16.2.7. Execution modes were
STATIC and LOCAL only, the agent host was Claude Code, and **zero scanners were enabled** — this was
code reading plus local runtime observation. Nothing outside `127.0.0.1` was contacted.

The full funnel:

```
1 external data source, 3 public routes, 0 authenticated actions
  -> 41 of 546 hypotheses applicable
  -> 3 candidates
  -> 1 verified, 2 refuted
  -> 1 fix + 1 hardening
  -> 10 regression assertions
  -> release decision: PASS after remediation
```

Note the second line before anything else. 546 hypotheses exist in the catalog; 41 were considered
applicable to this architecture. The other 505 were not fired at the target and then triaged away.
Applicability was decided from architecture evidence first.

## Four applicability outcomes, and the one that does the work

Every hypothesis resolves to one of four states:

- `APPLICABLE` — the required architecture capability is evidenced as present.
- `NOT_APPLICABLE` — the required capability is explicitly evidenced as absent.
- `UNKNOWN` — evidence is missing or unresolved.
- `BLOCKED` — authorization, access, tooling, or environment prevents a legitimate decision.

The load-bearing rule is that **missing evidence is never treated as absence.** The tempting collapse
is three states, where "I couldn't find it" quietly becomes "it isn't there." That collapse is how a
review produces a clean report about a system it never actually understood. `UNKNOWN` is uncomfortable
on purpose, and the release gate is allowed to return a fail-closed `INCOMPLETE` because of it.

## The evidence standard

Before any candidate becomes a finding, nine links have to hold:

1. **attacker control** — someone hostile can actually influence the input;
2. **reachability** — the vulnerable path is reachable in a deployed configuration;
3. **security boundary failure** — a control that should have stopped it did not;
4. **safe reproduction** — bounded, non-destructive, in an authorized environment;
5. **concrete impact** — what an attacker gets, stated without inflation;
6. **preconditions** — what must be true for the attack to work;
7. **root cause** — not the symptom;
8. **fix** — addressing the root cause;
9. **regression proof** — a test that fails if the fix is reverted.

Most false positives die at link 1 or link 3. The candidate below died at both.

## The candidate that wanted to be HIGH

Remote store-configuration values — `hero.ctaHref`, `footerLinks[].href`, `socials.*`, and a listing
`image` — flowed into `href` and `src` attributes with only `.trim()` applied.

Read that as a taint problem and it writes itself: remote source, URL sink, no scheme validation. That
is the canonical shape of a high-severity XSS report. A scanner would flag it. A confident human
reviewer would flag it. I wanted to flag it.

### Refutation one: the sink is not a sink here

A local mock configuration API served a hostile value, and the rendered document was inspected
directly:

```
# mock config served:
"hero": { "ctaHref": "javascript:alert(document.domain)" }

# rendered document contained:
href="javascript:throw new Error('React has blocked a javascript: URL as a security precaution.')"
```

React 19 neutralizes `javascript:` URLs before they reach the document. The hostile string never
becomes an executable URL. **No script execution is achievable through this path.**

This is the part that only runtime observation gives you. Static reasoning about the dataflow was
correct in every particular and wrong in its conclusion, because the framework behaviour at the sink
was not in the dataflow model. You cannot argue your way to this result; you have to look at the
document.

### Refutation two: attacker control was never established

The second refutation is independent of the first, and it is the more important one.

The configuration source is the operator's own workspace API. It is not an internet-reachable input.
There is no untrusted party who can write `hero.ctaHref`.

If nobody hostile can control the value, there is no vulnerability, however alarming the dataflow
diagram looks. Taint analysis that begins at "value arrives over HTTP" and stops there gets this
wrong every time. The question is never where a value is read from; it is who is permitted to write
it.

Two independent refutations, and the candidate was recorded as `FALSE_POSITIVE` with the refutation
reason retained.

### Why hardening was still shipped, and labelled as hardening

A scheme allowlist was added at the trust boundary anyway. Depending on a renderer internal for URL
safety is fragile: React's behaviour is a framework implementation detail, not a security contract I
control, and a future migration could remove it silently.

But the report labels that change **HARDENING**, not a vulnerability fix.

That distinction is not pedantry. If defence-in-depth changes get filed as vulnerability
remediations, your remediation counts inflate, your "vulnerabilities fixed this quarter" metric stops
meaning anything, and the next person reading the history believes the application once had an
exploitable XSS. It did not.

A second candidate — a suspected PII leak in a buyer-name masking helper — was also rejected, after
every code path was traced and every one returned a masked value.

## What actually survived

`SHX-F-GOS-HEADERS-001`. **MEDIUM.** Clickjacking / UI redress.

`next.config.ts` contained only an `images` block. The production build emitted no CSP, no
`X-Frame-Options`, no `X-Content-Type-Options`, no `Referrer-Policy`, no HSTS, no `Permissions-Policy`
— and advertised `X-Powered-By: Next.js`. A local probe page on a separate origin embedded the
storefront, and the entire interface rendered, including the *Sign in* entry point.

All nine evidence links held. Attacker control: the attacker owns the embedding page. Reachability:
every public route served without a framing policy. Boundary failure: no `frame-ancestors`, no
`X-Frame-Options`, browser default permits framing. Safe reproduction: local probe page, nothing
outside `127.0.0.1`.

Impact is where the discipline shows. Severity was held at **MEDIUM**, deliberately. The realistic
outcome is phishing amplification and brand abuse, not account takeover, because this application
performs no authenticated state-changing actions. There is no dangerous button to bait a click onto.

Severity inflation is the mirror image of false-positive fatigue. A queue full of HIGHs that are
really MEDIUMs trains a team to discount HIGHs, which is exactly the reflex you need intact on the day
a genuine one arrives.

The fix was a catch-all `headers()` rule: CSP with `frame-ancestors 'none'`, `X-Frame-Options: DENY`,
nosniff, referrer policy, `Permissions-Policy`, HSTS, COOP, plus `poweredByHeader: false`. The retest
evidence is the browser's own refusal:

```
Framing 'http://localhost:3009/' violates the following Content Security Policy
directive: "frame-ancestors 'none'". The request has been blocked.
```

Ten regression assertions were added so the header rule cannot vanish in a future config refactor
without a test going red.

## The retest that lied

The **first** retest appeared to fail. Headers still missing. Hostile URL still in the DOM.

The cause was a stale Next.js prerender cache plus a still-running server bound to the old port. The
fix was correct; the artifact under test was not the artifact I had fixed. Only a clean rebuild proved
it.

I recorded that in the case study because of which direction the error can run. A stale artifact that
makes a fixed thing look broken costs you an hour of confusion and nothing else. A stale artifact that
makes a broken thing look **fixed** closes the ticket, passes the gate, and ships.

Same root cause, opposite consequences. It is the single cheapest way to silently convert a real fix
into a false claim of remediation, and it does not announce itself. A green typecheck is not proof
that a built application is fixed. Retest environment provenance belongs in the evidence, not in
somebody's memory.

## What this does not do yet

I would rather you hear the limits from me.

**Benchmarks are NOT_MEASURED.** The documented blocker is `CONTAMINATED_EVALUATOR`: the eval fixture
suite was expanded on 2026-09-01 by the same assistant session that would have acted as the evaluated
model, so that session knew fixtures it had written itself. Scoring it would measure recall
of authored answers, not security-review capability. Unblocking requires a run by a model or session
that did not author the fixtures, using blind exported cases. I could have published a number; it
would have been a number about memory.

**The harness baseline is not a score.** `evals/results/baseline-keyword-v1.json` is explicitly marked
`is_sechelix_result: false`. It is a naive regex keyword matcher run against the fixtures for one
purpose: to prove the scoring harness works and that the fixtures cannot be solved by pattern
matching. It scored precision 0.511 and recall 0.632 on a balanced 38/38 split — chance level. That is a
statement about **fixture difficulty**, not about SecHelix performance, and it should never be quoted
without that clause.

**n=1, and it is a small n.** One ~600 LOC application with no authentication and no server-side
state. It measures nothing about general performance on a real service with roles, tenancy, money, and
state machines.

**The verified finding was MEDIUM.** Not a dramatic critical. The exciting candidate was the one that
got refuted, which is the entire point of the write-up, but it does mean there is no trophy here.

**No public third-party trophy-case entries exist yet.** The trophy case requires a public project and
a public advisory, issue, or fix reference. It is deliberately empty rather than padded.

**The target repository is private**, so this run is not independently reproducible by you. It is an
authorized owner self-audit. It has not been peer-reviewed and it has not been externally validated.

**It is alpha software** — release 3.0.0-alpha.4. Contracts and interfaces are still moving.

## The position

The framework is SecHelix, Apache-2.0, at https://github.com/omarmohelal/SecHelix. Install with
`npx skills@latest add omarmohelal/SecHelix --skill sechelix`. Structurally: 546 hypotheses across 21
families and 26 verification lenses, 17 model-neutral specialist role profiles including an
independent verifier, 18 JSON Schema Draft 2020-12 contracts, 18 Gold Check Packs, 38 paired eval
fixtures (76 cases across 10 families), and a knowledge graph of 76 nodes, 100 edges, and 11 lesson
cards.

None of that structure is the argument. The argument is one sentence, and the run above is the only
evidence for it I currently have:

**Security findings are claims. Verify them before you accuse.**
