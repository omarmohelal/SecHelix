# Flagship article

**Title:** Why an AppSec agent should try to disprove its own findings

**Canonical:** `https://sechelix.com/research` — set this as the canonical URL on Dev.to and
Hashnode so the duplicate does not compete with the original.

**Tags:** security, ai, appsec, opensource

---

## The failure mode nobody optimises for

Point a capable model at a codebase and ask it to find security problems, and it will find some. It
will also produce findings that are confident, well-structured, and wrong — and those read exactly
like the real ones, because nothing about a fluent explanation requires the underlying claim to be
true.

That asymmetry is the actual problem. A missed bug costs you the bug. A plausible false positive
costs a reviewer an hour, and the third one costs you their attention for every finding after it.

Teams do not abandon bad security tooling because it misses things. They abandon it because they
stop believing it. Once a tool has been wrong three times in a way that felt authoritative, its next
report gets skimmed — including the one that was right.

Most effort in this space goes into detection. I think the more useful lever is refusal.

## A finding is a claim

The design premise of SecHelix is one sentence: **a security finding is a claim, and a claim gets an
independent refutation attempt before anyone is told about it.**

Three mechanisms carry most of that.

### Applicability has four outcomes, and one of them cannot be laundered

Every check resolves to `APPLICABLE`, `NOT_APPLICABLE`, `UNKNOWN`, or `BLOCKED`. `UNKNOWN` and
`BLOCKED` can never be converted into `NOT_APPLICABLE`.

This sounds like bookkeeping. It is the single change with the largest effect on what a report
*means*.

Without it, "we could not evaluate this" and "this does not apply here" collapse into the same
clean-looking output, and a reader cannot tell a check that passed from a check that never ran. With
it, a clean report becomes a much stronger statement, because everything the tool could not
establish is still visible on the page.

### The verifier's job is to lose

Every candidate goes to an independent verifier prompted to disprove it — not to double-check it, to
attack it. Attacker control. Reachability. Missing guard assumptions. Role preconditions. Whether the
vulnerable state is producible at all. Whether some compensating control already blocks the exploit.

Findings that survive carry a seven-link evidence chain, and a finding that cannot name its links
does not ship. High and Critical additionally require regression proof: the assertion has to fail
against the vulnerable control and pass after the fix, or the claim that it was fixed is itself
unverified.

### The gate fails closed

The release decision is `PASS`, `PASS_WITH_KNOWN_RISK`, `BLOCKED`, or `INCOMPLETE`. Missing required
evidence returns `INCOMPLETE` and a non-zero exit — never a silent pass.

A gate that passes when it cannot see is worse than no gate, because it manufactures confidence.

## What this looks like on real code

An authorized self-audit of a small Next.js storefront I own. `STATIC` and `LOCAL` mode, zero
scanners enabled, nothing outside `127.0.0.1` contacted. One external data source, forty-one of 546
hypotheses applicable, three candidates.

**One verified.** No `CSP`, `X-Frame-Options` or `HSTS` on any route. A probe page served from a
separate origin framed the entire interface, including the sign-in entry point. The fix was a
catch-all headers rule; the proof was the browser's own refusal on retest:

> Framing 'http://localhost:3009/' violates the following Content Security Policy directive:
> "frame-ancestors 'none'". The request has been blocked.

It was held at **MEDIUM**, not High. The realistic outcome is phishing amplification, and the app
performs no authenticated state-changing actions. Severity you can defend under questioning is worth
more than severity that looks impressive in a summary.

**One refuted.** Remote configuration values reached `href` and `src` with only `.trim()` applied.
That is precisely the shape a scanner — or a confident reviewer — reports as high-severity XSS.

Verification killed it. React 19 rewrote the payload to
`href="javascript:throw new Error('React has blocked a javascript: URL as a security precaution.')"`,
and attacker control over the configuration source was never established. Recorded
`FALSE_POSITIVE`, with the refutation reasoning kept rather than deleted.

A scheme allowlist was added anyway — and labelled **hardening, not a vulnerability fix**, because
calling it a fix would imply there had been a vulnerability.

That second result is the one I would point at. Any tool can produce findings. Discarding one is the
part that costs something.

**And one process finding**, recorded because it is the interesting kind of near-miss. The first
retest *appeared to fail*. A stale prerender cache and a server still bound to the old port made a
real fix look broken — which is exactly the mechanism by which a real fix silently becomes a false
claim of remediation in the other direction. Only a clean rebuild settled it.

## The same discipline, turned inward

The uncomfortable version of this argument is what happens when you point the tool at itself.

Running the differential reviewer over its own changes produced findings for a docstring explaining
that a digest "is not a signature" — classified as a webhook change — and a comment about a
sample-size bucket, classified as storage access. Neither line does anything. The tool was flagging
its own prose.

Writing tests that tried to *break* the fail-closed guarantees, rather than confirm them, found
worse. An unresolved `CRITICAL` candidate passed the release gate, because the status enum covering
"unproven" listed several states and not the most common one. An empty commit string made every
report read as current, because two revisions were compared on the shorter of their lengths and
nothing enforced a floor — and an empty string is exactly what `git rev-parse` returns when it
produces no output rather than failing.

Both were fail-open paths in modules whose stated contract is fail-closed. Both are fixed. Both are
in the changelog under their own heading, because a project arguing that findings need proof does not
get to be quiet about its own.

## What I am not claiming

**The benchmark was unpublished for months, on purpose.** The repository contains 38 paired
vulnerable/clean fixtures and a working scoring harness. It also contained a machine-readable
blocker, `CONTAMINATED_EVALUATOR`, recording why no number was published: the fixtures were authored
by assistant sessions working in the repository, so scoring one of those sessions measures recall of
answers it wrote rather than security-review capability.

A sealed blind packet exists so an uncontaminated evaluator can produce a real measurement. On
2026-09-02 one finally ran: 76 cases, each judged by a separate process that had never seen the
repository, the fixtures, the labels or the pairings. Precision 0.950, detection recall 1.000,
false-positive rate 0.053.

**Read that result narrowly.** It measures a single-pass, label-only judgment — one question per
file, one label back. There was no attack-surface pass, no independent refutation pass, no adapters,
no evidence chain and no release gate. It is *not* a measurement of the workflow this article
describes, and `applicability_accuracy`, `regression_proof_rate` and `release_gate_accuracy` are
still the literal string `NOT_MEASURED`. One model, one run, on an authored and balanced suite. No
comparison to any other tool is offered or implied.

**The committed keyword baseline is not a score.** It is a regex matcher, flagged
`is_sechelix_result: false`, that lands at chance on the fixture suite. It exists to prove the
scoring harness works and that the fixtures resist pattern matching.

**One case study is not evidence of general performance.** One small app, self-audited by the author,
one verified MEDIUM finding, one refutation.

**It is alpha.** Contracts and interfaces can still change.

**It is built with substantial AI assistance**, directed by a human. Saying otherwise would be its
own kind of unverified claim.

## Try it

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

Then ask your agent for an authorized audit of a repository you own.

Apache-2.0, Python standard library only:
[github.com/omarmohelal/SecHelix](https://github.com/omarmohelal/SecHelix)

The critique I actually want is whether a refutation step run by the same class of model that
generated the candidate is meaningfully independent, or whether it only catches the shallowest
errors. I have a design opinion about that — the quorum mechanism exists because I am not sure — and
I do not have a measurement. I would rather say so than imply one.
