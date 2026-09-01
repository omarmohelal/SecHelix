# Article — Dev.to and Hashnode

Same body for both. Set canonical to `https://sechelix.com` on whichever publishes second.

**Title:** Security findings are claims

**Subtitle:** Building an AppSec review process around refutation instead of detection

**Tags:** security, ai, appsec, opensource

---

## The failure mode nobody optimises for

Point a capable model at a codebase and ask it to find security problems, and it will. Some of them
will be real. The rest will be confident, well-structured, and wrong — and they will read exactly
like the real ones, because nothing about a fluent explanation requires the underlying claim to be
true.

That asymmetry is the actual problem. A missed bug costs you the bug. A plausible false positive
costs a reviewer an hour, and the third one costs you their attention for every finding after it.
Teams do not stop using bad security tooling because it misses things. They stop because they stop
believing it.

Most of the effort in this space goes into detection. I think the more useful lever is refusal.

## Making a finding earn its place

The design premise of SecHelix is one sentence: a security finding is a claim, and a claim gets an
independent refutation attempt before anyone is told about it.

Three mechanisms carry most of that.

### Applicability has four outcomes, and one of them cannot be laundered

Every check resolves to `APPLICABLE`, `NOT_APPLICABLE`, `UNKNOWN`, or `BLOCKED`. `UNKNOWN` and
`BLOCKED` can never be converted into `NOT_APPLICABLE`.

This sounds like bookkeeping. It is the single change with the largest effect on what a report
means. Without it, "we could not evaluate this" and "this does not apply here" collapse into the
same clean-looking output, and a reader cannot tell the difference between a check that passed and a
check that never ran. With it, a clean report is a much stronger statement, because everything it
could not establish is still visible.

### The verifier's job is to lose

Every candidate goes to an independent verifier prompted to disprove it. Not to double-check it —
to attack it: attacker control, reachability, missing guard assumptions, role preconditions, whether
the vulnerable state is producible at all, and whether some compensating control already blocks the
exploit.

Findings that survive carry a seven-link evidence chain. A finding that cannot name its links does
not ship. High and Critical additionally require regression proof: the assertion has to fail against
the vulnerable control and pass after the fix, or the claim that it was fixed is itself unverified.

### The gate fails closed

The release decision is `PASS`, `PASS_WITH_KNOWN_RISK`, `BLOCKED`, or `INCOMPLETE`. Missing required
evidence returns `INCOMPLETE` and a non-zero exit, not a silent pass. A gate that passes when it
cannot see is worse than no gate, because it manufactures confidence.

## What it looks like on real code

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
`FALSE_POSITIVE`, with the refutation reasoning retained rather than deleted.

A scheme allowlist was added anyway — and labelled **hardening, not a vulnerability fix**, because
calling it a fix would imply there had been a vulnerability.

That second result is the one I would point at. Any tool can produce findings. Discarding one is the
part that costs something.

**And one process finding, recorded because it is the interesting kind of near-miss.** The first
retest *appeared to fail*. A stale prerender cache and a server still bound to the old port made a
real fix look broken — which is exactly the mechanism by which a real fix silently becomes a false
claim of remediation in the other direction. Only a clean rebuild proved it.

## Reviewing code you did not write

Pointing an agent at an unfamiliar repository is a prompt-injection surface. The files in that
repository can talk to your reviewer: `CLAUDE.md`, `AGENTS.md`, settings files, hooks, even
docstrings.

Under `UNTRUSTED_REPO` mode, repository content is data and never control. Nothing inside the target
can grant a capability, promote itself to instructions, or widen scope. Trust resolution fails
closed — a missing or malformed trust declaration is a refusal, not a default. And a file that tries
is itself reported as a finding, because attempting to steer the reviewer is information about the
repository.

## What I am not claiming

This is the part most launch posts skip.

**There is no benchmark.** The repository contains 38 paired vulnerable/clean fixtures and a working
scoring harness. It also contains a machine-readable blocker, `CONTAMINATED_EVALUATOR`, recording
why no number is published: the fixtures were authored by assistant sessions working in the
repository, so scoring one of those sessions measures recall of answers it wrote rather than
security-review capability. A sealed blind packet exists so an uncontaminated evaluator can produce
the first real measurement.

Publishing a number produced by the session that wrote the answers would have been easy and would
have been worthless. The status stays `NOT_MEASURED`.

**The committed keyword baseline is not a score.** It is a regex matcher, flagged
`is_sechelix_result: false`, that lands at chance on the fixture suite. It exists to prove the
scoring harness works and that the fixtures resist pattern matching. It says nothing about this
tool.

**One case study is not evidence of general performance.** It is one small app, self-audited by the
author, with one verified MEDIUM finding and one refutation.

**It is alpha.** Contracts and interfaces can still change.

## Try it

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

Then ask your agent for an authorized audit of a repository you own.

Apache-2.0, Python standard library only:
[github.com/omarmohelal/SecHelix](https://github.com/omarmohelal/SecHelix)

The critique I actually want is whether a refutation step run by the same class of model that
generated the candidate is meaningfully independent, or whether it only catches the shallowest
errors. I have a design opinion about that. I do not have a measurement, and I would rather say so.
