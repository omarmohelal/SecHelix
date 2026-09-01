# LinkedIn post draft

> **DRAFT — requires human review before publishing. Do not post automatically.**

Audience: engineering leaders, AppSec managers, security-conscious platform leads.
Angle: triage cost and whether a finding can be trusted.
Length: single post. Trim the middle if the platform truncates before the fold matters.

---

## Post

The most useful thing a security review did for me last month was **withdraw** a finding.

It had found what looked like a high-severity XSS: remote configuration values flowing straight into
`href` and `src` attributes with only `.trim()` applied. Remote source, URL sink, no scheme
validation. If that lands in your triage queue tagged HIGH, nobody argues. Someone schedules the fix.
Someone opens the ticket. If you are unlucky, someone starts drafting a customer notice.

Then it tried to prove the claim, and the claim did not survive.

A local mock config API served `javascript:alert(document.domain)`. The rendered page contained:

`href="javascript:throw new Error('React has blocked a javascript: URL as a security precaution.')"`

React 19 neutralizes `javascript:` URLs before they reach the document. No script execution was
achievable through that path.

And the more important half: **attacker control was never established.** The configuration source was
the operator's own workspace API, not an internet-reachable input. If nobody hostile can write the
value, there is no vulnerability — however alarming the dataflow looks on a diagram.

It was recorded as a FALSE_POSITIVE, with the refutation reason retained so that the next reviewer
does not re-raise it in six months. A scheme allowlist was still added at the trust boundary, and the
report labels that **hardening**, not a vulnerability fix. Two different words, two different
meanings. Conflating them is how remediation metrics quietly stop meaning anything.

Here is why I think this matters to anyone running an AppSec function.

Detection is largely a solved commodity. Triage is not. The scarce resource is engineer attention,
and every unverified HIGH spends it. Do that often enough and you get the failure mode nobody puts in
a board deck: the team stops reading the queue. At that point your tooling has negative value,
because it is manufacturing confidence you have already learned to discount.

So the question I care about is not "what did it find?" It is **"can I trust what it says it
found?"** A finding that has established attacker control, reachability, a failed security boundary,
a safe reproduction, concrete impact, preconditions, root cause, a fix, and regression proof is a
work item. Anything short of that is a hypothesis wearing a severity label.

For completeness — the finding that did survive the same run was clickjacking. The production build
emitted no CSP, no `X-Frame-Options`, no `X-Content-Type-Options`, no `Referrer-Policy`, no HSTS, no
`Permissions-Policy`, and advertised `X-Powered-By: Next.js`. A probe page on a separate origin
embedded the storefront and the entire interface rendered, sign-in entry point included.

I held it at **MEDIUM**. Phishing amplification and brand abuse, not account takeover, because that
application performs no authenticated state-changing actions. Severity inflation is the other half of
false-positive fatigue: a queue full of HIGHs that are really MEDIUMs teaches people to discount
HIGHs.

One more detail, for anyone who owns a remediation SLA. The **first** retest appeared to fail —
headers still missing, hostile URL still in the DOM. The cause was a stale Next.js prerender cache
plus a server still bound to the old port. Only a clean rebuild proved the fix.

Consider which direction that error runs in your pipeline. A stale artifact that makes a fixed thing
look broken costs an hour of confusion. A stale artifact that makes a broken thing look fixed closes
the ticket, passes the gate, and ships. Same root cause, opposite consequences. Retest environment
provenance belongs in the evidence, not in somebody's memory.

The whole run, end to end: 1 external data source, 3 public routes, 0 authenticated actions → 41 of
546 hypotheses applicable → 3 candidates → 1 verified, 2 refuted → 1 fix plus 1 hardening → 10
regression assertions → release decision PASS after remediation.

This is the methodology I have been building in the open as SecHelix — Apache-2.0,
github.com/omarmohelal/SecHelix. It is deliberately structured rather than vibes-based: 546 security
hypotheses across 21 families and 26 verification lenses, 15 JSON Schema contracts that a report has
to validate against, four honest applicability outcomes (APPLICABLE / NOT_APPLICABLE / UNKNOWN /
BLOCKED, where missing evidence is never treated as absence), and a release gate that returns PASS,
PASS_WITH_KNOWN_RISK, BLOCKED, or a fail-closed INCOMPLETE.

### What this does not do yet

*(On LinkedIn, post this as a plain bold line — LinkedIn does not render markdown headings.)*

Stated plainly, because I would rather you hear it from me than find it later:

• Benchmarks are **NOT_MEASURED**. The blocker is documented: the eval fixture suite was expanded on
2026-09-01 by the same assistant session that would have acted as the evaluated model, so it had
prior knowledge of 11 of the 19 fixtures. Scoring that would have measured recall of answers it wrote
itself, not security-review capability. Unblocking it requires a run by a model or session that did
not author the fixtures, on blind exported cases. I could have published a number. It would have been
a dishonest number.

• There is a harness baseline in the repo that is **explicitly not a SecHelix score**. It is a naive
regex keyword matcher, run only to prove the scoring harness works and that the fixtures cannot be
solved by pattern matching. It scored precision 0.5 and recall 0.53 on a balanced 19/19 split, which
is chance level. Read that as evidence about **fixture difficulty**, not about how SecHelix performs.

• This case study is **one** small application, roughly 600 lines, with no authentication and no
server-side state. It tells you nothing about behaviour on a real service with roles, tenancy, money,
and state machines.

• The verified finding was MEDIUM, not a dramatic critical.

• There are **no public third-party trophy-case entries yet.** The trophy case requires a public
project and a public advisory, issue, or fix reference, and it is empty on purpose rather than padded.

• The target repository is **private**, so this run is not independently reproducible by you, and it
is not peer-reviewed or externally validated. It is an authorized owner self-audit.

• It is **alpha** software (3.0.0-alpha.4).

If you run an AppSec program, I would genuinely like to hear where your triage cost actually
concentrates — detection, verification, remediation, or re-verification. My working assumption is
that it is the second and the fourth, and that we mostly instrument the first.

Security findings are claims. Verify before you accuse.
