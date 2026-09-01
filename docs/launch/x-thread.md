# X / Twitter thread draft

> **DRAFT — requires human review before publishing. Do not post automatically.**

Character counts below are raw character counts of the post body, verified programmatically. All 13
posts are under 280. Counts exclude the `<!-- -->` comment itself. A human should re-check counts
after any edit, and confirm link-shortening behaviour for the post that contains a URL.

Hashtags: exactly one, in the final post. Do not add more.

---

**1/13**

A security review I ran wanted to report a HIGH-severity XSS.

Then it verified the claim, and talked itself out of it.

The refutation is the point. Findings are claims. Verify before you accuse.

<!-- 196 chars -->

---

**2/13**

Setup: authorized self-audit of a private repo I own. 2026-09-01.

~600 LOC TypeScript/TSX, 19 files, Next.js 16.2.7.
STATIC + LOCAL only. Zero scanners enabled — code reading plus local runtime observation.

Nothing outside 127.0.0.1 was contacted.

<!-- 249 chars -->

---

**3/13**

The candidate: remote store-config values (hero.ctaHref, footerLinks[].href, socials.*, a listing image) flowed into href/src with only .trim() applied.

Remote source. URL sink. No scheme validation.

That is exactly the shape a scanner files as HIGH XSS.

<!-- 256 chars -->

---

**4/13**

Refutation 1. A local mock config API served javascript:alert(document.domain).

The rendered document contained:

href="javascript:throw new Error('React has blocked a javascript: URL as a security precaution.')"

React 19 neutralizes it before it reaches the document.

<!-- 270 chars -->

---

**5/13**

Refutation 2, the one that matters more: attacker control was never established.

The config source is the operator's own workspace API, not an internet-reachable input.

If nobody hostile can write the value, there is no vulnerability — however bad the dataflow looks.

<!-- 269 chars -->

---

**6/13**

Recorded outcome: FALSE_POSITIVE, with the refutation reason retained so nobody re-raises it in six months.

A scheme allowlist was still added at the trust boundary.

The report labels that HARDENING, not a vulnerability fix. Different words, different meanings.

<!-- 263 chars -->

---

**7/13**

What actually survived: SHX-F-GOS-HEADERS-001. MEDIUM. Clickjacking.

next.config.ts had only an images block. The build emitted no CSP, no X-Frame-Options, no nosniff, no Referrer-Policy, no HSTS, no Permissions-Policy — and advertised X-Powered-By: Next.js.

<!-- 259 chars -->

---

**8/13**

Held at MEDIUM on purpose. Phishing amplification and brand abuse, not account takeover, because the app performs no authenticated state-changing actions.

Severity inflation is how teams learn to ignore their own queue.

<!-- 220 chars -->

---

**9/13**

Fix: catch-all headers() rule — CSP frame-ancestors 'none', X-Frame-Options DENY, nosniff, referrer policy, Permissions-Policy, HSTS, COOP, poweredByHeader false.

Retest, in the browser's own words:

"The request has been blocked."

<!-- 232 chars -->

---

**10/13**

The first retest appeared to FAIL. Headers still missing, hostile URL still in the DOM.

Cause: stale Next.js prerender cache + a server still bound to the old port.

A stale artifact that makes a broken thing look fixed closes tickets and ships.

<!-- 246 chars -->

---

**11/13**

Whole run: 1 external data source, 3 public routes, 0 authenticated actions -> 41 of 546 hypotheses applicable -> 3 candidates -> 1 verified, 2 refuted -> 1 fix + 1 hardening -> 10 regression assertions -> release PASS after remediation.

<!-- 237 chars -->

---

**12/13**

Honest part: benchmarks are NOT_MEASURED. The fixtures were expanded by the same session that would have been the evaluated model — it knew fixtures it had written itself. Scoring that measures recall, not capability.

I would rather ship NOT_MEASURED than a number I don't believe.

<!-- 264 chars -->

---

**13/13**

One ~600 LOC app, no auth, no server-side state. Private repo, so you can't reproduce it. The finding was MEDIUM. No public trophy-case entries yet. Alpha.

Apache-2.0: github.com/omarmohelal/SecHelix

Security findings are claims. #appsec

<!-- 239 chars -->

---

## What this does not do yet

This section is **not** part of the thread. It is the reference the poster must be able to answer
from if replies get sharp. Post 12 and post 13 already carry the short version; if a reply demands
detail, quote from here rather than improvising.

- **Benchmarks are NOT_MEASURED.** Documented blocker: `CONTAMINATED_EVALUATOR`. The fixture suite
  was expanded on 2026-09-01 by the same assistant session that would have acted as the evaluated
  model, giving it prior knowledge of fixtures it had written itself. Scoring it would measure recall of
  authored answers, not security-review capability. Unblocking requires a run by a model/session that
  did not author the fixtures, using blind exported cases.
- The harness baseline at `evals/results/baseline-keyword-v1.json` is **explicitly not a SecHelix
  score** (`is_sechelix_result: false`). It is a naive regex keyword matcher run to prove the scoring
  harness works and that the fixtures resist pattern matching: precision 0.511 / recall 0.632 on a
  balanced 38/38 split, i.e. chance level. That is a **fixture-difficulty** statement, not a
  performance claim. Do not tweet the numbers without that clause attached.
- The case study is **one** small ~600 LOC app with no authentication and no server-side state. It
  measures nothing about general performance.
- The verified finding was **MEDIUM**, not a dramatic critical. Do not let a reply talk it upward.
- **No public third-party trophy-case entries exist yet.**
- The target repo is **private**, so the case study is not independently reproducible by a reader,
  and it is not peer-reviewed or externally validated. It is an owner self-audit.
- **Alpha** software (3.0.0-alpha.4).
