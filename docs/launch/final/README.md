# Final launch content

Ready-to-post copy for the `v3.4.0-alpha.1` launch. Everything here is final form — earlier
exploratory drafts live one directory up in `docs/launch/`.

**Publication state, 2026-09-02.** `linkedin.md` and `x-thread.md` have been posted and are
**historical records** — do not rewrite them to match the new benchmark wording; they say what was
said at publication time. `flagship-article.md` was published on sechelix.com, Dev.to and Hashnode
and has been synced to what actually went out. `show-hn.md`, `reddit-appsec.md` and
`reddit-netsec.md` are unposted and carry the current wording.

## The one story

> Security findings are claims. SecHelix independently verifies them before it accuses.

Every piece below carries the same worked example, because it is the only real evidence this project
has and it demonstrates both halves of the argument at once:

- **Verified** — `SHX-F-GOS-HEADERS-001`, a **MEDIUM** clickjacking finding. No `CSP`,
  `X-Frame-Options` or `HSTS` on any route; a probe page on a separate origin framed the whole UI
  including the sign-in entry point. Severity held at MEDIUM on purpose: phishing amplification, not
  account takeover, because the app performs no authenticated state-changing actions.
- **Refuted** — `SHX-F-GOS-URLSCHEME-001`. Remote config values reached `href`/`src` with only
  `.trim()`, which is exactly the shape a scanner or a confident reviewer reports as high-severity
  XSS. Verification killed it: React 19 rewrote the payload, and attacker control was never
  established. Recorded `FALSE_POSITIVE`.

The refuted one is the more interesting half. Anything can produce findings; throwing one away is
the part that costs something.

## Rules for every post

- **State the measurement boundary exactly.** The first blind label-suite run is measured
  (precision 0.950, detection recall 1.000, FP rate 0.053, TP 38 · FP 2 · TN 36 · FN 0). The
  **full SecHelix workflow is still `NOT_MEASURED`**. Never present 0.950 as "SecHelix accuracy":
  it is one model answering one question per file, with no verifier, adapters, remediation,
  regression proof or release gate in the loop. If a post cannot fit that caveat, drop the number.
- **No adoption, install, star or ranking claim.** The skills.sh install count is currently 2 and
  both are our own cold-install verification runs.
- **No comparison to another tool**, named or implied.
- **No "first", "best", "#1", or "leading".**
- Disclose authorship. The case study is an owner self-audit of a private app; say that.
- It is alpha. Say that too.

## Files

| File | Destination | Notes |
|---|---|---|
| `show-hn.md` | Show HN | Title is length-constrained; body goes in the first comment. |
| `reddit-appsec.md` | r/AppSec | Check the subreddit's self-promotion rule on the day. |
| `reddit-netsec.md` | r/netsec | Stricter. Only post if the mod rules allow a tool of this maturity. |
| `x-thread.md` | X | Seven posts. |
| `linkedin.md` | LinkedIn | One post. |
| `article.md` | Dev.to / Hashnode | Long form, same body for both, canonical to sechelix.com. |

## Before posting anything

1. Re-read the destination's current self-promotion rules. They change.
2. Be available to answer for the first few hours. A launch post you abandon reads worse than none.
3. The first hostile question will be "how do I know it works?" The honest answer is the whole
   point: *you don't yet, the benchmark is unmeasured and here is why, and here is the blind packet
   so someone uncontaminated can measure it.*
