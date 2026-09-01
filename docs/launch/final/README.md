# Final launch content

Ready-to-post copy for the `v3.2.0-alpha.1` launch. Everything here is final form — earlier
exploratory drafts live one directory up in `docs/launch/`.

**Nothing here has been posted.** Posting is a human decision.

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

- **No benchmark, accuracy, precision, recall or detection-rate claim.** The public benchmark is
  `NOT_MEASURED` and the blocker is documented. Say so plainly if asked.
- **No adoption, install, star or ranking claim.** The skills.sh install count is currently 1 and
  that 1 is our own verification run.
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
