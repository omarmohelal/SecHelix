# SecHelix demo app

A deliberately small, deliberately local target for trying SecHelix. Five
weaknesses, each paired with a corrected version of the same code.

```bash
sechelix audit examples/demo-app
```

**Nothing here talks to the internet.** There is no server to start, no
container to pull, and no external host to point at. Every file is a
self-contained snippet whose vulnerable and clean forms differ in exactly one
security-relevant way.

## Why pairs

A target that only contains bugs measures whether a tool can find things. It
cannot measure whether the tool *stops* — an agent that flags every line scores
perfectly on a vulnerable-only corpus and is useless in a real repository. Each
pair here exists so a false positive is visible.

| Pair | Vulnerable | Clean | The single difference |
|---|---|---|---|
| Object authorization | `vulnerable/orders.py` | `clean/orders.py` | ownership is checked before the object is returned |
| Business logic | `vulnerable/refund.py` | `clean/refund.py` | refund total is bounded by what was actually paid |
| Outbound request | `vulnerable/fetch_avatar.py` | `clean/fetch_avatar.py` | destination is validated against an allowlist |
| Template rendering | `vulnerable/render_profile.py` | `clean/render_profile.py` | user text is escaped rather than interpolated |
| Concurrency | `vulnerable/redeem.py` | `clean/redeem.py` | redemption is atomic and idempotent |

## What a correct result looks like

A tool that reports the five `vulnerable/` issues and **says nothing about**
`clean/` has done well. Reporting a clean file is a false positive and counts
against precision, which is the number this corpus exists to expose.

These are teaching examples, not a benchmark. They are too few and too obvious
to measure anything, and no accuracy claim should be made from them.
