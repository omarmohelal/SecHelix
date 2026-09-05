# X / Twitter thread draft

> **DRAFT — not posted.**

## X / Twitter

Thread, 4 posts.

**1/**
> An empty findings list looks exactly like a clean scan.
>
> Crashed scanner, expired key, exhausted budget, genuinely clean code — all four
> emit `findings: []`. CI goes green for all four.
>
> So I built one that refuses. 🧵

**2/**
> If a lane can't run, the gate returns INCOMPLETE:
>
> `RESULT INCOMPLETE — unsatisfied mandatory nodes: gate, verify`
> `No security claim can be made from this run.`
>
> A blocked verifier can never become a PASS. There's a test that starves the
> budget mid-verification to prove it.

**3/**
> The verifier is structurally blind. Confidence, severity and verdict are
> stripped before a candidate reaches it.
>
> I planted a fake finding on a clean file tagged HIGH/CRITICAL. It refuted the
> plant, kept the real one, and named the exact line that disproved it — having
> never seen the tags.

**4/**
> It also found a path traversal I'd written, in its own runner.
>
> Apache-2.0. Blind eval: precision 0.950 on 38 paired cases. The full workflow
> is still NOT_MEASURED and the README says so.
>
> github.com/omarmohelal/SecHelix

---

## Sequencing

1. DEV.to article first — the others link to it.
2. Show HN next, while the owner can answer for 2–3 hours.
3. Reddit after, linking the article rather than the repo.
4. LinkedIn / X last.

Never post to two link-aggregators within the same hour; simultaneous identical
submissions read as coordinated and get filtered on both.
