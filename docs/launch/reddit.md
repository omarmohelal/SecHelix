# Reddit drafts

> **DRAFT — not posted.** Post from the owner's own account.

## r/netsec

r/netsec removes vendor-style self-promotion. Lead with the technical finding,
not the product. Post the **article**, not the repo.

**Title**

```
Blinding the verifier: stripping confidence and severity before an independent
refutation pass
```

**Body**

> Working on an AppSec agent, I kept hitting a problem: a second-pass "verifier"
> that can see the first agent's confidence does not verify, it agrees.
>
> So the candidate is stripped before handover — confidence, severity, verdict,
> exploitability and the hunter's notes are removed, leaving the claim, the
> location and the source evidence.
>
> To test it I planted a fabricated finding against a deliberately clean file
> (the clean twin of a genuinely vulnerable one), tagged HIGH / CRITICAL /
> exploitable. The verifier refuted the plant, kept the real finding, and its
> stated reason named the specific line that made the claim false. A capture of
> the prompt confirms none of the conclusion fields reached it.
>
> Related design decision: when a lane cannot run, the release gate returns
> INCOMPLETE rather than an empty findings list, because an empty list is
> indistinguishable from a clean result.
>
> Full writeup with the transcript and the paired fixture corpus: <article URL>
>
> Apache-2.0, and the blind eval numbers plus what is still NOT_MEASURED are in
> the README.

**Rules:** one post, no comment-brigading, answer criticism directly. If it is
removed as self-promotion, accept it and do not repost.

---

## r/programming

**Title**

```
An empty findings list looks exactly like a clean result — so my scanner
refuses to produce one
```

Body: link the DEV.to article. One or two sentences of context only; r/programming
punishes long self-promotional preambles.

---
