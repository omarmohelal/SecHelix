# Show HN draft

**Status: DRAFT — not posted.** Post from the owner's own account, once.

---

## Title

```
Show HN: I pointed my security agent at itself and it found a bug I wrote
```

Alternates, in order of preference:

```
Show HN: SecHelix – a security agent that refuses to report "no findings"
Show HN: An AppSec agent where the verifier never sees the hunter's confidence
```

## URL

```
https://github.com/omarmohelal/SecHelix
```

## Comment (post immediately after submitting)

> I have been building an application-security agent, and the part I keep coming
> back to is not detection — it is what a tool is allowed to say when it did not
> actually check.
>
> Most scanners produce an empty findings list when they fail, and an empty list
> is indistinguishable from a clean result. So SecHelix refuses. If a specialist
> lane could not run — no reasoning provider configured, budget exhausted,
> missing context — the run ends `INCOMPLETE` and prints "No security claim can
> be made from this run." A blocked verifier can never become a PASS.
>
>     $ pip install sechelix
>     $ sechelix audit examples/demo-app
>
>     BLOCKED    authorization   no reasoning executor configured
>     SUCCEEDED  map
>     BLOCKED    verify          dependency not satisfied: authorization
>     BLOCKED    gate            dependency not satisfied: verify
>
>     RESULT  INCOMPLETE - unsatisfied mandatory nodes: gate, verify
>             No security claim can be made from this run.
>
> Two things that came out of building it.
>
> **The verifier is structurally blind.** A hunter proposes a finding; an
> independent verifier tries to refute it and is not told the hunter's
> confidence, severity, or wording — those fields are stripped before the
> candidate is handed over. I tested it by planting a fake finding against a
> deliberately clean file, tagged `confidence: HIGH`, `severity: CRITICAL`,
> `verdict: exploitable`. It refuted the plant and kept the real one, and its
> reason named the specific line: the clean variant compares `order['user_id']`
> to `session['user_id']` and returns 404 on mismatch. It never saw any of the
> conclusion fields.
>
> **It found a path traversal I had written.** Auditing the runner with itself:
> `run_id` came off the command line and was joined straight onto the runs
> directory, so `sechelix report ../../../../etc/hosts` resolved outside the
> workspace and printed the file. That is in the history with the fix and
> regression tests — commit `0e50b56`.
>
> Honest about what is not measured: there is a blind label evaluation
> (precision 0.950 on 38 paired vulnerable/clean cases, judged by 76 independent
> processes) but the **full** workflow is `NOT_MEASURED`, and I have not
> benchmarked against SEC-AF, Cloudflare's security-audit skill or Strix. The
> repo says so in the README rather than in a footnote.
>
> The Agent Skill works in Claude Code / Codex / Copilot with no Python. The
> runner is optional; a test asserts the skill ships no copy of it.
>
> Apache-2.0. Happy to answer anything, including where it is weak.

## BLOCKED — 2026-09-05

Submission was refused by Hacker News:

> We're temporarily restricting Show HNs because of a massive influx, mostly by
> users who aren't yet familiar with the site or its culture. You're welcome on
> HN! Take some time to get to know the community, become a good contributor,
> and then it will be fine to post an occasional Show HN.

Nothing was posted. This is an account-history requirement, not a content
problem, and the only legitimate way through it is genuine participation on HN
over time. Do not attempt to work around it: a Show HN from an account that
evaded the restriction is worse for the project than no Show HN at all.

Re-check eligibility after the owner has been commenting on HN for a while.

## Pre-flight checklist

Everything below must be true at the moment of posting.

- [x] `pip install sechelix` installs 0.2.1 from PyPI
- [x] `sechelix doctor` exits 0 with `core_contracts: True`
- [x] `sechelix audit examples/demo-app` prints the INCOMPLETE block above
- [x] commit `0e50b56` is reachable and contains the traversal fix
- [x] README states the full workflow is `NOT_MEASURED`
- [ ] posted from the owner's own account
- [ ] owner is available for the next 2–3 hours to answer comments

## Rules being followed

- Posted once, by the owner, from their own account.
- No upvote solicitation, anywhere, in any form.
- Every number in the text is reproducible from the repository.
- Weaknesses stated in the post itself, not waited for in comments.
