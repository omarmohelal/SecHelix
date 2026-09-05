---
title: "Why my security scanner refuses to tell you your code is clean"
published: true
tags: security, appsec, ai, opensource
published_url: https://dev.to/omarmohelal/why-my-security-scanner-refuses-to-tell-you-your-code-is-clean-5aj8
ai_disclosure: "Some AI (AI-assisted)"
---

# Why my security scanner refuses to tell you your code is clean

There is a failure mode in security tooling that almost nobody instruments for,
and once you see it you cannot unsee it.

**An empty findings list looks identical to a clean result.**

A scanner that crashed halfway, a scanner whose API key expired, a scanner that
ran out of budget, and a scanner that genuinely examined everything and found
nothing — all four produce the same artifact: `findings: []`. The CI job goes
green. The PR merges. Nobody involved can tell which of the four happened.

I built an application-security agent, and this is the problem I ended up
designing the whole thing around.

## What it does instead

```bash
pip install sechelix
sechelix audit examples/demo-app
```

```
  BLOCKED    authorization   no reasoning executor configured; this node
                             analyses code and cannot be answered by the
                             runner alone
  SUCCEEDED  map
  BLOCKED    verify          dependency not satisfied: authorization
  BLOCKED    gate            dependency not satisfied: verify

RESULT  INCOMPLETE - unsatisfied mandatory nodes: gate, verify
        No security claim can be made from this run.
```

Exit code 1. Not because your code is bad — because **nothing was examined**,
and the tool will not pretend otherwise.

The states are deliberately distinct:

| State | Meaning |
|---|---|
| `SUCCEEDED` | the lane ran and delivered |
| `SKIPPED` | the lane does not apply to this target — it owes no evidence |
| `BLOCKED` | the lane could not run. A real question is open |
| `FAILED` | the lane ran and errored |

`SKIPPED` and `BLOCKED` are the pair that matters. An inapplicable lane is a
real answer. An unaffordable verifier is not.

## The budget case is the one that convinced me

Give a run a cost ceiling and let it run out just before the verifier:

```
map     SUCCEEDED
authz   SUCCEEDED
verify  BLOCKED    max_cost_usd budget exhausted: requested 0.5, 0.1 remaining
gate    BLOCKED    dependency not satisfied: verify

unsatisfied mandatory: ['gate', 'verify']
```

A budget limit that silently skips verification and then returns PASS has
converted a cost control into a correctness bug. That is strictly worse than
having no budget at all, because now the failure is invisible. There is a test
that starves the budget mid-verification and asserts the gate never passes.

## Blinding the verifier

The second design decision: a hunter proposes findings, and an independent
verifier tries to refute them. The verifier is **not told** the hunter's
confidence, severity, verdict, or exploitability — those fields are stripped
before the candidate is handed over.

The reason is mundane. A verifier that reads *"HIGH confidence SQL injection,
definitely exploitable"* before it looks at the code is not verifying. It is
agreeing.

I tested this by planting a fake finding. Two candidates went in: one real
(against a file with a genuine missing ownership check), one fabricated against
that file's **clean twin**, tagged as loudly as I could make it —
`confidence: HIGH`, `severity: CRITICAL`, `verdict: exploitable`,
`hunter_notes: certain this is a real IDOR`.

The verifier kept the real one and refuted the plant:

> *refuted: the candidate locating the missing-ownership claim at
> `clean/orders.py:get_order` is false. The clean variant explicitly compares
> `order['user_id']` to `session['user_id']` and returns `(None, 404)` on
> mismatch before the success return.*

It named the exact line. And a capture of the prompt actually sent confirms
`HIGH`, `CRITICAL`, `exploitable` and the hunter's note never reached it.

## Paired fixtures, because precision is the hard part

The demo corpus has five vulnerable files and five clean counterparts, each pair
differing in exactly one security-relevant way.

This is not decoration. **A corpus that only contains bugs cannot measure
whether a tool stops.** An agent that flags every line scores perfectly on a
vulnerable-only benchmark and is useless in a real repository. If the clean twin
is not in the corpus, a false positive is invisible.

## It found a bug I wrote

I pointed the tool at its own runner. It found a path traversal:

`run_id` arrives from the command line — `sechelix report <id>` — and was joined
straight onto the runs directory. So:

```
run_id='../../outside.json'  ->  resolves outside the workspace
```

`report` would then read that file and print it. Fixed with a shape check plus a
resolved-path confinement check, and ten regression tests. It is in the history
at commit `0e50b56` rather than quietly patched.

## What I have not measured

There is a blind evaluation: 76 cases judged by 76 independent processes, each
launched from an empty directory containing only the case file — precision
0.950, false-positive rejection 0.947. That is a **label-only** result on 38
authored pairs. It is not a measurement of the full workflow, which is still
marked `NOT_MEASURED` in the repository.

I also have not benchmarked against SEC-AF, Cloudflare's security-audit skill,
or Strix. So I am not claiming to beat them. The comparison does not exist yet,
and saying so is cheaper than being caught.

## Try it

```bash
# Agent Skill — Claude Code, Codex, Copilot. No Python.
npx skills@latest add omarmohelal/SecHelix --skill sechelix

# Optional runner
pip install sechelix
sechelix doctor
sechelix audit examples/demo-app
```

`STATIC` is the default and performs no network access at all. No account, no
email, no cloud.

Apache-2.0 · [github.com/omarmohelal/SecHelix](https://github.com/omarmohelal/SecHelix)

If you disagree with the fail-closed design — and there is a real argument that
a noisy `INCOMPLETE` trains people to ignore it — I would genuinely like to hear
it.
