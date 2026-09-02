# r/AppSec

Check the subreddit's current self-promotion rule before posting. Flair as a tool/project release if
the sub uses flair.

## Title

```
I built an AppSec agent skill that has to disprove its own findings before it reports them
```

## Body

```
The problem I kept hitting with AI-assisted security review is not that the agent misses things.
It is that it produces confident, well-written, entirely wrong findings. A fluent explanation
does not require the underlying claim to be true, and a plausible false positive costs more
review time than a real bug saves.

So I built the review process around refutation instead of detection.

SecHelix is an Agent Skill — SKILL.md format, Apache-2.0, Python standard library only. The
shape of it:

- Map the attack surface, then select applicable checks from a frozen 546-item catalog
  (21 families x 26 verification lenses) rather than running everything at everything.
- Hunt in parallel across 17 specialist role profiles.
- Send every candidate to an independent verifier whose explicit job is to disprove it.
- Applicability resolves to APPLICABLE / NOT_APPLICABLE / UNKNOWN / BLOCKED. Missing evidence
  never becomes absence of a problem.
- High and Critical need regression proof: the test has to fail on the vulnerable control and
  pass after the fix.
- The release gate is fail-closed — PASS, PASS_WITH_KNOWN_RISK, BLOCKED, or INCOMPLETE. Missing
  required evidence yields INCOMPLETE, not a silent pass.

The worked example is one small Next.js app I own, audited STATIC + LOCAL with zero scanners
enabled and nothing outside 127.0.0.1 contacted:

VERIFIED — SHX-F-GOS-HEADERS-001, MEDIUM. No CSP, X-Frame-Options or HSTS on any route. A probe
page on a separate origin framed the entire UI including the sign-in entry point. Held at MEDIUM
rather than High on purpose: the realistic outcome is phishing amplification, not account
takeover, because the app performs no authenticated state-changing actions. Fixed with a
catch-all headers rule, then retested; the browser's own message on retest was
'Framing http://localhost:3009/ violates the following Content Security Policy directive:
"frame-ancestors none". The request has been blocked.'

REFUTED — SHX-F-GOS-URLSCHEME-001. Remote config values reached href/src with only .trim().
That is the exact shape a scanner or a confident reviewer reports as high-severity XSS.
Verification killed it: React 19 rewrote the payload, and attacker control over those config
values was never established. Recorded FALSE_POSITIVE with the refutation reason retained. A
scheme allowlist was still added — and labelled hardening, not a vulnerability fix, because
calling it a fix would imply there had been a vulnerability.

One more thing that might be relevant to this sub specifically: there is an UNTRUSTED_REPO mode
where repository content is data and never control. When you point an agent at code you did not
write, files inside that repo — CLAUDE.md, AGENTS.md, settings, hooks, even docstrings — cannot
grant it a capability, promote themselves to instructions, or widen scope. A file asking the
reviewer to skip a check is itself a finding. Trust resolution fails closed.

Where I am being honest about limits:

- One uncontaminated blind label run exists (2026-09-02): precision 0.950, detection recall
  1.000, FP rate 0.053 on 38 authored pairs. It is label-only — one question per file — so it is
  not a benchmark of the workflow. Applicability accuracy, regression-proof rate and release-gate
  accuracy remain NOT_MEASURED, and verified precision is 0.0 because verification was never run.
  Do not read it as "SecHelix accuracy".
- The keyword baseline in the repo is flagged is_sechelix_result: false. It is a regex matcher
  that lands at chance. It validates the harness and shows the fixtures resist pattern matching.
  It is not a score for this tool.
- One case study, one small app, self-audited by the author. It measures nothing general.
- Alpha.

Repo: https://github.com/omarmohelal/SecHelix
Install: npx skills@latest add omarmohelal/SecHelix --skill sechelix

I am the author. Genuinely interested in where the methodology is wrong — particularly whether
the refutation step is rigorous enough to be worth the tokens it costs, and whether the
applicability model maps onto how you actually scope reviews.
```
