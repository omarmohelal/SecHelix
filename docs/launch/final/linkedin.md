# LinkedIn

One post. No hashtag spray — three at most, at the end.

```
The problem with AI-assisted security review isn't that it misses things.

It's that it produces findings that are confident, well-structured, and wrong. A fluent
explanation doesn't require the underlying claim to be true — and a plausible false positive
costs a team more time than a real bug saves.

So I built the review process around disproving findings rather than producing them.

SecHelix is an open-source Agent Skill for application-security review of systems you're
authorized to test. The premise is that a security finding is a claim, and a claim gets an
independent refutation attempt before anyone is told about it.

Three decisions do most of the work:

Applicability has four outcomes — APPLICABLE, NOT_APPLICABLE, UNKNOWN, BLOCKED — and UNKNOWN can
never be converted into NOT_APPLICABLE. "We couldn't check this" never renders as "this is
fine." That single rule changes what a clean report actually means.

Every candidate goes to an independent verifier whose explicit job is to disprove it: attacker
control, reachability, whether the vulnerable state is producible at all, whether a compensating
control already blocks it.

The release gate fails closed. Missing required evidence returns INCOMPLETE, not a pass.

A worked example from the repository, on a small app I own:

One finding was verified — missing security headers allowed a page on another origin to frame
the entire interface, including the sign-in entry point. Fixed, then proved fixed by retesting
until the browser itself refused the frame. Held at MEDIUM rather than High, because the
realistic outcome is phishing amplification and the app performs no authenticated
state-changing actions.

One candidate was refuted — remote configuration values reaching href and src with minimal
sanitisation, which is exactly the shape that gets reported as high-severity XSS. Verification
killed it. The framework neutralised the payload, and attacker control was never established.
It was recorded as a false positive, with the reasoning kept.

The second one is the more useful result. Producing findings is easy. Discarding one is the part
that costs something.

What I'm not claiming: there is no published benchmark. The evaluation fixtures were authored by
the same kind of session that would be scored against them, so any number would measure recall
of authored answers rather than review capability. That's documented in the repository as a
blocker rather than papered over, and there's a sealed evaluation packet so someone
uncontaminated can produce the first real measurement.

It's alpha, it's Apache-2.0, and I'd rather hear where the methodology is wrong than where it
sounds good.

github.com/omarmohelal/SecHelix

#ApplicationSecurity #AppSec #AI
```

## Notes

- Do not add a chart. There is nothing measured to chart.
- If someone asks for the benchmark in comments, link the blind packet and say plainly that the
  number does not exist yet.
