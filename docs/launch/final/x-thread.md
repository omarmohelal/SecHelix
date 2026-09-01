# X thread

Seven posts. Post 1 carries the link; the rest are the argument.

---

**1/**

```
Security findings are claims.

The failure mode with AI security review isn't missed bugs. It's confident, well-written,
completely wrong findings — which read exactly like real ones.

So I built the review around disproving them.

SecHelix, Apache-2.0:
github.com/omarmohelal/SecHelix
```

---

**2/**

```
Every candidate goes to an independent verifier whose job is to refute it.

Attacker control. Reachability. Whether the vulnerable state is actually producible. Whether a
compensating control already blocks it.

Surviving that is the bar for being reported at all.
```

---

**3/**

```
The part that matters most is four-valued applicability:

APPLICABLE
NOT_APPLICABLE
UNKNOWN
BLOCKED

UNKNOWN can never be coerced into NOT_APPLICABLE.

"We couldn't check this" never renders as "this is fine." That one rule changes what a report
means.
```

---

**4/**

```
Real example. Small Next.js app, authorized self-audit.

Remote config reached href/src with only .trim() — the exact shape a scanner calls
high-severity XSS.

Verification killed it. React 19 rewrote the payload; attacker control was never established.

FALSE_POSITIVE.
```

---

**5/**

```
That's the interesting result.

Anything can produce findings. Throwing one away costs something.

A scheme allowlist was still added — and labelled hardening, not a fix. Calling it a fix would
imply there had been a vulnerability.
```

---

**6/**

```
The finding that survived was smaller: no CSP, no X-Frame-Options. A cross-origin page framed
the whole UI including sign-in.

Held at MEDIUM, not High. Realistic outcome is phishing amplification, and the app has no
authenticated state-changing actions.

Severity you can defend.
```

---

**7/**

```
Honest status, up front:

Benchmark is NOT_MEASURED. The eval fixtures were written by the same kind of session that
would be scored, so any number would measure recall, not capability. That's recorded in the
repo, and there's a sealed blind packet for whoever measures it properly.

Alpha.

npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

---

## Notes

- Do not add a metrics screenshot. There are no metrics.
- If the thread gets traction, the highest-value reply is the blind packet: it invites someone to
  produce the number rather than asking them to trust one.
