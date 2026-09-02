# Show HN

## Title

```
Show HN: SecHelix – an AppSec agent skill that tries to disprove its own findings
```

80 characters. Alternatives if that one reads wrong on the day:

```
Show HN: An AppSec agent skill that refutes its own findings before reporting
Show HN: SecHelix – security review where every finding must survive refutation
```

## URL

```
https://github.com/omarmohelal/SecHelix
```

## First comment

```
I built this because of a specific failure mode I kept hitting: an AI agent reviewing code
produces a confident, well-written, plausible security finding that is wrong. It reads better
than a real one, because nothing about a fluent explanation requires the underlying claim to be
true. You lose more time refuting those than you save finding real bugs.

SecHelix is an Agent Skill (SKILL.md format, Apache-2.0, Python standard library only) that
treats a finding as a claim. Every candidate goes to an independent verifier whose job is to
disprove it. Applicability resolves to APPLICABLE / NOT_APPLICABLE / UNKNOWN / BLOCKED, so
"we couldn't check" never silently becomes "it's fine". High and Critical findings need
regression proof. The release gate is fail-closed: PASS, PASS_WITH_KNOWN_RISK, BLOCKED, or
INCOMPLETE.

The worked example in the repo shows both halves. On a small Next.js app I own:

  Verified: no CSP, X-Frame-Options or HSTS on any route. A probe page on another origin
  framed the whole UI including the sign-in entry. Fixed, then the browser's own words on
  retest: 'Framing http://localhost:3009/ violates the following Content Security Policy
  directive: "frame-ancestors none". The request has been blocked.' Held at MEDIUM, not High —
  the realistic outcome is phishing amplification, and the app performs no authenticated
  state-changing actions.

  Refuted: remote config values reached href/src with only .trim(). That is exactly the shape
  a scanner reports as high-severity XSS. Verification killed it — React 19 rewrote the
  payload, and attacker control was never established. Recorded FALSE_POSITIVE. A scheme
  allowlist was added anyway and labelled hardening, not a vulnerability fix.

The second one is the point. Producing findings is easy. Throwing one away is the part that
costs something.

Honest status, because someone will ask and I would rather say it first:

- The public benchmark is NOT_MEASURED. There are 38 paired vulnerable/clean fixtures and a
  scoring harness, but the fixtures were authored by assistant sessions working in the repo, so
  scoring one of those sessions measures recall of answers it wrote. That is recorded
  machine-readably as CONTAMINATED_EVALUATOR, and there is a sealed blind packet so someone
  uncontaminated can run it. If you want to be the person who produces the first real number, the
  instructions are in evals/blind-packet/.
- The repo contains a keyword baseline flagged is_sechelix_result: false — a regex matcher that
  lands at chance on the fixtures. It exists to validate the harness and show the fixtures resist
  pattern matching. It is not a SecHelix score.
- One case study, one small app, self-audited. It measures nothing general.
- It is alpha.

Install: npx skills@latest add omarmohelal/SecHelix --skill sechelix

Happy to answer anything, including the uncomfortable version of "how do I know it works".
```

## Anticipated questions

**"How is this different from running Semgrep / CodeQL?"**
It is not a scanner and does not replace one. It consumes scanner output as *evidence* through
read-only adapters and treats every alert as a hypothesis until something supports it. The value is
in what it refuses to report, not in what it detects.

**"Isn't this just prompting?"**
The methodology is prompt-shaped, but the contracts are not: 21 JSON Schemas, a frozen 546-item check
catalog, a report renderer, and a fail-closed release gate that exits non-zero. A report either
validates or it does not.

**"You have no benchmark, so why should I care?"**
That is a fair position. The honest answer is that the benchmark is blocked on a contamination
problem I refuse to launder, and the alternative — publishing a number produced by the session that
wrote the fixtures — would be worse than having none.

**"Did an AI write this?"**
Yes, substantially, with a human directing it. Saying otherwise would be its own kind of unverified
claim.
