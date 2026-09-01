# r/netsec

**Post only if the current rules allow it.** r/netsec is stricter than r/AppSec and historically
declines tool announcements without a substantive technical writeup or novel research. A tool at
alpha with an unmeasured benchmark is a plausible decline.

**Recommended:** do not post the tool. Post the *methodology writeup* instead
(`article.md`), which is technical content that happens to reference the tool, and let the
repository link sit at the bottom. If the mods still consider that self-promotion, accept it and
move on rather than arguing.

## If posting is allowed

### Title

```
Treating security findings as claims: refutation-first review for AI coding agents
```

### Body

```
A pattern I have not seen addressed well: when an AI agent reviews code for security, its false
positives are more expensive than its misses. A fluent, well-structured, entirely wrong finding
reads exactly like a real one, and reviewers burn more time refuting it than a real bug would
have cost to fix.

The usual response is better detection. I think the more useful lever is a mandatory refutation
step, so I built the review process around it.

Structure:

- Applicability is a four-valued decision — APPLICABLE / NOT_APPLICABLE / UNKNOWN / BLOCKED.
  UNKNOWN and BLOCKED can never be coerced into NOT_APPLICABLE, so "we could not check this"
  never renders as "this is fine". This is the single change with the most effect on report
  honesty.
- Every candidate goes to an independent verifier prompted to disprove it: attacker control,
  reachability, missing guard assumptions, role preconditions, impact, whether the vulnerable
  state is actually producible, and whether a compensating control already blocks it.
- Findings carry a seven-link evidence chain. A finding that cannot name its links does not
  ship.
- High and Critical require regression proof — the assertion must fail on the vulnerable
  control and pass after the fix.
- The release gate is fail-closed. Missing required evidence yields INCOMPLETE, not a pass.

Worked example, an authorized self-audit of a small Next.js app:

The interesting result is the one that was thrown away. Remote config values reached href/src
with only .trim() — the exact shape a scanner reports as high-severity XSS. The verifier killed
it: React 19 rewrote the payload to href="javascript:throw new Error('React has blocked a
javascript: URL as a security precaution.')", and attacker control over the config source was
never established. Recorded FALSE_POSITIVE, refutation reason retained. A scheme allowlist was
added and explicitly labelled hardening rather than a fix, because calling it a fix implies
there was a vulnerability.

The finding that survived was smaller: missing CSP / X-Frame-Options / HSTS, a cross-origin
probe framing the sign-in entry point. Held at MEDIUM rather than High because the realistic
outcome is phishing amplification and the app performs no authenticated state-changing actions.

Also relevant here: an UNTRUSTED_REPO mode in which repository content is data and never
control. Pointing an agent at code you did not write is a prompt-injection surface — CLAUDE.md,
AGENTS.md, settings files, hooks and docstrings inside the target can all attempt to steer the
reviewer. Under that mode none of them can grant a capability or widen scope, trust resolution
fails closed, and a file attempting it is itself reported.

Limits, stated because they are the first thing worth attacking:

- Benchmark is NOT_MEASURED. 38 paired vulnerable/clean fixtures exist with a scoring harness,
  but the fixtures were authored by assistant sessions working in the repository, so scoring one
  of those sessions measures recall of authored answers. Recorded machine-readably as
  CONTAMINATED_EVALUATOR, with a sealed blind packet for an uncontaminated evaluator.
- The committed keyword baseline is flagged is_sechelix_result: false — a regex matcher at
  chance, present to validate the harness and evidence fixture difficulty.
- One case study, one small app, self-audited. Nothing general is claimed.

Apache-2.0, Python standard library only: https://github.com/omarmohelal/SecHelix

I am the author. The critique I actually want is whether a refutation step run by the same class
of model that generated the candidate is meaningfully independent, or whether it only filters
the shallowest errors.
```
