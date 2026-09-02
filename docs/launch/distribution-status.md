# Distribution status

Assessed **2026-09-02**. Every policy below was read from the target on that date. Nothing is
submitted on the strength of this page without re-reading the policy first — several changed
recently in response to a flood of AI-generated submissions.

## Open submissions

| Target | Submitted | State |
|---|---|---|
| [github/awesome-copilot#2899](https://github.com/github/awesome-copilot/issues/2899) | 2026-09-01 | OPEN — automated reputation check labelled `needs-review:MEDIUM`; no maintainer comment |
| [royalpinto007/awesome-agent-skills#4](https://github.com/royalpinto007/awesome-agent-skills/pull/4) | 2026-09-01 | OPEN — no review |
| [Ezeafk/awesome-agent-skills#33](https://github.com/Ezeafk/awesome-agent-skills/pull/33) | 2026-09-01 | OPEN — no review |

**Monitored, not chased.** A maintainer who has not replied in a day has not ignored anything.
Respond promptly and technically *when* there is something to respond to; do not bump.

## Blocked on a human account

### SkillMD — ELIGIBLE, needs sign-in

`https://skillmd.com/publish` reads: *"Submit a skill for review — a single `SKILL.md`, or a `.zip`.
**Sign in to publish**."*

It is a real, active registry (a Security category with ~1,976 entries) and SecHelix qualifies. It
cannot be submitted from here: publishing requires an authenticated account, and creating an account
on someone's behalf is not a step to take automatically.

**Manual, ~5 minutes.** Sign in at `skillmd.com`, choose *Publish*, upload
`skills/sechelix/SKILL.md`, category **Security**.

Description to paste, verbatim:

> Evidence-first application-security review skill. Every candidate finding goes to an independent
> verifier whose job is to disprove it before it is reported. Applicability resolves to APPLICABLE /
> NOT_APPLICABLE / UNKNOWN / BLOCKED so missing evidence is never treated as absence, High and
> Critical findings require regression proof, and the release gate is fail-closed. For code you own
> or are explicitly authorized to test. Apache-2.0. Public benchmark is NOT_MEASURED.

Confirm afterwards that the listing does not display an install or adoption figure as though it were
a SecHelix claim.

### claudemarketplaces.com — NEEDS A HUMAN READ

Resolves (200), but no `/submit` path and no machine-readable contribution policy was found. Someone
should read the site and find the actual submission route before anything is sent.

### aigearbase.com — NEEDS ASSESSMENT

`/submit` exists (200). **Not assessed for trust.** Directory quality matters more than backlink
count, and a listing on a low-trust aggregator is worth less than no listing. Read it properly
first: is it curated or scraped, is it maintained, does it have a real audience?

## Deferred, with the condition that clears them

Each has a stated gate SecHelix does not currently pass. Recorded so the date is visible rather than
guessed.

| Target | Gate, quoted | Earliest |
|---|---|---|
| `hesreallyhim/awesome-claude-code` | *"Be at least 14 days old … OR have at least 100 stars"* | 2026-09-14 |
| `travisvn/awesome-claude-skills` | *"if your skill hasn't acquired a basic 10 stars, it will be closed automatically"* — and *"the PR not be explicitly generated / submitted with AI-assistance"* | On stars **and a human author** |
| `analysis-tools-dev/static-analysis` | *"exist for at least six months / at least 20 stars / more than one contributor"* | ~2027-03 |
| `VoltAgent/awesome-agent-skills` | *"Skill must have real community usage … Brand new skills that were just created are not accepted"* | On adoption |

The `travisvn` rule is binding, not a formality: that submission must be written and sent by a
person, not generated.

## Declined, with the reason

| Target | Why |
|---|---|
| `claude-market/marketplace` | Vendors plugin source into its own tree (all entries use `"source": "./name"`). Copying SecHelix there forks the canonical skill and guarantees drift. |
| `ComposioHQ/awesome-claude-skills` | Same vendoring model. |
| `OWASP/www-community` | *"contributions are vendor and product neutral"* — a tool listing is out of scope. |
| `paragonie/awesome-appsec` | Dormant since 2025-02; scoped to learning resources. |
| `patrickclery/awesomer` | Automated star-growth aggregator, ranked by stars gained. That is the metric this project has committed not to pursue. |

## Rule for anything not on this page

Read the current policy. Verify eligibility honestly. Tailor the description — an identical body
posted to five lists reads as spam and is treated as such. Submit **once**. Record the URL and
status here.

Do not submit to a stale or low-trust directory for backlink count. A listing nobody reads costs
credibility with the people who notice, and buys nothing from anyone else.
