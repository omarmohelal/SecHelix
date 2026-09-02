# Distribution status

Assessed **2026-09-02**, on the day `v3.4.0-alpha.1` was released. Every policy below was read from
the target on that date. Nothing is submitted on the strength of this page without re-reading the
policy first — several changed recently in response to a flood of AI-generated submissions.

Search visibility for everything on this page is measured separately in
[`../research/discovery-v3.4-release.md`](../research/discovery-v3.4-release.md).

## Live listings

| Target | Listing | State |
|---|---|---|
| skills.sh | [`www.skills.sh/omarmohelal/sechelix`](https://www.skills.sh/omarmohelal/sechelix) | LIVE — 1 skill. The install figure it shows is **2**, and both are our own cold-install verification runs. |
| AwesomeSkills | [`www.awesomeskills.dev/en/skill/sechelix-sechelix`](https://www.awesomeskills.dev/en/skill/sechelix-sechelix) | LIVE — name, description, install command, platforms and GitHub URL are all correct. **Auto-categorised as "Image"**, which is wrong; the listing page exposes no edit, report or contact control, so it is not self-service correctable. |

Only the AwesomeSkills URL was added to the site's `Organization.sameAs`. skills.sh was already
there. Nothing pending, and no open pull request, is listed as an identity for this entity.

## Open submissions

| Target | Submitted | State |
|---|---|---|
| [github/awesome-copilot#2899](https://github.com/github/awesome-copilot/issues/2899) | 2026-09-01 | OPEN — automated reputation check labelled `needs-review:MEDIUM`; still the only comment on the issue as of 2026-09-02 |
| [royalpinto007/awesome-agent-skills#4](https://github.com/royalpinto007/awesome-agent-skills/pull/4) | 2026-09-01 | OPEN — no review, no comments |
| [Ezeafk/awesome-agent-skills#33](https://github.com/Ezeafk/awesome-agent-skills/pull/33) | 2026-09-01 | OPEN — no review, no comments |

**Monitored, not chased.** A maintainer who has not replied in a day has not ignored anything.
Respond promptly and technically *when* there is something to respond to; do not bump. Re-read on
2026-09-02 confirmed nothing has been asked of us.

## Blocked on a human account

### Anthropic community marketplace — BOTH FORMS GATED

Third-party plugins do not land in `claude-plugins-official`. Per
`code.claude.com/docs/en/plugins`, the official marketplace is curated by Anthropic at its
discretion, *"there is no application process, and the submission form does not add plugins to the
official marketplace."* Submissions go to `anthropics/claude-plugins-community` after review. **No
"Anthropic Verified" status exists to claim, and none is claimed.**

`claude plugin validate .` passes locally: *"Validation passed with warnings"*, one warning —
`CLAUDE.md` at the plugin root is not loaded as project context. That warning is about a repository
development file, not the shipped skill, and does not fail validation.

Both documented submission routes are gated:

| Form | Requirement | Observed |
|---|---|---|
| `claude.ai/admin-settings/directory/submissions/plugins/new` | Team or Enterprise organisation with directory management access | The owner's authenticated session returns *"You don't have access to organization settings."* |
| `platform.claude.com/plugins/submit` | Claude Console sign-in | No Console session in this browser; the page is the Console sign-in wall |

**Manual, one step.** Sign in to the Console as the owner, open the form, and submit the values in
[`final/README.md`](final/README.md) and the plugin manifest. Nothing else about the submission is
outstanding.

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

### claudemarketplaces.com — NO PUBLIC SUBMISSION ROUTE

Re-checked 2026-09-02. Its `/api/search` endpoint now answers HTTP 410 with
`{"error":"Marketplace discovery is local-only. Run bun run discovery:weekly instead."}`, and
`/api/plugins` is a 404. `/api/skills` and `/api/marketplaces` return whole indexes and ignore query
parameters; neither contains `sechelix`.

There is still no `/submit` path and no machine-readable contribution policy. The index appears to
be crawler-populated rather than submission-driven, so **no submission workflow was invented and
nothing was sent.** If SecHelix appears there later it will be because their crawler found it.

### Hacker News, Reddit, X — NOT AUTHENTICATED

Recorded because "we chose not to" and "we could not" are different sentences.

| Target | Observed 2026-09-02 |
|---|---|
| Hacker News | `news.ycombinator.com/submit` returns *"You have to be logged in to submit."* Nothing posted. |
| r/netsec, r/AppSec | The current rules could not be read: the new UI serves anonymous visitors a JS challenge, and `old.reddit.com` now requires an account. Posting without reading the rules is exactly what the plan forbids, so nothing was posted. |
| X | `x.com` shows the signed-out landing page. Nothing posted; `final/x-thread.md` stays as saved copy. |

LinkedIn **is** authenticated as the owner. The post in [`final/linkedin.md`](final/linkedin.md) is
ready to go and was not published, because social publishing has not been explicitly authorised for
this session.

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
