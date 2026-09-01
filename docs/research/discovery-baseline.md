# Discovery baseline — measured, 2026-09-01

This is a **measurement**, not a plan. Every row below is a query that was actually run on the date
shown, with the outcome recorded as observed. Nothing here is projected, estimated, or aspirational.

The purpose is to establish a zero point. Discoverability work is otherwise unfalsifiable: without a
recorded starting position, any later claim of improvement is unverifiable.

## Method

- Engine: web search as exposed to this session, US region.
- Date: **2026-09-01**.
- `FOUND` requires a SecHelix-owned property (`sechelix.com`, `github.com/omarmohelal/SecHelix`, or
  the marketplace repository) appearing in the returned results.
- `POSITION` is the rank within the returned result list, or `—` when not present.
- Queries were run once each. A single sample from one engine on one day is a weak signal about
  ranking, and a strong signal about absence.

## Results

| # | Query | Found | Position | Notes |
|---|---|---|---|---|
| 1 | `SecHelix` | **NOT_FOUND** | — | Results resolved to unrelated terms: a Star Wars character, a GitHub user `sechel`, Seychelles, a helical orbit spectrometer. The engine did not interpret the token as a product name. |
| 2 | `SecHelix AppSec agent skill` | **NOT_FOUND** | — | All results were vendor marketing on "agentic AppSec" (Legit, Endor, Checkmarx, Palo Alto, OpenText). |
| 3 | `github.com omarmohelal SecHelix` | **NOT_FOUND** | — | Returned other GitHub users matching `omar`. Neither the account nor the repository appeared. |
| 4 | `Claude Code security skill evidence-based vulnerability verification` | **NOT_FOUND** | — | The category query. Occupied by Trail of Bits, StackHawk, Snyk, Phoenix Security, and Anthropic's own solutions page. |
| 5 | `awesome agent skills security list SKILL.md application security audit` | **NOT_FOUND** | — | The submission-target query. Surfaced curated lists SecHelix is not in. |
| 6 | `security scanner false positive rejection evidence chain proof AI code review skill open source` | **NOT_FOUND** | — | The differentiator query — the phrasing closest to what SecHelix actually does. Still absent. |

**Score: 0 of 6.** SecHelix is not discoverable by any tested query, including its own name.

## What this means

Query 1 is the load-bearing one. A brand-name query returning nothing means there is no index entry
at all, so the site is not competing for rank — it is absent. Ranking work is premature until that
changes; indexing is the prerequisite.

Query 6 is the most useful signal for positioning. The phrasing that most precisely describes
SecHelix returns established projects, which means the differentiator is legible to a search engine
as a category, and the category already has occupants.

## Landscape observed while measuring

Recorded because it was visible in the results, not because it was researched. No comparative or
competitive claim is made, and none of this has been independently assessed.

| Project | What the results attributed to it |
|---|---|
| [`anthropics/claude-code-security-review`](https://github.com/anthropics/claude-code-security-review) | A GitHub Action using Claude to review code changes for vulnerabilities. First-party. |
| [`trailofbits/skills`](https://github.com/trailofbits/skills) | Claude Code and Codex security skills. Results attribute code review, **differential review**, **false-positive analysis**, supply-chain checks, Actions auditing, and **Semgrep rule generation** to it. |
| Phoenix Security skills | Open-sourced security practitioner skills for Claude Code. |
| StackHawk / Snyk / Checkmarx | Vendor skills wrapping their own scanners. |

**The Trail of Bits overlap is the finding that matters.** Differential review, false-positive
analysis, and Semgrep rule generation are three things SecHelix either just built (`diff_review.py`)
or has planned (Variant Hunter V2). They are not differentiators. What remains distinct is the
evidence chain as a *contract* — a schema-validated, gate-enforced artifact — rather than a
reporting style. Positioning that leans on "we reduce false positives" is competing directly with a
better-known project on its own ground.

Also observed: Snyk published a study reporting that 36% of audited agent skills contained security
flaws and 13.4% critical ones. That figure is **theirs, not verified here**, and is recorded only
because it is the public context in which the `UNTRUSTED_REPO` work will be read.

## Submission targets discovered

Two lists surfaced that are not in `docs/launch/submissions/`:

- [`LLMSecurity/awesome-agent-skills-security`](https://github.com/LLMSecurity/awesome-agent-skills-security) — attacks, defenses, frameworks and benchmarks for agent skill security. Plausible fit for the `UNTRUSTED_REPO` work specifically.
- [`scadastrangelove/awesome-ai-security-tools`](https://github.com/scadastrangelove/awesome-ai-security-tools) — AI security and AI-assisted security tooling, including agent security.

Neither has been read for contribution policy. Do not submit before doing that.

[OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/) also appeared and
is worth mapping the AI family against — as a reference, not as a compliance claim.

## Re-running this

Run the same six queries, record the same columns, append a dated table. Do not overwrite this one;
the value is in the comparison. Do not report an improvement without a recorded prior measurement to
compare against.

## Limitations

- One engine, one region, one day, one sample per query.
- Search results are personalized and volatile; another observer may see different results.
- `NOT_FOUND` establishes absence at the time of measurement. It does not establish that the site is
  unindexed — only that these queries did not surface it.
- No paid placement, no ranking tooling, and no third-party index inspection were used.
