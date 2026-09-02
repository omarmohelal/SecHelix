# Discovery baseline — 3.4.0-alpha.1 release day, 2026-09-02

Third measurement. The earlier two are [`discovery-baseline.md`](discovery-baseline.md) (before any
release existed) and [`discovery-post-launch.md`](discovery-post-launch.md) (within an hour of
`v3.2.0-alpha.1`). This one was taken on the day `v3.4.0-alpha.1` was published, after the Claude
marketplace manifest was merged and after the AwesomeSkills listing went live.

## Method

- Date: **2026-09-02**.
- `FOUND` requires a SecHelix-owned property in the returned results.
- `RATE_LIMITED` means the API refused the request. **It is never rewritten as `NOT_FOUND`.**
  Every row below that was rate-limited on a first attempt was re-run after the window reset, and
  the recorded value is from the completed attempt.
- The GitHub rows were run through an authenticated `gh` session belonging to the repository owner.
  That session sees the owner's private repositories, so a row that names one is not evidence that
  an anonymous searcher would see it.

## `gh skill search`

All six queries completed. None was left rate-limited.

| Query | Result | Position | Notes |
|---|---|---|---|
| `sechelix` | NOT_FOUND | — | Empty result set, exit 0. |
| `appsec` | NOT_FOUND | — | 15 results returned, none SecHelix. |
| `application security` | NOT_FOUND | — | 15 results returned, none SecHelix. |
| `security audit` | NOT_FOUND | — | 2 results returned, none SecHelix. |
| `mcp security` | NOT_FOUND | — | 18 results returned, none SecHelix. |
| `authorization audit` | NOT_FOUND | — | 2 results returned, none SecHelix. |

`security audit`, `mcp security` and `authorization audit` returned
`GitHub API rate limit exceeded` on the first attempt. They were re-run after the window reset and
the completed results are what is recorded.

## GitHub repository search

| Query | Result | Position | Notes |
|---|---|---|---|
| `sechelix` | **FOUND** | 1, 2 | `omarmohelal/sechelix-marketplace`, then `omarmohelal/SecHelix`. Five results total; the other three are the owner's private site repositories and the owner profile repository, visible because the session is authenticated as the owner. |
| `topic:agent-skills security` | NOT_FOUND | — | 15 results returned, none SecHelix. |

## Registries and directories

| Source | Result | URL | Notes |
|---|---|---|---|
| skills.sh | **FOUND** | `https://www.skills.sh/omarmohelal/sechelix` | 1 skill. The page reports **2 total installs**. Both are our own cold-install verification runs. That is not adoption and must never be cited as adoption. |
| AwesomeSkills | **FOUND** | `https://www.awesomeskills.dev/en/skill/sechelix-sechelix` | Live. Miscategorised by their auto-classifier as **Image**; no self-service edit, report or contact control exists on the listing page. |
| SkillMD | NOT_FOUND | — | Site search for `sechelix` returns 50 fuzzy matches (Orlix, Sox, Lex, …), none SecHelix. Publishing requires sign-in; no owner session exists in this browser. |
| Claude community catalog (`anthropics/claude-plugins-community`) | NOT_FOUND | — | The catalog `marketplace.json` contains zero occurrences of `sechelix`. No submission has been accepted because both submission forms are gated (see below). |
| claudemarketplaces.com — skills index | NOT_FOUND | — | `/api/skills` returns the full index (17.98 MB) and ignores query parameters; zero occurrences of `sechelix`. |
| claudemarketplaces.com — marketplaces index | NOT_FOUND | — | `/api/marketplaces` returns the full index (2.36 MB); zero occurrences of `sechelix`. |
| claudemarketplaces.com — plugins index | NO_SUCH_ENDPOINT | — | `/api/plugins` returns HTTP 404. |
| claudemarketplaces.com — search API | GONE | — | `/api/search` returns HTTP 410 with `{"error":"Marketplace discovery is local-only. Run bun run discovery:weekly instead."}`. There is no documented public submission workflow, and none was assumed. |

## Web search

| Engine | Query | Result | Position |
|---|---|---|---|
| Google | `SecHelix` | **FOUND** | **1** — `https://sechelix.com/` |
| Google | `SecHelix AppSec Agent Skill` | NOT_FOUND | — (9 results, none SecHelix) |
| Google | `"evidence-first" appsec agent skill` | NOT_FOUND | — (9 results, none SecHelix) |
| Google | `site:sechelix.com` | **FOUND** | 4 pages indexed: `/`, `/benchmarks`, `/docs/teams/risk-acceptance`, `/docs/using/pr-review` |
| Bing | `SecHelix` | **FOUND** | **2** — `SecHelix/README.md` on GitHub. Position 1 is an unrelated Instagram account with the same handle. |
| Bing | `SecHelix AppSec Agent Skill` | **FOUND** | **1** — `SecHelix/SKILL.md` on GitHub |
| Bing | `site:sechelix.com` | NOT_FOUND | — 0 results. The domain is not in Bing's index. |

## What moved since the post-launch baseline

| Surface | 2026-09-01 | 2026-09-02 |
|---|---|---|
| Google brand query | NOT_FOUND | **FOUND, position 1** |
| Google `site:` coverage | not recorded | 4 of 53 sitemap URLs |
| Bing brand query | not recorded | **FOUND, position 2** (GitHub, not the site) |
| Bing site coverage | not recorded | **0 pages** |
| AwesomeSkills | submitted | **live listing** |
| `gh skill search` | 3 completed, all NOT_FOUND | 6 completed, all NOT_FOUND |
| skills.sh | FOUND, 1 install | FOUND, 2 installs — **both ours** |

The honest reading: the brand name now resolves on both engines, and nothing category-level does.
`gh skill search` has not picked the skill up on any of the six terms, which is the surface that
would matter most for an agent-skill user, and no directory beyond skills.sh and AwesomeSkills lists
it.

## Blocked measurements, and why

These are recorded as blocked rather than as absence, because a gate is not a measurement.

- **Anthropic community-marketplace submission.** Both documented forms are gated. The claude.ai
  form at `claude.ai/admin-settings/directory/submissions/plugins/new` requires a Team or
  Enterprise organisation; the owner's authenticated session returns *"You don't have access to
  organization settings."* The Console form at `platform.claude.com/plugins/submit` requires a
  Console sign-in that does not exist in this browser. `claude plugin validate .` passes locally
  with one warning (`CLAUDE.md` at the plugin root is not loaded as project context).
- **SkillMD.** `skillmd.com/publish` requires sign-in and no owner session exists. No account was
  created.
- **Bing Webmaster Tools.** Requires a Microsoft/Google/Facebook sign-in that does not exist in this
  browser. The site was therefore never added and no sitemap was submitted, which is consistent with
  the zero-result `site:sechelix.com` row above.
- **Reddit.** Anonymous access to `r/netsec` rules is behind a JS challenge, and `old.reddit.com`
  now requires an account to read. The current rules could not be read, so nothing was posted.
- **Hacker News.** `news.ycombinator.com/submit` returns *"You have to be logged in to submit."*
  Nothing was posted.
