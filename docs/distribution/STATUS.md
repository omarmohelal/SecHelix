<!-- doc-consistency: snapshot -->
# Distribution status

The one tracker for where SecHelix can be installed or found. Every row was checked against the
live listing or pull request, not against earlier notes. **Checked: 2026-09-15.** A row is only as
current as that date; re-check before acting on it.

Columns: **Auto** = automation permitted by the target's rules. **Owner** = the repository owner
must act personally (login, OAuth, CAPTCHA, or a rule requiring a human submitter).

## Installable channels

| Platform | Listing / submission | Mechanism | Status | Last meaningful event | Blocker | Next action | Auto | Owner |
|---|---|---|---|---|---|---|---|---|
| GitHub releases | [v4.0.0-alpha.6](https://github.com/omarmohelal/SecHelix/releases/tag/v4.0.0-alpha.6) | `version-release` workflow | LIVE, marked latest | 2026-09-15 release | none | none | yes | no |
| Agent Skills CLI / skills.sh | [skills.sh/omarmohelal/sechelix](https://skills.sh/omarmohelal/sechelix) | install telemetry | LIVE | listed 2026-09-01 | Socket audit shown is of pre-packaging-fix commit `c3d17b2` (vulnerable eval fixtures were then in the package) | none; the listing re-audits from installs | n/a | no |
| GitHub CLI `gh skill` | `gh skill install omarmohelal/SecHelix sechelix` or `sechelix-lite` | repository convention | LIVE | both verified 2026-09-15 at `v4.0.0-alpha.6` | none | none | n/a | no |
| Claude Code plugin marketplace | [omarmohelal/sechelix-marketplace](https://github.com/omarmohelal/sechelix-marketplace) | own marketplace repo | LIVE, version synced to 4.0.0-alpha.6 | [PR #3](https://github.com/omarmohelal/sechelix-marketplace/pull/3) merged 2026-09-15 | none | bump with each release | yes | no |
| GitHub Marketplace (Action) | [sechelix-security-review](https://github.com/marketplace/actions/sechelix-security-review) | release checkbox | LIVE | page renders `@v4.0.0-alpha.6` | none | none | no | yes, for listing a new release |
| PyPI (runner) | [sechelix](https://pypi.org/project/sechelix/) | trusted publishing | LIVE at 0.3.0 | runner unchanged since 0.3.0 | none | publish on the next runner change | yes | no |
| Official MCP Registry | `io.github.omarmohelal/sechelix` | `publish-mcp` workflow | LIVE at 0.3.0, `active` | published 2026-09-09 | none; 0.3.0 is the current runner version | publish with the next runner release | yes | no |

## Directories and lists

| Platform | Listing / submission | Mechanism | Status | Last meaningful event | Blocker | Next action | Auto | Owner |
|---|---|---|---|---|---|---|---|---|
| GitHub awesome-copilot | [#3147](https://github.com/github/awesome-copilot/issues/3147) (`sechelix-lite`) | issue form | INTAKE PASSED, `ready-for-review` | opened 2026-09-15; all automated gates pass | maintainer review | wait; no follow-up comments | yes | no |
| GitHub awesome-copilot (earlier) | [#2899](https://github.com/github/awesome-copilot/issues/2899) (`sechelix`) | issue form | REJECTED, terminal | 2026-09-15: self-promotional; skill too complex | addressed by the curated edition in #3147 | none | n/a | no |
| Tenable CyberAgents Exchange | [exchange.tenable.com/skills/sechelix](https://exchange.tenable.com/skills/sechelix/), [PR #160](https://github.com/tenable/cyberagents-exchange/pull/160) | PR | LIVE | merged 2026-09-14 | page shows no version and no install block | optional separate Agent or MCP listing | yes | no |
| punkpeye/awesome-mcp-servers | [PR #14084](https://github.com/punkpeye/awesome-mcp-servers/pull/14084) | PR (agent fast-track) | OPEN, conflict resolved, checks pass | branch updated 2026-09-15 | Glama shows no tool-quality grade yet, which the maintainers require | owner adds the Dockerfile in Glama admin so tools are introspected and graded | yes | yes (Glama login) |
| Glama | [glama.ai/mcp/servers/omarmohelal/SecHelix](https://glama.ai/mcp/servers/omarmohelal/SecHelix) | GitHub OAuth claim, Docker build | LISTED, claimed; quality "Not graded" | claimed 2026-09-09 | no build/introspection has run | owner: Dockerfile in Glama admin → build → release | no | yes |
| ottosulin/awesome-ai-security | [PR #452](https://github.com/ottosulin/awesome-ai-security/pull/452) | PR | OPEN | opened 2026-09-15 | maintainer review | wait | yes | no |
| scadastrangelove/awesome-ai-security-tools | [PR #109](https://github.com/scadastrangelove/awesome-ai-security-tools/pull/109) (WATCHLIST) | PR | OPEN | opened 2026-09-15 | maintainer review | wait; graduate to main list once adoption exists | yes | no |
| ComposioHQ/awesome-claude-skills | [PR #1836](https://github.com/ComposioHQ/awesome-claude-skills/pull/1836) | PR | OPEN, `validate` now passes | ordering fixed 2026-09-15 | repository has merged nothing since 2026-05-22 | wait | yes | no |
| karanb192/awesome-claude-skills | [PR #279](https://github.com/karanb192/awesome-claude-skills/pull/279) | PR | OPEN, mergeable | opened 2026-09-06 | maintainer review | wait | yes | no |
| royalpinto007/awesome-agent-skills | [PR #4](https://github.com/royalpinto007/awesome-agent-skills/pull/4) | PR | LIVE | merged 2026-09-04 | none | none | yes | no |
| Ezeafk/awesome-agent-skills | [PR #33](https://github.com/Ezeafk/awesome-agent-skills/pull/33) | PR | OPEN, mergeable | opened 2026-09-01 | maintainer inactive, no PR ever merged | none | yes | no |
| AwesomeSkills | [awesomeskills.dev](https://awesomeskills.dev/en/skill/sechelix-sechelix) | URL paste, unmoderated | LIVE | snapshot predates 4.0.0-alpha.5 | filed under "Image"; no edit control | none (resubmitting would duplicate) | n/a | no |
| SkillMD | [skillmd.com/skills/omar-mohamed/sechelix](https://skillmd.com/skills/omar-mohamed/sechelix) | signed-in form | LIVE | updated 2026-09-02 | stale copy of SKILL.md | owner refreshes from "My skills"; never resubmit | no | yes |
| agent-skills.md | [agent-skills.md/…/sechelix](https://agent-skills.md/skills/omarmohelal/SecHelix/sechelix) | URL form | LIVE | snapshot predates 4.0.0-alpha.5 | none | none | n/a | no |
| verified-skill.com | [verified-skill.com/…/sechelix](https://verified-skill.com/skills/omarmohelal/sechelix/sechelix) | crawler | LIVE | updated 2026-09-14 | none | none | n/a | no |
| hesreallyhim/awesome-claude-code | [recommend-resource form](https://github.com/hesreallyhim/awesome-claude-code/issues/new?template=recommend-resource.yml) | web issue form only | ELIGIBLE, not submitted | 14-day rule met 2026-09-14 | rules require a human submitter via the web UI; `gh` and PRs are refused | owner submits by hand, category Security | no | yes |
| Anthropic community plugin marketplace | [platform.claude.com/plugins/submit](https://platform.claude.com/plugins/submit) | signed-in form | NOT SUBMITTED | `claude plugin validate` passes (one CLAUDE.md warning) | owner login | owner submits the Claude Code plugin | no | yes |
| Anthropic official marketplace | anthropics/claude-plugins-official | Anthropic selects | NOT LISTED | no application process exists | none possible | none | no | n/a |
| mcpservers.org (wong2/awesome-mcp-servers) | [mcpservers.org/submit](https://mcpservers.org/submit) | web form (email), free tier | NOT SUBMITTED | README: PRs not accepted | form needs owner's email | owner submits the free tier only; do not pay | no | yes |
| claudskills.com | web form | web form (email) | NOT LISTED | none | form needs owner's email | optional | no | yes |
| claudeskills.info | web form | OAuth sign-in | NOT LISTED | none | OAuth sign-in | optional | no | yes |
| analysis-tools-dev/static-analysis | CONTRIBUTING | PR | NOT ELIGIBLE | rules re-read 2026-09-15 | needs 6 months, 20 stars, >1 contributor (now: 15 days, 1 star, 1 contributor) | re-check on or after 2027-02-28 | yes | no |
| VoltAgent/awesome-agent-skills | CONTRIBUTING | PR | NOT ELIGIBLE | rules re-read 2026-09-15 | requires established community usage | re-check when adoption exists | yes | no |
| travisvn/awesome-claude-skills | CONTRIBUTING | PR | NOT ELIGIBLE | rules re-read 2026-09-15 | 10-star minimum; no AI-assisted PRs | re-check at 10 stars, human-authored PR | no | yes |
| Smithery | smithery.ai | login + MCPB bundle or HTTPS remote | NOT LISTED | none | no MCPB bundle exists | build an MCPB bundle first | no | yes |
| Claude Market (claudemarket.ai) | n/a | unknown | UNVERIFIED | bot challenge blocks automated reads | cannot inspect | owner checks in a browser | no | yes |
| skillsdir.dev | n/a | issue link and CLI | NOT LISTED | both submission routes 404 | site broken | none | n/a | n/a |
| AgentSkillsRepo | n/a | unknown | SITE DOWN | domain does not resolve | site down | none | n/a | n/a |

## Deferred candidates

Researched and legitimate, but not submitted yet, to avoid listing a two-week-old project where its
adoption does not yet justify the space:

- **OWASP Source Code Analysis Tools** (`OWASP/www-community`, `_data/tools.json`): its categories
  are SAST-style scanners; SecHelix is an agent-guided review workflow, so the `SAST` type would
  misdescribe it.
- **TalEliyahu/Awesome-AI-Security** `MCP_Servers.md`, AppSec & DevSecOps: lists established vendor
  servers; last updated 2026-07-18.
- **sottlmarek/DevSecOps**: PRs must state stars and maturity.
- **docker/mcp-registry**: requires review from the Docker team (1,200+ open PRs); the repository
  root to volume mapping needs verifying first.

Launch venues (Show HN, Product Hunt, Reddit) are tracked outside the repository.
