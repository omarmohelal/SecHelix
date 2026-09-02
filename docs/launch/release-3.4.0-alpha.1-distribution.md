# Distribution report — 3.4.0-alpha.1

**Date:** 2026-09-02. One pass, one release, no re-tagging.

This is the record of what shipped, what was installed and verified, what was submitted, and what is
still blocked and on whom. Live states move; the two companion pages
[`distribution-status.md`](distribution-status.md) and
[`../research/discovery-v3.4-release.md`](../research/discovery-v3.4-release.md) are the ones to
re-read later.

## Release

| Item | Value |
|---|---|
| Release | <https://github.com/omarmohelal/SecHelix/releases/tag/v3.4.0-alpha.1> |
| Tag | `v3.4.0-alpha.1`, prerelease |
| Tag commit | `f76d32cf54d30ff9862e674b817d92df77289406` |
| `main` | `f76d32cf54d30ff9862e674b817d92df77289406` — identical to the tag |
| Notes | `docs/releases/3.4.0-alpha.1.md`, verbatim |
| SBOM | `sechelix-sbom.cdx.json` (19,406 B), CycloneDX 1.5, 15 components, subject `sechelix 3.4.0-alpha.1` |
| SBOM checksum | `sechelix-sbom.cdx.json.sha256` (94 B) — downloaded and re-computed independently; matches |

The previous tag `v3.2.0-alpha.1` was not moved, rewritten or deleted.

`gh skill publish` created the release as a stable release. It was corrected to a prerelease with
`gh release edit --prerelease`, which is a metadata change on the existing release, not a re-tag.

## Version drift

Only current-state surfaces were changed. Dated release notes, the changelog, the branch-protection
worked example and dated research snapshots still say `3.2.0-alpha.1`, because that is what they were
about.

Fixed via PR #23, squash-merged with the title `docs: align public version with 3.4.0-alpha.1` and an
empty body — no trailers, no session lines, no diary:

- `README.md` — the shields.io badge (which escapes the version as `3.2.0--alpha.1`, so a naive grep
  for the plain version missed it) and the Alpha sentence
- `docs/launch/awesome-list-submission.md`
- `docs/launch/final/README.md`

## Cold installs

Every install was into a fresh empty temporary directory. **`gh skill install --scope project`
silently resolves nowhere unless the working directory is a git repository**, which is why each
temporary directory is `git init`-ed first; without it the command reports success and writes zero
files.

| Route | Agent | Exit | Files | Size | Destination |
|---|---|---|---|---|---|
| `npx skills@latest add` | — | 0 | 155 | 2,312 KB | `.agents/skills/sechelix/` |
| `gh skill install` | `claude-code` | 0 | 154 | 2,271 KB | `.claude/skills/sechelix/SKILL.md` |
| `gh skill install` | `codex` | 0 | 154 | 2,271 KB | `.agents/skills/sechelix/SKILL.md` |
| `gh skill install` | `github-copilot` | 0 | 154 | 2,271 KB | `.agents/skills/sechelix/SKILL.md` |
| `gh skill install` | `cursor` | 0 | 154 | 2,271 KB | `.agents/skills/sechelix/SKILL.md` |
| `gh skill install` | `gemini-cli` | 0 | 154 | 2,271 KB | `.agents/skills/sechelix/SKILL.md` |

No tests, evals or repository scaffolding leaked into any portable install. Every module imported and
the release gate returned `PASS` from the `npx` install.

**What this proves and what it does not.** It proves packaging and host-path placement. It does
**not** prove that a real Codex, Copilot, Cursor or Gemini session loaded and followed SecHelix.
Compatibility statements stay at the level the evidence supports.

## Claude marketplace

| Item | Value |
|---|---|
| Repository | <https://github.com/omarmohelal/sechelix-marketplace> |
| Merge commit | `cac034702ba5a101ff3753b827b35e2cc97c8a72` (default branch `master`) |
| Manifest version | `3.4.0-alpha.1` |
| Source | `{"source": "url", "url": "https://github.com/omarmohelal/SecHelix.git"}` — no vendored copy |

Cold-tested from the remote after the merge, with the stale user-scope marketplace and plugin removed
first so the test was genuinely cold: `/plugin marketplace add` then `/plugin install
sechelix@sechelix` resolves **3.4.0-alpha.1, 1 skill, 17 agents**. The manifest was not merged until
the release existed.

## Submissions and listings

| Target | State |
|---|---|
| Anthropic community marketplace | **BLOCKED — both forms gated.** claude.ai form needs a Team/Enterprise org (owner's session: *"You don't have access to organization settings"*); Console form needs a Console sign-in that does not exist here. `claude plugin validate .` passes with one warning. No submission was made and **no "Anthropic Verified" status is claimed** — third-party plugins go to `claude-community`, and the official marketplace has no application process at all. |
| AwesomeSkills | **LIVE** — <https://www.awesomeskills.dev/en/skill/sechelix-sechelix>. Auto-categorised as "Image", which is wrong; the page exposes no edit, report or contact control, so it cannot be corrected from outside. |
| SkillMD | **BLOCKED — sign-in required**, no owner session. No account was created. Site search for `sechelix` returns nothing. |
| Claude Market / claudemarketplaces.com | **NOT INDEXED.** Search API returns HTTP 410 (*"discovery is local-only"*); the two full indexes contain zero occurrences of `sechelix`; `/api/plugins` is 404. No submission workflow was invented, and nothing was paid for. |
| `github/awesome-copilot#2899` | OPEN, unchanged. Only comment is the automated `needs-review:MEDIUM` reputation check. Nothing requested of us; not bumped. |
| `royalpinto007/awesome-agent-skills#4` | OPEN, no review, no comments. Not bumped. |
| `Ezeafk/awesome-agent-skills#33` | OPEN, no review, no comments. Not bumped. |

## Search and indexing

| Item | State |
|---|---|
| Google Search Console | Domain property `sechelix.com`, authenticated. **Exactly one sitemap submitted** — `https://sechelix.com/sitemap.xml`, status Success, 53 pages discovered. No HTML page is registered as a sitemap, and no second SecHelix property exists, so there was nothing to remove. |
| Google indexing | All 10 named URLs inspected, live-tested and submitted. Every one returned *"URL is available to Google"* on the live test and *"Indexing requested"* on submission. No quota error was hit. `/` and `/docs` were already indexed; the other eight were not. |
| Bing Webmaster Tools | **BLOCKED — sign-in required.** The site was not added and no sitemap was submitted. `site:sechelix.com` on Bing returns 0 results, which is consistent. |
| `/robots.txt` | 200, `text/plain`. `OAI-SearchBot` and `PerplexityBot` both have explicit `Allow: /` groups, both blocked only from `/admin/` and `/api/admin/`. One `Sitemap:` line, absolute https, pointing at `/sitemap.xml`. |
| `/sitemap.xml` | 200, `application/xml`, 9,944 B |
| `/llms.txt` | 200, 4,215 B |
| `/llms-full.txt` | 200, 20,867 B |
| `/feed.xml` | 200, `application/atom+xml`, 2,876 B |

No AI-specific SEO text was added, and no claim is made anywhere that any assistant will recommend
SecHelix.

## Entity consistency

Both repositories were searched for `Sec Helix`, `Sec-Helix` and `SecHelix AI Security Scanner`.
**Zero occurrences.** Every use of "scanner" on the site is a contrast — *not* a scanner, scanner
output as evidence, a scanner-shaped false positive — which is the intended positioning: SecHelix is
an AppSec Agent Skill and evidence-first framework.

Canonical identifiers, used everywhere: `SecHelix` · <https://sechelix.com> ·
<https://github.com/omarmohelal/SecHelix> · <https://github.com/omarmohelal/sechelix-marketplace>.

## External `sameAs`

`Organization.sameAs` on `https://sechelix.com/` now carries three URLs: the GitHub repository, the
skills.sh listing, and the AwesomeSkills listing added this pass. All three are live and resolve.

No open pull request, pending submission, search-result page or self-created profile was added.

## Publishing

| Channel | State |
|---|---|
| Hacker News | NOT POSTED — not authenticated. Copy stays in `final/show-hn.md`; it needed no version refresh. |
| Dev.to / Hashnode | NOT POSTED — neither platform is reachable from this browser session, and there is no authenticated account. The canonical for the flagship article is `https://sechelix.com/research`, the research surface that already exists, so the copies have something to point at whenever they are published. No competing canonical was created. |
| LinkedIn | **POSTED once**, after the owner explicitly authorised it — <https://www.linkedin.com/feed/update/urn:li:activity:7500865884689850370/>. `final/linkedin.md` verbatim, public visibility. The only change was reflowing the file's hard line wraps into paragraphs; no wording, claim or fact was altered. |
| X | NOT POSTED — not authenticated. `final/x-thread.md` stays as saved copy. No account was created. |
| r/netsec, r/AppSec | NOT POSTED — the current subreddit rules could not be read anonymously, and posting without reading them is precisely what the plan forbids. |

## Adoption

Nothing was manufactured. No stars, forks, installs, directory views, search clicks, issues,
testimonials or benchmark runs.

The skills.sh listing shows **2 installs. Both are ours** — the cold-install verifications recorded
above. That number is a test artifact, not adoption, and is never to be cited as adoption.

The public benchmark remains `NOT_MEASURED` with blocker `CONTAMINATED_EVALUATOR`. This session read
fixtures and ground truth and is therefore disqualified as an evaluator.

## What is left, and who has to do it

Every remaining item needs a human with an account. None is a code change.

1. **Anthropic community marketplace** — sign in to `platform.claude.com/plugins/submit` as the owner
   and submit. All values are ready.
2. **SkillMD** — sign in at `skillmd.com`, publish, category Security, description in
   [`distribution-status.md`](distribution-status.md).
3. **Bing Webmaster Tools** — sign in, add `https://sechelix.com`, import from Search Console,
   submit the sitemap.
4. **Hacker News, X, Reddit** — authenticate, then post once, having re-read the destination's
   current rules on the day.
5. **AwesomeSkills category** — contact them through whatever route exists off the listing page; the
   "Image" category is wrong and cannot be fixed from the listing itself.

LinkedIn is done. Be available on that post for the next few hours — the first hostile question will
be *"how do I know it works?"*, and the honest answer is the whole argument: you don't yet, the
benchmark is `NOT_MEASURED`, here is why, and here is the blind packet.
