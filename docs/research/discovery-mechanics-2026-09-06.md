# How discovery actually ranks us — 2026-09-06

Measured, not assumed. The question was why SecHelix does not appear when
someone searches for security tooling. The answer is different per surface, and
on one of them nothing we write can change it.

## 1. SkillMD search does not index descriptions

Its search matches the **name/slug only**. Proof:

| Word | Times on the live SecHelix listing | SecHelix returned by search |
|---|---|---|
| `BOLA` | 4 | **0** |
| `IDOR` | 3 | **0** |
| `false positive` | 2 | **0** |
| `evidence-first` | 4 | **0** |
| `regression` | 8 | **0** |

Every one of those words is on the page. None of them retrieves it.

Two more signals: `?q=Sec` returns **846 results** ordered alphabetically by
owner slug, and unrelated queries (`BOLA`, `IDOR`, `regression proof`,
`refutes`) all return a near-constant 50–56 results — a fuzzy substring match,
not relevance ranking. Searching the exact name `sechelix` returns 51 results
whose first entries are `26bb/lex`, `akillness/astryx`, `akillness/mex`.

**Consequence: rewriting the SkillMD description cannot improve its position.**
Any advice to "optimise the listing" for this surface would be advice that
cannot work. The listing is worth having; it is not worth tuning.

## 2. GitHub search is popularity-weighted, and we have one star

Not in the top 100 for any of: `appsec agent`, `security audit skill`,
`agent skill security`, `claude code security`.

What ranks instead:

| Repository | Stars |
|---|---|
| NVIDIA/SkillSpector | 16,346 |
| trailofbits/skills | 6,980 |
| anthropics/claude-code-security-review | 6,172 |
| cloudflare/security-audit-skill | 3,231 |
| snyk/agent-scan | 3,013 |
| **omarmohelal/SecHelix** | **1** |

This is not a metadata problem and no wording fixes it. It is a cold start.

## 3. Narrow topic pages are the one metadata lever that works

Topic pages are far less crowded than free-text search, and position there
tracks the size of the topic rather than the size of the project.

Before: 16 topics, the useful ones being `business-logic` (225 repos),
`mcp-security` (407), `codeql` (339), `semgrep` (414). The rest —
`claude-code` (68,799), `cybersecurity` (38,221), `codex` (29,191),
`agent-skills` (21,357) — are unwinnable and contribute nothing.

Four accurate narrow topics were added, taking the repository to GitHub's
20-topic maximum:

| Added topic | Repos in topic | Our rank after |
|---|---|---|
| `false-positives` | 21 | **#5** |
| `secure-code-review` | 20 | **#7** |
| `bola` | 75 | #26 |
| `idor` | 217 | #61 |

Each is an accurate description of what the project does, not keyword padding:
false-positive refutation is its central design, and BOLA/IDOR are named
families in the catalog.

**Honest ceiling:** a topic page with 21 repositories also has few visitors.
This is worth doing because it is free, accurate and immediate. It buys tens of
views, not thousands.

`codeql` was checked and kept: the adapters genuinely ingest CodeQL SARIF
(`adapters/registry.py`, `adapters/sarif.py`), so the topic is accurate.

## 4. Curated lists are the largest untapped surface

People browsing for Claude Skills read lists, and SecHelix was in none of them.

| List | Stars | Open issues | Last push |
|---|---|---|---|
| ComposioHQ/awesome-claude-skills | 74,578 | 1,405 | 2026-08-10 |
| travisvn/awesome-claude-skills | 14,978 | 796 | 2026-04-28 |
| BehiSecc/awesome-claude-skills | 10,101 | 145 | 2026-08-02 |
| karanb192/awesome-claude-skills | 506 | 215 | **2026-09-01** |

Two submissions opened, chosen for reach and for likelihood of being merged:

- **ComposioHQ #1836** — its Security & Systems section holds four entries
  (forensics, secure deletion, metadata extraction, threat hunting) and **none**
  covers application-security code review. A genuine gap, not a squeeze-in.
- **karanb192 #279** — this list marks `security-review` as *Community-needed*;
  the PR supplies a real implementation of that stated need. Least starred of
  the four but the only one pushed within the week, so most likely to merge.

Backlogs of 796–1,405 open issues mean the larger lists may never respond. That
is recorded so a future reader does not mistake silence for rejection.

## What this changes about the plan

Three surfaces rank by popularity, one ranks by name only, and one ranks by
topic size. Only the last is movable by editing metadata, and it has been moved.

Everything else needs someone to actually use the tool and say so. That is the
constraint, and no amount of listing work substitutes for it.
