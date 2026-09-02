# Discovery surface baseline — 2026-09-02

Where SecHelix can and cannot be found today, measured by hand on the day `3.4.0-alpha.2` shipped.
Companion to [`gemini-discovery-baseline.md`](./gemini-discovery-baseline.md) (Gemini) and
[`search-intent-baseline-2026-09-02.md`](./search-intent-baseline-2026-09-02.md) (Search Console).

Everything here was checked manually in a browser. **No search-result scraping was automated, no
traffic was manufactured, and no query was repeated to improve a number.** Where a surface says
"not found", that is the measurement.

## 1. Google AI Mode

Three questions, each asked once, via Google's AI Mode (`&udm=50`) while signed in.

| Query | SecHelix in the answer? | `sechelix.com` in the sources? |
|---|---|---|
| *open source appsec agent skill for code security audits* | **No** | No |
| *What is SecHelix?* | **No** — see below | No |
| *security agent that verifies or refutes findings instead of trusting scanner alerts* | **No** | No |

What AI Mode named instead, across the three answers: Cloudflare Security Audit Skill, OWASP Secure
Agent Playbook, LLMSecurity SkillGuard, AgentSecOps SecOpsAgentKit, OpenFang Security Audit,
Cynative.

### The branded query is the entity problem in one screenshot

Asked *"What is SecHelix?"*, AI Mode did not return the project. It treated the name as a probable
typo and offered six unrelated entities:

- **Helix (by SafeHill)** — an AI SAST tool
- **Trellix Helix** — a SaaS security-operations / SIEM platform
- **Cyberhelix** — a Greek cybersecurity firm
- **Sec61α2 translocon** — a protein channel in pancreatic cells
- **Sellix** — an e-commerce platform
- **Helix DEX** — a decentralised exchange on Injective

It closed by asking where the term had been encountered. Gemini, separately, guessed **Sceelix**.

This is the exact failure mode the entity work in `3.4.0-alpha.2` targets: *SecHelix* being absorbed
into the crowd of unrelated security-`Helix` brands. The `@id`-linked structured-data graph, the
`/about` entity page and the "independent open-source project, not a company or hosted service"
wording all shipped **before** this measurement and have not yet had time to take effect. Recording
the confusion now is what makes it possible to say later whether they worked.

**Generative AI / AI features report in Search Console:** still not available on this property, so
there is no first-party impression data for AI Mode to cross-check against. This measurement is
observational only.

## 2. Google Search (classic index)

`site:sechelix.com` returns **10 indexed pages**, five days after the domain was verified:

`/` · `/docs` · `/case-studies` · `/claude-code-security-skill` · `/codex-security-skill` ·
`/copilot-security-skill` · `/authorization-bola-idor` · `/business-logic-security` ·
`/mcp-security-audit` · `/docs/teams/enterprise-adoption`

Two things follow:

- **Indexing is working.** The task pages made it in without any submission being accepted — the
  Search Console *Request Indexing* quota was exhausted before any of the priority URLs could be
  queued.
- **The index snapshot is stale.** The homepage still shows the pre-`alpha.2` title, *"SecHelix —
  AppSec Verification Operating System"*, rather than the shipped *"SecHelix — AppSec Agent for
  Security Audits"*. The new pillar `/appsec-agent` and
  `/research/how-to-secure-ai-generated-code` are not indexed yet. Both were published today; this
  is normal recrawl latency and not a defect.

## 3. Bing

`site:sechelix.com` on Bing returns **nothing** — the engine falls through to unrelated results.
**0 pages indexed.** No conclusion should be drawn from this beyond "Bing has not crawled the site
yet".

## 4. Skill directories

| Directory | Listing live? | Found by brand? | Found by category (`appsec`)? |
|---|---|---|---|
| **skills.sh** | Yes — `omarmohelal/sechelix`, 4 installs | **Yes** | **No** |
| **AwesomeSkills** | Yes — `/en/skill/sechelix-sechelix` | **Yes** | not measured |
| **Anthropic directory** | Submission pending review | n/a | n/a |
| **SkillMD** | Listed | n/a | n/a |

`skills.sh` ranks its search results by install count. A search for `appsec` returns 20+ skills
ordered by installs — `openai/skills` at 5.2K, `usestrix/strix` at 2.9K, down to entries with 29 —
and SecHelix's 4 installs place it below all of them. Searching `sechelix` finds it immediately.

That gap is a **popularity ranking**, and the only honest way to close it is for people to actually
install the skill. It will not be closed by re-listing, by re-submitting, or by any technique this
project is willing to use. It is recorded here as a fact about the directory, not as a task.

**AwesomeSkills carries no version string** on the listing, so `3.4.0-alpha.2` introduces no version
drift there and the entry needs no edit.

## 5. Summary

| Surface | SecHelix findable by **name**? | Findable by **category**? |
|---|---|---|
| Google Search (classic) | Yes — 10 pages indexed | Not measured at rank level |
| Google AI Mode | **No** — confused with 6 unrelated entities | **No** |
| Gemini (Flash-Lite) | **No** — confused with Sceelix | **No** (0/6 queries) |
| Bing | **No** — 0 pages indexed | **No** |
| skills.sh | Yes | **No** — outranked on installs |
| AwesomeSkills | Yes | not measured |

One surface out of six discovers SecHelix by category today: none of them.

## What this does not license

- It does **not** support any claim that an assistant will recommend SecHelix, now or later.
- It does **not** mean the discovery work in `3.4.0-alpha.2` failed. All of it shipped hours before
  this measurement; a baseline taken at t=0 measures the "before", not the effect.
- It does **not** justify creating keyword pages, duplicate directory submissions, or synthetic
  installs to move any number in the tables above.

## Re-run protocol

Re-measure at **2026-12-02**, using the same queries and the same surfaces, and append rather than
overwrite. The delta is the finding; a single snapshot is not.
