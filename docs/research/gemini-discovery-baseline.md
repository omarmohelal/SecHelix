# Gemini discovery baseline — 2026-09-02

A measurement, not a campaign. Six non-branded questions were put to Google Gemini once each, in a
single conversation that had never been told the SecHelix URL, the repository name, or that the
person asking had any connection to the project. The result is recorded whether or not it is
flattering, and it is not.

**Headline: SecHelix appeared in 0 of 6 answers.**

## Method

| Field | Value |
|---|---|
| Assistant | Google Gemini (`gemini.google.com`), web app |
| Model shown in the composer | **Flash-Lite** |
| Grounding | Web search was active — the UI showed *"Searching the web"* and answers carried GitHub source chips |
| Conversation | One fresh thread, no system prompt, no prior SecHelix context |
| Queries | 6, each asked **exactly once** |
| Date | 2026-09-02 |

Rules the run was held to:

- The SecHelix URL was **never** given to the model, in any query or follow-up.
- **No prompt was retried until SecHelix appeared.** A failure to appear is a valid measurement, and
  five of these are failures.
- No account, extension, or grounding setting was changed to favour the result.
- Answers are quoted from what Gemini rendered, not paraphrased into something kinder.

One caveat that matters for interpretation: the model in use was **Flash-Lite**, the smallest tier.
A larger Gemini model, or Gemini with a different grounding configuration, may behave differently.
This document measures the tier that was actually served, and does not extrapolate to the others.

## Results

| # | Query | SecHelix present? | Position | Citation | What was recommended instead |
|---|---|---|---|---|---|
| 1 | *What is SecHelix?* | **NOT_FOUND** | — | none | — (denied the name is recognisable; guessed **Sceelix**) |
| 2 | *Recommend an open-source AppSec agent skill for code security audits.* | **NOT_FOUND** | — | none | Cloudflare Security Audit Skill; "Audit Integrity Skill"; "Phoenix Security Skills" |
| 3 | *What Agent Skill can help audit application security in Claude Code or Codex?* | **NOT_FOUND** | — | none | `s-open-io/prompts` → `codex-security` |
| 4 | *I need an AI security agent for reviewing AI-generated code, authorization and business logic. What open-source options exist?* | **NOT_FOUND** | — | none | SEC-AF (`Agent-Field/sec-af`); Cloudflare Security Audit Skill; `b-open-io/prompts` |
| 5 | *What agent skill can audit MCP tool permissions and application-security vulnerabilities?* | **NOT_FOUND** | — | none | `github/awesome-copilot/skills/mcp-security-audit` |
| 6 | *What security agent verifies or refutes findings instead of trusting scanner alerts?* | **NOT_FOUND** | — | none | SEC-AF (`Agent-Field/sec-af`); generic "adversarial skeptic architectures" |

Description accuracy for SecHelix: **not applicable in five of six cases** — the model never
described SecHelix, so there was nothing to be accurate or inaccurate about. Query 1 is the
exception, and it was wrong.

## Query 1 — the entity problem, stated by Gemini itself

Asked the direct branded question, Gemini did not say "I don't know". It said the name does not
correspond to anything recognisable, and then guessed:

> "Because 'SecHelix' doesn't correspond to a widely recognized mainstream platform, software, or
> standardized industry term… It could be a blend of cybersecurity terms (such as a security helix
> architecture) or a misspelling of a niche software tool, procedural generation engine (like
> Sceelix), or compliance framework."

Two separate failures are stacked there:

1. **No entity.** Gemini has no grounded record of SecHelix as a project, so it cannot describe one.
2. **Wrong entity.** It offered **Sceelix** — an unrelated procedural-generation engine — as a likely
   intended target. This is exactly the confusion the entity-disambiguation work in
   `3.4.0-alpha.2` exists to prevent, observed in the wild rather than hypothesised.

The `@id`-linked `Organization` / `SoftwareApplication` / `WebSite` graph, the `/about` entity page
and the explicit "not a company, not a hosted service" wording were all shipped *before* this
measurement. They have not yet had any effect, and this run is the reason to expect one only later.

## Query 6 — the closest miss, and the most useful finding

Query 6 describes SecHelix's central design claim almost verbatim: an agent that tries to *refute*
its own findings rather than trusting a scanner alert. Gemini answered it confidently and named
**SEC-AF**:

> "an independent adversarial 'prover' agent actively attempts to disprove and invalidate the
> findings"

So the *category* is legible to Gemini, and the *thesis* is legible to Gemini. What is missing is
any grounded association between that thesis and SecHelix. The gap is not conceptual — it is a
retrieval gap. Nothing about that is fixed by writing the thesis down again more loudly; it is fixed,
if at all, by the content existing long enough, in enough indexed places, to be retrievable.

## Why this result is expected, and what it does not license

The honest reading is boring:

- `sechelix.com` was verified in Search Console on 2026-09-01 and had **0 impressions** as of
  2026-09-02 (see [`search-intent-baseline-2026-09-02.md`](./search-intent-baseline-2026-09-02.md)).
- `Google-Extended` was added to `robots.txt` on 2026-09-02 — hours before this run.
- Gemini grounding draws on content Google has already crawled and retained. A site that Search has
  barely finished crawling cannot be grounded against.

Therefore:

- **This is a baseline, not a verdict.** It is the "before" number.
- **Allowing `Google-Extended` did not and does not cause citation.** It removes a prohibition. It
  is a permission, not a promise, and this run is the evidence that permission alone changes nothing
  on day one.
- **No claim is made that Gemini will recommend SecHelix**, later or ever. If a re-run shows
  SecHelix appearing, that will be recorded here with the same detail. If it never appears, that
  stays recorded too.

## Re-run protocol

Re-run no earlier than **2026-12-02** (roughly 90 days), using the same six queries, once each, in a
fresh conversation, without supplying the URL. Record the model tier shown in the composer, because
it is a confound. Append the new table below this one rather than overwriting it — the value of this
document is the delta, and a document that only ever shows the current answer cannot show a delta.
