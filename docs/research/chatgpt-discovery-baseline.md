# ChatGPT discovery baseline — 2026-09-03

Four non-branded questions, asked **once each**, in one signed-in ChatGPT
session that was never given the SecHelix URL or name.

**SecHelix appeared in 0 of 4 answers.**

## Method

| Field | Value |
|---|---|
| Surface | `chatgpt.com`, signed in, web search active (answers carried GitHub citations) |
| Queries | 4, each asked exactly once |
| Date | 2026-09-03 |
| Retries | none — a failure to appear is the measurement |

Two things were checked rather than assumed:

- **No prompt named SecHelix**, its repository, or its domain.
- **The `sechelix` string does appear on the page**, but only as an unrelated
  item in the account's chat sidebar (`SecHelix Directory Watch`). Asserting
  against assistant messages specifically returns
  `sechelix_in_any_answer: false`. Searching the whole page would have produced
  a false positive, and did.

**One confound worth stating:** the account's language context caused answer 2
to come back in Arabic. Answers 3 and 4 were prefixed with "Answer in English."
to control for it. The recommendations were unaffected — the same projects were
named in both languages.

## Results

| # | Query | SecHelix? | Recommended instead |
|---|---|---|---|
| 1 | *What open-source AppSec agent can audit code?* | **NOT_FOUND** | OWASP AppSec Agent (`code_reviewer`, `pr_adversary`, `fp_adversary`, `finding_validator`, `threat_modeler`); OWASP Secure Agent Playbook |
| 2 | *Recommend an Agent Skill for application-security review.* | **NOT_FOUND** | `OWASP/secure-agent-playbook`, `code-review-security`, `api-security-review`, `secrets-scan`, `sca-audit`, `web-security-review`, `security-team-lead` |
| 3 | *What security agent verifies false positives before reporting vulnerabilities?* | **NOT_FOUND** | OWASP AppSec Agent `fp_adversary`, `pr_adversary`, `finding_validator` |
| 4 | *What Agent Skill can audit authorization, business logic and MCP security?* | **NOT_FOUND** | `code-review-security`, `security-guidance`, `mcp-server-review`, `agent-security-audit` |

Citation URL for SecHelix: **none, in any answer.** Description accuracy: not
applicable — SecHelix was never described.

## The two answers worth reading

**Query 3** returned SecHelix's central design principle, credited to nobody:

> "A particularly good architecture is to keep that verifier independent from the
> discovering agent … rather than blindly trusting the original security agent."

The idea is legible to the model. The association with SecHelix is not.

**Query 4** is the sharpest statement of the gap:

> "There isn't really one single Skill that deeply covers classic application
> authorization/business logic and MCP security."

That sentence is SecHelix's positioning almost word for word, and the model
concludes no such thing exists. The need is recognised, the product exists, and
the retrieval path between them does not.

## Crawler access, verified separately

Discovery cannot happen if the crawler is blocked, so this was checked rather
than assumed:

```
User-Agent: OAI-SearchBot
Allow: /
Disallow: /admin/
Disallow: /api/admin/
```

- `OAI-SearchBot` is explicitly allowed on public pages and denied on admin.
- Fetching `/try-sechelix` with the `OAI-SearchBot` user agent returns **HTTP
  200** — no CDN or WAF rule is blocking it.
- `GPTBot` is **not** mentioned in `robots.txt`, and is deliberately not
  conflated with `OAI-SearchBot`. They are different crawlers: `OAI-SearchBot`
  serves ChatGPT search results, `GPTBot` gathers training data. A rule for one
  is not a rule for the other.

## What this does and does not mean

**Does:** SecHelix is not currently retrievable through ChatGPT for the queries
its own capabilities describe. The site was first indexed on 2026-09-02, so this
is the expected reading for a domain days old.

**Does not:** this is not evidence that anything is misconfigured. The crawler is
allowed and reachable; there is simply nothing yet in the index for it to
surface. Allowing a crawler is a permission, not a promise.

Nothing here supports a claim that ChatGPT will recommend SecHelix later, and
nothing about this project attempts to influence a model's recommendations. The
objective is to be discoverable and citable, which is a different thing.

## Re-run protocol

Re-run no earlier than **2026-12-03**, same four queries, once each, in a fresh
conversation, without supplying the URL. Assert against assistant messages
rather than the page body — the sidebar will produce a false positive otherwise.
Append the new table below this one; the delta is the value, and a document that
only ever shows the current answer cannot show one.
