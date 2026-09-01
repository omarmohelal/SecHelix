# Discovery baseline — post-launch, 2026-09-01

Second measurement. The first is [`discovery-baseline.md`](discovery-baseline.md), taken before the
`v3.2.0-alpha.1` release existed; this one was taken **within an hour of publishing it**.

That gap matters more than any number below. Search indexes, registry crawlers and repository search
all update on their own schedule, and an hour is not enough time for any of them. These rows are a
starting line, not a verdict, and they should be re-run in a week and a month.

## Method

- Date: **2026-09-01**, within one hour of `gh skill publish` and the production deploy.
- `FOUND` requires a SecHelix-owned property in the returned results.
- Sources: `gh skill search`, `gh search repos`, skills.sh, and general web search.
- A row is recorded `RATE_LIMITED` when the API refused the request. **It is not recorded as
  `NOT_FOUND`.** An error is not a measurement, and the first pass at this table wrongly read
  rate-limit responses as absence until the responses were actually inspected.

## Results

### `gh skill search`

| Query | Result | Position |
|---|---|---|
| `sechelix` | NOT_FOUND | — |
| `appsec` | NOT_FOUND | — |
| `application security` | NOT_FOUND | — |
| `security audit` | RATE_LIMITED | — |
| `claude security` | RATE_LIMITED | — |
| `codex security` | RATE_LIMITED | — |
| `copilot security` | RATE_LIMITED | — |
| `mcp security` | RATE_LIMITED | — |
| `authorization audit` | RATE_LIMITED | — |
| `business logic security` | RATE_LIMITED | — |

Each `gh skill search` call consumes roughly a third of the GitHub search-API window, so only three
queries completed per window. The three that did complete are the ones that matter most — the brand
name and the two broadest category terms — and all three returned nothing. Complete the remaining
seven on a later pass rather than inferring them.

### GitHub repository search

| Query | Result | Notes |
|---|---|---|
| `topic:agent-skills security` | NOT_FOUND | Eight results returned, none SecHelix. The `agent-skills` topic was added the same hour. |

### skills.sh

| Query | Result | Notes |
|---|---|---|
| `skills.sh/omarmohelal/SecHelix` | **FOUND** | The listing exists and resolves: 1 skill, install command shown. This is the only surface where SecHelix is discoverable today. |

The registry page reports an install count. **It is 1, and that 1 is this session's own cold-install
verification.** It is not adoption, it must never be cited as adoption, and the README badge
deliberately shows the skill count rather than the install count for exactly that reason.

### Web search

| Query | Result | What the results were instead |
|---|---|---|
| `SecHelix AppSec Agent Skill` | NOT_FOUND | Vendor marketing on "agentic AppSec" — Legit, Endor, Checkmarx, Palo Alto, OpenText. |
| `sechelix.com evidence-first security findings are claims` | NOT_FOUND | Unrelated: an insurance claims process, a SOC 2 article, `evidence.dev`. |

## Comparison with the pre-launch baseline

| Surface | Before | After |
|---|---|---|
| Brand-name web search | NOT_FOUND | NOT_FOUND |
| Category web search | NOT_FOUND | NOT_FOUND |
| `gh skill search` | not applicable (nothing published) | NOT_FOUND |
| skills.sh listing | did not exist | **FOUND** |
| GitHub release / installable artifact | did not exist | **exists** |

One surface moved. That is what publishing on the same day buys, and pretending otherwise would make
this document worthless.

## What would actually change these rows

- **Time.** Indexing latency dominates everything here.
- **Inbound links from indexed pages.** The two directory submissions
  ([royalpinto007#4](https://github.com/royalpinto007/awesome-agent-skills/pull/4),
  [Ezeafk#33](https://github.com/Ezeafk/awesome-agent-skills/pull/33)) and the Awesome Copilot
  marketplace submission ([issue #2899](https://github.com/github/awesome-copilot/issues/2899)) are
  the highest-value pending items, because each is an already-indexed page linking here.
- **A measured benchmark.** Still `NOT_MEASURED`, still blocked on an uncontaminated evaluator. It is
  the single most citable thing this project could add, and it cannot be faked into existence.

## Limitations

- One day, one region, one sample per query, and the release was an hour old.
- Seven `gh skill search` queries were never completed because of API limits.
- Search results are personalized and volatile.
- `NOT_FOUND` here establishes absence at the moment of measurement and nothing else. It does not
  establish that a surface will not index the project tomorrow.
