# Discovery — recurring measurement

Successor to [`discovery-baseline.md`](discovery-baseline.md) (pre-launch, 0 of 6) and
[`discovery-post-launch.md`](discovery-post-launch.md) (release day). Append a dated block each time;
do not overwrite. The value is entirely in the comparison.

`RATE_LIMITED` is recorded when an API refused the request. **It is never recorded as `NOT_FOUND`** —
an error is not a measurement, and an earlier pass at this table read rate-limit responses as
absence until the responses were actually inspected.

---

## 2026-09-01 (V3.3)

| Surface | Result | Change since release day |
|---|---|---|
| GitHub repository search, `sechelix` | **FOUND** — `omarmohelal/SecHelix`, position 2 | **NOT_FOUND → FOUND** |
| skills.sh listing | **FOUND** — 1 skill | unchanged |
| `gh skill search sechelix` | NOT_FOUND | unchanged |
| `gh skill search appsec` | NOT_FOUND | unchanged |
| `gh skill search "application security"` | NOT_FOUND | unchanged |
| Web search, brand name | NOT_FOUND | unchanged |
| Web search, category | NOT_FOUND | unchanged |

One surface moved. GitHub's own repository index picked up the project, which is the first
discovery result this project has that was not created by publishing an artifact.

### A badge was removed, not added

The V3.2 launch added a skills.sh badge to the README on the reading that its endpoint returned a
**skill count**. It does not. Today the listing page reads "1 skill, 2 total installs" while the
badge endpoint returns `2` — the badge tracks **installs**, and its `Skills` label is misleading.

Both of those installs are this project's own cold-install verification runs.

A badge displaying an adoption-shaped number that is entirely self-generated is exactly the vanity
metric this project refuses, so the badge is gone. The listing itself is real and still worth having;
it just does not belong in a badge row.

### Also noticed

`omarmohelal/SecHelix-Site` appears in repository search results. It is not one of the three
maintained repositories and was not part of any release. Worth reviewing — an abandoned public repo
with a confusingly similar name splits search results and invites someone to install the wrong
thing. **No action taken**: changing another repository's visibility is the owner's decision.

---

## What would actually move these

In descending order of expected effect:

1. **A merged directory submission.** Three are open —
   [awesome-copilot#2899](https://github.com/github/awesome-copilot/issues/2899),
   [royalpinto007#4](https://github.com/royalpinto007/awesome-agent-skills/pull/4),
   [Ezeafk#33](https://github.com/Ezeafk/awesome-agent-skills/pull/33). Each is an already-indexed
   page linking here, which is worth more than any on-site change.
2. **An uncontaminated benchmark result.** Still `NOT_MEASURED`. It is the single most citable thing
   this project could have, and it cannot be manufactured.
3. **Time.** Indexing latency dominates everything above.

## Method

- `gh skill search` consumes roughly a third of the GitHub search-API window per query, so only
  about three complete per window. The three run here are the brand name and the two broadest
  category terms.
- One engine, one region, one sample per query.
- `NOT_FOUND` establishes absence at the moment of measurement and nothing more.
