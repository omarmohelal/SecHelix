# Submission draft — `patrickclery/awesomer`

> **DRAFT — requires human review before submitting. Do not submit automatically.**

---

## Status: NOT_APPLICABLE — there is nothing to submit, and no entry text is provided

**Do not open a PR or an issue against this repository.** This is not a curated list that accepts
entries. It is an **automated aggregator** that scrapes other people's awesome lists and renders
star-growth trending pages for them. Its entire content is machine-generated.

Because there is no submission mechanism, this file deliberately contains **no entry text, no table
row, and no JSON** — inventing one would imply a path that does not exist. What it contains instead
is the evidence for that conclusion and the only real way SecHelix could ever appear there.

### The one thing SecHelix would need is a metric we do not have and will not claim

Awesomer ranks repositories by **stars gained over 7, 30, and 90 days**. Appearing there is a
function of star growth. That is an adoption metric. SecHelix has no adoption numbers to offer, and
the absolute rule for this launch is that we do not state, estimate, or pursue one. So this
destination is not merely closed — it is measuring the exact thing we have committed not to claim.

---

## 1. Evidence, read on 2026-09-01

Repository: <https://github.com/patrickclery/awesomer>
Live site: <https://patrickclery.com/awesomer/>
Sources read: `README.md` (raw), `l/agent-skills.md`, `l/claude-skills.md`, root and `.github`
directory listings, `CONTRIBUTING.md` (**HTTP 404 — the file does not exist**).

### 1a. What it is, quoted from the README

> "# Awesomer
>
> What if every Awesome List had a trending page? Now they do."

The README consists of a "Hottest This Week" block, a "Top 10 Trending Repos" table, and an "All
Awesome Lists" table with `Stars | 7d | 30d | 90d` columns. It ends with a generation stamp:

> "*Updated: 2026-08-26 | [View live site ↗](https://patrickclery.com/awesomer/)*"

### 1b. It aggregates lists it does not own

`/l` holds one generated page per tracked upstream list; `/r` holds one generated page per tracked
repository. Each `/l` page links out to the list it mirrors. For example, `l/agent-skills.md`:

> "[Home](../README.md) | [Live site ↗](https://patrickclery.com/awesomer/l/agent-skills/) | [Source ↗](https://github.com/VoltAgent/awesome-agent-skills)"

and `l/claude-skills.md` sources from `https://github.com/ComposioHQ/awesome-claude-skills`.

Note that neither of the two `awesome-agent-skills` repositories assigned elsewhere in this task
(`royalpinto007`, `Ezeafk`) is currently a tracked source — `l/agent-skills.md` tracks
`VoltAgent/awesome-agent-skills`.

### 1c. There is no contribution process

- `CONTRIBUTING.md`: **404**.
- `.github/` contains exactly one file: `dependabot.yml`. No issue templates, no PR template.
- The set of tracked lists is not a committed config file; the repo is a NestJS API + web front end
  with a Prisma datastore (`api/prisma`), so the tracked-list set lives in a database the public
  cannot PR against.

### 1d. Correction — a misreading to avoid

A quick scan of the README turns up this string, and it is easy to mistake for awesomer's own policy:

> "Pull requests are temporarily disabled until I have a chan"

**It is not awesomer's policy.** It is the truncated GitHub *description* of `sindresorhus/awesome`,
scraped into the "All Awesome Lists" table's Description column. The same column shows
`awesome-nodejs` carrying "[BECAUSE OF TOO MUCH SPAM AND LOW-QUALITY SUBMISSIONS, SUBMISSIONS ARE
PAUSE", which is likewise that list's own description, not awesomer's.

The accurate statement is stronger and simpler: awesomer has **no stated contribution process at
all**, because it does not take contributions.

---

## 2. The only real path — and it is indirect

SecHelix can only appear on awesomer as a **downstream consequence** of two things it does not
control:

1. **Get listed in an upstream list that awesomer already tracks.** From the "All Awesome Lists"
   table, the plausible candidates for a security-focused agent skill are `awesome-agent-skills`
   (source: `VoltAgent/awesome-agent-skills`), `awesome-claude-skills` (source:
   `ComposioHQ/awesome-claude-skills`), and `awesome-claude-code`. Each has its own contribution
   policy that a human must read separately — **none of them was reviewed for this draft**, and none
   should be submitted to on the strength of this file.
2. **Accumulate enough star growth to rank.** Not actionable, not claimable, and not a goal we are
   permitted to pursue or state.

Step 1 is a legitimate, separate piece of work. Step 2 is not work at all — it is an outcome. Treat
awesomer as a possible side effect of good upstream listings, never as a destination.

---

## 3. Pre-submission checklist

There is nothing to submit, so this is a checklist for **not** wasting effort here.

- [ ] **A-1.** Confirm nobody opens a PR or issue on `patrickclery/awesomer`. There is no submission
      path and an entry cannot be hand-added; `/l` and `/r` are generated output.
- [ ] **A-2.** Do not treat the "Pull requests are temporarily disabled" string as awesomer's rule —
      it is `sindresorhus/awesome`'s scraped description. See 1d.
- [ ] **A-3.** If awesomer coverage is genuinely wanted, re-scope the work to the **upstream** lists
      it tracks (`VoltAgent/awesome-agent-skills`, `ComposioHQ/awesome-claude-skills`,
      `awesome-claude-code`), and read each one's `CONTRIBUTING.md` in full first. That is new work,
      not covered by this draft.
- [ ] **A-4.** Do not set, track, or communicate any star-growth target in order to surface here.
      Ranking on awesomer is an adoption metric and is out of bounds for this launch.
- [ ] **A-5.** Re-check this conclusion if awesomer later publishes a `CONTRIBUTING.md` or an issue
      template. As of 2026-09-01 it has neither, and its README was last generated 2026-08-26.

---

## 4. For the record

- **Benchmarks are NOT_MEASURED.** Stated here for consistency with every other submission draft,
  even though nothing is being submitted to this destination. The blocker is documented in the
  repository: the eval fixture suite was authored by the same assistant session that would have acted
  as the evaluated model, so scoring it would measure recall of authored answers rather than
  security-review capability. Unblocking requires a run by a model or session that did not author the
  fixtures, on blind exported cases.
- No adoption, star, install, user, or comparison claim is made in this file, and none should be made
  in pursuit of this destination.
