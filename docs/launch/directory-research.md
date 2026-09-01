# Directory research — Agent Skill and AppSec listings

**Research only. Nothing here has been submitted, and nothing should be
submitted on the strength of this page without re-reading the target's policy
first** — these policies change, and several of them changed recently in
response to a flood of AI-generated submissions.

Assessed **2026-09-01**. Repository metadata (stars, last push, archived state,
license) came from the GitHub REST API on that date. Every policy is quoted
verbatim from the target repository's own `CONTRIBUTING.md` or `README.md` as it
stood that day; where a rule decides a verdict, the quote is the reason, not a
paraphrase of it.

Existing submission drafts live in [`awesome-list-submission.md`](awesome-list-submission.md)
and [`submissions/`](submissions/README.md).

## Where things already stand

| Directory | State |
| --- | --- |
| `github/awesome-copilot` | Submitted — issue 2899 |
| `royalpinto007/awesome-agent-skills` | Submitted — PR 4 |
| `Ezeafk/awesome-agent-skills` | Submitted — PR 33 |
| `claude-market/marketplace` | Declined — vendors the source into their repository |
| `VoltAgent/awesome-agent-skills` | Deferred — requires established usage |
| `khasky/awesome-agent-skills` | Declined — hosts its own skills; not a directory |

## The facts that decide most of these

Nearly every credible directory now gates on project age, stars, or contributor
count. SecHelix's own numbers as of 2026-09-01:

- repository created **2026-08-31** (one day old);
- **0 stars**, 0 forks;
- **1 contributor**;
- Apache-2.0, public, no signup and no paid tier;
- ships a portable Agent Skill bundle *and* a Claude Code plugin manifest;
- public benchmark status is `NOT_MEASURED`.

Three of those are disqualifying under published rules today and stop being
disqualifying on a knowable date. That is what most of the `DEFERRED` verdicts
below mean: not "unsuitable", but "the rule says no, and the rule is public".

## Summary

| Repo | Stars | Last push | External submissions | Verdict |
| --- | --- | --- | --- | --- |
| `anthropics/claude-plugins-official` | 35,795 | 2026-09-01 | Yes — submission form | **ELIGIBLE** |
| `hesreallyhim/awesome-claude-code` | 53,337 | 2026-09-01 | Yes — issue form only | **DEFERRED** — 14-day / 100-star rule |
| `analysis-tools-dev/static-analysis` | 14,757 | 2026-08-30 | Yes — PR adding a YAML file | **DEFERRED** — six months, 20 stars, >1 contributor |
| `travisvn/awesome-claude-skills` | 14,927 | 2026-04-28 | Yes — PR | **DEFERRED** — 10-star floor, and no AI-assisted PRs |
| `ComposioHQ/awesome-claude-skills` | 74,225 | 2026-08-10 | Yes — PR | **NOT_ELIGIBLE** — vendors the source |
| `sottlmarek/DevSecOps` | 6,863 | 2026-08-12 | Yes — PR | **DEFERRED** — maturity is an explicit PR field |
| `OWASP/www-community` | 1,405 | 2026-08-25 | Yes — fork and pull | **NOT_ELIGIBLE** — vendor and product neutral |
| `paragonie/awesome-appsec` | 7,051 | 2025-02-22 | Yes — PR | **NOT_ELIGIBLE** — dormant, and wrong scope |

---

## `anthropics/claude-plugins-official` — ELIGIBLE

- **Repo:** https://github.com/anthropics/claude-plugins-official
- **Stars:** 35,795 · **forks:** 3,995 · **open issues:** 1,070
- **Created:** 2025-11-20 · **last push:** 2026-09-01 · **not archived** · Apache-2.0
- **Accepts external submissions:** yes, through a form rather than a PR.

**Stated policy, quoted:**

> Third-party partners can submit plugins for inclusion in the marketplace.
> External plugins must meet quality and security standards for approval. To
> submit a new plugin, use the [plugin directory submission form](https://clau.de/plugin-directory-submission).

The README also documents a **skill-bundle** entry shape for source
repositories that ship `SKILL.md` files, using `strict: false` and an explicit
`skills` array, alongside the ordinary plugin shape.

**Why ELIGIBLE.** This is the only assessed directory that is first-party,
actively maintained, and imposes **no age, star, or contributor gate** in its
published policy. SecHelix already satisfies the structural precondition: it
ships `.claude-plugin/plugin.json`, and `claude plugin validate .` passes
(recorded under "How this was tested" in
[`docs/reference/compatibility.md`](../reference/compatibility.md)). The listing
is a pointer to this repository — no vendored copy, so there is no second source
of truth to drift.

**Caveats to carry into a submission.** "Partners" is the README's word, and
approval is explicitly conditional on unstated "quality and security standards";
a submission can be declined without a reason. The form is off-GitHub, so there
is no public thread to track. Two facts should be stated plainly in the
submission rather than discovered by a reviewer: the project is alpha, and its
public benchmark status is `NOT_MEASURED`.

---

## `hesreallyhim/awesome-claude-code` — DEFERRED

- **Repo:** https://github.com/hesreallyhim/awesome-claude-code
- **Stars:** 53,337 · **forks:** 4,643 · **open issues:** 967
- **Created:** 2025-04-19 · **last push:** 2026-09-01 · **not archived**
- **Accepts external submissions:** yes — issue form only, PRs are refused.

**Stated policy, quoted:**

> ## GROUND RULES:
>
> Any resource that is recommended must either:
>
> (i) Be at least 14 days old (14 days since first commit on default branch) AND
> show signs of active development (I expect there to be also additional commits
> after the first day);
>
> OR
>
> (ii) Have at least 100 stars.
>
> In addition: **You may not recommend more than one resource at a time.**
>
> Resources that fail these criteria will be closed automatically.

and on the mechanism:

> **NOTE: ALL RECOMMENDATIONS MUST BE MADE USING THE WEB UI ISSUE FORM TEMPLATE,
> OR YOU RISK BEING RESTRICTED FROM INTERACTING WITH THIS REPOSITORY
> TEMPORARILY.**
>
> Do not open a PR. Just fill out the form.

> It is **not** possible to submit a resource recommendation using the `gh` CLI.

and on motive:

> Too many people think like this: (i) Build something awesome; (ii) Submit to
> Awesome Claude Code; (iii) Get accepted, because of being awesome; (iv) Get
> users. However, a more likely chain of events is: (i) Build something awesome;
> (ii) Get users; (iii) Submit it to Awesome Claude Code […] If "getting on the
> list" is any part of a promotional strategy for your project, you should be
> prepared to have a backup plan.

**Why DEFERRED.** SecHelix fails both limbs today: the repository's first commit
on the default branch is 2026-08-31, and it has 0 stars. Criterion (i) becomes
satisfiable on or after **2026-09-14**, and only with commits after the first
day — which the repository does have. Submitting before then is auto-closed, and
a closed submission is worse than none.

**How, when it is time.** Web UI issue form only:
`https://github.com/hesreallyhim/awesome-claude-code/issues/new?template=recommend-resource.yml`.
The `gh` CLI cannot do it, PRs are refused, and the form must be filled in by a
human — the policy says recommendations "must be created by human beings" even
where the resource itself was written with a coding agent. Description style is
prescribed: one line, descriptive rather than promotional, no emojis, no
second-person address.

**Why it is worth waiting for.** Hand-curated, high traffic, explicitly
selective, and a link-only listing that does not fork the source. It is also the
list whose stated philosophy most closely matches this project's own posture
about unearned visibility.

---

## `analysis-tools-dev/static-analysis` — DEFERRED

- **Repo:** https://github.com/analysis-tools-dev/static-analysis (renders
  https://analysis-tools.dev)
- **Stars:** 14,757 · **forks:** 1,511 · **open issues:** 11
- **Created:** 2015-12-18 · **last push:** 2026-08-30 · **not archived** · MIT
- **Accepts external submissions:** yes — a PR adding one YAML file.

**Stated policy, quoted:**

> ### Requirements
>
> Each tool on the list should
>
> - have existed for at least six months
> - have at least 20 stars on GitHub
> - have more than one contributor

> ⚠️ **The main `README.md` is just a rendered version of the data. Do not edit
> it manually.**
>
> To add a new tool, please create a file in the `data/tools` directory like
> `data/tools/<toolname>.yml`.

> For AI-related tools, add `ai-generated-code` if the tool analyzes
> AI-generated code, and add `uses-llm` if it invokes an LLM or other model
> while analyzing code.

**Why DEFERRED.** SecHelix fails all three requirements today: one day old,
0 stars, 1 contributor. The six-month clock runs out around **2027-03-01**, and
the star and contributor bars are not on a clock at all. Only 11 issues are open
against 14,757 stars, which is a maintained list rather than a dumping ground —
so the requirements are likely enforced.

**Fit, separately from eligibility.** This is a directory of *tools*, and
SecHelix is a methodology plus an Agent Skill that consumes SAST output as
evidence rather than producing it. The `uses-llm` tag exists and would apply,
which is evidence the list has already made room for this category of thing —
but the fit argument still has to be made explicitly in the PR, and it may be
refused on scope even after the numeric gates are met. Worth re-assessing in
2027 rather than assuming.

---

## `travisvn/awesome-claude-skills` — DEFERRED

- **Repo:** https://github.com/travisvn/awesome-claude-skills
- **Stars:** 14,927 · **forks:** 1,928 · **open issues:** 785
- **Created:** 2025-10-16 · **last push:** 2026-04-28 · **not archived** · no license
- **Accepts external submissions:** yes — PR. Link-only; the repository holds
  only `README.md` and `CONTRIBUTING.md`, so nothing is vendored.

**Stated policy, quoted:**

> #### Social Proof
>
> Skills must have gathered enough attention from the community so-as to have
> acquired a number of GitHub stars to be considered in most cases.

> Due to the volume of PR submissions that do not conform to these contribution
> guidelines, if your skill hasn't acquired a basic 10 stars, it will be closed
> automatically.

> #### AI Automated Submissions
>
> Due to the influx of PRs, there is a requirement now that the PR not be
> explicitly generated / submitted with AI-assistance.

> While not an absolute requirement, a strong general guideline would be that
> more exists to the skill than a single `SKILL.md` file.

**Why DEFERRED.** The 10-star floor is automatic and SecHelix has none. The
second rule matters operationally and should be recorded rather than quietly
worked around: **this PR must be written and opened by a human, without AI
assistance.** That is the maintainer's stated condition for review, and a
project whose entire thesis is evidence honesty does not get to treat someone
else's submission rule as advisory.

The "more than a single `SKILL.md`" guideline is comfortably met.

**Caution.** Last push 2026-04-28 — roughly four months of no commits, though
the repository is still being interacted with (785 open issues, recent activity
timestamps). Re-check that the list is still being merged into before spending
the effort.

---

## `ComposioHQ/awesome-claude-skills` — NOT_ELIGIBLE

- **Repo:** https://github.com/ComposioHQ/awesome-claude-skills
- **Stars:** 74,225 · **forks:** 8,508 · **open issues:** 1,378
- **Created:** 2025-10-17 · **last push:** 2026-08-10 · **not archived** · no license
- **Accepts external submissions:** yes — PR.

**Stated policy, quoted:**

> ## Skill Structure
>
> Create a new folder with your skill name (use lowercase and hyphens):
>
> ```
> skill-name/
> └── SKILL.md
> ```

> 3. Add your skill folder with SKILL.md
> 4. Update README.md with your skill in the appropriate category

and the README entry format:

> `- [Skill Name](./skill-name/) - One-sentence description.`

**Why NOT_ELIGIBLE.** The entry links to `./skill-name/` — a copy of the skill
living inside their repository. This is a **skill host**, not a pointer
directory, and it is the same reason `claude-market/marketplace` was already
declined. A vendored copy creates a second `SKILL.md` that nobody re-syncs,
which is precisely the failure this repository guards against with a canonical
skill and generated mirrors: an outdated fork of a *security* skill is worse
than no listing, because a reader cannot tell which one they are running.

The repository has no license file, which also leaves the terms of a vendored
copy unstated.

**What would change the verdict.** A link-only entry form, or a documented
policy for keeping vendored copies in sync with upstream. Neither exists today.

---

## `sottlmarek/DevSecOps` — DEFERRED

- **Repo:** https://github.com/sottlmarek/DevSecOps ("Ultimate DevSecOps library")
- **Stars:** 6,863 · **forks:** 1,196 · **open issues:** 21
- **Created:** 2018-06-27 · **last push:** 2026-08-12 · **not archived** · MIT
- **Accepts external submissions:** yes — PR against the README tables.

**Stated policy, quoted:**

> ## Contribution rules
> If you want to contribute to this library of knowledge please create proper PR
> (Pull Request) with description what you are adding following these set of
> rules:
>
> * Clear description of PR (which tool, why, number of stars, maturity and topic)
> * Keep it simple - Fill the description properly
> * Fact over feelings or personal opinions
> * Add source and follow the library style

**Why DEFERRED.** The submission itself must state "number of stars, maturity"
— and the honest statement today is *0 stars, one day old, alpha*. The list's
entries also carry a live GitHub-stars badge per row, so a zero-star entry is
visibly the weakest row on the page. Nothing here is dishonest to submit; it is
simply a submission that argues against itself. Re-assess once there is any
adoption signal.

**Fit.** Good, and better than `static-analysis`: the library is organised by
DevSecOps practice and has an `AI` section, so a methodology and Agent Skill has
somewhere to sit rather than being wedged into a SAST tool table. Low open-issue
count against a large list suggests real maintenance.

---

## `OWASP/www-community` — NOT_ELIGIBLE

- **Repo:** https://github.com/OWASP/www-community (renders
  https://owasp.org/www-community/, which hosts the widely-cited
  "Source Code Analysis Tools" page)
- **Stars:** 1,405 · **last push:** 2026-08-25 · **not archived**
- **Accepts external submissions:** yes — fork and pull.

**Stated policy, quoted:**

> ### Rules for Contributors
>
> 1. Your contribution must be your own original work. You may not submit
>    copyrighted content you do not own. Please do not plagiarize.
> 2. Please ensure that contributions are vendor and product neutral.

**Why NOT_ELIGIBLE.** Rule 2 decides it. Adding SecHelix to an OWASP community
page is a product addition by that product's author, which is not
vendor-neutral, however the entry is worded. The `Source_Code_Analysis_Tools`
page is a curated inventory maintained under that neutrality rule, and a project
that publicly criticises benchmark theater should not be the one bending a
neutrality rule for a link.

**What is legitimate here instead.** Contributing *content* — a
vendor-neutral community page about verification-first review, or corrections to
an existing page — under the same rule that governs everyone. That is a real
contribution and is worth doing on its own merits, but it is not a directory
submission and should never be a disguised one.

---

## `paragonie/awesome-appsec` — NOT_ELIGIBLE

- **Repo:** https://github.com/paragonie/awesome-appsec
- **Stars:** 7,051 · **forks:** 804 · **open issues:** 42
- **Created:** 2015-04-30 · **last push:** **2025-02-22** · not archived · MIT
- **Accepts external submissions:** in principle — PR adding a JSON file.

**Stated policy, quoted:**

> To add to this list, please clone the repository then follow the following
> steps:
>
> 1. Create a new JSON file with the desired information. […] The following
>    fields are required: `name`, `remark`, `url`
>
> 2. Commit your changes, send a pull request.

**Why NOT_ELIGIBLE.** Two reasons, either sufficient.

*Maintenance.* No push in roughly eighteen months, with 42 issues open. The
policy is permissive precisely because nobody is applying it. A merge is
unlikely, and a listing on a list nobody updates delivers nothing.

*Scope.* Its own description is "A curated list of resources for **learning
about** application security" — books, courses, and reading. SecHelix is a tool
and a methodology, not a learning resource. It would be off-topic even if the
list were active.

**Re-check trigger.** Renewed commit activity. Until then this is a dead list
with a friendly `CONTRIBUTING.md`.

---

## Rejected without full assessment

Named so that the omissions are visible decisions rather than oversights.

- **`sickn33/agentic-awesome-skills`** — describes itself as a "local,
  agent-first control plane" that hosts a catalog. That is a product with a
  bundled catalog, not a directory accepting third-party listings; same category
  as the already-declined `khasky/awesome-agent-skills`.
- **`BehiSecc/awesome-claude-skills`, `heilcheng/awesome-agent-skills`,
  `libukai/awesome-agent-skills`, `zhuyansen/agent-skills-hub`,
  `0xNyk/awesome-hermes-agent`** — the same-name cluster of skill lists. Several
  are genuinely maintained, but submitting to all of them is list-spraying, not
  distribution: it multiplies places where a stale description of a security tool
  can sit. Reassess individually only if one develops a distinct audience.
- **`Shubhamsaboo/awesome-llm-apps`, `ruvnet/RuView`, `infoslack/awesome-web-hacking`,
  `Hack-with-Github/Awesome-Hacking`-style mega-lists** — scope mismatch or
  low curation. Volume listings do not carry a real audience for an AppSec
  methodology.
- **`devsecops/awesome-devsecops` (last push 2024-05-11),
  `jakob-pennington/awesome-devsecops` (2024-08-02),
  `hysnsec/awesome-threat-modelling` (2024-08-02)** — dead by the same test
  applied to `paragonie/awesome-appsec`: over a year without a push.

## Re-check calendar

| Date | Target | What changes |
| --- | --- | --- |
| Now | `anthropics/claude-plugins-official` | Nothing blocks a submission; only the decision to make one |
| 2026-09-14 | `hesreallyhim/awesome-claude-code` | 14-days-since-first-commit rule satisfied, given continued commits |
| At 10 stars | `travisvn/awesome-claude-skills` | Auto-close floor cleared; PR must still be human-authored |
| Any adoption signal | `sottlmarek/DevSecOps` | The "number of stars, maturity" line stops arguing against itself |
| 2027-03-01 | `analysis-tools-dev/static-analysis` | Six-month age met; 20 stars and a second contributor still required |

Re-read every policy before acting on a row. Three of the six live policies here
were tightened in response to AI-generated submissions, and that direction of
travel is continuing.
