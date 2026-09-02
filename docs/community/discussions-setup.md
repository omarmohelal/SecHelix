# GitHub Discussions setup

Discussions are enabled on `omarmohelal/SecHelix`, but the category list is still
the GitHub default (`Announcements`, `General`, `Ideas`, `Polls`, `Q&A`,
`Show and tell`). Those defaults do not match what this project actually needs
people to bring: refutations, methodology arguments, pack proposals, and host
compatibility reports.

**Categories can only be created through the web UI.** There is no REST or
GraphQL mutation for creating a discussion category, so this page is a manual
runbook rather than a script. Everything below is ready to paste.

## The standing rule, before anything else

Discussions are **public**. Nothing posted here is private, and GitHub keeps edit
history.

> Never paste credentials, API keys, tokens, private or proprietary source code,
> customer data, real internal hostnames, or a live third-party target into a
> public thread. Reproduce the behaviour with a synthetic snippet instead. If the
> only way to show the problem is with material you cannot publish, do not post
> it — use
> [private vulnerability reporting](https://github.com/omarmohelal/SecHelix/security/advisories/new)
> for a vulnerability in SecHelix itself, and redact everything else down to a
> synthetic case before it goes in a thread.

That paragraph is repeated inside each seed post below on purpose. It is the one
rule a first-time poster is most likely to break.

## The six categories

| Category | Format | Description field (paste verbatim) |
| --- | --- | --- |
| Announcements | Announcement | Releases, contract changes, and evaluation results. Maintainer-posted; comments open. |
| Q&A | Question / Answer | Ask how to install SecHelix, run an audit, read a report, or interpret UNKNOWN and BLOCKED. |
| False positives | Open-ended discussion | A finding SecHelix asserted that verification should have refuted — bring the minimal reproduction. |
| Methodology | Open-ended discussion | Argue with the evidence standard: applicability, verification, severity, and what counts as proof. |
| Gold Pack proposals | Open-ended discussion | Shape a Gold Check Pack before writing it: bug class, invariant, refutation tests, fixtures. |
| Integrations | Open-ended discussion | Hosts, scanners, and CI: what loaded, what did not, and which evidence adapter is missing. |

`Announcements` and `Q&A` already exist with the GitHub default descriptions
(`Updates from maintainers` and `Ask the community for help`). Edit those two
rather than creating duplicates; create the other four.

### The unused defaults

`General`, `Ideas`, `Polls`, and `Show and tell` are all empty today. Deleting
them is optional but recommended: an empty catch-all category collects
off-topic threads, and `Ideas` in particular will collect roadmap requests that
belong in an issue. Deleting a category that still holds discussions makes GitHub
ask which category to move them into; while they are empty, deletion is clean.

## Exact click path

**Create a category**

1. Open `https://github.com/omarmohelal/SecHelix/discussions/categories`.
   (Equivalent click path: repository → **Discussions** tab → in the left
   sidebar, the pencil icon next to **Categories**.)
2. Click **New category** (top right).
3. Fill **Category name** — exactly as written in the table above.
4. Optionally pick an emoji. GitHub requires one and defaults to 💬.
5. Fill **Description** — paste the description column verbatim. It is shown in
   the sidebar and on the "start a discussion" picker, so it is the last thing a
   poster reads before choosing where to post.
6. Under **Discussion format**, choose one:
   - **Announcement** — only maintainers can post; anyone can comment.
   - **Open-ended discussion** — anyone can post; no accepted answer.
   - **Question / Answer** — anyone can post; comments can be marked as the answer.
   - **Poll** — not used by this project.
7. Click **Create**.

**Edit an existing category** (for `Announcements` and `Q&A`): same page, click
the pencil icon on the category row, change the description, **Save changes**.

**Delete a category**: same page, pencil icon on the row, **Delete** at the
bottom, then confirm.

**Order** the sidebar by dragging rows on that page. Suggested order:
Announcements, Q&A, False positives, Methodology, Gold Pack proposals,
Integrations.

## Seed posts

One per new category. Post them from the maintainer account immediately after
creating the category, and pin each one in its category (open the discussion →
**⋯** menu → **Pin discussion**). An empty category reads as abandoned; a pinned
seed post tells the first visitor what a good post looks like.

Each block below is the complete body. Titles are given above their blocks.

### False positives

**Title:** `Read this first: how to report a false positive so it becomes a test`

````markdown
This category exists because of one claim SecHelix makes: **a finding is not
true until verification could have refuted it and did not.** Every time that
fails, the project needs to hear about it — a false positive is worth more here
than a new check.

**Public thread. Do not paste credentials, API keys, tokens, private or
proprietary source, customer data, real internal hostnames, or a live
third-party target.** Reduce it to a synthetic snippet first. If you cannot,
do not post it.

## What makes a report actionable

Five things. Missing any one of them turns a report into a conversation instead
of a fix.

**1. The finding id, and the version it came from.**
The `SHX-...` hypothesis id if you have it, the finding id from the report, and
the SecHelix version or commit. Without a version, nobody can tell whether the
behaviour still exists.

**2. What SecHelix claimed, quoted.**
Paste the finding as it appeared — the claim, the severity, and the evidence it
cited. Redact first.

**3. A minimal reproduction.**
The smallest synthetic file that produces the claim. Not your repository: a
reduced case. This is the part that makes the report reusable, because it can
become a fixture almost unchanged.

**4. Why the claim is wrong, in terms of the evidence standard.**
A verified finding is supposed to establish attacker control, reachability, a
failed security boundary, safe reproducibility, and concrete impact. Say which
one does not hold, and how you know. "It's not exploitable" is not a refutation;
"the value can only come from a server-side config the caller cannot write, so
attacker control is not established" is.

**5. Which compensating control holds the invariant — if one does.**
The most valuable false positive is code that *looks* vulnerable and is not,
because a real control elsewhere holds. Name it precisely: the framework version
that changed the default, the database policy that binds the role, the type that
refuses the undeclared attribute, the header that is actually on the response.
"Looks fine to me" is not a compensating control.

## What happens to a confirmed report

A confirmed false positive usually becomes **a paired eval fixture** — a
`vulnerable` variant and a `clean` variant that share the same alarming surface
and differ only in whether the control actually binds. That pair then scores
every future evaluation run, so the same mistake gets measured instead of
remembered. Where the class is already covered by a Gold Check Pack, the
refutation is also added to that pack's `false_positive_filters`, which is what
a reviewer reads before reporting.

So: your report does not just get fixed. It becomes a regression test that
argues with the project forever.

## Discussion here, or the issue form?

- **Use the issue form** when you have the five things above and you are
  confident the claim is wrong:
  https://github.com/omarmohelal/SecHelix/issues/new?template=false-positive.yml
- **Use this category** when you are not sure — when you think a finding is
  wrong but cannot yet name which part of the evidence standard fails, when you
  want a second opinion on whether a control really binds, or when you are
  arguing about severity rather than existence.

Both are welcome. Uncertainty is not a reason to stay quiet; it is a reason to
post here instead of there.

## Also wanted: the opposite

False *negatives* — a real, verifiable issue SecHelix walked past — are just as
useful and follow the same shape: minimal synthetic reproduction, and what makes
it real.
````

### Methodology

**Title:** `What this category is for: argue with the evidence standard`

````markdown
SecHelix asserts a specific and contestable position:

> A scanner alert is not a vulnerability. A model suspicion is not a
> vulnerability. Two models agreeing is not independent proof.

and that a trusted finding should establish attacker control, reachability, a
failed security boundary, bounded safe reproduction, concrete impact, root
cause, a fix, and regression proof.

That standard is a design decision, not a law. This category is where it gets
argued with.

**Public thread. No credentials, private source, customer data, or live
third-party targets — use synthetic examples.**

## Questions worth opening a thread about

- **Where does the standard cost more than it is worth?** Requiring runtime
  proof for a class that static evidence settles conclusively is friction with
  no gain. Which classes are those?
- **Applicability.** SecHelix returns `APPLICABLE`, `NOT_APPLICABLE`, `UNKNOWN`,
  or `BLOCKED`, and never converts missing evidence into absence. That means an
  under-instrumented run returns a lot of `UNKNOWN`. Is that the right failure
  mode, and where does it stop being useful?
- **Severity.** The published case study holds a clickjacking finding at MEDIUM
  because the application performs no authenticated state-changing actions.
  Argue with calls like that one — with the reasoning, not the label.
- **Independent verification.** The verifier is supposed to try to *disprove* a
  candidate. What does independence actually require when the same model family
  runs both lanes?
- **What counts as proof at which layer.** Browser, API, database, migration,
  local runtime — when does a green unit test not settle a question?

## What a good thread looks like

State the claim you are disputing, quote the document you are disputing (link
the file and line), and say what evidence would change your mind. Concrete
disagreement beats a general opinion, and a worked counter-example beats both.

## Out of scope here

- Roadmap and feature requests — open an issue.
- Proposing a new security check — that is a testable hypothesis, and it has its
  own form:
  https://github.com/omarmohelal/SecHelix/issues/new?template=check-proposal.yml
- Full-workflow benchmark claims. The blind label suite has one measured run; the
  blocker and the procedure to remove it are written down:
  https://github.com/omarmohelal/SecHelix/blob/main/docs/EVALUATION.md

Start here: the evidence standard and the four applicability outcomes are in the
README, and the full protocol is in
https://github.com/omarmohelal/SecHelix/blob/main/docs/EVALUATION.md
````

### Gold Pack proposals

**Title:** `Propose a Gold Check Pack here before you write one`

````markdown
A Gold Check Pack is a reusable **investigation plan** for one security bug
class: what to look for, how to look safely, what would refute the hypothesis,
and what a fix has to preserve. It is not a scanner rule, not a signature, and
not a finding.

Writing one is a real piece of work — the contract has 22 required sections and
a validator that refuses shortcuts. This category exists so that work starts
after the shape is agreed, not before.

**Public thread. No credentials, private source, customer data, or live
third-party targets — synthetic examples only.**

Read first:
https://github.com/omarmohelal/SecHelix/blob/main/gold-packs/README.md

## What to put in a proposal

**1. The bug class, in one sentence.** Narrow enough that one invariant covers
it.

**2. The invariant.** The single sentence a reviewer checks. The existing packs
are the calibration — for example, the Express/Node pack anchors on: *every
route that needs a guard is registered after that guard on a path the guard
matches, and every value the handler takes from the request is constrained in
both value and shape before it is used.* If you cannot write that sentence, the
pack is not ready.

**3. Where it applies.** For a framework pack, the framework-specific capability
tags that make it self-select — a Django review must not pick up a Next.js pack.
For a bug-class pack, what architecture makes the class possible at all.

**4. The sinks.** The operations that can break the invariant.

**5. False-positive filters.** The schema requires at least two; the existing
packs carry between four and twelve, and the thin ones are the weakest. This is
the part that separates a pack from a lint rule: code that *looks* vulnerable
and is not, because a real control holds. Version-dependent defaults belong here — if a framework changed a
security-relevant default between versions, the pack names the versions rather
than assuming one.

**6. The refutation tests.** What a verifier runs to try to kill a candidate.

**7. Fixtures.** Which existing paired fixtures would catch a regression, or
which new pair you would add.

## Ground rules that are not negotiable

- `lifecycle` starts at `REFERENCE`. Higher states are assigned by maintainer
  review, never self-declared.
- `calibration.measurement_status` stays `NOT_MEASURED` with `sample_size: 0`.
  No pack in this repository claims a precision or recall number, and none may,
  without a reproducible benchmark run that publishes its inputs and outputs.
- `verification.independent_required` is `true` in every pack. A pack cannot
  waive independent verification.
- Non-destructive by default: no destructive actions, no production mutation.

## Currently uncovered ground

Framework packs exist for Next.js, Express/Node, Django, Supabase/PostgREST,
Spring Boot, and Laravel. Rails, FastAPI, Go/Gin, ASP.NET Core, and Flask are
open. Bug-class gaps are worth proposing too — say what the invariant is and why
the existing packs do not already cover it.
````

### Integrations

**Title:** `Report what loaded, what did not, and which adapter is missing`

````markdown
SecHelix is a methodology plus a portable Agent Skill. It does not run itself:
output quality depends on the host, the model, and the tools you enable. So the
two most useful things you can post here are **what actually happened in your
host** and **which scanner output has nowhere to go**.

**Public thread. Do not paste credentials, tokens, private source, customer
data, real internal hostnames, or scanner output containing any of those.**
Scanner reports in particular are full of paths, hostnames, and sometimes
captured secret material — redact before pasting, or paste a hand-written
minimal example instead.

## 1. Host compatibility reports

The compatibility matrix separates what was *tested here* from what a vendor
*documents*, and nothing is upgraded without a recorded run:
https://github.com/omarmohelal/SecHelix/blob/main/docs/reference/compatibility.md

Several rows say `DOCUMENTED` — the vendor documents the discovery path, but
SecHelix has not been observed loading in that host. If you can run one of them,
post:

- host and exact version;
- how you installed (installer command, plugin, or manual copy) and the target
  directory;
- whether the skill was actually loaded, and how you could tell — the command
  you ran and the output you saw, not an impression;
- anything that failed, verbatim.

**A failed load is as valuable as a successful one** and will be recorded as
such. This project would rather publish `UNVERIFIED` than an upgrade it cannot
evidence.

## 2. Missing evidence adapters

Adapters normalize third-party scanner output into evidence records. Every
record comes out as `CANDIDATE` / `UNASSESSED` — an adapter never promotes a
scanner's own severity into an assessment, because a scanner alert is not a
finding.

Current adapters are registered here:
https://github.com/omarmohelal/SecHelix/blob/main/adapters/registry.py

If your scanner is not in that list, post: the tool, the exact output format
(and the flag that produces it), a small **synthetic** sample, and what the
fields mean. Adapters are thin, dependency-free, and standard-library only, so a
well-specified request is close to a finished one.

## 3. CI and pipeline integration

How you wired the release gate, what broke, and what the gate decided. Real
pipeline shapes are useful, including the ones that made SecHelix awkward to
use — especially those.

## What belongs somewhere else

- A bug in SecHelix itself → the bug issue form.
- A vulnerability *in* SecHelix → private reporting:
  https://github.com/omarmohelal/SecHelix/security/advisories/new
- A finding you disagree with → the **False positives** category.
````

## After the categories exist

- Update the issue-template chooser
  ([`.github/ISSUE_TEMPLATE/config.yml`](../../.github/ISSUE_TEMPLATE/config.yml))
  with a `contact_links` entry pointing at the Discussions tab, so people who
  open "New issue" for a question are routed to Q&A instead.
- Link the **False positives** category from
  [`CONTRIBUTING.md`](../../CONTRIBUTING.md), next to the existing false-positive
  issue form, with the distinction the seed post draws: confident report → issue
  form, uncertain → discussion.
- Keep the seed posts pinned. If a category's seed post falls off the top, the
  category stops teaching anyone how to use it.
