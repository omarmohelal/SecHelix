# Targeted submission drafts

> **DRAFT — requires human review before submitting. Do not submit automatically.**

Per-destination submission drafts for specific lists, registries, and marketplaces. Each file records
the destination's contribution policy **as read on 2026-09-01**, quotes the parts that bind us, and
provides paste-ready entry text in that destination's required format.

These are distinct from the general-purpose launch copy in `docs/launch/` (`show-hn.md`, `reddit.md`,
`x-thread.md`, `linkedin.md`, `technical-article.md`, `awesome-list-submission.md`). That material is
generic; this directory is destination-specific and follows each destination's own template.

**No PR or issue has been opened for any destination below.**

---

## Index

| Destination | Status | One-line reason |
|---|---|---|
| [`github/awesome-copilot`](./awesome-copilot.md) | **BLOCKED** | Submittable in principle, but the external-plugin form requires an immutable ref/version and the repo has **zero git tags** plus a manifest version (`3.0.0-alpha.5`) inconsistent with the `v3.2` branch. |
| [`claude-market/marketplace`](./claude-market-marketplace.md) | **READY_FOR_REVIEW** | Repo confirmed to exist and nothing disqualifies SecHelix, but it vendors the whole plugin into its monorepo (drift risk) and its last push was 2025-11-04 — two human decisions first. |
| [`royalpinto007/awesome-agent-skills`](./royalpinto007-awesome-agent-skills.md) | **READY_FOR_REVIEW** | Qualifies today; JSON entry for `data/tools.json` under `category: "security"` is drafted and ready to paste. |
| [`Ezeafk/awesome-agent-skills`](./ezeafk-awesome-agent-skills.md) | **READY_FOR_REVIEW** | Qualifies today; table row for the Security Skills section is drafted, with an honest rubric self-assessment (9/10, Validation scored 1 because benchmarks are `NOT_MEASURED`). |
| [`patrickclery/awesomer`](./patrickclery-awesomer.md) | **NOT_APPLICABLE** | Not a curated list — an automated star-growth aggregator of other lists, with no `CONTRIBUTING.md`, no issue/PR template, and machine-generated content. Nothing to submit. |

---

## Rules that apply to every draft in this directory

These are non-negotiable and were applied throughout. Re-verify them before any submission.

**Never claim:** adoption numbers, star counts, install counts, user counts, testimonials, "better
than X" comparisons, or benchmark results of any kind (accuracy, precision, recall, detection rate).

**Benchmarks are `NOT_MEASURED`,** and every draft says so explicitly. The blocker is documented in
the repository rather than hidden: the eval fixture suite was authored by the same assistant session
that would have acted as the evaluated model, so scoring it would measure recall of authored answers
rather than security-review capability. Unblocking requires a run by a model or session that did not
author the fixtures, on blind exported cases.

**If a destination's template asks for a metric SecHelix does not have,** write `NOT_MEASURED` or
leave it blank with a note. Never estimate. Only one destination's forms touch this
(`royalpinto007`'s generator auto-renders a star count from the `repo` field — that is the list's own
automation and must never be quoted back as a SecHelix claim; see checklist item R-6).

**Self-disclose authorship** in every PR body or submission note.

---

## Facts used across the drafts, verified against the working tree

Verified on 2026-09-01 on branch `v3.2/trust-discovery`. Re-verify at submission time — every draft's
checklist includes this step, and `python scripts/validate_catalog.py` is the structural check.

| Fact | Value | Where verified |
|---|---|---|
| Licence | Apache-2.0 | `LICENSE`, `SKILL.md` frontmatter |
| Hypotheses | 546 (21 families x 26 lenses) | `catalog/checks.json`, invariant in `CLAUDE.md` |
| Specialist roles | 17 | `agents/` |
| JSON contracts | 15 | `schemas/*.json` |
| Evidence adapters | 9 — Semgrep, Trivy, OSV, Gitleaks, ZAP, Nuclei, Playwright, package audit, SARIF | `adapters/` |
| Gold Check Packs | 12 | `gold-packs/` |
| Eval fixtures | 33 (66 cases) | `evals/fixtures/` |
| Knowledge graph | 73 nodes / 96 edges | repo docs |
| `UNTRUSTED_REPO` mode | present | `docs/reference/untrusted-repo-mode.md`, `schemas/scope-v1.schema.json` |
| Install (skills) | `npx skills@latest add omarmohelal/SecHelix --skill sechelix` | `README.md` |
| Install (marketplace) | `/plugin marketplace add omarmohelal/sechelix-marketplace` then `/plugin install sechelix@sechelix` | cold-install verified |
| Case study | one verified MEDIUM finding, one REFUTED high-severity candidate | `docs/case-studies/` |
| Benchmarks | **NOT_MEASURED** | documented blocker |

### Two inconsistencies to resolve before any submission

Both are called out in the individual drafts, and both affect more than one destination:

1. **No git tag exists.** `git tag` returns zero results. This hard-blocks `github/awesome-copilot`,
   whose form asks for an immutable ref or SHA, and it weakens every other submission that quotes a
   version.
2. **Manifest version is stale.** `.claude-plugin/plugin.json` declares `"version": "3.0.0-alpha.5"`
   while the working branch is `v3.2/trust-discovery` carrying the `UNTRUSTED_REPO` work. Any
   destination asking for a version string needs these reconciled first.

### Correction to an earlier draft

`docs/launch/awesome-list-submission.md` describes the adapters as covering "multiple hosts". That is
wrong and is not repeated here: the 9 adapters are **scanner/evidence adapters**, not host adapters.
That file also carries pre-`v3.2` counts (5 Gold Check Packs, 19 fixtures / 38 cases); the table above
reflects the current tree.

---

## Destinations researched but not assigned

Recorded so nobody duplicates the research. No drafts were written for these.

- **`anthropics/claude-plugins-community`** and **`anthropics/claude-plugins-official`** — Anthropic's
  own plugin directories. The community repo's README states it is *"A read-only mirror"* and that
  *"Pull requests opened directly against this repo are closed automatically."* Submission is via the
  web form at <https://clau.de/plugin-directory-submission>. The form's own fields were **not** read,
  so a human must check them before reusing any copy from these drafts. Detail is in
  [`claude-market-marketplace.md`](./claude-market-marketplace.md) section 6.
- **Upstream lists tracked by awesomer** — `VoltAgent/awesome-agent-skills`,
  `ComposioHQ/awesome-claude-skills`, `awesome-claude-code`. These are the only indirect route to
  awesomer coverage. Their contribution policies were **not** reviewed. Detail is in
  [`patrickclery-awesomer.md`](./patrickclery-awesomer.md) section 2.
