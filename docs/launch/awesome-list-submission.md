# Awesome-list submission draft

> **DRAFT — requires human review before publishing. Do not post automatically.**

---

## 1. The entry line

Primary (20-word description, well under the ~25-word cap):

```markdown
- [SecHelix](https://github.com/omarmohelal/SecHelix) - Evidence-first AppSec agent skill: maps attack surface, selects applicable checks from 546 hypotheses, and independently verifies candidates before reporting them.
```

Alternates, in case a list's style guide requires a different separator, a shorter description, or
forbids numbers:

```markdown
- [SecHelix](https://github.com/omarmohelal/SecHelix) — Evidence-first application security skill for coding agents; an independent verifier tries to refute candidates before they become findings. (18 words)
```

```markdown
- [SecHelix](https://github.com/omarmohelal/SecHelix) - Open-source AppSec methodology and agent skill that requires attacker control, reachability, safe reproduction, and regression proof before a finding is reported. (21 words)
```

**Style notes for whoever submits.** Most awesome lists mandate: a hyphen bullet, the link first, a
separator (` - ` in the original awesome style, an em dash in some forks), a capitalised description,
and a full stop at the end. Match the surrounding entries in the target file rather than this draft.
Some lists require alphabetical ordering within the section — insert accordingly, do not append.

**The entry must not claim benchmarks.** No accuracy, precision, recall, detection-rate, or
"outperforms" language. No star counts, download counts, or adoption claims. No competitor
comparisons. The description above deliberately describes *what the process requires*, not *how well
it does it*.

---

## 2. PR description

Title:

```
Add SecHelix (evidence-first AppSec agent skill)
```

Body:

```markdown
### What

Adds SecHelix to the <SECTION NAME> section.

`- [SecHelix](https://github.com/omarmohelal/SecHelix) - Evidence-first AppSec agent skill: maps attack surface, selects applicable checks from 546 hypotheses, and independently verifies candidates before reporting them.`

### Why it fits this list

SecHelix is an open-source (Apache-2.0) application-security methodology and portable Agent Skill for
repositories and environments you are authorized to test. It is not a scanner wrapper. The design
premise is that a security finding is a claim, and a claim gets an independent refutation attempt
before it is reported.

Structurally it ships: 546 structured security hypotheses (21 families x 26 verification lenses), 17
model-neutral specialist role profiles including an independent verifier, 22 JSON Schema Draft
2020-12 contracts, 18 Gold Check Packs, 11 read-only evidence adapters, 38 paired eval fixtures
(76 cases across 10 families), and a
knowledge graph of 76 nodes, 100 edges, and 11 lesson cards. Applicability resolves to APPLICABLE,
NOT_APPLICABLE, UNKNOWN, or BLOCKED — missing evidence is never treated as absence — and the release
gate returns PASS, PASS_WITH_KNOWN_RISK, BLOCKED, or a fail-closed INCOMPLETE.

Install: `npx skills@latest add omarmohelal/SecHelix --skill sechelix`

### Disclosure and honest status

- I am the author of this project.
- **The full-workflow benchmark is NOT_MEASURED.** One blind label-suite run is measured and is not a workflow benchmark. The remaining blocker is documented in the repository: the eval fixture
  suite was expanded on 2026-09-01 by the same assistant session that would have acted as the
  evaluated model, so it had prior knowledge of the fixtures it authored. Scoring that would measure
  recall of authored answers, not capability. Unblocking requires a run by a model/session that did
  not author the fixtures, on blind exported cases. The entry makes no performance claim.
- The repository contains a keyword baseline (`evals/results/baseline-keyword-v1.json`) that is
  explicitly flagged `is_sechelix_result: false`. It is a naive regex matcher used to validate the
  scoring harness and to show the fixtures resist pattern matching (chance-level results on a
  balanced split). It is not a SecHelix score.
- There is one published case study: an authorized owner self-audit of a private ~600 LOC Next.js
  app. One MEDIUM finding verified and fixed, two candidates refuted (including a plausible-looking
  high-severity XSS that did not survive verification). It is a worked example, not a performance
  claim.
- The trophy case is currently empty on purpose; it only accepts public, attributable results.
- Release 3.4.0-alpha.1 — alpha software.

### Checklist

- [ ] Entry placed in the correct section, in the correct order (alphabetical if the list requires it)
- [ ] Description matches the list's style guide (separator, capitalisation, terminal full stop, length cap)
- [ ] Link is HTTPS and resolves
- [ ] No benchmark, accuracy, adoption, or comparison claims in the entry
- [ ] `awesome-lint` / the list's own CI passes locally, if it has one
- [ ] Self-promotion disclosed in the PR body
- [ ] One entry per PR, if the list requires that
```

---

## 3. Candidate lists — a human must verify each one before submitting

For every list below, a human must read `CONTRIBUTING.md` **and** the list's own README preamble
before opening anything. Several of these lists reject self-submissions outright, require a minimum
project age or star count, or restrict entries to a narrow category. Do not batch-submit. Do not
submit to a list where the fit is arguable.

### AppSec / security lists

- [ ] `sindresorhus/awesome` — the root list. Almost certainly out of scope for an individual tool; it
      indexes lists, not projects. Check before spending effort.
- [ ] `sbilly/awesome-security` — broad security list. Verify there is a fitting section (SAST, code
      review, methodology) and that it is still maintained.
- [ ] `paragonie/awesome-appsec` — application-security resources. Historically leans toward reading
      material and standards; verify whether tooling entries are accepted.
- [ ] `analyst1/awesome-application-security` (and similar forks) — verify maintenance status and
      section fit.
- [ ] `Hack-with-Github/Awesome-Hacking` — verify scope; this leans offensive tooling, which may make
      an evidence-first review framework a poor fit.
- [ ] `TheHive-Project` / DevSecOps-oriented lists (e.g. `devsecops/awesome-devsecops`) — verify
      whether a methodology + agent skill qualifies, or whether entries must be CI-runnable tools.
- [ ] Any `awesome-sast` / `awesome-static-analysis` list — **check carefully.** SecHelix is not a
      static analyzer; it consumes scanner evidence. Submitting it as a SAST tool would be a
      mischaracterisation.

### Claude / agent-skill / AI-tooling lists

- [ ] `hesreallyhim/awesome-claude-code` — verify current scope (commands, hooks, skills, plugins) and
      whether Agent Skills have their own section.
- [ ] Any `awesome-claude-skills` / `awesome-agent-skills` list — likely the strongest fit, since
      SecHelix ships a portable Agent Skills bundle plus a Claude Code plugin and marketplace entry.
- [ ] `punkpeye/awesome-mcp-servers` and similar MCP lists — **probably out of scope.** SecHelix is a
      skill, not an MCP server. Do not submit unless the list explicitly covers skills.
- [ ] `e2b-dev/awesome-ai-agents` or comparable agent directories — verify whether a methodology/skill
      qualifies versus a standalone agent product.
- [ ] Any `awesome-ai-security` / `awesome-llm-security` list — verify the section: SecHelix includes
      an AI/Agent/MCP hypothesis family, but the project is general AppSec, not an LLM-security
      research collection.

### Per-list pre-submission checks (repeat for each)

- [ ] Read `CONTRIBUTING.md` in full; follow its exact entry format
- [ ] Confirm the list accepts self-submissions from authors
- [ ] Confirm there is no minimum stars / age / "must be widely used" requirement that this project
      fails — if there is, do not submit and revisit later
- [ ] Confirm the list is actively maintained (recent merged PRs), not archived
- [ ] Confirm the chosen section genuinely describes the project; a forced fit gets closed and burns
      goodwill
- [ ] Confirm the entry contains **no benchmark or adoption claims**
- [ ] Check open PRs for a duplicate or already-rejected submission

---

## What this does not do yet

Whoever submits should be ready to answer these in a PR thread, and should not overstate anything to
get an entry merged.

- **Benchmarks are NOT_MEASURED.** The documented blocker is `CONTAMINATED_EVALUATOR`: the fixture
  suite was expanded on 2026-09-01 by the same assistant session that would have acted as the
  evaluated model, giving it prior knowledge of the fixtures it authored. Scoring it would measure recall
  of authored answers, not security-review capability. Unblocking requires a run by a model/session
  that did not author the fixtures, using blind exported cases.
- The repository's keyword baseline is **explicitly not a SecHelix score**
  (`is_sechelix_result: false`). It is a naive regex matcher that scored precision 0.511 / recall 0.632
  on a balanced 38/38 split — chance level — proving the harness works and the fixtures resist
  pattern matching. That is a **fixture-difficulty** statement, not a performance claim, and it must
  never appear in the entry line.
- The single case study is **one** small ~600 LOC app with no authentication and no server-side state.
  It measures nothing about general performance.
- The verified finding in that case study was **MEDIUM**, not a dramatic critical; the
  plausible-looking high-severity candidate was refuted.
- **No public third-party trophy-case entries exist yet.** The trophy case requires a public project
  and a public advisory, issue, or fix reference, and is empty on purpose.
- The case-study target repository is **private**, so the run is not independently reproducible by a
  reader, and it is neither peer-reviewed nor externally validated.
- Release 3.0.0-alpha.4 — **alpha** software. Some lists exclude pre-1.0 projects; check.
