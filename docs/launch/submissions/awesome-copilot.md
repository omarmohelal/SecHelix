# Submission draft — `github/awesome-copilot`

> **DRAFT — requires human review before submitting. Do not submit automatically.**

---

## Status: BLOCKED TODAY — two prerequisites are unmet

Read the whole of section 1 before doing anything. SecHelix is **not disqualified in principle** — the
list does accept Claude-oriented, externally-hosted plugins — but two of the submission form's
**required** fields cannot be answered truthfully today:

1. **No published release.** `git tag` in the SecHelix repo returns **zero tags**. The submission
   form asks for an immutable **ref** (release tag) or **commit SHA**. A raw SHA is technically
   accepted, but the reviewed artefact would then be an untagged mid-branch commit on
   `v3.2/trust-discovery`, which is not a thing a marketplace should be pinning users to.
2. **Version string is inconsistent with the working branch.** `.claude-plugin/plugin.json` declares
   `"version": "3.0.0-alpha.5"`, while the current branch is `v3.2/trust-discovery` and carries the
   new `UNTRUSTED_REPO` work. The form requires a single **Version** value. Submitting `3.0.0-alpha.5`
   would point reviewers at a manifest that does not describe the submitted tree.

**What would qualify it later:** cut and push a real git tag (e.g. `v3.2.0`), reconcile
`.claude-plugin/plugin.json` `version` with that tag, and confirm the Copilot plugin loader can read
the repo at that ref (see checklist item C-4 — SecHelix ships `.claude-plugin/plugin.json`, which is
the Claude Code convention, and that layout has **not** been verified against Copilot's loader).

There is no star minimum, no adoption requirement, and no "must be a Copilot-specific extension"
rule. Once a tagged release exists, this becomes submittable.

---

## 1. Policy as read on 2026-09-01

Repository: <https://github.com/github/awesome-copilot>
Sources read: repo README, `CONTRIBUTING.md`, `.github/ISSUE_TEMPLATE/external-plugin.yml`,
`plugins/external.json`.

### 1a. Accepted item types

`CONTRIBUTING.md` lists seven categories: Instructions, Agents, **Skills**, Canvas Extensions,
**Plugins**, Hooks, Agentic Workflows. Two of these are plausible routes for SecHelix.

### 1b. Route A — contribute a Skill *into* this repo (in-repo copy)

| Type | Directory | Filename | Required frontmatter |
|---|---|---|---|
| Skills | `skills/{name}/` | `SKILL.md` | `name`, `description` |

Quoted from `CONTRIBUTING.md`:

> "Self-contained folders in the `skills/` directory that include a `SKILL.md` file (with front
> matter) and optional bundled assets."

> "Ensure the `name` matches the folder name (lowercase with hyphens) and the `description` is clear
> and non-empty"

> "Run `npm run skill:validate` and then `npm run build` to update the generated README tables"

PR process, quoted:

> "Target **`main` branch only** (not `staged`)"

> "AI agents should append `🤖🤖🤖` to PR title for expedited review"

**Route A is not recommended.** It vendors a *copy* of SecHelix's `SKILL.md` into a third-party repo,
where it would drift from the canonical `skills/sechelix/SKILL.md`. The SecHelix repo invariant in
`CLAUDE.md` is that `skills/sechelix/SKILL.md` is canonical. A stale security skill is worse than no
listing. Route B keeps a single source of truth.

### 1c. Route B — external plugin submission (recommended once unblocked)

Quoted from `CONTRIBUTING.md`:

> "Public external plugin submissions are GitHub-only in v1. The submitted plugin must live in a
> public GitHub repository and use `source.source: \"github\"`."

> "Public contributors should **not** open a PR that edits `plugins/external.json` directly."

Quoted from `.github/ISSUE_TEMPLATE/external-plugin.yml`:

> "Public submissions are **GitHub-only** in v1.
> The plugin must live in a **public GitHub repository**.
> Provide an immutable **ref**, **sha**, or both for review.
> If your plugin includes a canvas extension, include the **canvas** keyword.
> Canvas plugins are validated for `logo: \"assets/preview.png\"` using the submitted immutable **sha** or **ref**.
> Do **not** open a PR that edits `plugins/external.json` directly."

Required form fields (`validations: required: true`): Plugin name, Short description, GitHub
repository, Version, License identifier, Author name, Keywords.
Optional: Plugin path, Ref to review, Commit SHA to review, Author URL, Homepage URL, Additional
notes.

Issue title prefix is auto-filled: `[External Plugin]: `. Labels applied: `external-plugin`,
`awaiting-review`.

### 1d. Rejection criteria

`CONTRIBUTING.md` states the repo rejects contributions that:

> - Circumvent Responsible AI guidelines
> - Compromise security or bypass policies
> - Enable malicious activities
> - Duplicate frontier model capabilities without meaningful uplift
> - Include unreviewed third-party plugins in direct PRs

The fourth bullet is the one to be ready to answer on. See the "Additional notes" text below.

### 1e. Precedent that Claude-oriented plugins are in scope

`plugins/external.json` already contains entries whose `keywords` include `claude-code` and `mcp`
(e.g. `agent-council`, `repository: https://github.com/Avyayalaya/agent-council`,
`source: {"source": "github", "repo": "Avyayalaya/agent-council", "ref": "v0.1.3"}`). Note that this
precedent entry pins a **release tag**, not a bare SHA.

---

## 2. Submission is an ISSUE, not a PR

Open: <https://github.com/github/awesome-copilot/issues/new?template=external-plugin.yml>

**Do not open a pull request.** Editing `plugins/external.json` by PR is explicitly forbidden.

### Issue title

```
[External Plugin]: sechelix
```

### Form field values — ready to paste

**Plugin name**
```
sechelix
```

**Short description**
```
Evidence-first application-security review skill for repositories and environments you are authorized to test. Maps trust boundaries, selects applicable checks, independently verifies candidate findings and refutes false positives, and requires regression proof before reporting High or Critical issues.
```

**GitHub repository**
```
omarmohelal/SecHelix
```

**Plugin path inside the repository**
```
(leave blank — the plugin manifest is at the repository root under .claude-plugin/)
```
> Verify this against checklist item C-4 before submitting. If Copilot's loader requires the manifest
> at a different path, enter that path here instead.

**Ref to review**
```
<FILL IN — a pushed git tag, e.g. v3.2.0. BLOCKED: the repo currently has zero tags.>
```

**Commit SHA to review**
```
<FILL IN — full 40-char SHA of the tagged commit. HEAD at time of drafting was
8991d595388192503473a73c424c705e6cc5e5e6, which is an untagged commit on v3.2/trust-discovery
and should NOT be submitted as-is.>
```

**Version**
```
<FILL IN — must match the tag and .claude-plugin/plugin.json. Currently inconsistent: the manifest
says 3.0.0-alpha.5 while the branch is v3.2/trust-discovery.>
```

**License identifier**
```
Apache-2.0
```

**Author name**
```
SecHelix
```

**Author URL**
```
https://sechelix.com
```

**Homepage URL**
```
https://sechelix.com
```

**Keywords**
```
appsec
security-audit
security-review
agent-skills
authorization
business-logic
ai-security
mcp-security
verification
claude-code
```
> Do **not** include the `canvas` keyword — SecHelix ships no canvas extension, and including it would
> trigger a `logo: "assets/preview.png"` validation that would fail.

**Additional notes**
```
Disclosure: I am the author of this project.

What it is: an Apache-2.0 Agent Skill and methodology for application-security review of systems the
operator owns or is explicitly authorized to test. It is not a scanner and not a scanner wrapper; it
consumes scanner evidence through 11 adapters (Semgrep, Trivy, OSV, Gitleaks, ZAP, Nuclei, Playwright,
package audit, SARIF) and treats every scanner alert or model suspicion as a hypothesis until
evidence supports it.

On "meaningful uplift" over base model capability, since that is a stated rejection criterion: the
uplift claimed is structural, not stylistic. The repo ships a validated catalog of 546 security
hypotheses (exactly 21 families x 26 verification lenses), 17 model-neutral specialist role profiles
including an independent verifier, 22 JSON Schema Draft 2020-12 contracts that reports must validate
against, 18 Gold Check Packs, 38 eval fixtures (76 cases), and a provenance-backed knowledge graph of
76 nodes and 100 edges. Applicability resolves to APPLICABLE / NOT_APPLICABLE / UNKNOWN / BLOCKED, so
missing evidence is never silently treated as absence, and the release gate is fail-closed, returning
PASS / PASS_WITH_KNOWN_RISK / BLOCKED / INCOMPLETE. High and Critical findings require regression
proof before they are reported.

Coverage emphasis is on classes that pattern-matching handles poorly: business logic, payments and
money invariants, race conditions and idempotency, authorization (BOLA/IDOR/BFLA), and AI/agent/MCP
security. This release adds an UNTRUSTED_REPO zero-trust mode, in which repository content is treated
as data and never as control, plus differential security review.

Safety posture: the skill defaults to STATIC or LOCAL mode, forbids destructive payloads, credential
theft, persistence, denial-of-service and data exfiltration as verification methods, and requires
explicit authorization before any test that could mutate money, identity, inventory, authorization,
external providers, or customer data.

Benchmarks are NOT_MEASURED. The blocker is documented in the repository rather than hidden: the
eval fixture suite was authored by the same assistant session that would have acted as the evaluated
model, so scoring it would measure recall of authored answers rather than capability. Unblocking
requires a run by a model or session that did not author the fixtures, on blind exported cases. I
make no accuracy, precision, recall, or detection-rate claim, and no comparison to any other tool.

There is one published case study: an authorized owner self-audit in which one MEDIUM finding was
verified, fixed and regression-proved, and one plausible high-severity candidate was REFUTED. It is a
worked example of the process, not a performance claim.

Install (Agent Skills): npx skills@latest add omarmohelal/SecHelix --skill sechelix
Install (Claude marketplace): /plugin marketplace add omarmohelal/sechelix-marketplace then
/plugin install sechelix@sechelix (cold-install verified).
```

---

## 3. If Route A is chosen instead (in-repo Skill) — PR title and body

Only use this if a maintainer explicitly asks for an in-repo skill rather than an external plugin
listing, and only after accepting the drift risk in section 1b.

### PR title

```
Add sechelix skill (evidence-first AppSec review)
```

> If a coding agent opens the PR rather than a human, `CONTRIBUTING.md` asks that `🤖🤖🤖` be appended
> to the title. A human submitting by hand should **not** append it.

### PR body

```markdown
### What

Adds `skills/sechelix/SKILL.md` — an evidence-first application-security review skill for
repositories and environments the operator is authorized to test.

### Why it fits

Security review is a task where a confident wrong answer is expensive. This skill encodes an evidence
standard rather than a prompt style: a scanner alert is a hypothesis, a model suspicion is a
hypothesis, and two models agreeing is not independent proof. Candidates go to an independent
verifier whose job is to refute them, missing evidence maps to UNKNOWN or BLOCKED rather than
NOT_APPLICABLE, and High/Critical findings require regression proof before they are reported.

Canonical source: https://github.com/omarmohelal/SecHelix (Apache-2.0)

### Disclosure and honest status

- I am the author of this project.
- **Benchmarks are NOT_MEASURED**, with the blocker documented in the repository. No accuracy,
  precision, recall, detection-rate, or comparison claim is made anywhere in this contribution.
- One published case study exists: one verified MEDIUM finding, one REFUTED high-severity candidate.
  It is a worked example, not a performance claim.

### Validation

- [ ] `npm run skill:validate` passes
- [ ] `npm run build` run, generated README tables committed
- [ ] Branch created from `main`, targeting `main` (not `staged`)
```

---

## 4. Pre-submission checklist — the maintainer must verify each

### Blocking prerequisites

- [ ] **C-1.** A git tag exists and is pushed (repo currently has **zero** tags). Record the exact tag.
- [ ] **C-2.** `.claude-plugin/plugin.json` `"version"` matches that tag. It currently reads
      `3.0.0-alpha.5` on branch `v3.2/trust-discovery` — reconcile before submitting.
- [ ] **C-3.** The tagged commit is on a branch that is merged/public, not a mid-flight feature branch.
- [ ] **C-4.** Confirm Copilot's plugin loader can read SecHelix at that ref. SecHelix ships
      `.claude-plugin/plugin.json` (Claude Code convention). This has **not** been verified against
      awesome-copilot's `npm run plugin:validate` or the Copilot plugin spec. If it is incompatible,
      either add a Copilot-compatible manifest at the submitted `plugin_path` or withdraw the
      submission — do not submit and hope.

### Content accuracy

- [ ] **C-5.** Every number in the submission matches the tagged tree: 546 hypotheses, 21 families,
      26 lenses, 17 roles, 16 JSON contracts, 11 adapters, 18 Gold Check Packs, 38 fixtures / 76 cases,
      knowledge graph 76 nodes / 100 edges. Re-run `python scripts/validate_catalog.py` at the tag.
- [ ] **C-6.** The `UNTRUSTED_REPO` mode and differential security review are present and documented
      at the tagged ref (`docs/reference/untrusted-repo-mode.md` exists on the current branch).
- [ ] **C-7.** Both install commands work from a clean machine at the tagged ref.
- [ ] **C-8.** The description contains **no** adoption, star, install, user, testimonial, benchmark,
      accuracy, or "better than X" claim. Re-read it once specifically looking for this.
- [ ] **C-9.** `NOT_MEASURED` appears in the Additional notes and is not softened.

### Process

- [ ] **C-10.** Submitted as an **issue** using the `external-plugin.yml` template. **No PR** editing
      `plugins/external.json`.
- [ ] **C-11.** The `canvas` keyword is **absent**.
- [ ] **C-12.** Authorship self-disclosed in Additional notes.
- [ ] **C-13.** Searched open and closed issues for a prior SecHelix submission to avoid a duplicate.
- [ ] **C-14.** The repo is public and the `LICENSE` file is present and Apache-2.0.
- [ ] **C-15.** Ready to answer the "duplicates frontier model capability" question in the thread
      without overstating — the honest answer is the schemas, catalog, fail-closed gate and regression
      requirement, not the wording.
