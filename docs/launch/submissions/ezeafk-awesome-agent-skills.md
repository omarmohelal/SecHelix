# Submission draft — `Ezeafk/awesome-agent-skills`

> **DRAFT — requires human review before submitting. Do not submit automatically.**

---

## Status: READY_FOR_REVIEW — SecHelix qualifies today

Nothing in this list's policy disqualifies SecHelix. There is **no star minimum**, no published-release
requirement, and no adoption threshold. The bar is a scored rubric about the *substance* of the skill,
and SecHelix clears the stated inclusion threshold on an honest reading.

Two things need a human decision before submitting, both flagged in the checklist:

1. The **Platform** column value — `Codex` support has not been verified and must not be asserted
   without testing (checklist E-4).
2. The **Risk** label — the draft proposes `High`, matching every existing entry in the Security
   Skills section. That is the reviewer's call, not ours (checklist E-6).

The rubric's **Validation** dimension is where SecHelix scores worst, because benchmarks are
`NOT_MEASURED`. The self-assessment in section 4 scores that dimension honestly at 1/2 rather than
inflating it. Do not raise it to get over a threshold.

---

## 1. Policy as read on 2026-09-01

Repository: <https://github.com/Ezeafk/awesome-agent-skills>
Sources read: repo README, `CONTRIBUTING.md`.

### 1a. What the list is

Quoted from the README:

> "This list focuses on reusable capabilities that help AI agents complete real tasks. It is not a
> prompt dump."

### 1b. Must-have inclusion criteria

Quoted from `CONTRIBUTING.md`, a submission must have:

> - "a clear use case"
> - "reusable structure beyond a single prompt"
> - "explains installation, copying, or usage"
> - "states the platform or runtime"
> - "makes inputs and outputs understandable"

Plus safety documentation for sensitive operations. Preferred elements are examples, validation steps,
safety boundaries, and complete workflows rather than isolated instructions.

### 1c. Required table format

Columns, in order: **Skill | Platform | Use case | Includes | Status | Risk**

Quoted format line from `CONTRIBUTING.md`:

> "| [Skill](https://github.com/owner/repo) | Codex, Claude | Repo analysis and PR prep. | Workflow, scripts | Active | Medium |"

Live header in the README's Security Skills section:

```
| Skill | Platform | Use case | Includes | Status | Risk |
|---|---|---|---|---|---|
```

Observed conventions in the live table (follow these over the CONTRIBUTING example, which uses a
placeholder link text):

- Link text is **`owner/repo`**, not a display name.
- The **Use case** cell is a full sentence ending in a full stop.
- The **Includes** cell is a short comma-separated noun list, no terminal full stop.
- Every entry currently in Security Skills carries `Active` / `High`.

### 1d. Existing Security Skills entries, verbatim (for calibration)

```
| [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector) | Claude, Codex, Generic Agent | Scan AI agent skills for malicious patterns, unsafe instructions, and security risks before installation. | Security scanner, CLI, reports, examples | Active | High |
| [trailofbits/skills](https://github.com/trailofbits/skills) | Claude Code | Security research, vulnerability detection, and audit workflows from Trail of Bits. | Skills, audit workflows, examples | Active | High |
| [snyk/agent-scan](https://github.com/snyk/agent-scan) | MCP, Generic Agent, Claude, Codex | Scan AI agents, MCP servers, and agent skills for vulnerabilities and risky tool behavior. | Security scanner, CLI, rules | Active | High |
```

> Note that most existing Security Skills entries are skill *scanners* — they audit skills. SecHelix
> audits **application code**, which is a different job in the same section. If a maintainer pushes
> back on section fit, `Coding` is the fallback, but `Security Skills` is the better read because the
> output is security findings.

### 1e. Scoring rubric

`CONTRIBUTING.md` documents five dimensions, 0–2 points each:

1. **Task clarity** — real-world use case and user needs
2. **Reusable structure** — beyond prompts (files, workflows, templates)
3. **Platform fit** — support for specified agent platforms
4. **Validation** — demos, tests, or verification methods
5. **Maintenance** — activity level, safety defaults, credentials guidance

Inclusion thresholds, quoted: **8–10 points recommended; 6–7 acceptable with notes; below 4 rejected.**

### 1f. PR requirements

Submitters must verify: canonical repository link; not a prompt-only project; minimum score of 6 (or
justification for lower); complete metadata fields; appropriate risk/status labels; passing link
checks.

### 1g. Available sections

Core Skill Registries, Coding, Data Analysis, Documents, Design and Frontend, Browser and Web,
**Security Skills**, DevOps and Cloud, Research, MCP and Tool Integration, Finance Skills, Business
Workflows, Personal Productivity, Use With Care.

**Chosen section: Security Skills.**

---

## 2. Exact table row — ready to paste

Insert into the **Security Skills** table. Match the surrounding rows' position convention (append
unless the table is ordered).

```
| [omarmohelal/SecHelix](https://github.com/omarmohelal/SecHelix) | Claude, Generic Agent | Evidence-first application-security review of repositories you are authorized to test, with independent verification and explicit false-positive refutation before anything is reported. | Skill, hypothesis catalog, JSON contracts, gold check packs, scanner adapters, eval fixtures | Active | High |
```

### Alternate Use case cell, if the maintainer wants the coverage emphasis instead

```
| [omarmohelal/SecHelix](https://github.com/omarmohelal/SecHelix) | Claude, Generic Agent | Review code for business logic, payments, race and idempotency, authorization, and AI/MCP security flaws, requiring regression proof before High or Critical findings. | Skill, hypothesis catalog, JSON contracts, gold check packs, scanner adapters, eval fixtures | Active | High |
```

**Do not** submit both rows. Pick one.

### Cell-by-cell rationale

| Cell | Value | Why |
|---|---|---|
| Skill | `[omarmohelal/SecHelix](...)` | `owner/repo` link text, matching every live row |
| Platform | `Claude, Generic Agent` | Ships an Agent Skills–format `SKILL.md` plus a Claude Code plugin. `Codex` is **omitted deliberately** — untested. See E-4. |
| Use case | one sentence, ends in a full stop | Matches live rows |
| Includes | comma-separated noun list, no full stop | Matches live rows |
| Status | `Active` | Repo is under active development |
| Risk | `High` | Consistent with every existing Security Skills entry; it performs security testing and can run local dynamic checks. Maintainer's call. |

---

## 3. PR title and body

### PR title

```
Add omarmohelal/SecHelix to Security Skills
```

### PR body

```markdown
### Entry

Adding one row to the **Security Skills** table:

| Skill | Platform | Use case | Includes | Status | Risk |
|---|---|---|---|---|---|
| [omarmohelal/SecHelix](https://github.com/omarmohelal/SecHelix) | Claude, Generic Agent | Evidence-first application-security review of repositories you are authorized to test, with independent verification and explicit false-positive refutation before anything is reported. | Skill, hypothesis catalog, JSON contracts, gold check packs, scanner adapters, eval fixtures | Active | High |

### Against the must-have criteria

**Clear use case.** Reviewing application code for security weaknesses in a repository or environment
the operator owns or is explicitly authorized to test, and producing a defensible release decision.

**Reusable structure beyond a single prompt.** The repository ships, as files: 546 structured security
hypotheses (exactly 21 families x 26 verification lenses) in a validated catalog with stable IDs; 17
model-neutral specialist role profiles, including an independent verifier; 15 JSON Schema Draft
2020-12 contracts that reports must validate against; 18 Gold Check Packs; 11 evidence adapters
(Semgrep, Trivy, OSV, Gitleaks, ZAP, Nuclei, Playwright, package audit, SARIF); 38 eval fixtures /
76 cases with a scoring harness; and a provenance-backed knowledge graph of 76 nodes and 100 edges.
The catalog shape is enforced by `scripts/validate_catalog.py` in CI-checkable form.

**Installation and usage.**
- Agent Skills: `npx skills@latest add omarmohelal/SecHelix --skill sechelix`
- Claude marketplace: `/plugin marketplace add omarmohelal/sechelix-marketplace` then
  `/plugin install sechelix@sechelix` (cold-install verified)

**Platform / runtime.** Ships a `SKILL.md` in Agent Skills format plus a Claude Code plugin manifest.
Listed as `Claude, Generic Agent`. I have not tested it on Codex, so I have not claimed Codex.

**Inputs and outputs.** Input is a scope definition (repository, mode, authorization). Output is a
schema-validated report: findings with evidence, refuted candidates recorded as `FALSE_POSITIVE` with
the refutation reason retained, and a release decision. Every check resolves to `APPLICABLE`,
`NOT_APPLICABLE`, `UNKNOWN`, or `BLOCKED` — missing evidence is never silently treated as absence —
and the release gate is fail-closed, returning `PASS`, `PASS_WITH_KNOWN_RISK`, `BLOCKED`, or
`INCOMPLETE`.

**Safety documentation for sensitive operations.** The skill's non-negotiable rules are explicit:
work only on systems owned or explicitly authorized; default to `STATIC` or `LOCAL` mode and never
turn a code-review request into uncontrolled internet scanning; no destructive payloads, credential
theft, persistence, denial-of-service, malware, or data exfiltration as verification methods; in
production prefer read-only evidence, and any test that could mutate money, identity, inventory,
authorization, external providers, or customer data requires explicit authorization or moves to
local/staging fixtures. This release also adds an `UNTRUSTED_REPO` zero-trust mode in which
repository content is treated as data and never as control instructions, plus differential security
review.

### Why the High risk label

Consistent with the other Security Skills entries. It performs security review and can run bounded
local dynamic verification, so it warrants the same caution label as its neighbours. Happy to take a
different label if you read it differently.

### Self-assessment against the rubric

Scored honestly, including where it is weak. Your scoring governs, not mine.

| Dimension | Self-score | Reasoning |
|---|---|---|
| Task clarity | 2 | Specific, real, bounded: authorized AppSec review with an explicit release decision. |
| Reusable structure | 2 | Catalog, schemas, role profiles, gold packs, adapters, and fixtures are files, not prose. |
| Platform fit | 2 | Agent Skills `SKILL.md` plus a Claude Code plugin; cold-install verified from the marketplace. |
| Validation | 1 | Fixtures, a scoring harness, gold packs, and one published case study exist — but **benchmarks are NOT_MEASURED**, so I am not claiming a validated detection rate. Scoring this 2 would be dishonest. |
| Maintenance | 2 | Actively developed, safety defaults are fail-closed, and authorization guidance is explicit. Caveat: alpha software. |
| **Total** | **9** | Offered as a starting point for your review, not a claim on your rubric. |

### Disclosure and honest status

- I am the author of this project. This is a self-submission.
- **Benchmarks are NOT_MEASURED.** The blocker is documented in the repository rather than hidden:
  the eval fixture suite was authored by the same assistant session that would have acted as the
  evaluated model, so scoring it would measure recall of authored answers rather than security-review
  capability. Unblocking requires a run by a model or session that did not author the fixtures, on
  blind exported cases. The entry makes no accuracy, precision, recall, or detection-rate claim, and
  no comparison to any other tool.
- There is one published case study: an authorized owner self-audit in which one MEDIUM finding was
  verified, fixed, and regression-proved, and one plausible high-severity candidate was **REFUTED**.
  It is a worked example of the process, not a performance claim.
- Alpha software; contracts and interfaces can still change. If the list prefers stable-only entries,
  I am happy to withdraw and resubmit later.
- Apache-2.0, canonical repository link above.

### PR checklist

- [ ] Canonical repository link
- [ ] Not a prompt-only project
- [ ] Self-assessed score >= 6
- [ ] Complete metadata fields
- [ ] Risk and Status labels set
- [ ] Link check passes
```

---

## 4. Pre-submission checklist — the maintainer must verify each

### Format

- [ ] **E-1.** Row has exactly **six** cells in order: Skill, Platform, Use case, Includes, Status, Risk.
- [ ] **E-2.** Link text is `owner/repo`, matching the live rows (not the placeholder style in
      `CONTRIBUTING.md`).
- [ ] **E-3.** Row inserted into the **Security Skills** table, and the table still renders. Confirm
      no stray pipe characters in any cell.

### Claims that must be verified, not assumed

- [ ] **E-4.** **Do not add `Codex` to the Platform cell unless it has actually been tested on Codex.**
      The draft omits it deliberately. If tested and working, add it; otherwise leave as
      `Claude, Generic Agent`.
- [ ] **E-5.** Verify `Generic Agent` is a fair claim — i.e. the `SKILL.md` really is host-neutral and
      does not depend on Claude-only affordances. If it does, reduce to `Claude`.
- [ ] **E-6.** Confirm `High` is the right Risk label with the maintainer if they comment. It is
      consistent with peers but it is their taxonomy.
- [ ] **E-7.** Confirm both install commands work from a clean machine before claiming
      "cold-install verified" in the PR body.

### Content accuracy

- [ ] **E-8.** Every number in the PR body matches the tree at submission time: 546 hypotheses, 21
      families, 26 lenses, 17 roles, 15 contracts, 11 adapters, 18 Gold Check Packs, 38 fixtures /
      76 cases, 76 nodes / 100 edges. Re-run `python scripts/validate_catalog.py`.
- [ ] **E-9.** No adoption, star, install, user, testimonial, benchmark, accuracy, or "better than X"
      claim anywhere in the row or the PR body.
- [ ] **E-10.** The Validation self-score stays at **1**. Do not raise it. `NOT_MEASURED` is stated
      plainly and not softened.
- [ ] **E-11.** The self-assessment is framed as a starting point, not as an assertion of the
      reviewer's score.

### Process

- [ ] **E-12.** Authorship self-disclosed in the PR body.
- [ ] **E-13.** Checked open and closed PRs and the README for an existing SecHelix entry.
- [ ] **E-14.** Confirm the list is still actively merging before opening.
- [ ] **E-15.** Confirm the section list and rubric have not changed since 2026-09-01 — re-read
      `CONTRIBUTING.md` at submission time.
