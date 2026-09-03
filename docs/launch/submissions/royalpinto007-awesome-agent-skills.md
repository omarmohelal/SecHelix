# Submission draft — `royalpinto007/awesome-agent-skills`

> **DRAFT — requires human review before submitting. Do not submit automatically.**

---

## Status: READY_FOR_REVIEW — SecHelix qualifies today

Nothing in this list's policy disqualifies SecHelix. There is **no star minimum**, no published-release
requirement, no adoption threshold, and no metric field. The stated bar is open-source, honest,
correctly categorised, and not a dead link — all of which SecHelix meets today.

One thing the submitter must be aware of, because it is easy to miss: **the list's generator
automatically renders a star count** next to every entry that carries a `repo` field. That number is
produced by the list's own tooling, not asserted by us. It is not a claim we are making, and we must
not reference it anywhere. See checklist R-6.

---

## 1. Policy as read on 2026-09-01

Repository: <https://github.com/royalpinto007/awesome-agent-skills>
Sources read: repo README, `CONTRIBUTING.md`, `data/tools.json`.

### 1a. What the list is

Quoted from the README:

> "A small, verified, security-aware list of Agent Skills ... curated for trust, not a 1,400-skill
> dump."

> "volume is not trust"

The list is CC0 1.0, auto-refreshed weekly, and prioritises entries from known, verifiable sources
over quantity. This is a curation posture SecHelix's own framing is compatible with — but it also
means an inflated description will stand out badly. Keep the entry plain.

### 1b. How to submit — do NOT edit the README

Quoted from `CONTRIBUTING.md`:

> "Edit `data/tools.json`, run `node scripts/generate.mjs`, open a PR."

The README's list section is **auto-generated** from `data/tools.json`; direct README edits are
overwritten by the build.

### 1c. Required entry shape

Quoted from `CONTRIBUTING.md`:

> ```json
> {
>   "name": "Name",
>   "repo": "owner/repo",
>   "url": "https://github.com/owner/repo",
>   "category": "<a valid category>",
>   "desc": "One honest sentence: what it does and who it is for."
> }
> ```

The `repo` field is what enables automatic star-count population for GitHub projects.

`data/tools.json` is a **top-level JSON array** of these objects (no wrapper object). Observed field
set per entry: `name`, `url`, `category`, `desc`, and optional `repo`.

### 1d. Inclusion criteria

Quoted from `CONTRIBUTING.md`:

> "Open-source or genuinely useful. No pure marketing, no paid placements."

> "No dead links. Prefer things you have actually used."

> "One honest sentence per entry. Put it in the right category."

### 1e. Valid category strings

Observed in `data/tools.json`:

`official`, `collections`, `coding`, `docs`, `security`, `authoring`, `market`, `guides`, `related`

**Chosen category: `security`.** SecHelix is a security-review skill, which is the section's subject.
`coding` is the plausible alternative, but the README renders that section as "Coding and review" —
general-purpose coding skills — and putting an AppSec workflow there would be the weaker fit.

### 1f. Existing entries in `security`, verbatim (for tone calibration)

```json
{
  "name": "OWASP Agentic Skills Top 10",
  "url": "https://owasp.org/www-project-agentic-skills-top-10/",
  "category": "security",
  "desc": "OWASP project cataloguing the top security risks specific to agent skills."
}
```

```json
{
  "name": "Snyk: ToxicSkills study",
  "url": "https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/",
  "category": "security",
  "desc": "Research finding prompt injection in 36 percent of tested skills and 1,467 malicious payloads across the skill supply chain."
}
```

> Note the register: flat, factual, one sentence, no adjectives of praise. The draft entry below
> matches it deliberately.

---

## 2. Exact JSON entry — ready to paste into `data/tools.json`

```json
{
  "name": "SecHelix",
  "repo": "omarmohelal/SecHelix",
  "url": "https://github.com/omarmohelal/SecHelix",
  "category": "security",
  "desc": "Evidence-first AppSec review skill that independently verifies candidate findings and refutes false positives before reporting, for developers auditing code they are authorized to test."
}
```

Word count of `desc`: 26 words, one sentence, states what it does and who it is for — the exact shape
`CONTRIBUTING.md` asks for.

### Alternates, if a maintainer asks for a different emphasis

Shorter (18 words):

```json
"desc": "Evidence-first AppSec skill for authorized code review; candidates must survive an independent refutation attempt before becoming findings."
```

Emphasising the fail-closed gate (24 words):

```json
"desc": "Evidence-first AppSec review skill for authorized repositories; requires regression proof before High or Critical findings and fails closed when evidence is missing."
```

Emphasising the zero-trust mode, if the maintainer prefers the security-of-the-skill angle given the
list's curation posture (25 words):

```json
"desc": "Evidence-first AppSec review skill for authorized repositories, with an untrusted-repo mode that treats repository content as data and never as control instructions."
```

**Do not** submit more than one. Pick one with the maintainer's steer.

### Placement

`data/tools.json` is a flat array. Insert the object adjacent to the other `security` entries if the
file is grouped by category; otherwise append. Match the file's existing key ordering and indentation
exactly — run the generator and diff before committing.

---

## 3. PR title and body

### PR title

```
Add SecHelix to security
```

### PR body

````markdown
### What

Adds one entry to `data/tools.json` under `category: "security"`, and regenerates the README.

```json
{
  "name": "SecHelix",
  "repo": "omarmohelal/SecHelix",
  "url": "https://github.com/omarmohelal/SecHelix",
  "category": "security",
  "desc": "Evidence-first AppSec review skill that independently verifies candidate findings and refutes false positives before reporting, for developers auditing code they are authorized to test."
}
```

### Why it fits a list curated for trust

SecHelix is an Apache-2.0 Agent Skill (`SKILL.md` format) for application-security review of systems
the operator owns or is explicitly authorized to test. It is not a scanner and not a scanner wrapper;
it consumes scanner evidence through 12 adapters and treats every scanner alert or model suspicion as
a hypothesis until evidence supports it.

The design premise is that a security finding is a claim, and a claim gets an independent refutation
attempt before it is reported. Concretely: candidates go to an independent verifier whose job is to
disprove them, applicability resolves to `APPLICABLE` / `NOT_APPLICABLE` / `UNKNOWN` / `BLOCKED` so
missing evidence is never silently treated as absence, High and Critical findings require regression
proof, and the release gate is fail-closed — `PASS` / `PASS_WITH_KNOWN_RISK` / `BLOCKED` /
`INCOMPLETE`.

Structure behind that: 546 structured hypotheses (21 families x 26 verification lenses), 17
model-neutral specialist role profiles, 22 JSON Schema Draft 2020-12 contracts, 18 Gold Check Packs,
12 evidence adapters (Semgrep, Trivy, OSV, Gitleaks, ZAP, Nuclei, Playwright, package audit, SARIF),
38 eval fixtures / 76 cases, and a provenance-backed knowledge graph of 76 nodes and 100 edges.
Coverage emphasis is on business logic, payments, race conditions and idempotency, authorization, and
AI/agent/MCP security.

This release adds an `UNTRUSTED_REPO` zero-trust mode, in which repository content is treated as data
and never as control, plus differential security review. Given this list's own emphasis on the skill
supply chain, that mode is probably the most relevant part: the skill is built on the assumption that
the repository it is reading may be hostile to it.

Safety posture: defaults to `STATIC` or `LOCAL` mode; destructive payloads, credential theft,
persistence, denial-of-service, and data exfiltration are forbidden as verification methods; anything
that could mutate money, identity, inventory, authorization, external providers, or customer data
requires explicit authorization or moves to local/staging fixtures.

Install: `npx skills@latest add omarmohelal/SecHelix --skill sechelix`
Claude marketplace: `/plugin marketplace add omarmohelal/sechelix-marketplace` then
`/plugin install sechelix@sechelix`.

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
- This is alpha software; contracts and interfaces can still change. Happy to be listed with a caveat,
  or to wait, if you would rather the list only carry stable projects.

### Process

- [ ] Edited `data/tools.json` only — the README list section was not hand-edited
- [ ] Ran `node scripts/generate.mjs` and committed the regenerated README
- [ ] Link is HTTPS and resolves
- [ ] One entry, one PR
````

---

## 4. Pre-submission checklist — the maintainer must verify each

### Process

- [ ] **R-1.** Edited **`data/tools.json`**, not the README. README list edits are overwritten.
- [ ] **R-2.** Ran `node scripts/generate.mjs` and committed the regenerated README in the same PR.
- [ ] **R-3.** The JSON parses, and key order / indentation match the surrounding entries in the file.
- [ ] **R-4.** Exactly one entry added. One entry per PR.
- [ ] **R-5.** Checked open and closed PRs and `data/tools.json` for an existing SecHelix entry.

### Content accuracy

- [ ] **R-6.** Understand that including `repo` makes the generator render a **star count** next to
      the entry. That number is the list's own automation. Do not quote it, screenshot it, or refer
      to it in the PR body or anywhere else. Omitting `repo` would deviate from the documented
      schema, so keep the field — just never treat its output as a SecHelix claim.
- [ ] **R-7.** `desc` is **one sentence**, honest, and says what it does and who it is for.
- [ ] **R-8.** `desc` contains no adoption, star, install, user, testimonial, benchmark, accuracy, or
      "better than X" claim. Re-read it once looking specifically for this.
- [ ] **R-9.** `category` is `security` and is spelled exactly as it appears in `data/tools.json`.
      Confirm the valid category list has not changed since 2026-09-01.
- [ ] **R-10.** `url` resolves over HTTPS and the repo is public.
- [ ] **R-11.** Every number in the PR body matches the tree at the time of submission: 546
      hypotheses, 21 families, 26 lenses, 17 roles, 16 contracts, 12 adapters, 18 Gold Check Packs,
      38 fixtures / 76 cases, 76 nodes / 100 edges. Re-run `python scripts/validate_catalog.py`.
- [ ] **R-12.** `NOT_MEASURED` appears in the PR body and is not softened.
- [ ] **R-13.** Authorship self-disclosed in the PR body.

### Judgment

- [ ] **R-14.** Decide whether to disclose the alpha status as a listing caveat. This list explicitly
      curates for trust; volunteering the caveat is more likely to help than hurt.
- [ ] **R-15.** Confirm the list is still actively merging (recent merged PRs) before opening.
