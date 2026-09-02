# Submission draft — `claude-market/marketplace`

> **DRAFT — requires human review before submitting. Do not submit automatically.**

---

## Status: SUBMITTABLE, but two judgment calls must be made first

The repo **exists and was confirmed**, so this destination is real (the task brief flagged it as
possibly unverifiable — it verified fine):

- `full_name`: `claude-market/marketplace`
- URL: <https://github.com/claude-market/marketplace>
- Description: *"Open source, hand-curated marketplace for Claude Code tools, agents and skills."*
- `archived`: `false`, `default_branch`: `main`

Nothing in its policy disqualifies SecHelix. There is **no star minimum, no adoption requirement, no
benchmark field, and no published-release requirement.** SecHelix already satisfies the hard
requirements (Apache-2.0 licence, `.claude-plugin/plugin.json`, README, a skill). But two things
should be decided by a human before any fork happens:

**Judgment call 1 — this marketplace vendors your whole plugin into its monorepo.** It is not a link
registry. `CONTRIBUTING.md` requires the plugin be added as a **top-level directory containing the
actual plugin files**. That means a full copy of the SecHelix skill would live in a third-party repo
and would drift from the canonical `skills/sechelix/SKILL.md`. `CLAUDE.md` in this repo states that
`skills/sechelix/SKILL.md` is canonical. A stale copy of a *security* skill is a real hazard, not a
cosmetic one — a user could install a version whose hypothesis catalog, contracts, and safety rules
no longer match. Whoever submits must decide who re-syncs it and how often.

**Judgment call 2 — apparent dormancy.** Last push to the default branch was **2025-11-04**, roughly
ten months before this draft was written (2026-09-01). Aside from the `plugin-builder` tooling, the
repo contains only two plugin directories (`specforge`, `specforge-backend-rust-axum`). Confirm the
maintainers are still merging before investing the effort of a full vendored submission.

**Also note:** SecHelix already publishes its own marketplace
(`/plugin marketplace add omarmohelal/sechelix-marketplace`). Listing in a second, third-party
marketplace duplicates the distribution path. That may be fine for discovery, but it is a choice, not
an obligation.

---

## 1. Policy as read on 2026-09-01

Repository: <https://github.com/claude-market/marketplace>
Sources read: repo README, `CONTRIBUTING.md`, root file listing, GitHub API repo metadata.

### 1a. Required directory structure

Quoted from `CONTRIBUTING.md`:

> "Plugins are placed at the top level of the repository:
> ```
> your-plugin-name/
> ├── .claude-plugin/
> │   └── plugin.json          # Required: Plugin manifest
> ├── commands/                # Optional: Slash commands
> ├── agents/                  # Optional: Agents
> ├── hooks/                   # Optional: Hooks
> ├── skills/                  # Optional: Skills
> ├── mcp-servers/             # Optional: MCP servers
> ├── CODEOWNERS               # Required: Maintainers and reviewers
> ├── README.md                # Required: Documentation
> └── LICENSE                  # Required: Open source license
> ```"

### 1b. `plugin.json` schema

Quoted:

> "**Required:**
> - `name` (string, kebab-case)
> - At least one of: `commands`, `agents`, `hooks`, `skills`, or `mcpServers`
>
> **Recommended:**
> - `version` (string, semantic versioning)
> - `description` (string, clear and concise)
> - `author` (string)
> - `license` (string)
> - `keywords` (array of strings)
> - `homepage` (string, URL)
> - `repository` (string, URL)"

> Note the divergence: this marketplace documents `author` as a **string**, whereas SecHelix's
> `.claude-plugin/plugin.json` uses an **object** (`{"name": ..., "url": ...}`). See checklist M-5.

### 1c. CODEOWNERS is mandatory

Quoted:

> "Every plugin must include a CODEOWNERS file at its root."

> "**Format:**
> ```
> # Plugin maintainers and reviewers
> * @claude-market @your-github-username Your Name
> ```"

> "This ensures:
> - The Claude Market organization (@claude-market) is notified of all changes
> - Your GitHub account (@your-username) is tagged as a reviewer
> - Your name is listed for visibility"

### 1d. Submission process

Quoted:

> "### 1. Prepare Your Plugin
> - Create plugin in `./{plugin-name}/` (top-level directory)
> - Ensure all requirements are met (including CODEOWNERS file)
> - Test thoroughly"

> "### 2. Validate
> Use the plugin-builder validator:
> ```bash
> /plugin-builder:validate
> ```"

> "### 3. Test Locally
> Install and test your plugin:
> ```bash
> /plugin install ./{plugin-name}
> ```"

> "### 4. Update marketplace.json
> Add your plugin entry to `.claude-plugin/marketplace.json`"

> "### 5. Create Pull Request
> - Fork the repository
> - Create a branch: `git checkout -b add-your-plugin-name`"

The README additionally documents a generator:

> "Run the following command to automatically generate your plugin's entry in
> `.claude-plugin/marketplace.json`" — `make generate-marketplace-json`

> Prefer the generator over hand-editing; the JSON below is what it should produce, for review.

### 1e. Review criteria

Quoted:

> "### Must Have
> - ✓ All files present and properly structured
> - ✓ CODEOWNERS file with @claude-market and plugin author
> - ✓ Valid JSON in all .json files
> - ✓ Clear documentation in README
> - ✓ Open source license
> - ✓ Components work as described
> - ✓ No security vulnerabilities
> - ✓ No malicious code"

> "### Grounds for Rejection
> - ✗ Malicious code or security issues
> - ✗ Plagiarism or copyright violation
> - ✗ Incomplete or missing documentation
> - ✗ Components don't work
> - ✗ Poor quality or unclear instructions
> - ✗ Violates terms of service"

No metric, star, or usage field appears anywhere in the criteria. Nothing needs a `NOT_MEASURED`
placeholder in the machine-readable entry.

---

## 2. Exact `.claude-plugin/marketplace.json` entry — ready to paste

Generate this with `make generate-marketplace-json` and diff against the block below rather than
pasting blind.

```json
{
  "name": "sechelix",
  "source": "./sechelix",
  "version": "<FILL IN — must match the vendored .claude-plugin/plugin.json; currently 3.0.0-alpha.5>",
  "description": "Evidence-first application-security review for repositories and environments you are authorized to test. Maps trust boundaries, selects applicable checks, independently verifies candidate findings and refutes false positives, and requires regression proof before reporting High or Critical issues.",
  "author": "SecHelix",
  "license": "Apache-2.0",
  "keywords": [
    "appsec",
    "security-audit",
    "security-review",
    "agent-skills",
    "authorization",
    "business-logic",
    "ai-security",
    "mcp-security",
    "verification"
  ],
  "skills": [
    {
      "name": "sechelix",
      "description": "Evidence-first AppSec audit workflow for authorized repositories and environments. Maps attack surface, selects applicable checks, runs specialist review, independently verifies material findings, refutes false positives, fixes root causes, and requires regression proof before reporting High or Critical issues."
    }
  ]
}
```

## 3. Exact `sechelix/CODEOWNERS` — ready to paste

```
# Plugin maintainers and reviewers
* @claude-market @omarmohelal Omar Mohelal
```

> Confirm the GitHub handle and the display name before committing.

---

## 4. PR title and body

### PR title

```
Add sechelix plugin (evidence-first AppSec review)
```

### PR body

```markdown
### What this plugin does

SecHelix is an evidence-first application-security review workflow for repositories and environments
the operator owns or is explicitly authorized to test. It is not a scanner and not a scanner wrapper.
The operating premise is that a scanner alert is a hypothesis, a model suspicion is a hypothesis, and
two models agreeing is not independent proof — so candidates go to an independent verifier whose job
is to refute them before anything is reported.

### Components it provides

- **Skill: `sechelix`** — the full review workflow: scope and trust-boundary mapping, applicable-check
  selection, specialist review, independent verification, root-cause fix, regression proof, and a
  release decision.

Structurally, the skill is backed by:

- 546 structured security hypotheses (exactly 21 families x 26 verification lenses)
- 17 model-neutral specialist role profiles, including an independent verifier
- 19 JSON Schema Draft 2020-12 contracts that reports must validate against
- 18 Gold Check Packs (including IDOR, SSRF, race/idempotency, money invariants, AI/MCP tool authority)
- 11 evidence adapters: Semgrep, Trivy, OSV, Gitleaks, ZAP, Nuclei, Playwright, package audit, SARIF
- 38 eval fixtures / 76 cases, and a provenance-backed knowledge graph of 76 nodes and 100 edges

Coverage emphasis is on classes that pattern matching handles poorly: business logic, payments and
money invariants, race conditions and idempotency, authorization (BOLA/IDOR/BFLA), and AI/agent/MCP
security.

New in this release: an `UNTRUSTED_REPO` zero-trust mode, in which repository content is treated as
data and never as control, plus differential security review.

### Usage example

```
/plugin install sechelix
```

Then, in a repository you are authorized to review:

> Run a SecHelix review of this repo in STATIC mode.

The workflow resolves each check to `APPLICABLE`, `NOT_APPLICABLE`, `UNKNOWN`, or `BLOCKED` — missing
evidence is never silently treated as absence — and the release gate is fail-closed, returning
`PASS`, `PASS_WITH_KNOWN_RISK`, `BLOCKED`, or `INCOMPLETE`.

### Special requirements and safety notes

- Run only against systems you own or are explicitly authorized to test.
- Defaults to `STATIC` or `LOCAL` mode. It does not turn a code-review request into internet scanning.
- Destructive payloads, credential theft, persistence, denial-of-service, and data exfiltration are
  forbidden as verification methods.
- Any test that could mutate money, identity, inventory, authorization, external providers, or
  customer data requires explicit authorization or must be moved to local/staging fixtures.
- The scanner adapters are optional; the skill runs with zero scanners enabled.

### Licence

Apache-2.0. Canonical repository: https://github.com/omarmohelal/SecHelix

### Disclosure and honest status

- I am the author of this project.
- **Benchmarks are NOT_MEASURED.** The blocker is documented in the repository rather than hidden:
  the eval fixture suite was authored by the same assistant session that would have acted as the
  evaluated model, so scoring it would measure recall of authored answers rather than security-review
  capability. Unblocking requires a run by a model or session that did not author the fixtures, on
  blind exported cases. I make no accuracy, precision, recall, or detection-rate claim, and no
  comparison to any other tool.
- There is one published case study: an authorized owner self-audit in which one MEDIUM finding was
  verified, fixed, and regression-proved, and one plausible high-severity candidate was **REFUTED**.
  It is a worked example of the process, not a performance claim.
- This is alpha software; contracts and interfaces can still change.
- SecHelix also publishes its own marketplace. I am submitting here for discovery, and I am happy to
  discuss how the vendored copy stays in sync with the canonical repository — see the note below.

### Sync question for maintainers

This marketplace vendors plugin files rather than linking to a source repository. Since a stale
security skill is worse than no skill, I would like to agree an update mechanism before merge —
whether that is me opening a sync PR on each release, or something you already have in place.
```

---

## 5. Pre-submission checklist — the maintainer must verify each

### Decisions before any work

- [ ] **M-1.** Confirm the marketplace is still actively merging. Last push to `main` was
      **2025-11-04**. Check recent merged PRs / open an issue asking, before vendoring anything.
- [ ] **M-2.** Accept the vendoring/drift risk explicitly, and decide who re-syncs the copy on each
      SecHelix release. Do not submit without an answer.
- [ ] **M-3.** Decide whether a second distribution path is wanted at all, given
      `omarmohelal/sechelix-marketplace` already exists.

### Structural

- [ ] **M-4.** The vendored `sechelix/` directory contains `.claude-plugin/plugin.json`, `CODEOWNERS`,
      `README.md`, and `LICENSE` at its root, per the quoted structure.
- [ ] **M-5.** Resolve the `author` type mismatch: SecHelix's manifest uses an object
      (`{"name": "SecHelix", "url": "https://sechelix.com"}`); this marketplace documents a string.
      Verify what `make generate-marketplace-json` emits and that the resulting JSON is valid.
- [ ] **M-6.** Verify the skill layout is accepted. This marketplace's docs show `skills/skill.md`;
      SecHelix uses the Agent Skills directory convention `skills/sechelix/SKILL.md`. Confirm with
      `/plugin-builder:validate` rather than assuming.
- [ ] **M-7.** `version` in `marketplace.json` matches the vendored `plugin.json`. The manifest
      currently reads `3.0.0-alpha.5` while the working branch is `v3.2/trust-discovery` — reconcile.
- [ ] **M-8.** `CODEOWNERS` includes both `@claude-market` and the author's real GitHub handle.

### Validation

- [ ] **M-9.** `/plugin-builder:validate` run and clean.
- [ ] **M-10.** `/plugin install ./sechelix` tested locally from the fork, and the skill actually
      activates. "Components work as described" is a stated Must Have.
- [ ] **M-11.** All `.json` files parse.
- [ ] **M-12.** Every number in the PR body matches the vendored tree: 546 hypotheses, 21 families,
      26 lenses, 17 roles, 16 contracts, 11 adapters, 18 Gold Check Packs, 38 fixtures / 76 cases,
      76 nodes / 100 edges. Re-run `python scripts/validate_catalog.py`.

### Content accuracy

- [ ] **M-13.** No adoption, star, install, user, testimonial, benchmark, accuracy, or "better than X"
      claim anywhere in the entry, README, or PR body.
- [ ] **M-14.** `NOT_MEASURED` is stated in the PR body and not softened.
- [ ] **M-15.** Authorship self-disclosed.
- [ ] **M-16.** Checked open and closed PRs for a prior SecHelix submission.

---

## 6. Related destination found while researching — Anthropic's own directory

Recorded here so nobody wastes a PR on it. This is **not** the destination assigned in the brief, and
no draft is provided because **no PR is possible**.

- `anthropics/claude-plugins-community` — <https://github.com/anthropics/claude-plugins-community>
  README, read 2026-09-01, states verbatim: *"A **read-only mirror** of the community plugin
  marketplace."* and *"Pull requests opened directly against this repo are closed automatically — all
  changes flow from the internal review pipeline."* Submission is via the form at
  <https://clau.de/plugin-directory-submission>. The README also states: *"Every plugin listed here
  has been submitted via [claude.ai], passed automated security scanning, and been approved for
  distribution."*
- `anthropics/claude-plugins-official` — <https://github.com/anthropics/claude-plugins-official> —
  described as the Anthropic-managed directory. Same submission form.

If a human wants SecHelix in the first-party directory, the route is that web form, not GitHub. The
copy in section 4 can be reused for it, but the form's own fields were not read for this draft and
would need to be checked first.
