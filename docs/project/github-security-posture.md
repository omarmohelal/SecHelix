# GitHub security posture

This document records the supply-chain and repository-security controls that
SecHelix enforces **in code**, and the controls that can only be switched on by
the repository owner in the GitHub web UI.

The split matters. Everything in the first section is auditable by reading this
repository: you can verify it from a clone, without trusting a screenshot or a
badge. Everything in the second section lives in GitHub's settings database,
where nothing committed to the repository can enable it — **an automated agent
working in a clone cannot perform any of it.** Those items are listed with the
exact click-path so the owner can complete them, and with the API call that
proves whether they were completed.

Scope of this document: repository and CI hardening. The security policy for
*reporting vulnerabilities in SecHelix itself* lives in
[`SECURITY.md`](../../SECURITY.md).

---

## 1. Enforced in this repository (verifiable from a clone)

### 1.1 All GitHub Actions are pinned to immutable commit SHAs

A mutable tag (`@v4`) is a name the upstream maintainer — or anyone who
compromises them — can silently repoint at different code. Every `uses:` in
this repository is pinned to a full 40-character commit SHA with the human
readable version in a trailing comment, so a compromised upstream tag cannot
change what runs here.

| Action | Version | Commit SHA |
| --- | --- | --- |
| `actions/checkout` | v6.1.0 | `d23441a48e516b6c34aea4fa41551a30e30af803` |
| `actions/setup-python` | v6.3.0 | `ece7cb06caefa5fff74198d8649806c4678c61a1` |
| `actions/configure-pages` | v6.0.0 | `45bfe0192ca1faeb007ade9deae92b16b8254a0d` |
| `actions/upload-pages-artifact` | v5.0.0 | `fc324d3547104276b827a68afc52ff2a11cc49c9` |
| `actions/deploy-pages` | v5.0.0 | `cd2ce8fcbc39b97be8ca5fce6e763baed58fa128` |
| `actions/upload-artifact` | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| `actions/download-artifact` | v8.0.1 | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` |
| `actions/attest-build-provenance` | v4.2.2 | `4d101475d8b20a2381f78447822ac1eab6504dd8` |
| `actions/dependency-review-action` | v5.0.0 | `a1d282b36b6f3519aa1f3fc636f609c47dddb294` |
| `github/codeql-action/init` | v4.37.9 | `cdf488f595d80d6e07e03d4674febd5ab45fa938` |
| `github/codeql-action/analyze` | v4.37.9 | `cdf488f595d80d6e07e03d4674febd5ab45fa938` |
| `github/codeql-action/upload-sarif` | v4.37.9 | `cdf488f595d80d6e07e03d4674febd5ab45fa938` |
| `ossf/scorecard-action` | v2.4.4 | `2d1146689b8cda280b9bc96326124645441f03bc` |

Verify every pin resolves to a real commit on the upstream repository:

```bash
grep -rhoE 'uses: [^ ]+' .github/workflows/ \
  | sed 's/uses: //' \
  | sort -u \
  | while read -r ref; do
      repo="${ref%@*}"; repo="${repo%%/*}/$(echo "${repo#*/}" | cut -d/ -f1)"
      gh api "repos/${repo}/commits/${ref##*@}" --jq '.sha' >/dev/null \
        && echo "ok   ${ref}" || echo "FAIL ${ref}"
    done
```

### 1.2 Least-privilege `GITHUB_TOKEN` permissions

Every workflow declares `permissions: {}` at the top level — the token starts
with **no** scopes — and each job re-grants only what that job needs.

| Workflow | Job | Permissions | Why |
| --- | --- | --- | --- |
| `validate.yml` | `validate` | `contents: read` | Read the tree to test it. |
| `pages.yml` | `build` | `contents: read` | Build the static handoff. |
| `pages.yml` | `deploy` | `pages: write`, `id-token: write` | Only the deploy job can publish. |
| `codeql.yml` | `analyze` | `security-events: write`, `actions: read`, `contents: read` | Upload SARIF to code scanning. |
| `dependency-review.yml` | `dependency-review` | `contents: read` | Diff the dependency graph. |
| `scorecard.yml` | `analysis` | `security-events: write`, `id-token: write`, `contents: read`, `actions: read` | Upload SARIF; sign published results. |
| `release.yml` | `sbom` | `contents: read`, `id-token: write`, `attestations: write` | Build and attest; **cannot write to the repo.** |
| `release.yml` | `publish` | `contents: write` | The only write-capable job in the repository, and it only attaches release assets. |

Note the shape of `release.yml` in particular: the job that runs a build script
has no write access, and the job that has write access runs no build script.
That separation means a compromised build step cannot push to the repository.

### 1.3 Checkout credentials are not persisted

`actions/checkout` writes the job's `GITHUB_TOKEN` into `.git/config` by
default, leaving it readable by every subsequent step. None of these workflows
push, so every checkout sets `persist-credentials: false`. A malicious or
buggy later step cannot recover a usable token from the git config.

### 1.4 Redundant runs are cancelled

`validate.yml`, `codeql.yml`, `dependency-review.yml`, and `pages.yml` use a
`concurrency` group keyed on `${{ github.workflow }}-${{ github.ref }}` with
`cancel-in-progress: true`, so a force-push supersedes its own in-flight runs
instead of racing them.

`release.yml` deliberately sets `cancel-in-progress: false` — a half-cancelled
release is worse than a slow one.

### 1.5 CI gaps that were closed

These were real holes: work that existed in the repository but that CI never
executed, so it could rot without turning a check red.

- **`adapters/tests/` was never run.** `validate.yml` ran only
  `discover -s tests`, so the 19 adapter and agent-profile tests in
  `adapters/tests/` were dead weight in CI. They now run as their own step
  (`discover -s adapters/tests -t .`).
- **A stale portable bundle passed CI.** `skills/sechelix/` is generated from
  canonical sources by `scripts/sync_portable_skill.py`, but nothing verified
  that the committed bundle matched those sources. The published skill could
  silently ship an older catalog, schema, or adapter than the repository it was
  built from. CI now regenerates the bundle and fails if
  `git status --porcelain skills/` is non-empty, with the diff printed in the
  log. This is the check most likely to catch a real distribution bug: it fires
  on *any* edit to `adapters/`, `catalog/`, `schemas/`, `policies/`,
  `gold-packs/`, `knowledge/`, `agents/`, `references/`, `reports/`, or
  `sechelix_core/` that is not mirrored into the bundle.
- **The SBOM generator was unverified.** `validate.yml` now runs
  `scripts/generate_sbom.py` on every push and PR, so a broken generator is
  caught in CI rather than during a release.

### 1.6 Static analysis

[`codeql.yml`](../../.github/workflows/codeql.yml) runs CodeQL against Python
on every push and PR to `main`, plus weekly at 05:27 UTC on Mondays. The weekly
run matters because CodeQL ships new queries continuously: code that was clean
when it was merged can become a finding without anyone touching it.

It uses the `security-extended` query suite and `build-mode: none` (SecHelix is
pure interpreted Python; there is nothing to compile).

### 1.7 Supply-chain review

- [`dependency-review.yml`](../../.github/workflows/dependency-review.yml) runs
  on every pull request. **SecHelix currently has no package manifest** — every
  module imports only the Python standard library — so there is no dependency
  graph to diff. Rather than fail the job for a reason that is not a security
  signal, or paper over it with `continue-on-error`, the workflow detects
  whether any supported manifest is tracked and emits an explicit skip notice
  when none is. The gate opens automatically the first time a manifest is
  committed, at which point it fails on moderate-or-higher advisories and on
  copyleft licences incompatible with Apache-2.0 redistribution.
- [`scorecard.yml`](../../.github/workflows/scorecard.yml) runs OpenSSF
  Scorecard weekly and on push to `main`, uploads SARIF to code scanning, and
  publishes results to the OpenSSF API so the score is independently
  verifiable rather than self-reported.
- [`dependabot.yml`](../../.github/dependabot.yml) watches the one dependency
  ecosystem that actually exists here: the pinned GitHub Actions. Dependabot
  updates the SHA **and** the trailing version comment, so pins stay current
  without giving up immutability. No npm or pip ecosystem is configured,
  because no such manifest exists and a config pointing at a missing manifest
  is a permanently silent updater.

### 1.8 Release artifacts: SBOM and provenance

[`release.yml`](../../.github/workflows/release.yml) fires on `v*` tag pushes.
It runs [`scripts/generate_sbom.py`](../../scripts/generate_sbom.py) — standard
library only, so producing the SBOM does not itself introduce a dependency —
to emit a CycloneDX 1.5 JSON SBOM, attests it with
`actions/attest-build-provenance`, and attaches it plus its SHA-256 to the
GitHub Release.

The SBOM describes what SecHelix actually is: fourteen first-party components
(code, data, and the packaged skill bundle), each with a SHA-256 content
digest, plus **one** external requirement — a CPython interpreter, recorded as
the runtime platform and explicitly marked as not vendored. It does not invent
transitive dependencies. An empty third-party dependency set is a checkable
claim; a fabricated one is not.

The SBOM is byte-reproducible: it honours `SOURCE_DATE_EPOCH` (the release
workflow binds it to the tagged commit's timestamp) and derives its
`serialNumber` deterministically from the version plus a digest of the tree.
Two builds of the same tag produce identical bytes, so anyone can regenerate
the SBOM from the tag and compare hashes:

```bash
git checkout v3.0.0-alpha.5
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)" \
  python scripts/generate_sbom.py --output /tmp/sbom.cdx.json
sha256sum /tmp/sbom.cdx.json   # compare with the .sha256 asset on the release
```

Verify the provenance attestation:

```bash
gh attestation verify sechelix-sbom.cdx.json --repo omarmohelal/SecHelix
```

The generated document was validated against the upstream
`bom-1.5.schema.json` from `CycloneDX/specification` (with its `spdx` and
`jsf-0.82` subschemas) and reports zero errors. That validation is intentionally
*not* wired into CI: it needs `jsonschema` and a network fetch, and adding a
third-party package to prove "this project has no third-party packages" would
be self-defeating. CI runs the generator instead, so a generator that cannot
produce output fails the build.

### 1.9 Ownership and provenance metadata

- [`.github/CODEOWNERS`](../../.github/CODEOWNERS) assigns `@omarmohelal` as
  owner, with explicit entries for the security-critical surfaces:
  `.github/workflows/`, `skills/`, `schemas/`, `catalog/`, `policies/`, and
  `gold-packs/`. **CODEOWNERS is advisory until the owner enables "Require
  review from Code Owners"** — see [§2.1](#21-branch-protection-for-main).
- [`CITATION.cff`](../../CITATION.cff) provides CFF 1.2.0 citation metadata,
  validated against the official `citation-file-format` 1.2.0 schema with zero
  errors. It carries no DOI or ORCID, because none has been issued; inventing
  either would be a fabricated identifier.

### 1.10 Why `.agents/skills/` and `.claude/skills/` are tracked

`gh skill publish --dry-run` warns that these directories "contain installed
skills" and suggests gitignoring them. That heuristic is right for a *consumer*
repository, where those paths hold third-party skills fetched by a package
manager.

SecHelix is the inverse case: it **is** the skill. `skills/sechelix/` is the
canonical source and these two directories are first-party adapter mirrors of
it, published deliberately so the skill resolves in each harness with no
install step. Nothing under them is third-party, and both
`scripts/validate_skill.py` and the "Ensure adapter mirrors exist" step in
`validate.yml` fail if they are missing.

The warning is therefore rejected on purpose. That reasoning is recorded as a
comment in [`.gitignore`](../../.gitignore) so a reviewer who hits the same
warning finds the decision instead of assuming it was overlooked.

---

## 2. Requires manual action by the repository owner

**None of the following could be performed by the agent that prepared this
work.** They are changes to GitHub's settings database, not to files in the
repository: there is no commit that enables them, and a personal access token
scoped for code cannot substitute for the owner's decision. Each item below
gives the click-path and a read-only API call to confirm the result.

Status column reflects a read of the GitHub API at the time this document was
written. Re-run the verification command to get current state.

| # | Control | Status when documented |
| --- | --- | --- |
| 2.1 | Branch protection / ruleset for `main` | **Not configured** |
| 2.2 | Tag protection ruleset for `v*` | **Not configured** |
| 2.3 | Secret scanning | Enabled |
| 2.4 | Secret scanning push protection | Enabled |
| 2.5 | Secret scanning: non-provider patterns + validity checks | **Disabled** |
| 2.6 | Private vulnerability reporting | **Disabled** |
| 2.7 | Dependabot alerts | **Disabled** |
| 2.8 | Dependabot security updates | **Disabled** |
| 2.9 | Actions: restrict allowed actions | **All actions allowed** |
| 2.10 | Actions: require SHA pinning | **Not required** |
| 2.11 | Code scanning default setup | Correctly left off (see note) |
| 2.12 | `github-pages` environment protection | Environment exists; rules unreviewed |

### 2.1 Branch protection for `main`

Currently `main` has **no** protection: `GET /repos/omarmohelal/SecHelix/branches/main/protection`
returns `404 Branch not protected`. Every control in section 1 is a check that
*reports*; without this, none of them can *block*. CODEOWNERS is also inert
until "Require review from Code Owners" is on.

**Click-path:** repository → **Settings** → **Rules** → **Rulesets** →
**New ruleset** → **New branch ruleset**.

1. **Ruleset name:** `main-protection`.
2. **Enforcement status:** `Active`.
3. **Target branches** → **Add target** → **Include default branch**.
4. Enable **Restrict deletions**.
5. Enable **Block force pushes**.
6. Enable **Require linear history**.
7. Enable **Require a pull request before merging**:
   - Required approvals: `1`
   - Tick **Dismiss stale pull request approvals when new commits are pushed**
   - Tick **Require review from Code Owners** — this is what activates
     `.github/CODEOWNERS`
8. Enable **Require status checks to pass**:
   - Tick **Require branches to be up to date before merging**
   - Add checks: `validate` (from `validate.yml`), `Analyze Python` (from
     `codeql.yml`), `Review dependency changes` (from
     `dependency-review.yml`)
   - These names only appear in the picker after each workflow has run at
     least once on the default branch, so merge these workflows first, then
     add the checks.
9. **Create**.

> Solo-maintainer note: with a single maintainer, "require 1 approval" means
> every change must go through a PR that someone else approves, or that you
> merge using a bypass. Add yourself to **Bypass list** with the
> `Pull requests` bypass only if that is a deliberate trade-off — and be aware
> that a reviewer reading this document will see the bypass in the ruleset.

**Verify:**

```bash
gh api repos/omarmohelal/SecHelix/rulesets --jq '.[] | {name, target, enforcement}'
```

### 2.2 Tag protection ruleset for `v*`

`release.yml` triggers on `v*` tag pushes and its `publish` job holds
`contents: write`. Without tag protection, a tag can be deleted and re-pointed
at different code, and the release pipeline will happily build and attest that
different code under the same version number. This is the single highest-value
manual item for a project that publishes signed artifacts.

Currently `GET /repos/omarmohelal/SecHelix/rulesets` returns `[]`.

**Click-path:** **Settings** → **Rules** → **Rulesets** → **New ruleset** →
**New tag ruleset**.

1. **Ruleset name:** `release-tags`.
2. **Enforcement status:** `Active`.
3. **Target tags** → **Add target** → **Include by pattern** → enter `v*`.
4. Enable **Restrict creations** only if you want to limit who can cut a
   release; leave off for a solo maintainer.
5. Enable **Restrict updates** — this is the control that stops a tag from
   being moved.
6. Enable **Restrict deletions**.
7. **Create**.

**Verify:**

```bash
gh api repos/omarmohelal/SecHelix/rulesets --jq '.[] | select(.target=="tag")'
```

### 2.3 / 2.4 Secret scanning and push protection

**Already enabled** — no action needed. Confirmed via
`security_and_analysis.secret_scanning.status = "enabled"` and
`secret_scanning_push_protection.status = "enabled"`.

Note that `scripts/check_no_secrets.py` (run in CI) is a *second*, independent
control on the same risk: it scans tracked text for high-confidence token
patterns and fails the build. GitHub's scanner catches provider-issued
credentials at push time; the repository's own check catches whatever lands in
the tree regardless.

### 2.5 Secret scanning: non-provider patterns and validity checks

Both currently **disabled**. Non-provider patterns catch generic credentials
(private keys, connection strings) that no vendor has registered a pattern for
— a meaningful gap for a repository that ships example configuration.

**Click-path:** **Settings** → **Advanced Security** (older layout: **Code
security and analysis**) → **Secret Protection** section → enable
**Scan for non-provider patterns** and **Validity checks**.

**Verify:**

```bash
gh api repos/omarmohelal/SecHelix --jq '.security_and_analysis'
```

### 2.6 Private vulnerability reporting

Currently **disabled** (`GET /repos/omarmohelal/SecHelix/private-vulnerability-reporting`
returns `{"enabled": false}`). [`SECURITY.md`](../../SECURITY.md) documents a
disclosure process, but without this toggle there is no in-GitHub private
channel, and a researcher's fallback is a public issue — which is the failure
mode the policy exists to prevent. For a security tool, this is a credibility
item as much as a technical one.

**Click-path:** **Settings** → **Advanced Security** (older layout: **Code
security and analysis**) → **Private vulnerability reporting** → **Enable**.

**Verify:**

```bash
gh api repos/omarmohelal/SecHelix/private-vulnerability-reporting
```

### 2.7 / 2.8 Dependabot alerts and security updates

Both currently **disabled**. The dependency graph itself is always on for
public repositories, but alerts are a separate opt-in.

This matters less today than it will tomorrow: with no package manifest there
is nothing to alert on right now. Enabling it in advance means the day a
manifest is added, coverage is already in place rather than being remembered
after the fact.

**Click-path:** **Settings** → **Advanced Security** (older layout: **Code
security and analysis**) → enable **Dependabot alerts**, then enable
**Dependabot security updates**.

**Verify:**

```bash
gh api repos/omarmohelal/SecHelix/vulnerability-alerts   # 204 = enabled, 404 = disabled
gh api repos/omarmohelal/SecHelix --jq '.security_and_analysis.dependabot_security_updates'
```

### 2.9 Actions: restrict which actions may run

Currently `allowed_actions: "all"`. Section 1.1 pins every action this
repository *intends* to use, but that only governs the workflows in the tree.
Restricting allowed actions at the repository level means a workflow added by a
future PR cannot pull in an arbitrary third-party action.

**Click-path:** **Settings** → **Actions** → **General** → **Actions
permissions** → select **Allow <owner>, and select non-<owner>, actions and
reusable workflows**, then tick **Allow actions created by GitHub** and add to
**Allow specified actions and reusable workflows**:

```
ossf/scorecard-action@*
```

(Everything else currently used is a first-party `actions/*` or
`github/codeql-action` action, covered by the GitHub-created option.)

**Verify:**

```bash
gh api repos/omarmohelal/SecHelix/actions/permissions
```

### 2.10 Actions: require SHA pinning

Currently `sha_pinning_required: false`. GitHub can now *enforce* what section
1.1 does by convention: reject any workflow that references an action by tag or
branch instead of a full commit SHA. This turns pinning from a practice a
reviewer must remember into an invariant the platform holds.

**Click-path:** **Settings** → **Actions** → **General** → **Actions
permissions** → tick **Require actions to be pinned to a full-length commit
SHA**.

Do this *after* the workflows in this branch are merged — every `uses:` here
already complies, so nothing will break, but enabling it against a
non-compliant workflow blocks all Actions runs.

**Verify:**

```bash
gh api repos/omarmohelal/SecHelix/actions/permissions --jq '.sha_pinning_required'
```

### 2.11 Code scanning default setup — leave OFF

`GET /repos/omarmohelal/SecHelix/code-scanning/default-setup` reports
`"state": "not-configured"`, which is **correct and should stay that way**.

This is a trap worth stating explicitly: enabling default setup in the UI
disables the advanced workflow. `codeql.yml` would still run, but its results
would be rejected with "CodeQL default setup is enabled" and the
`security-extended` query suite configured there would be silently replaced by
the default suite. Do not enable it.

If you ever want to migrate to default setup, delete `codeql.yml` in the same
change.

### 2.12 `github-pages` environment protection

The `github-pages` environment exists (created by the Pages deployment). Its
protection rules were not inspected as part of this work.

**Click-path:** **Settings** → **Environments** → **github-pages** →
under **Deployment branches and tags**, confirm it is restricted to `main`.

This bounds the blast radius of `pages.yml`: the `deploy` job holds
`pages: write` and `id-token: write`, and the environment is what stops a
branch other than `main` from claiming those.

**Verify:**

```bash
gh api repos/omarmohelal/SecHelix/environments/github-pages
```

---

## 3. Deliberately not done

Recording what was rejected, and why, so the absences read as decisions rather
than gaps.

- **No status badges.** A badge asserts a state to a reader who cannot check
  it. Everything in section 1 is verifiable from a clone; everything in
  section 2 has a `gh api` command attached. Neither needs a badge, and a badge
  would not make either more true.
- **No fabricated dependency manifest.** Creating a `requirements.txt` would
  make `dependency-review.yml` and a pip Dependabot ecosystem "work", at the
  cost of the SBOM and the dependency graph both describing a project that does
  not exist.
- **No DOI or ORCID in `CITATION.cff`.** Neither has been issued. An invented
  identifier in a citation file is a fabricated provenance claim.
- **No `continue-on-error` on the dependency review job.** That would convert a
  real failure signal into a green check. The manifest-detection gate in
  section 1.7 achieves graceful degradation without ever masking a genuine
  failure.
