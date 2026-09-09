# SecHelix GitHub Action

Run SecHelix in CI and get one word back: `PASS`, `PASS_WITH_KNOWN_RISK`,
`BLOCKED` or `INCOMPLETE`.

```yaml
- uses: omarmohelal/SecHelix@v4.0.0-alpha.4
  with:
    executor: none
```

A complete workflow is in
[`../examples/ci/sechelix-review.yml`](../examples/ci/sechelix-review.yml).

## The one thing to understand first

`executor: none` is the default and it **does not analyse code**. It runs the
review graph, blocks every reasoning lane, and reports `INCOMPLETE`.

That is not a bug and it is not a soft failure. It is the answer to the question
"what did this run establish?" — nothing. Configure a reasoning executor to get a
review; until then the action will keep saying so rather than showing you a green
check it has not earned.

## Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Directory to audit, relative to the workspace |
| `depth` | `standard` | `quick`, `standard` or `thorough` |
| `executor` | `none` | `none`, `claude-code` or `gemini-cli` |
| `model` | — | Provider model override |
| `max-cost-usd` | — | Hard spend ceiling |
| `node-timeout` | — | Seconds allowed per reasoning node |
| `fail-on` | `blocked` | `never`, `blocked` or `incomplete` |
| `upload-sarif` | `true` | Upload to GitHub code scanning |
| `sarif-category` | `sechelix` | Code scanning category |
| `upload-artifact` | `true` | Upload run, SARIF and Markdown as an artifact |
| `artifact-name` | `sechelix-report` | Artifact name |
| `python-version` | `3.12` | Python used to run SecHelix |

## Outputs

| Output | Values |
|---|---|
| `outcome` | `PASS`, `PASS_WITH_KNOWN_RISK`, `BLOCKED`, `INCOMPLETE` |
| `reason` | One sentence explaining the outcome |
| `run-id` | The recorded run id |
| `incomplete` | `true` when mandatory nodes did not deliver |
| `blocking-count` | Open verified findings at `CRITICAL` or `HIGH` |
| `sarif-file`, `report-file` | Paths to the generated files |

## How `fail-on` decides

| `fail-on` | `PASS` / `PASS_WITH_KNOWN_RISK` | `BLOCKED` | `INCOMPLETE` |
|---|---|---|---|
| `never` | pass | pass | pass |
| `blocked` *(default)* | pass | **fail** | pass, with a warning annotation |
| `incomplete` | pass | **fail** | **fail** |

`blocked` is the default rather than `incomplete` for a specific reason: a run
that could not analyse anything is not evidence against the pull request, and
turning it into a red X teaches people to ignore red Xs. The outcome is still
`INCOMPLETE` in the summary, the SARIF and the outputs — it is reported loudly
and simply does not block the merge by default. Choose `incomplete` when your
release process requires a review to have actually happened.

## What it does with `outcome`

Mapping lives in [`../scripts/ci_outcome.py`](../scripts/ci_outcome.py) and reuses
the vocabulary in `sechelix_core/pr_review.py` — the same words
`scripts/security_gate.py` uses. There is no second definition of a finding here.

The ordering is the part worth reading:

1. **Any unsatisfied mandatory node → `INCOMPLETE`, decided before findings are
   examined at all.** A run whose lanes were blocked produces an empty finding
   list, and so does a run over genuinely clean code. Deciding `INCOMPLETE`
   first is what stops the first from being read as the second.
2. An open finding that is `VERIFIED` **and** `CRITICAL`/`HIGH` → `BLOCKED`.
   All three clauses matter: a severe *candidate* does not block, and neither
   does a severe finding already marked `FIXED`.
3. Other open findings → `PASS_WITH_KNOWN_RISK`.
4. Nothing open → `PASS`.

An unreadable or malformed run artifact is `INCOMPLETE`, never `PASS`. A step
that cannot read its own evidence has established nothing.

Exit codes match `security_gate.py`: `0` for either pass, `1` for `BLOCKED`,
`2` for `INCOMPLETE` or bad input.

## Permissions

The action needs no secrets of its own.

```yaml
permissions:
  contents: read
  security-events: write   # only while upload-sarif is true
```

`security-events: write` is required by GitHub's code-scanning upload, and on a
private repository that upload additionally requires GitHub Advanced Security.
The upload step is `continue-on-error`, so a repository without it still gets the
outcome, the summary and the artifact — you are not forced to choose between the
action and your plan.

## Security notes

- **Inputs never reach a shell as code.** Every input crosses into the step as an
  environment variable and is quoted at the point of use. Interpolating
  `${{ inputs.* }}` into a `run:` block would let a workflow input close the
  command and start another one; a test in
  `.github/workflows/action-selftest.yml` passes `.; touch /tmp/... #` as `path`
  and asserts nothing executed.
- **Pinned by commit.** `actions/setup-python`, `actions/upload-artifact` and
  `github/codeql-action/upload-sarif` are pinned to immutable SHAs.
- **No runtime dependencies.** SecHelix installs with an empty dependency list —
  a security tool that drags in a dependency tree has widened the attack surface
  of the thing it was installed to protect.
- **The uploaded artifact is the redacted one.** `sechelix audit --json` prints
  the raw result; only the runner's storage layer runs a result through the
  redactor. The action therefore re-reads the persisted copy with
  `sechelix report --format json` before uploading, so a secret-shaped value in
  a node payload does not reach a build artifact that anyone with repository
  read access can download.
- **No value can forge a second step output.** `$GITHUB_OUTPUT` is
  newline-delimited, so a value containing a newline can write a further key —
  including `outcome=PASS` after a real `outcome=BLOCKED`. Every field is
  flattened to one line before it is written.
- **Nothing is logged that was not already public.** The action reads no secrets
  and echoes no environment.
- Do not run this from `pull_request_target` with a fork-head checkout. That is
  true of any action, and truer of one you gave `security-events: write`.

## Versioning

Pin a release tag:

```yaml
uses: omarmohelal/SecHelix@v4.0.0-alpha.4
```

The action installs SecHelix from its own checkout, so the tag you pin is exactly
the code that runs — there is no floating release resolved at run time.
