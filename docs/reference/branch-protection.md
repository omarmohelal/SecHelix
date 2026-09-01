# Branch and tag protection

Two rulesets protect `omarmohelal/SecHelix`. Both are **active**, and both were verified by
attempting the thing they forbid rather than by reading the settings page.

## `Protected main`

Target: `refs/heads/main`.

| Rule | Effect |
|---|---|
| `pull_request` | Changes reach `main` only through a PR. Required approvals: 0 — this is a single-maintainer project, and a self-approval requirement is theatre. Review threads must be resolved. |
| `required_status_checks` | `validate` and `Analyze Python` must pass. `strict` is on, so a branch must be current with `main` before merging. |
| `non_fast_forward` | Force-pushes rejected. |
| `deletion` | `main` cannot be deleted. |

**Bypass:** repository admin, `bypass_mode: pull_request` only. The owner can merge their own PR
without waiting for a second human; the owner **cannot** push straight to `main`.

### How it was verified

The first version of this ruleset granted admins `bypass_mode: always`. A probe commit was pushed
directly to `main` to test it — and succeeded. An "always" bypass on the only account that uses the
repository is not protection, it is a setting.

The probe was reverted (not force-pushed away — the commit and its revert are both in history, which
is the honest record), the bypass narrowed to `pull_request`, and the push retried:

```
remote: error: GH013: Repository rule violations found for refs/heads/main.
remote: - Changes must be made through a pull request.
remote: - 2 of 2 required status checks are expected.
```

A protection rule nobody has tried to break is an assumption.

## `Immutable release tags`

Target: `refs/tags/v*`.

| Rule | Effect |
|---|---|
| `deletion` | A published release tag cannot be removed. |
| `update` | A tag cannot be moved to a different commit. |
| `non_fast_forward` | No rewriting. |

This exists because a release tag is the immutable reference a directory submission or a pinned
install resolves against. A tag that can move means `--pin v3.2.0-alpha.1` guarantees nothing.

`gh skill publish` warns when no tag protection exists; that warning is now clear.

### Consequence worth knowing

Because tags are immutable, a mistake in a release is fixed by publishing a new version, never by
moving the tag. When the Awesome Copilot submission needed a tree containing a file added after the
tag, the submission cited the **commit SHA** rather than moving `v3.2.0-alpha.1` — which is the
behaviour this ruleset is meant to force.

## Reproducing these

Rulesets are stored server-side, not in the repository, so they are recorded here rather than as
config. To recreate:

```bash
gh api -X POST repos/omarmohelal/SecHelix/rulesets --input main-ruleset.json
gh api -X POST repos/omarmohelal/SecHelix/rulesets --input tag-ruleset.json
```

To confirm what is actually active:

```bash
gh api repos/omarmohelal/SecHelix/rulesets --jq '.[]|"\(.name) target=\(.target) \(.enforcement)"'
```

Do not trust this page over that command. This page can go stale; the API cannot.
