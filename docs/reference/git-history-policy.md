# Public git history policy

`git log` is a permanent, reader-facing artifact. It should read like a changelog the project wrote,
not a transcript of how the project was built.

## What lands on `main`

Every change enters through a pull request. Merges are **squash only** — merge commits and rebase
merges are disabled at both the repository setting and the branch ruleset, so there is no path that
produces anything else.

The squash commit is configured as:

| Setting | Value |
|---|---|
| `squash_merge_commit_title` | `PR_TITLE` |
| `squash_merge_commit_message` | `BLANK` |
| `delete_branch_on_merge` | `true` |

So a merge produces **one commit, titled by the PR, with an empty body**. The reasoning lives in the
pull request, where it is reviewable, linked, and archived — rather than in `git log`, where it is
load-bearing forever and cannot be edited without breaking every reference to it.

Verify what is actually configured rather than trusting this page:

```bash
gh api repos/omarmohelal/SecHelix \
  --jq '{allow_squash_merge,allow_merge_commit,allow_rebase_merge,
         delete_branch_on_merge,squash_merge_commit_title,squash_merge_commit_message}'
```

## What must not appear

- assistant co-author trailers (`Co-Authored-By: Claude …`)
- session URLs (`Claude-Session:`, `claude.ai/code/session_…`)
- generated-by attribution in trailers
- development diaries — a commit body should summarise the change, not narrate arriving at it

`scripts/check_commit_hygiene.py` enforces this in CI. It checks only commits **after a declared
baseline**, currently the V3.3 merge.

## Why existing history is not rewritten

Commits before the baseline carry these trailers. They stay.

Rewriting published history invalidates every SHA anyone already holds — the release tags, the
Awesome Copilot submission that cites a commit SHA, any fork, any bookmark, any citation. The cure
is worse than untidy trailers, and a project that argues for evidence should not quietly replace the
record of its own past.

The trailers are also *true*: this project was built with substantial AI assistance. Removing them
from history would erase an accurate record. Going forward that fact belongs in documentation, where
it can be stated once and read in context, rather than repeated in every commit.

## Disclosure

SecHelix is developed with substantial AI assistance, directed by a human maintainer. That is stated
in the README and in launch material rather than in commit trailers.

## Amending

A commit that has **not** been merged may be amended freely. A commit that has been merged to `main`
must not be — fix it forward.
