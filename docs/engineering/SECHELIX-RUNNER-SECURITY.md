# SecHelix self-hosted runner: security posture

SecHelix CI runs its required checks on a **self-hosted GitHub Actions runner**
(`labels: self-hosted, sechelix-wsl`) hosted in WSL on a maintainer workstation.
This exists because the GitHub-hosted runners cannot start while the account is
billing-locked. A self-hosted runner on a **public** repository is a real risk:
a pull request can run its own code on the runner host. This document records
the threat model, the controls in place, and the residual limitations.

## Threat model

- The repository is public, so anyone can open a pull request.
- A workflow that both triggers on `pull_request` and runs on the self-hosted
  runner would otherwise execute attacker-controlled code on the host.
- The host runs a reachable Docker daemon; code with Docker access is
  effectively host-root (it can mount the host filesystem into a container).
- The host is a personal workstation, not an isolated throwaway machine.

## Controls in place

1. **Fork-PR runs require maintainer approval for every outside contributor.**
   The repository Actions policy is set to `all_external_contributors`
   (Settings -> Actions -> General -> "Fork pull request workflows from outside
   collaborators"). No pull request from a fork runs any workflow -- hosted or
   self-hosted -- until a maintainer reviews the diff and clicks
   *Approve and run*. Returning contributors are **not** exempted.
2. **No `pull_request_target`.** Every self-hosted workflow triggers on plain
   `pull_request`, so PR code runs without repository secrets and without a
   write-scoped token. Introducing `pull_request_target` on a self-hosted job
   would hand secrets to untrusted code and is prohibited (see Rules).
3. **Least-privilege token.** `default_workflow_permissions` is `read` and
   workflows cannot approve pull-request reviews.
4. **Only non-publishing checks run self-hosted.** `validate`, CodeQL,
   `action-selftest`, and `dependency-review` run on the runner. The
   publish/release workflows and Pages deploy stay on GitHub-hosted runners so
   publishing secrets and deploy credentials never reach the workstation.
5. **Single-repository registration.** The runner is registered to this
   repository only; its per-job `GITHUB_TOKEN` is ephemeral and read-only.

## Rules (must follow)

- Never combine `runs-on: [self-hosted, ...]` with `pull_request_target`, or
  with any job that reads repository secrets or a write-scoped token.
- Keep `default_workflow_permissions` at `read`; grant write scopes per-job only
  where a specific step needs them (for example CodeQL SARIF upload).
- Review the full diff of a fork PR, including workflow and script changes,
  before approving its run. An approval runs the PR's code on the workstation.
- Do not move publish, release, or Pages-deploy jobs onto the self-hosted runner.
- Prefer bringing a reviewed fork contribution onto an in-repository branch
  (same-repo PR) rather than approving repeated fork runs.

## Residual limitations

- **No host isolation.** The runner executes jobs as the WSL user with full
  access to that user's files and to the Docker socket. An approved-but-hostile
  PR could read user-readable secrets or escalate through Docker. The approval
  gate is therefore the primary control, and careful review before approval is
  mandatory.
- **Persistent host.** The runner is long-lived (a logon-triggered service), so
  state can persist between jobs.

## Recommended future hardening (needs infrastructure not yet set up)

- Run untrusted or expensive dynamic jobs on **ephemeral** runners
  (`--ephemeral`, re-registered per job) inside a disposable container or VM.
- Use a dedicated low-privilege user and rootless / socket-restricted Docker.
- Restrict runner egress to only what jobs require.

Until that exists, the safe posture is: approval-gated fork runs, no secrets or
publishing on the runner, and manual review before every outside-contributor run.
