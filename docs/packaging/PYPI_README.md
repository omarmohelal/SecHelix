# sechelix

Optional execution runtime for the **SecHelix AppSec Agent Skill**.

The Agent Skill is the product and works without this package. Install `sechelix`
when you want the workflow orchestrated by code instead of by an agent reading
`SKILL.md`.

```bash
pipx install sechelix     # or: uv tool install sechelix
sechelix doctor
sechelix audit .
```

## What it does

- a deterministic reasoner DAG over 18 node roles, with cycle rejection
- per-node telemetry: model, provider, tokens, cost, duration, context digest
- a budget governor that **fails closed** — running out before a required
  verification produces `INCOMPLETE`, never a clean gate
- least-context specialist views, so a dependency reasoner never sees the whole
  repository narrative
- a coverage ledger that records what previous runs did **not** examine
- replayable run workspaces with tamper detection

## The first run will say INCOMPLETE

That is correct. The runner orchestrates; it does not reason about code. With no
reasoning executor configured every specialist lane is `BLOCKED` and the run
reports `No security claim can be made from this run.`

A stub returning "no findings" would be indistinguishable from a genuine clean
audit, and a fail-closed gate would hand out a PASS for a run that examined
nothing. To actually analyse code, pass `--executor claude-code` with an
authenticated Claude Code CLI on `PATH`.

## No dependencies

The runner uses the standard library only, and a test asserts it. A security tool
that drags in a dependency tree has widened the attack surface of the thing it
was installed to protect.

## Status

Alpha. Nothing here has been measured against another tool, and no comparative
claim is made. See the repository for what is measured and what is not.

- Repository: https://github.com/omarmohelal/SecHelix
- Quickstart: https://github.com/omarmohelal/SecHelix/blob/main/docs/v4-quickstart.md
- Licence: Apache-2.0
