# SecHelix V4 runner — quickstart

**This documents what is built. It is not a release.** The current release line
is `3.4.0-alpha.2` and contains none of this. Capabilities marked `SPECIFIED` or
`OPEN` in
[`architecture/v4-adaptive-evidence-runtime.md`](architecture/v4-adaptive-evidence-runtime.md)
are not documented here, because documenting unbuilt work is how a roadmap turns
into a claim.

## The runner is optional

The portable Agent Skill is the product. It cold-installs and works with none of
this installed, and `sechelix_core` never imports the runner — there is a test
that fails if it ever does. Install the runner when you want SecHelix
orchestrated by code instead of by an agent reading `SKILL.md`.

The runner uses the standard library only. There is nothing to `pip install`.

```bash
git clone https://github.com/omarmohelal/SecHelix
cd SecHelix
python -m sechelix_runner.cli doctor .
```

## The first thing you will see, and why

```
$ python -m sechelix_runner.cli audit . --depth quick

  BLOCKED    authorization   no reasoning executor configured; this node
                             analyses code and cannot be answered by the
                             runner alone
  SUCCEEDED  map
  BLOCKED    verify          dependency not satisfied: ai_mcp, api_protocol…
  BLOCKED    gate            dependency not satisfied: verify

RESULT  INCOMPLETE - unsatisfied mandatory nodes: gate, verify
        No security claim can be made from this run.
```

**That is correct behaviour, not a broken install.** The runner orchestrates; it
does not reason about code. With no reasoning executor configured, every
specialist lane is `BLOCKED` and the run ends `INCOMPLETE`.

The alternative would be worse. A stub returning "no findings" would produce a
report indistinguishable from a genuine clean audit, and a fail-closed release
gate would hand out a PASS for a run in which nothing was examined. So the
default executor blocks and says why.

Exit codes: `0` clean, `1` not clean, `2` usage error, `3` could not run.

## Commands

| Command | What it does |
|---|---|
| `doctor [path]` | Report available components. Optional ones may be absent. |
| `audit [path] --depth quick\|standard\|thorough` | Build and execute the graph, record the run |
| `runs [path]` | List recorded runs and their integrity |
| `replay <run-id> [path]` | Re-execute a recorded run offline |
| `report [run-id] --format markdown\|json` | Render a recorded run |
| `coverage [path]` | What previous runs did **not** examine |

Every command takes `--json` for machine-readable output.

Budget flags on `audit`: `--max-cost`, `--max-seconds`, `--max-nodes`.

## Where a run is stored

```
.sechelix/runs/<run-id>/
    run.json         records, routing, budget, context views
    graph.json       the nodes and dependencies that were executed
    events.jsonl     append-only, one JSON object per line, in order
    manifest.json    digest of every file above
    coverage.json    coverage report for this run
    replay/          recorded node outputs
```

`.sechelix/` is gitignored. Run data is working data, never repository content.
Values are redacted on write: anything whose key looks like a credential is
replaced, while token *counts* and structure survive so the record stays
readable and replayable.

## Replay

```bash
$ python -m sechelix_runner.cli replay RUN-349F873410204608 .
  faithful            True
  statuses match      True
  routing matches     True
  graph digest match  True
```

Replay re-executes routing, budget arithmetic, context projection and blocking
**for real**, playing back only node outputs — the part no rerun can reproduce.
It does not claim a model is deterministic; it claims the orchestration history
is.

Two refusals: a workspace whose bytes moved since `manifest.json` was written is
refused rather than replayed, and a recording that does not cover the graph
raises rather than inventing an outcome for the missing node.

## Coverage

```bash
$ python -m sechelix_runner.cli coverage .
coverage for SecHelix @ 9250b8015c57
  NEVER_COVERED    465

465 blind spot(s) - never covered or stale since coverage
```

The ledger answers what a findings list structurally cannot: *what did the last
audit not look at?* Seven states, and the distinctions matter:

- `NEVER_COVERED` — seen to exist, never examined by any run
- `NOT_REVISITED` — examined once, skipped this time
- `STALE` — examined at one commit, contents moved, nobody looked again
- `CHANGED` — re-examined *after* the contents moved
- `REUSED` — re-examined and still matches what was covered
- `NEW`, `UNKNOWN`

Coverage is credited only for lanes that actually delivered. Crediting a blocked
lane would turn this run's gap into next run's false reassurance.

## Local API

```bash
python -c "from sechelix_runner.api import serve; serve('.')"
```

Binds `127.0.0.1` and **refuses any non-loopback address**. It is read-mostly and
wraps the same run workspace the CLI reads — it computes no status of its own, so
it has no opinion that could disagree with the CLI.

`GET /runs`, `/runs/{id}`, `/runs/{id}/graph`, `/events`, `/findings`,
`/evidence`, `/report`, `/coverage`, `POST /runs/{id}/cancel`.
`POST /runs` returns `501` and points at the CLI rather than faking a run id.

## Network and sandbox posture

`STATIC` is the default and performs no network access at all; it will refuse to
issue a network grant. Under `LOCAL`/`STAGING`, egress is denied by default and
every grant names a host, port, protocol, **purpose**, scope and expiry. A grant
with no stated purpose is refused.

Public out-of-band interaction services (`interact.sh`, `oast.*`,
`burpcollaborator.net`, …) are refused by construction, subdomains included.
SecHelix does not prove findings by routing a target's traffic through a third
party.

The sandbox spec defaults to read-only root, all Linux capabilities dropped, no
new privileges, no network, and bounded memory/CPU/pids. It emits `docker run`
arguments; it does not start containers. `STATIC` needs no Docker.

## What this does not do

No reasoning provider is wired in. No protocol packs, no native lane, no browser
or HTTP evidence capture, no Workbench surfaces, and no competitive benchmark.
Those are `SPECIFIED` or `OPEN`, and nothing in this document should be read as
claiming otherwise.
