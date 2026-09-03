# Project history

A map of the commit history, so it reads as a sequence of decisions rather than
a wall of 131 entries.

The history is deliberately **not** squashed or rewritten. This project's claim
is that evidence survives, and a rewritten history is the one artifact that
would contradict it most directly. Every tag, every published release SHA, and
the commit id referenced in the pending Awesome Copilot submission all still
resolve.

## Shape

| | |
|---|---|
| Commits | 131 |
| Span | 2026-08-31 → 2026-09-03 |
| Merge commits | 2 (PRs #1 and #5, before the squash-only policy) |
| Everything since | squash-merged, one PR per commit |
| Tags | `v3.2.0-alpha.1`, `v3.4.0-alpha.1`, `v3.4.0-alpha.2` |

Prefix distribution: `docs` 50, `feat` 25, `V4` 12, `chore` 7, `ci` 6, `site` 4,
`release` 2, and one each of `eval`, `fix`, `test`.

**Fifty documentation commits against twenty-five feature commits is the ratio
this project intends.** Most of them record what was measured, what was not, and
what a number does not license — which is the product, not overhead around it.

## Phases

### 1 — Foundation (`d0ac961` → `c41272e`, 2026-08-31)

The catalog, the evidence contracts, the specialist agents and the release gate.
Establishes the 546-hypothesis model (21 families × 26 lenses) and the schema set
that everything later consumes.

### 2 — Public surfaces and distribution (→ `aba5a15`, 2026-09-01/02)

Website, marketplace, plugin manifests, directory submissions. Also where the
CI gates that still run today were added: catalog validation, doc-consistency,
commit hygiene, secret scanning, private-site leakage.

### 3 — The first uncontaminated measurement (`75d25b0`, 2026-09-02)

The blind label suite finally ran clean: 76 cases judged by 76 independent
processes, precision 0.950, FP rejection 0.947. The same commit fixed a defect
the run exposed in the protocol itself — the published packet digest had been
computed on a Windows working copy with CRLF endings, so anyone following the
documented download got a different hash.

`0acb080` and `23997c2` immediately follow, and they exist to stop that number
being over-claimed: the blind suite is `MEASURED`, the full workflow stays
`NOT_MEASURED`, and every public surface says so.

### 4 — Release 3.4.0-alpha.2 (`61f72fd` → `266fcfc`, 2026-09-02)

Version bump, then the discovery baselines. `266fcfc` records that SecHelix
appeared in **0 of 6** Gemini answers and 0 of 3 Google AI Mode answers, and that
the branded query returned six unrelated entities. Recording a result that
unflattering is the point of keeping the file.

### 5 — V4 groundwork (`142190e`, 2026-09-02)

Five competitor implementations read from cloned source at pinned commits. The
audit exposed a defect in SecHelix's own contract: a finding could declare
`impact` established while `attacker_control` was not — exactly what
`runtime_trace.py` promises in prose and nothing enforced.

### 6 — V4 runner, stages 1–7 (`7f378b2` → `5d7a609`, 2026-09-02/03)

One PR per stage: DAG and telemetry, run storage and replay, coverage ledger and
adaptive routing, compliance mapping, sandbox and proof policy, the self-audit,
then the local API.

`0e50b56` is the one worth reading. Pointing SecHelix at its own runner found a
path traversal: `run_id` came from the command line and was joined straight onto
the runs directory, so `../../outside.json` escaped the workspace and `report`
would read and print it.

### 7 — V4 made real (`fd265a6` → `375c00b`, 2026-09-03)

The runner stopped being an orchestrator with nothing to orchestrate: a
provider-neutral reasoning executor, packaging for `pipx`, actual container
execution with seven confinement probes, SARIF and HTML output, a GitHub Action,
and an MCP adapter.

## Reading conventions

- **One commit per merged PR.** The reasoning lives in the pull request; the
  commit body is a summary. `scripts/check_commit_hygiene.py` enforces a 25-line
  ceiling and rejects assistant co-author trailers and session links.
- **A `docs:` commit is usually a measurement**, not prose. If it records a
  number, it also records what the number does not support.
- **`baseline 1598faa20306`** in `check_commit_hygiene.py` is the point from
  which hygiene is enforced. Commits before it predate the policy.
