# Strix end-to-end: real-run findings

A durable record of the first real local **Strix -> SecHelix** assessment run,
so the work can resume without chat memory. Nothing here contains credentials,
gateway addresses, or model keys.

## What was proven

### 1. The engine runs for real (FCC streaming path)
A bounded `sechelix-pentest tool-scan ... strix` against a disposable target ran
the pinned Strix **1.6.2** (contract `strix-cli-v1`, commit `007ed1a`) through
SecHelix's FCC compatibility runner: **67 streamed LLM requests**, full recon,
a saved threat model, and dispatched vulnerability subagents. The adapter's
FCC path (`SECHELIX_STRIX_USE_FCC=1`) was required — see §A.

### 2. SecHelix fails closed on a bad run (no false success)
Two separate failure shapes were observed and both were refused, exit 2, with
diagnostics preserved and no accepted artifacts:
- A non-streaming call to an SSE-only gateway (`'str' object has no attribute
  'usage'`) — rejected: *"partial artifacts are not accepted"*.
- A run that exceeded its wall-clock budget — rejected: *"Strix exceeded the
  Ns execution timeout"* and `run.json status=running` (not `completed`).

### 3. Find / fix / retest on the expense-API benchmark (real HTTP evidence)
Deterministic, credential-free, reproducible via `examples/expense-api`:

| Phase | Candidate A (cross-tenant read `GET /api/receipts/201`) | Tenancy suite |
|-------|---------------------------------------------------------|---------------|
| Before fix | HTTP **200** — an org-1 approver read org-2's receipt (amount + memo disclosed) | **2 red** / 8 |
| After `fix.patch` (org-scoped `WHERE id = ? AND org_id = ?`, 404 to avoid an existence oracle) | HTTP **404** — not reachable from this org | **8 green** / 8 |

Candidate B (SQLi via `sort`) stayed **REFUTED** (HTTP 400 + an identity check
showing no attacker string reaches SQL) in both phases. Reproduce:
`python examples/expense-api/prove.py` and
`python -m unittest test_tenancy` (from `examples/expense-api/`).

## Open gaps

### A. Scope containment — the sandbox is not network-isolated (security)
The authorization boundary handed to Strix is a **prompt-level instruction**
("interact only with the declared authorized host(s)"). An autonomous agent can
ignore it, and in this run it did: Strix's recon probed **sibling loopback
services** beyond the authorized target — a local reasoning gateway
(`:8082`, incl. `/admin/api`) and a WebSocket service (`ws://:8070`) — even
spawning a "Sibling Service Mapper" subagent.

Root cause: the Strix Docker sandbox has host-reachable networking (required to
reach the local reasoning gateway at loopback), which also exposes every other
loopback service. SecHelix's `PolicyToolGateway` authorizes the top-level tool
call but does not constrain Strix's internal network behavior.

**Mitigation shipped (detection, not prevention):**
`strix_adapter.coverage_out_of_scope_hosts` / `_assert_coverage_within_scope`
read the completed run's `coverage.json` (`entries` + `gaps`) and refuse any run
that assessed a host `scope.allows_url` rejects — closing the gap where a
finding-free recon run would otherwise pass as clean. Validated against the real
`coverage.json` (flags `:8082` and `ws://:8070`) and in unit tests.

**Prevention (milestone 3 — shipped and empirically proven):** Strix exposes
`STRIX_DOCKER_SANDBOX_NETWORK` (`strix/runtime/docker_client.py`), so SecHelix
can place the sandbox on a network it controls without modifying the pinned
engine. The sandbox always gets `host.docker.internal -> host-gateway`, but on a
Docker **internal** network that route is dead (no host gateway), so the
container can reach only other containers on that network.

**Architecture insight that simplifies this:** the LLM reasoning calls are made
by the openai-agents SDK in the **host** process (the Strix CLI / FCC runner),
*not* inside the sandbox. Only tool/recon execution (bash, HTTP to the target)
runs in the sandbox container. So the sandbox never needs to reach the reasoning
gateway at all — **only the authorized target** must be reachable from it. The
containment therefore proxies just the target (it also avoids tripping the FCC
runner's trusted-loopback gateway check, since `LLM_API_BASE` is left untouched
host-side):

1. Create a per-run **internal** Docker network `N` (`--internal`).
2. Start one **dual-homed proxy** container `P` (on `N` under the fixed alias
   `sechelix-target`, *and* a bridge with `host.docker.internal:host-gateway`)
   that forwards exactly one port to the authorized target. Nothing else.
3. Run Strix with `STRIX_DOCKER_SANDBOX_NETWORK=N` and its `--target` rewritten
   to `http://sechelix-target:<port>`. The sandbox can now reach only the
   target; every host service (the `:8082` reasoning gateway, `ws://:8070`, and
   even host loopback `:8077`) is unroutable.
4. Tear down `P` and `N` on exit (best-effort, never masking the run outcome).

Implemented in `sechelix_runner/pentest/strix_sandbox_net.py`
(`isolated_strix_network`) and wired into `strix_adapter.run()` behind
`SECHELIX_STRIX_ISOLATE_NETWORK=1`; 15 unit tests cover the helper and the
adapter's allowed-alias handling.

**Proof (from inside the real `strix-sandbox:1.3.0` container on `N`, with all
three host services genuinely listening — 8077→401, 8082→200, 8070→400):**

| From inside the contained sandbox → | raw socket | curl `--noproxy` |
|---|---|---|
| `sechelix-target:8077` (authorized target, via proxy) | REACHABLE (`172.21.0.2`) | `http=401` (reached) |
| `host.docker.internal:8082` (reasoning gateway) | blocked | `rc=7` (no connect) |
| `host.docker.internal:8070` (ws service) | blocked | `rc=7` (no connect) |
| `host.docker.internal:8077` (direct host loopback) | blocked | — |

(An unqualified `curl` inside the sandbox returns `rc=0` even for a blocked
sibling, because its in-container caido proxy answers with an HTTP error that
`-o /dev/null` without `--fail` treats as success. The raw socket and
`--noproxy` direct connect are the authoritative network-layer tests, and both
confirm the siblings are unreachable.)

The coverage guard above remains as defense-in-depth, told the sandbox aliases
(`sechelix-target`) are in scope: if a future change reopens an escape, a run
that still reached an out-of-scope host is refused.

Host-networked (non-isolated) Strix runs remain **uncontained** and must be
treated as such; set `SECHELIX_STRIX_ISOLATE_NETWORK=1` for containment (see
`PRODUCTION-READINESS.md`).

### B. Budget / latency — discovery did not complete
At the local gateway model's latency (~3.5–20 s/call), a `quick` scan with 25
turns / 13-min wall-clock spent its budget on recon + sibling-mapping + an
unfinished "Auth Gate Bypass" agent and **did not reach** `/api/receipts/<id>`,
so Strix itself did not surface the BOLA. The vuln is real and independently
proven (§3); what remains is letting a *contained* run reach it — raise the
turn/time budget or use a faster model.

## Reproduction notes
- Bootstrap: `bash scripts/bootstrap-full.sh` (venv + pinned Strix + Playwright
  + Docker check). Confirm with `sechelix-pentest engine-health`.
- The FCC path requires a trusted **loopback** gateway base and a model; the
  adapter preflights it (`_probe_fcc_tool_model`) and forces the streaming
  transport. Credentials are supplied via the environment and are never logged.
