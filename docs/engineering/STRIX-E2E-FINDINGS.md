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

**Prevention (milestone 3 — shipped and proven working): an in-netns egress
firewall.** Keep Strix on its **default** network so its published ports and
`host.docker.internal` route are untouched — Caido bootstraps exactly as it does
uncontained — and constrain egress from *inside* the sandbox's network namespace
instead of rerouting it.

*Why not a custom Docker network (the first attempt, now abandoned).* Strix
exposes `STRIX_DOCKER_SANDBOX_NETWORK`, so the sandbox can be put on a per-run
`--internal` network + a dual-homed target proxy. That provably blocks the
siblings, but it also **breaks the assessment**: setting that knob makes Strix
drop the sandbox's published ports and resolve **Caido** (its HTTP-interception
proxy, the backbone of its web testing) at the container's own network IP. On
Docker Desktop / WSL2 the host cannot reach a container IP (measured — true even
on a normal bridge), so Caido never bootstraps
(`InstanceNotReadyError` → "proxy tools unavailable"), every agent HTTP request
fails, and the run assesses nothing. So a custom network is a non-starter here.

*The shipped design.* The sandbox reaches the authorized target **and** the
sibling host services through the same `host.docker.internal` gateway IP
(`192.168.65.254` on Docker Desktop), differing only by port — so filter that
gateway by port:

1. Leave `STRIX_DOCKER_SANDBOX_NETWORK` unset (default network; Caido works).
2. A background watcher spots the sandbox the moment it appears (matched by image
   name — a tagless `--filter ancestor=` resolves to `:latest` and matches
   nothing).
3. Because the strix-sandbox image has no `iptables` and we cannot inject one at
   creation, a short-lived **sidecar** that shares the sandbox's network
   namespace (`--net=container:<sandbox>` + `NET_ADMIN`) carries its own
   `iptables` and installs rules on the gateway IP: accept established/related,
   accept the single target port, drop everything else. Rules persist in the
   shared namespace and die with the sandbox.
4. On exit the watcher stops and force-removes any sandbox it firewalled (a
   timed-out run can orphan one, and an orphan is a reuse hazard).

The LLM reasoning is made by the host process, not the sandbox, so nothing the
sandbox legitimately needs (other than the target) lives behind the gateway; a
blanket drop of the other gateway ports costs the assessment nothing.

Implemented in `sechelix_runner/pentest/strix_sandbox_net.py`
(`firewalled_strix_sandbox`) and wired into `strix_adapter.run()` behind
`SECHELIX_STRIX_ISOLATE_NETWORK=1`; 11 unit tests cover the helper.

**Proof — live, from inside the real Strix sandbox during a contained OpenRouter
run** (`SECHELIX_STRIX_ISOLATE_NETWORK=1`, with the real reasoning gateway
genuinely serving HTTP 200 on `:8082`):

| From inside the running sandbox → | Result |
|---|---|
| `host.docker.internal:8077` (authorized target) | **http=200** — reachable |
| `host.docker.internal:8082` (reasoning gateway, live) | **blocked** (`rc=28` timeout) |
| `host.docker.internal:8070` (ws service) | **blocked** (`rc=28` timeout) |

And in the same run: **Caido bootstrapped** (`host=http://127.0.0.1:45933`,
project selected — no failure), the run **completed in budget**, `coverage.json`
recorded **only** the target, and teardown left zero sandboxes/sidecars. So the
containment now blocks siblings *and* keeps the assessment working — the
`--internal` Caido breakage is resolved.

The coverage-record guard remains as fail-closed defence in depth, using the
real target scope: if the firewall's small apply-after-start window were ever
lost, a run that still reached an out-of-scope host is refused.

Host-networked runs without `SECHELIX_STRIX_ISOLATE_NETWORK=1` remain
**uncontained** and must be treated as such.

### B. Budget / latency — resolved; model capability now the only open item
At the local gateway model's latency (~3.5–20 s/call), a `quick` scan with 25
turns / 13-min wall-clock spent its budget on recon + sibling-mapping + an
unfinished "Auth Gate Bypass" agent and **did not reach** `/api/receipts/<id>`,
so Strix itself did not surface the BOLA.

Raising the budget did **not** close this on the slow model: a contained run at
**45 turns / 2000s** still exhausted its time on recon and SecHelix fail-closed
on the timeout (`SCAN_EXIT=2`, refused — the run never counted as complete),
coverage again in scope.

**A faster model fixes the throughput problem.** Rerun on OpenRouter
`openai/gpt-4o-mini` (probed at ~1 s/call vs the local gateway's 3.5–20 s): the
contained run **completed within budget** (`run_status: completed`,
`SCAN_EXIT=0`) — no timeout. Wiring: non-FCC path, env overrides cli-config to
point Strix at OpenRouter as an OpenAI-compatible endpoint
(`STRIX_LLM=openai/openai/gpt-4o-mini`, `LLM_API_BASE=https://openrouter.ai/api/v1`);
reasoning is host-side so containment is unchanged.

With the firewall containment (§A) a `gpt-4o-mini` run **completes in budget with
Caido working**, so neither throughput nor the old Caido breakage is a blocker
any more. What remains is **model capability**: `gpt-4o-mini` finished the loop
but did not drill into `/api/receipts/<id>` (it guessed `/api/v1/users` and a
`/search` endpoint), so it did not surface the BOLA itself. The vuln is real and
independently proven (§3); having Strix *itself* surface it is now purely a
matter of a stronger (still fast) reasoning model driving the agent — the
remaining open item here. Containment and throughput are resolved.

## Reproduction notes
- Bootstrap: `bash scripts/bootstrap-full.sh` (venv + pinned Strix + Playwright
  + Docker check). Confirm with `sechelix-pentest engine-health`.
- The FCC path requires a trusted **loopback** gateway base and a model; the
  adapter preflights it (`_probe_fcc_tool_model`) and forces the streaming
  transport. Credentials are supplied via the environment and are never logged.
