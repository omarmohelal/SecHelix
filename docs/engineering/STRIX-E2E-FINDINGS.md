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

### A. Scope containment — fail-closed bounded egress (shipped and proven)
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

**Prevention (shipped and proven working): a fail-closed, bounded-egress
in-netns firewall.** Keep Strix on its **default** network so its published
ports and `host.docker.internal` route are untouched — Caido bootstraps exactly
as it does uncontained — and constrain egress from *inside* the sandbox's network
namespace with a **default-DROP** policy, proven from inside the sandbox before
the run is accepted.

*Why not a custom Docker network (the first attempt, abandoned).* Strix exposes
`STRIX_DOCKER_SANDBOX_NETWORK`, so the sandbox can be put on a per-run
`--internal` network + a dual-homed target proxy. That blocks egress, but it also
**breaks the assessment**: that knob makes Strix drop the sandbox's published
ports and resolve **Caido** (its HTTP-interception proxy, the backbone of its web
testing) at the container's own network IP. On Docker Desktop / WSL2 the host
cannot reach a container IP (measured — true even on a normal bridge), so Caido
never bootstraps (`InstanceNotReadyError` → "proxy tools unavailable"), every
agent HTTP request fails, and the run assesses nothing. So a custom network is a
non-starter here.

*The shipped design (bounded egress, not just a sibling-port filter).* An
earlier version filtered only the `host.docker.internal` gateway by port — which
left the sandbox's **ordinary outbound internet access wide open**; that is *not*
a real egress boundary. The shipped policy is default-DROP:

1. Leave `STRIX_DOCKER_SANDBOX_NETWORK` unset (default network; Caido works).
2. A background watcher spots the sandbox the moment it appears (matched by image
   name — a tagless `--filter ancestor=` resolves to `:latest` and matches
   nothing) and **pauses it immediately** so it cannot emit a packet while the
   rules go in. This shrinks the create-to-enforce race to the sub-second
   detection latency rather than the whole rule-install duration.
3. A short-lived **sidecar** built from a **pinned, prebuilt helper image**
   (`sechelix-strix-fw`, iptables baked in — no per-scan `apk` download) shares
   the sandbox's netns (`--net=container:<sandbox>` + `NET_ADMIN`) and installs a
   default-DROP OUTPUT chain: accept loopback (Caido + the embedded DNS resolver
   at `127.0.0.11`), established/related, DNS to the resolver, and the single
   target port on the gateway — **drop everything else** (other gateway ports,
   sibling services, and the entire public internet). Rules persist in the shared
   namespace and die with the sandbox.
4. The watcher **unpauses and independently verifies from inside the sandbox**
   that the target connects while a non-target gateway port and the public
   internet are dropped. Only then is the run marked *contained*. Any failure
   kills the sandbox; `strix_adapter` **refuses a run that is not proven
   contained** (fail-closed — nothing is silently continued).

*Per-run ownership (safe under concurrency).* At entry we snapshot the
pre-existing sandboxes (`baseline`) and never touch them, and we claim each newly
appearing sandbox through an **atomic cross-process registry** (one lock file per
container id, carrying the owner pid). A sandbox owned by another live run is
skipped; teardown force-removes **only** sandboxes this run claimed; a startup
reaper clears claims whose owner process is dead and removes the orphan. A run
can therefore never firewall or delete another scan's container.

The LLM reasoning runs in the host CLI process, not the sandbox, so nothing the
sandbox legitimately needs (other than the target) lives beyond the firewall; a
default drop costs the assessment nothing.

Implemented in `sechelix_runner/pentest/strix_sandbox_net.py`
(`firewalled_strix_sandbox`, `_contain_one`, claim registry, helper image) and
wired into `strix_adapter.run()` behind `SECHELIX_STRIX_ISOLATE_NETWORK=1`;
**22 unit tests** cover the module and **3 adapter tests** cover the fail-closed
gate.

**Proof A — mechanism, LLM-free, against a real strix-sandbox container:** the
target port is reachable (rc 0) while a sibling host port *and the public
internet* (`1.1.1.1:80`, `8.8.8.8:443`) are dropped (rc 28), DNS still resolves
the target, `_verify_containment` passes, a pre-existing foreign sandbox is left
running and un-firewalled, and teardown leaves zero sidecars.

**Proof B — live, from inside the real Strix sandbox during a contained
OpenRouter run** (`SECHELIX_STRIX_ISOLATE_NETWORK=1`, the real reasoning gateway
serving on `:8082`):

| From inside the running sandbox → | Result |
|---|---|
| `host.docker.internal:8077` (authorized target) | **http=200, rc=0** — reachable |
| `host.docker.internal:8082` (reasoning gateway, live) | **blocked** (`rc=28`) |
| `host.docker.internal:9999` (dead port) | **blocked** (`rc=28`, drop not reset) |
| `1.1.1.1:80` (public internet) | **blocked** (`rc=28`) |

And in the same run: the adapter **accepted** it (`SCAN_EXIT=0` — containment was
proven), **Caido bootstrapped** (`host=http://127.0.0.1:45915`, project
selected — no failure, *despite the pause*), `coverage.json` recorded **only**
the target, and teardown left **zero** sandboxes, sidecars, and claim files. So
the containment is a real bounded-egress boundary *and* keeps the assessment
working.

**Known, bounded limitation.** Strix creates the sandbox itself, so there is a
sub-second window between the sandbox starting and the watcher pausing it, before
which a rule is not yet in force. The sandbox spends that first moment on Caido
bootstrap (host-driven), not egress, and the coverage-record guard below refuses
any run that still reached an out-of-scope host — but the window is non-zero.
Closing it fully would require a sandbox-creation hook Strix does not expose.

The coverage-record guard remains as fail-closed defence in depth, using the
real target scope.

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
