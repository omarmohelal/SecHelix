# Deterministic-first discovery engine

`sechelix_runner/pentest/autodiscovery/` closes the discovery gap for the
expense-API benchmark: it finds the cross-tenant BOLA **without being supplied
the answer**, and refutes the SQL-pattern decoy, deterministically and with zero
model spend. (Named `autodiscovery` to avoid colliding with the existing
persona/authorization `discovery.py`.)

## Why deterministic-first

The last Strix run completed but did not drill into `/api/receipts/<id>`
(`gpt-4o-mini` guessed wrong paths). Rather than buy a bigger model and hope, the
reliable signal for object-level authorization flaws is mechanical: enumerate the
object ids each identity may legitimately see, then try them under a *different*
identity. A standard multi-account IDOR matrix finds the BOLA every time, for
free, and the result is reproducible evidence an independent verifier can confirm.

## What it is given (never the answer)

* a base URL (scope-locked — the probe cannot leave the authorized host);
* **legitimate test identities**, labelled only by `tenant` and `role` (e.g.
  `ada / northwind / approver`) — the kind of thing an operator knows about their
  own test users, not which object is sensitive;
* **documented routes** (`GET /api/receipts` with its documented `sort`/`dir`
  inputs) — the authoritative route information the brief says to use rather than
  guess.

## Pipeline

1. **Inventory** (`inventory.py`). Differential probing decides whether a route
   needs auth and which roles it accepts. Listing as each identity harvests the
   objects each one sees. The resource-id field and the **tenant-discriminator
   field** are *inferred from observed responses*: the discriminator is the field
   whose value partitions objects exactly as the known tenant labels do, tie-broken
   toward tenancy-like names (so `org_id` wins over a `memo` two receipts happen to
   share). The REST item endpoint (`/api/receipts/{id}`) is inferred and confirmed
   to exist, and its roles learned by differential probing.
2. **Hypotheses** (`hypotheses.py`). Bounded, testable questions ranked by value:
   object-level authz (BOLA, 90) > function-level authz (BFLA, 70) > injection on
   a reachable input (50). The planner runs credible high-value questions first.
3. **Execution** (`engine.py`). BOLA: the cross-identity matrix (try each
   harvested id under each identity; a cross-tenant `200` whose tenant field
   differs from the caller's is CONFIRMED). BFLA: a lower-privilege role against
   its *own* tenant's object (isolating the role control) — refused here, so
   REFUTED. Injection: a benign value vs classic payloads; all payloads rejected
   with no error-based signal ⇒ REFUTED ("no injection evidence").

Every step is written to a decision log with its evidence. Candidates are
**CANDIDATE**, not verified findings — they carry the HTTP evidence an independent
verifier reproduces.

## Proof on `examples/expense-api` (unseeded)

| Candidate | Result | Evidence |
|---|---|---|
| Cross-tenant read `GET /api/receipts/{id}` | **CONFIRMED** | org-1 approver read object 201 (`org_id=2`), HTTP 200 |
| Function-level authz on the item endpoint | **REFUTED** | employee → own-tenant item → HTTP 403 |
| SQL injection via `sort` | **REFUTED** | benign `sort=id` → 200; four payloads → 400/400/400/400 |

Inventory inferred: `tenant_field=org_id`, `resource id=id`, item endpoint
roles = `("approver",)` — none supplied. The org-1 list never shows 201; it is
harvested from the org-2 approver's own list and then read cross-tenant. A guard
test asserts no source file hardcodes `201` or the seed data.

Run it:

```bash
python -m sechelix_runner.pentest.autodiscovery http://127.0.0.1:8077 \
    --identities identities.json --routes routes.json
```

Tests: `tests/runner/test_discovery_engine.py` (6, spins up the real app).
Tokens are redacted from all output.

## Full remediation loop (discover -> verify -> fix -> retest)

`verifier.py` and `remediate.py` close the loop end to end (acceptance C -> D -> E),
run by `autodiscovery.run_remediation` over a `RemediationTarget`:

1. stand the target up **vulnerable** (throwaway copy) and **discover** candidates;
2. an **independent verifier** -- separate code path, re-derives attacker/owner
   from fresh listings, reads nothing from the discovery engine's state --
   reproduces each confirmed candidate against the vulnerable copy (**CONFIRMED**);
3. apply the target's **reference fix** (`fix.patch`) to an isolated copy;
4. the independent verifier re-runs against the **fixed** copy (**REFUTED**);
5. the **regression suite** runs against the fixed copy.

A candidate is FIXED only when it was reproduced before, refused after, *and* the
suite passes -- never because a patch merely applied. The working tree is never
touched; both states run from temp copies.

Real report on `examples/expense-api`:

```
bola GET /api/receipts/{id}
  before: CONFIRMED  approver/northwind read object 201 owned by tenant value 2 (HTTP 200)
  after : REFUTED    cross-tenant read was refused (HTTP 404); object-level ownership holds
  FIXED : True
regression: test_tenancy.py rc=0 OK   prove.py rc=0 OK
ALL_FIXED: True
```

Honesty note: the fix applied is the target's **reference** remediation, not an
LLM-synthesised patch. What is proven here is the discover -> independent-verify ->
before/after-regression -> retest loop with real HTTP evidence. Autonomous patch
*synthesis* for arbitrary code is a separate, unclaimed capability.

Tests: `tests/runner/test_remediation_flow.py` (4, spins up both states as real
subprocesses and runs the suites).

## Next slices (not done here)

* **Autonomous fix synthesis** (step 5 above currently applies the reference fix):
  localize the root cause in source and generate the minimal scoped-query patch.
* **Guide Strix** with the inventory + ranked hypotheses (the deterministic engine
  is the reliable floor; Strix can widen it). The remaining half of "guide Strix".
* **Multi-framework route extraction** (Flask/FastAPI/Express/Next.js/OpenAPI/
  GraphQL) beyond documented-route + REST inference.
* **Write / state-changing endpoints** and broader hypothesis classes.
