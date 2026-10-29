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

The fix in step 3 can come from either of two sources, held to the same bar.

Tests: `tests/runner/test_remediation_flow.py` (8: the loop in both fix modes,
spinning up both states as real subprocesses and running the suites).

## Autonomous fix synthesis (deterministic, no reference patch)

`fix_synth.py` makes step 3 real: instead of applying the target's `fix.patch`,
it **localizes the root cause in source and synthesizes the minimal scoped-query
patch** for the cross-tenant object-read class. Run with `run_remediation(target,
synthesize=True)`.

Given only the confirmed BOLA candidate (which names the tenant field, `org_id`)
and the app's source, it:

1. scans the app's own `*.py` for a parameterized `SELECT` that fetches an object
   by its resource id whose `WHERE` does **not** constrain the tenant column;
2. finds the authenticated principal already resolved in that handler (an
   assignment from `identify`/`authenticate`/…) to bind the caller's tenant from;
3. rewrites the lookup to `... AND org_id = ?` with `person["org_id"]` bound at the
   matching parameter position — a no-row result then falls through to the
   handler's existing 404, so the diff adds one predicate and one bound value and
   nothing else;
4. **abstains** (emits no patch) if any precondition fails — no parameterized id
   predicate, the query already scopes by the tenant column, the params are not an
   inline tuple, or no principal is in scope. The flow then reports that synthesis
   produced no patch rather than inventing one or silently falling back to the
   reference fix.

The patch is never trusted because it was generated. It is proven by the **same**
before/after independent-verification regression and retest suite as the reference
fix. Real run on `examples/expense-api` (reference `fix.patch` played no part):

```
FIX SOURCE: synthesized
LOCALIZED : app.py -- object fetched by 'id' with a query that does not constrain the caller's 'org_id'
SYNTHESIZED PATCH
   row = self.store.execute(
-      "SELECT * FROM receipt WHERE id = ?", (receipt_id,)
+      "SELECT * FROM receipt WHERE id = ? AND org_id = ?", (receipt_id, person["org_id"])
   ).fetchone()
  bola GET /api/receipts/{id}
    before: CONFIRMED  read object 201 owned by tenant value 2 (HTTP 200)
    after : REFUTED    cross-tenant read was refused (HTTP 404)
    FIXED : True
regression: test_tenancy.py rc=0 OK   prove.py rc=0 OK
ALL_FIXED: True
```

This is deliberately narrow: one root-cause shape, with explicit preconditions and
honest abstention — not a general code-repair model. The synthesized patch is the
behavioural core of the hand-written reference fix, derived from source rather than
supplied. Tests: `tests/runner/test_fix_synthesis.py` (9: the real-app synthesis
and four abstention cases).

## Next slices (not done here)

* **Guide Strix** with the inventory + ranked hypotheses (the deterministic engine
  is the reliable floor; Strix can widen it). The remaining half of "guide Strix".
* **Multi-framework route extraction** (Flask/FastAPI/Express/Next.js/OpenAPI/
  GraphQL) beyond documented-route + REST inference.
* **Write / state-changing endpoints** and broader hypothesis classes.
