# Demo: one real vulnerability, one refuted false positive

A small multi-tenant expense API with two candidate security issues. One is
real. One looks worse than the real one and is not exploitable at all.

Telling them apart is the entire job, and it is the thing SecHelix is built to
do. Everything below runs locally, needs no install, and takes about 90 seconds.

**Requirements:** Python 3.10+. No dependencies, no network, no containers.

---

## 1. See both candidates (30s)

```bash
python examples/expense-api/prove.py
```

Real output, abbreviated:

```text
CANDIDATE A -- cross-tenant read via GET /api/receipts/<id>

  GET /api/receipts/201   Authorization: Bearer tok-ada
  -> HTTP 200
  -> {"id": 201, "merchant": "Legal counsel", "amount_cents": 750000,
      "memo": "Retainer re: Project Halcyon acquisition", "org_id": 2}

  STATUS: VERIFIED -- a caller in org 1 read a record owned by org 2.

  Control that does work: employee token -> HTTP 403

CANDIDATE B -- SQL injection via the sort parameter (decoy)

  sort='id; DROP TABLE receipt--'      -> HTTP 400
  sort='id) UNION SELECT * FROM person--' -> HTTP 400
  receipt table after every payload: 3 rows (unchanged)

  STATUS: REFUTED -- reachable, but not exploitable. Not a finding.
```

The script asserts everything it prints and exits non-zero if reality stops
matching, so this page cannot drift into describing a run that no longer happens.

---

## 2. Why each one is what it is

### Candidate B is the one a scanner reports

`reports.py` builds an `ORDER BY` clause with an f-string:

```python
query = f"SELECT * FROM receipt WHERE org_id = ? ORDER BY {column} {order}"
```

That is the exact shape of a SQL injection. It is also not one. `resolve_sort`
does not sanitize the caller's string — it *maps* it onto one of five constants
defined in the module and rejects everything else:

```python
SORTABLE_COLUMNS = ("id", "merchant", "amount_cents", "status", "person_id")
```

The refutation is structural, not just empirical. `prove.py` checks by identity
that the object reaching the query text is the module constant itself, so it is
not enough to say "the payloads I thought of were rejected" — no string derived
from the request can survive the mapping at all.

Reporting this costs a reviewer an hour, and reporting several of them costs you
the next real finding.

### Candidate A is the one a scanner walks past

`app.py` has an authorization check on the endpoint:

```python
auth.require_role("approver")(person)
```

The check is present, correct, and enforced — an employee token really does get
`403`. A tool looking for missing authorization finds authorization and moves on.

The check answers the wrong question. It asks *"may someone like you open a
receipt?"* and never *"is this receipt yours?"*. The lookup underneath is
unscoped:

```python
row = self.store.execute("SELECT * FROM receipt WHERE id = ?", (receipt_id,))
```

So any approver at any tenant can read any receipt in the system by id.

**Root cause:** the query is scoped by nothing. Role and tenancy are different
questions, and the endpoint answers only the first.

---

## 3. Regression proof *before* the fix (15s)

```bash
python examples/expense-api/test_tenancy.py
```

```text
Ran 8 tests
FAILED (failures=2)
AssertionError: 200 == 200 : cross-tenant read succeeded and returned
  {'id': 201, 'merchant': 'Legal counsel', ...}
```

Two red, six green. The six that pass are the controls the fix must not break:
same-org reads still work, the role check still applies, listing is still scoped,
unknown ids are still `404`, bad tokens are still `401`, and the decoy is still
rejected.

**Writing the test first is the point.** A test added after a fix, that never
failed, is evidence of nothing.

---

## 4. Apply the smallest fix (15s)

```bash
git apply examples/expense-api/fix.patch
```

Two changed lines:

```diff
-                "SELECT * FROM receipt WHERE id = ?", (receipt_id,)
+                "SELECT * FROM receipt WHERE id = ? AND org_id = ?",
+                (receipt_id, person["org_id"]),
```

Scoping the query rather than filtering the row afterwards is deliberate.
Fetching the row and then comparing `org_id` also works, but it leaves a moment
where a record the caller may not see exists in a local variable, and every
future edit to the handler has to remember the comparison. A row from another
tenant is now never loaded at all.

The response is `404`, not `403`. A `403` would confirm the id exists, which is
an existence oracle over every other tenant's receipt ids.

---

## 5. Regression proof after the fix (15s)

```bash
python examples/expense-api/test_tenancy.py
python examples/expense-api/prove.py
```

```text
Ran 8 tests
OK

  Candidate A : REFUTED (fix applied)
  Candidate B : REFUTED (decoy)
```

The same test that failed now passes, the six controls still pass, and the
original reproduction no longer reproduces. That is what "verified fixed" means
here.

Put it back with `git apply -R examples/expense-api/fix.patch`.

---

## What this demo does and does not show

**Does.** The difference between a candidate and a finding; a refutation that is
structural rather than "I tried some payloads"; a root cause rather than a
symptom; a regression test that was red first; and a re-run that closes the loop.

**Does not.** Measure detection rate. Two hand-built cases measure nothing, and
no accuracy claim should be made from this page. SecHelix's public benchmark
position is `NOT_MEASURED`, deliberately.

The API here is a teaching target — a real one would have sessions, rate limits,
audit logging and rather more than four users.

## Running the API yourself

```bash
python examples/expense-api/app.py --port 8077
curl -H "Authorization: Bearer tok-ada" http://127.0.0.1:8077/api/receipts/201
```

| Token | Org | Role |
|---|---|---|
| `tok-ada` | Northwind (1) | approver |
| `tok-bo` | Northwind (1) | employee |
| `tok-cy` | Contoso (2) | approver |
| `tok-dee` | Contoso (2) | employee |

## Files

| File | What it is |
|---|---|
| `app.py` | Routes, and the unscoped lookup that is candidate A |
| `auth.py` | Token identity and the role check that is present but insufficient |
| `reports.py` | The f-string SQL that is candidate B, and the mapping that refutes it |
| `db.py` | Schema and seed data for two tenants |
| `prove.py` | Safe local reproduction of both candidates; asserts what it prints |
| `test_tenancy.py` | The security regression test — red before the fix, green after |
| `fix.patch` | The smallest safe remediation |

`tests/test_demo_expense_api.py` in the repository suite drives all of the above
in both states on every CI run, so the walkthrough cannot silently stop working.
