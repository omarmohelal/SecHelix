"""Safe local proof for the two candidates SecHelix raises against this app.

Everything here runs against a throwaway SQLite database on 127.0.0.1. Nothing
leaves the machine, nothing is destructive, and the script exits non-zero if
reality stops matching what it claims -- so a stale transcript cannot masquerade
as a current result.

    python examples/expense-api/prove.py

Two candidates, opposite outcomes:

  A. GET /api/receipts/<id> checks a role and never checks tenancy.
  B. reports.list_receipts interpolates a column name into SQL.

A is the real one. B is the decoy, and refuting it is as much the point as
proving A.
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import app  # noqa: E402
import db  # noqa: E402
import reports  # noqa: E402

HOST = "127.0.0.1"


def serve(database: Path) -> tuple[ThreadingHTTPServer, int]:
    handler = app.build(database)
    server = ThreadingHTTPServer((HOST, 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def get(port: int, path: str, token: str) -> tuple[int, dict]:
    request = urllib.request.Request(
        f"http://{HOST}:{port}{path}", headers={"Authorization": f"Bearer {token}"}
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


def rule(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def main() -> int:
    database = Path(tempfile.mkdtemp()) / "expense-proof.sqlite"
    server, port = serve(database)
    failures: list[str] = []

    try:
        # ------------------------------------------------------------------
        rule("CANDIDATE A -- cross-tenant read via GET /api/receipts/<id>")

        print("Ada is an approver at Northwind (org 1).")
        print("Receipt 201 belongs to Dee at Contoso (org 2).\n")

        status, body = get(port, "/api/receipts/201", "tok-ada")
        print(f"  GET /api/receipts/201   Authorization: Bearer tok-ada")
        print(f"  -> HTTP {status}")
        print(f"  -> {json.dumps(body)}\n")

        if status == 200 and body.get("org_id") == 2:
            print("  Attacker control : any authenticated approver, any receipt id")
            print("  Boundary failed  : tenant isolation between org 1 and org 2")
            print(f"  Data disclosed   : {body['merchant']!r}, {body['amount_cents']} cents,")
            print(f"                     memo {body['memo']!r}")
            print("\n  STATUS: VERIFIED -- a caller in org 1 read a record owned by org 2.")
        elif status == 404:
            print("  STATUS: REFUTED -- the receipt is not reachable from this org.")
            print("  (Expected once the fix is applied. 404 rather than 403 is")
            print("  deliberate: a 403 would confirm the id exists, which is an")
            print("  existence oracle over every other tenant's receipt ids.)")
        else:
            failures.append(f"candidate A produced an unexpected result: {status} {body}")

        # The control that *is* present, so nobody mistakes this for "no authz".
        status_employee, _ = get(port, "/api/receipts/201", "tok-bo")
        print(f"\n  Control that does work: employee token -> HTTP {status_employee}")
        if status_employee != 403:
            failures.append("the role check itself is broken; that is a different bug")
        print("  The role check is present and correct. It answers 'may someone like")
        print("  you open a receipt?' and never 'is this receipt yours?'.")

        # ------------------------------------------------------------------
        rule("CANDIDATE B -- SQL injection via the sort parameter (decoy)")

        print("reports.py builds ORDER BY with an f-string. Pattern matchers flag it.\n")

        payloads = [
            "id; DROP TABLE receipt--",
            "id) UNION SELECT * FROM person--",
            "(SELECT token FROM person LIMIT 1)",
            "amount_cents--",
        ]
        for payload in payloads:
            path = "/api/receipts?sort=" + urllib.parse.quote(payload, safe="")
            status, body = get(port, path, "tok-ada")
            print(f"  sort={payload!r}")
            print(f"  -> HTTP {status} {json.dumps(body)}")
            if status != 400:
                failures.append(f"payload {payload!r} was not rejected: {status} {body}")

        connection = db.connect(database)
        still_there = connection.execute("SELECT COUNT(*) FROM receipt").fetchone()[0]
        print(f"\n  receipt table after every payload: {still_there} rows (unchanged)")
        if still_there != 3:
            failures.append("the receipt table changed; candidate B is not a decoy")

        # The refutation is structural, not just empirical: show that the only
        # values that can reach the query text are constants defined in source.
        print("\n  Structural refutation -- the value that reaches the SQL string is")
        print("  never derived from the request. resolve_sort returns an element of")
        print(f"  reports.SORTABLE_COLUMNS = {reports.SORTABLE_COLUMNS}")
        for column in reports.SORTABLE_COLUMNS:
            resolved, _ = reports.resolve_sort(column, "asc")
            if resolved is not column:
                failures.append(f"resolve_sort returned a non-constant for {column!r}")
        print("  and each returned object is the module constant itself (identity check")
        print("  passed for all five), so no attacker-controlled string survives.")
        print("\n  STATUS: REFUTED -- reachable, but not exploitable. Not a finding.")

        # ------------------------------------------------------------------
        rule("RESULT")
        if failures:
            for failure in failures:
                print(f"  MISMATCH: {failure}")
            print("\n  This script asserts what it prints. Something changed.")
            return 1

        fixed = get(port, "/api/receipts/201", "tok-ada")[0] == 404
        print("  Candidate A : " + ("REFUTED (fix applied)" if fixed else "VERIFIED"))
        print("  Candidate B : REFUTED (decoy)")
        print("\n  One real vulnerability, one refuted false positive.")
        return 0
    finally:
        server.shutdown()


if __name__ == "__main__":
    import urllib.parse  # noqa: E402  (used above; imported late to keep the header short)

    raise SystemExit(main())
