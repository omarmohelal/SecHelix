"""Security regression test for the tenancy boundary.

    python examples/expense-api/test_tenancy.py

**This test fails on the code as shipped.** That is the point: it is written
against the vulnerability, so it is red before the fix and green after, which is
the only thing that makes it evidence rather than decoration. A test written
after a fix that never failed proves nothing about the fix.

It is not collected by the repository's own suite. `tests/test_demo_expense_api.py`
drives it deliberately, in both states.
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import app  # noqa: E402

HOST = "127.0.0.1"

#: (token, org) pairs. Ada approves for Northwind; Cy approves for Contoso.
NORTHWIND_APPROVER = "tok-ada"
NORTHWIND_EMPLOYEE = "tok-bo"
CONTOSO_APPROVER = "tok-cy"

NORTHWIND_RECEIPT = 101
CONTOSO_RECEIPT = 201


class TenancyBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        database = Path(tempfile.mkdtemp()) / "expense-test.sqlite"
        cls.server = ThreadingHTTPServer((HOST, 0), app.build(database))
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def get(self, path: str, token: str):
        request = urllib.request.Request(
            f"http://{HOST}:{self.port}{path}", headers={"Authorization": f"Bearer {token}"}
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")

    # -- the regression itself ------------------------------------------------

    def test_approver_cannot_read_another_orgs_receipt(self):
        """The bug. Red before the fix, green after."""
        status, body = self.get(f"/api/receipts/{CONTOSO_RECEIPT}", NORTHWIND_APPROVER)
        self.assertNotEqual(
            status, 200,
            f"cross-tenant read succeeded and returned {body}",
        )
        self.assertIn(status, (403, 404))

    def test_the_reverse_direction_too(self):
        """Fixing one direction and not the other is a half fix."""
        status, _ = self.get(f"/api/receipts/{NORTHWIND_RECEIPT}", CONTOSO_APPROVER)
        self.assertIn(status, (403, 404))

    # -- what the fix must not break -----------------------------------------

    def test_approver_can_still_read_their_own_orgs_receipt(self):
        status, body = self.get(f"/api/receipts/{NORTHWIND_RECEIPT}", NORTHWIND_APPROVER)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["org_id"], 1)

    def test_role_check_still_applies_within_the_org(self):
        """An employee in the right org is still not an approver."""
        status, _ = self.get(f"/api/receipts/{NORTHWIND_RECEIPT}", NORTHWIND_EMPLOYEE)
        self.assertEqual(status, 403)

    def test_listing_is_still_scoped_to_the_callers_org(self):
        status, body = self.get("/api/receipts", NORTHWIND_APPROVER)
        self.assertEqual(status, 200)
        self.assertTrue(body["receipts"])
        for receipt in body["receipts"]:
            self.assertEqual(receipt["org_id"], 1)

    def test_unknown_receipt_is_still_a_404(self):
        status, _ = self.get("/api/receipts/9999", NORTHWIND_APPROVER)
        self.assertEqual(status, 404)

    def test_unauthenticated_is_still_a_401(self):
        status, _ = self.get(f"/api/receipts/{NORTHWIND_RECEIPT}", "nonsense")
        self.assertEqual(status, 401)

    # -- the decoy stays refuted ---------------------------------------------

    def test_sort_parameter_rejects_anything_but_a_known_column(self):
        for payload in ("id; DROP TABLE receipt--", "id) UNION SELECT * FROM person--"):
            with self.subTest(payload=payload):
                status, _ = self.get(
                    "/api/receipts?sort=" + urllib.parse.quote(payload, safe=""),
                    NORTHWIND_APPROVER,
                )
                self.assertEqual(status, 400)


if __name__ == "__main__":
    import urllib.parse  # noqa: E402

    unittest.main(verbosity=2)
