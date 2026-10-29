"""Benchmark: deterministic discovery on examples/expense-api, unseeded.

The engine is given only the base URL, the four labelled test identities, and the
documented ``GET /api/receipts`` route (with its documented ``sort``/``dir``
inputs). It is never told that receipt 201 leaks or that the ``sort`` parameter
is the decoy. It must, from observation alone:

* discover and CONFIRM the cross-tenant read on ``GET /api/receipts/{id}`` (the
  BOLA), with reproducible HTTP evidence; and
* REFUTE the SQL-injection candidate on ``sort``.

This is acceptance criteria C and D for milestone 1, run against the real app.
"""

from __future__ import annotations

import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from sechelix_runner.pentest.autodiscovery import (
    Confidence,
    Identity,
    RouteSpec,
    run_discovery,
)

EXPENSE_API = Path(__file__).resolve().parents[2] / "examples" / "expense-api"
sys.path.insert(0, str(EXPENSE_API))

import app as expense_app  # noqa: E402  (fixture under examples/expense-api)

# Labels only -- tenant + role, as an operator knows their own test users. These
# never say which object is sensitive.
IDENTITIES = [
    Identity(name="ada", token="tok-ada", tenant="northwind", role="approver"),
    Identity(name="bo", token="tok-bo", tenant="northwind", role="employee"),
    Identity(name="cy", token="tok-cy", tenant="contoso", role="approver"),
    Identity(name="dee", token="tok-dee", tenant="contoso", role="employee"),
]
ROUTES = [RouteSpec(method="GET", path="/api/receipts", inputs=("sort", "dir"))]


class DiscoveryBenchmark(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        database = Path(tempfile.mkdtemp()) / "discovery-bench.sqlite"
        handler = expense_app.build(database)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def test_discovers_bola_and_refutes_sqli_unseeded(self) -> None:
        report = run_discovery(self.base, IDENTITIES, ROUTES)

        # --- C: the cross-tenant read is discovered and CONFIRMED ---
        bola = [c for c in report.candidates if c.kind == "bola"]
        confirmed = [c for c in bola if c.confidence is Confidence.CONFIRMED]
        self.assertTrue(confirmed, f"no confirmed BOLA; candidates={report.candidates}")
        ev = confirmed[0].evidence
        self.assertEqual(ev["http_status"], 200)
        # The attacker and the object's owner are different tenants.
        self.assertNotEqual(ev["owner_tenant_value"], None)
        self.assertEqual(confirmed[0].endpoint_key, "GET /api/receipts/{id}")

        # --- D: the SQLi candidate is REFUTED ---
        sqli = [c for c in report.candidates if c.kind == "sqli"]
        self.assertTrue(sqli, "no sqli candidate was produced")
        self.assertTrue(all(c.confidence is Confidence.REFUTED for c in sqli),
                        f"sqli not refuted: {[(c.confidence, c.evidence) for c in sqli]}")

        # The item endpoint was inferred (not documented) and is in the inventory.
        keys = {e.key() for e in report.endpoints}
        self.assertIn("GET /api/receipts/{id}", keys)
        self.assertIn("GET /api/receipts", keys)

    def test_inventory_infers_tenant_field_and_roles(self) -> None:
        report = run_discovery(self.base, IDENTITIES, ROUTES)
        item = next(e for e in report.endpoints if e.path_template == "/api/receipts/{id}")
        # org_id is the tenant discriminator, inferred from observed responses.
        self.assertEqual(item.tenant_field, "org_id")
        self.assertEqual(item.resource_identifiers, ("id",))
        # Only approvers may open an item (learned by differential probing).
        self.assertEqual(item.roles_allowed, ("approver",))
        self.assertEqual(item.source, "rest-inferred")

    def test_no_hardcoded_answer_in_source(self) -> None:
        # Guard against regressions that quietly seed the benchmark: the engine
        # must not mention the vulnerable id or the decoy param by name.
        import sechelix_runner.pentest.autodiscovery as pkg

        pkg_dir = Path(pkg.__file__).resolve().parent
        for py in pkg_dir.glob("*.py"):
            text = py.read_text("utf-8")
            self.assertNotIn("201", text, f"{py.name} hardcodes the vulnerable id")
            self.assertNotIn("Halcyon", text, f"{py.name} references seed data")

    def test_bfla_control_is_refuted(self) -> None:
        # The role control on the item endpoint is present and correct, so the
        # function-level-authz hypothesis must come back refuted, not confirmed.
        report = run_discovery(self.base, IDENTITIES, ROUTES)
        bfla = [c for c in report.candidates if c.kind == "bfla"]
        self.assertTrue(bfla)
        self.assertTrue(all(c.confidence is Confidence.REFUTED for c in bfla))

    def test_decisions_are_recorded(self) -> None:
        report = run_discovery(self.base, IDENTITIES, ROUTES)
        stages = {d.stage for d in report.decisions}
        for expected in {"auth", "inventory", "item-probe", "bola-test", "sqli-test"}:
            self.assertIn(expected, stages)

    def test_cli_exits_2_and_never_leaks_tokens(self) -> None:
        import json
        import tempfile

        from sechelix_runner.pentest.autodiscovery.__main__ import main

        with tempfile.TemporaryDirectory() as d:
            ids = Path(d) / "ids.json"
            routes = Path(d) / "routes.json"
            out = Path(d) / "report.json"
            ids.write_text(json.dumps([vars(i) | {"token": i.token} for i in IDENTITIES]))
            routes.write_text(json.dumps([{"method": "GET", "path": "/api/receipts",
                                           "inputs": ["sort", "dir"]}]))
            code = main([self.base, "--identities", str(ids),
                         "--routes", str(routes), "--out", str(out)])
            self.assertEqual(code, 2)  # a candidate was confirmed
            blob = out.read_text("utf-8")
            for ident in IDENTITIES:
                self.assertNotIn(ident.token, blob)  # tokens must be redacted


if __name__ == "__main__":
    unittest.main()
