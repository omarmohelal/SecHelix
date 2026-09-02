import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from sechelix_runner import cli
from sechelix_runner.api import ROUTES, RunStore, handle, make_server


class ApiRoutingTests(unittest.TestCase):
    """The router is pure, so the whole surface is testable without a socket."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        (self.root / "app.py").write_text("def handler(request): pass\n", encoding="utf-8")
        cli.main(["audit", str(self.root), "--depth", "quick"])
        self.store = RunStore(self.root)
        self.run_id = self.store.list()[-1]

    def test_run_listing(self) -> None:
        status, body = handle(self.store, "GET", "/runs")
        self.assertEqual(status, 200)
        self.assertIn(self.run_id, body["runs"])

    def test_run_detail_includes_integrity(self) -> None:
        status, body = handle(self.store, "GET", f"/runs/{self.run_id}")
        self.assertEqual(status, 200)
        self.assertEqual(body["integrity"], "ok")
        self.assertEqual(body["run_id"], self.run_id)

    def test_graph_events_and_coverage_are_served(self) -> None:
        for section, key in (("graph", "nodes"), ("events", "events"), ("coverage", "totals")):
            with self.subTest(section=section):
                status, body = handle(self.store, "GET", f"/runs/{self.run_id}/{section}")
                self.assertEqual(status, 200)
                self.assertIn(key, body)

    def test_empty_findings_carry_the_reason_they_are_empty(self) -> None:
        """An empty list must not read as "nothing was wrong"."""
        status, body = handle(self.store, "GET", f"/runs/{self.run_id}/findings")
        self.assertEqual(status, 200)
        self.assertEqual(body["findings"], [])
        self.assertIn("not a statement that none exist", body["note"])
        self.assertTrue(body["unsatisfied_mandatory"])

    def test_cancel_is_advisory_and_does_not_mutate_the_record(self) -> None:
        before = (self.store.workspace(self.run_id).path / "run.json").read_bytes()
        status, body = handle(self.store, "POST", f"/runs/{self.run_id}/cancel")
        self.assertEqual(status, 200)
        self.assertTrue(body["cancelled"])
        after = (self.store.workspace(self.run_id).path / "run.json").read_bytes()
        self.assertEqual(before, after)
        self.assertEqual(self.store.integrity(self.run_id), [])

    def test_run_creation_is_not_faked(self) -> None:
        status, body = handle(self.store, "POST", "/runs")
        self.assertEqual(status, 501)
        self.assertIn("sechelix audit", body["hint"])

    def test_unknown_run_is_404(self) -> None:
        status, _ = handle(self.store, "GET", "/runs/RUN-DOESNOTEXIST")
        self.assertEqual(status, 404)

    def test_traversal_in_a_run_id_is_rejected_not_served(self) -> None:
        """The same refusal the CLI inherits; not re-implemented here."""
        status, body = handle(self.store, "GET", "/runs/..%2F..%2Fetc")
        self.assertIn(status, (400, 404))
        status, body = handle(self.store, "GET", "/runs/../../etc")
        self.assertIn(status, (400, 404))

    def test_wrong_method_is_405(self) -> None:
        status, _ = handle(self.store, "POST", f"/runs/{self.run_id}/graph")
        self.assertEqual(status, 405)

    def test_unknown_path_lists_the_routes(self) -> None:
        status, body = handle(self.store, "GET", "/nope")
        self.assertEqual(status, 404)
        self.assertEqual(len(body["routes"]), len(ROUTES))


class ApiBindingTests(unittest.TestCase):
    def test_non_loopback_bind_is_refused(self) -> None:
        with self.assertRaises(PermissionError):
            make_server(tempfile.mkdtemp(), host="0.0.0.0")

    def test_loopback_bind_is_allowed(self) -> None:
        server = make_server(tempfile.mkdtemp(), host="127.0.0.1", port=0)
        server.server_close()

    def test_a_real_request_over_loopback_returns_json(self) -> None:
        root = Path(tempfile.mkdtemp())
        (root / "app.py").write_text("x = 1\n", encoding="utf-8")
        cli.main(["audit", str(root), "--depth", "quick"])
        server = make_server(root, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address[:2]
            with urllib.request.urlopen(f"http://{host}:{port}/runs", timeout=10) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
                body = json.loads(response.read())
            self.assertTrue(body["runs"])
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
