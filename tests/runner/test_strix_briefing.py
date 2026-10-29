"""The Strix discovery briefing: a surface map that guides, never the answer.

Three things are proven here:

* the briefing renders the inventory an engine needs -- endpoints, the object
  model, the ranked hypothesis classes, the identity labels;
* it **leaks no finding** -- built from an executed, answer-bearing discovery
  report, it still contains no confirmed object id and no verdict word; and
* the adapter injects it as *advisory* text after the authorization boundary,
  where it cannot widen scope (``TargetScope`` stays the authority).
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
from sechelix_runner.pentest.autodiscovery.models import Endpoint, Hypothesis
from sechelix_runner.pentest.scope import ScopeEndpoint, TargetScope
from sechelix_runner.pentest.strix_adapter import StrixEngine
from sechelix_runner.pentest.strix_briefing import briefing_from_report, build_briefing
from sechelix_runner.sandbox import ExecutionMode

EXPENSE_API = Path(__file__).resolve().parents[2] / "examples" / "expense-api"
sys.path.insert(0, str(EXPENSE_API))

import app as expense_app  # noqa: E402  (fixture under examples/expense-api)

IDENTITIES = [
    Identity(name="ada", token="tok-ada", tenant="northwind", role="approver"),
    Identity(name="bo", token="tok-bo", tenant="northwind", role="employee"),
    Identity(name="cy", token="tok-cy", tenant="contoso", role="approver"),
    Identity(name="dee", token="tok-dee", tenant="contoso", role="employee"),
]
ROUTES = [RouteSpec(method="GET", path="/api/receipts", inputs=("sort", "dir"))]


def _local_scope() -> TargetScope:
    return TargetScope(
        primary_url="http://127.0.0.1:3000",
        mode=ExecutionMode.LOCAL,
        endpoints=(ScopeEndpoint("127.0.0.1", ("http",), (3000,)),),
    )


class BriefingShape(unittest.TestCase):
    def setUp(self) -> None:
        self.endpoints = [
            Endpoint(method="GET", path_template="/api/receipts",
                     auth_required=True, inputs=("sort", "dir"), source="documented"),
            Endpoint(method="GET", path_template="/api/receipts/{id}",
                     auth_required=True, roles_allowed=("approver",),
                     resource_identifiers=("id",), tenant_field="org_id",
                     source="rest-inferred"),
        ]
        self.hyps = [
            Hypothesis(kind="bola", endpoint_key="GET /api/receipts/{id}",
                       title="x", priority=90),
            Hypothesis(kind="bfla", endpoint_key="GET /api/receipts/{id}",
                       title="x", priority=70),
            Hypothesis(kind="sqli", endpoint_key="GET /api/receipts",
                       title="x", priority=50, param="sort"),
            Hypothesis(kind="sqli", endpoint_key="GET /api/receipts",
                       title="x", priority=50, param="dir"),
        ]
        self.brief = build_briefing(self.endpoints, self.hyps, IDENTITIES)

    def test_lists_endpoints_and_object_model(self) -> None:
        self.assertIn("GET /api/receipts/{id}", self.brief)
        self.assertIn("tenant field: org_id", self.brief)
        self.assertIn("id: id", self.brief)
        self.assertIn("inputs: sort, dir", self.brief)

    def test_lists_identity_labels_without_tokens(self) -> None:
        self.assertIn("role 'approver', tenant 'northwind'", self.brief)
        for ident in IDENTITIES:
            self.assertNotIn(ident.token, self.brief)

    def test_names_the_hypothesis_classes_with_priority(self) -> None:
        self.assertIn("object-level authorization", self.brief)
        self.assertIn("function-level authorization", self.brief)
        self.assertIn("injection", self.brief)
        self.assertIn("[priority 90]", self.brief)

    def test_highest_value_endpoint_comes_first(self) -> None:
        item = self.brief.index("GET /api/receipts/{id}")
        coll = self.brief.index("- GET /api/receipts |")
        self.assertLess(item, coll, "the priority-90 endpoint should lead")

    def test_contains_no_host_or_url_so_it_cannot_widen_scope(self) -> None:
        for token in ("http://", "https://", "://", "127.0.0.1"):
            self.assertNotIn(token, self.brief)

    def test_folds_repeated_sqli_params_into_one_class_line(self) -> None:
        self.assertEqual(self.brief.count("injection — probe"), 1)


class BriefingLeaksNoFinding(unittest.TestCase):
    """Built from a *real executed* report, the briefing still has no answer."""

    def setUp(self) -> None:
        import tempfile

        database = Path(tempfile.mkdtemp()) / "briefing.sqlite"
        handler = expense_app.build(database)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.report = run_discovery(base, IDENTITIES, ROUTES)
        self.brief = briefing_from_report(self.report, IDENTITIES)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def test_the_report_actually_confirmed_the_bola(self) -> None:
        # Guard: if discovery stopped confirming, the leak test below is vacuous.
        confirmed = [c for c in self.report.candidates
                     if c.kind == "bola" and c.confidence is Confidence.CONFIRMED]
        self.assertTrue(confirmed, "no confirmed BOLA to test exclusion against")
        self.confirmed_id = str(confirmed[0].evidence["object_id"])

    def test_briefing_excludes_the_confirmed_object_id(self) -> None:
        confirmed = [c for c in self.report.candidates
                     if c.kind == "bola" and c.confidence is Confidence.CONFIRMED]
        leaked_id = str(confirmed[0].evidence["object_id"])
        self.assertNotIn(leaked_id, self.brief,
                         f"briefing leaked the confirmed object id {leaked_id}")

    def test_briefing_has_no_verdict_words(self) -> None:
        low = self.brief.lower()
        for word in ("confirmed", "refuted", "vulnerable", "exploited"):
            self.assertNotIn(word, low, f"briefing leaked a verdict word: {word}")

    def test_briefing_still_guides_to_the_right_surface(self) -> None:
        self.assertIn("GET /api/receipts/{id}", self.brief)
        self.assertIn("org_id", self.brief)
        self.assertIn("object-level authorization", self.brief)


class AdapterInjection(unittest.TestCase):
    def _instruction(self, command: tuple[str, ...]) -> str:
        i = command.index("--instruction")
        return command[i + 1]

    def test_guidance_is_appended_after_the_authorization_boundary(self) -> None:
        command = StrixEngine().build_command(
            scope=_local_scope(), guidance="SURFACE-MAP-MARKER")
        instr = self._instruction(command)
        self.assertIn("authorization boundary", instr)
        self.assertIn("SURFACE-MAP-MARKER", instr)
        self.assertIn("advisory", instr)
        self.assertLess(instr.index("authorization boundary"),
                        instr.index("SURFACE-MAP-MARKER"),
                        "the boundary must stay first and authoritative")

    def test_no_guidance_leaves_the_plain_boundary(self) -> None:
        instr = self._instruction(StrixEngine().build_command(scope=_local_scope()))
        self.assertIn("authorization boundary", instr)
        self.assertNotIn("advisory", instr)

    def test_blank_guidance_is_ignored(self) -> None:
        instr = self._instruction(
            StrixEngine().build_command(scope=_local_scope(), guidance="   \n  "))
        self.assertNotIn("advisory", instr)

    def test_guidance_cannot_widen_the_target(self) -> None:
        # Even if the briefing text mentioned a host, --target is scope-derived.
        command = StrixEngine().build_command(
            scope=_local_scope(), guidance="see http://evil.example/")
        self.assertEqual(command.count("--target"), 1)
        i = command.index("--target")
        self.assertEqual(command[i + 1], "http://127.0.0.1:3000")


if __name__ == "__main__":
    unittest.main()
