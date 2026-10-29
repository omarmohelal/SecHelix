"""Benchmark: the full discover -> verify -> fix -> retest loop, unseeded.

Runs the whole SecHelix remediation flow over examples/expense-api from throwaway
copies (the working tree is never touched):

* discovery finds the cross-tenant BOLA;
* the *independent* verifier reproduces it against the vulnerable copy (CONFIRMED);
* the reference fix is applied to an isolated copy;
* the independent verifier re-runs against the fixed copy (REFUTED);
* the tenancy regression suite goes green.

This is acceptance criteria C -> D -> E end to end, with real HTTP evidence.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from sechelix_runner.pentest.autodiscovery import (
    Confidence,
    Identity,
    RouteSpec,
    run_remediation,
)
from sechelix_runner.pentest.autodiscovery.remediate import RemediationTarget

REPO = Path(__file__).resolve().parents[2]
DEMO = REPO / "examples" / "expense-api"

IDENTITIES = [
    Identity("ada", "tok-ada", "northwind", "approver"),
    Identity("bo", "tok-bo", "northwind", "employee"),
    Identity("cy", "tok-cy", "contoso", "approver"),
    Identity("dee", "tok-dee", "contoso", "employee"),
]
ROUTES = [RouteSpec("GET", "/api/receipts", ("sort", "dir"))]


def _target() -> RemediationTarget:
    return RemediationTarget(
        demo_dir=DEMO,
        relative="examples/expense-api",
        patch=DEMO / "fix.patch",
        identities=IDENTITIES,
        routes=ROUTES,
        start_cmd=(sys.executable, "app.py", "--port", "{port}"),
        ready_path="/api/receipts",
        retest_cmds=(
            (sys.executable, "test_tenancy.py"),
            (sys.executable, "prove.py"),
        ),
    )


class RemediationLoop(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # One (slow) run; every assertion reads the same report.
        cls.report = run_remediation(_target())

    def test_a_bola_was_discovered_and_is_the_subject(self) -> None:
        kinds = {o.candidate_kind for o in self.report.outcomes}
        self.assertIn("bola", kinds, f"outcomes={self.report.outcomes}")

    def test_before_confirmed_after_refuted(self) -> None:
        bola = next(o for o in self.report.outcomes if o.candidate_kind == "bola")
        self.assertIs(bola.before.confidence, Confidence.CONFIRMED, bola.before.rationale)
        self.assertEqual(bola.before.evidence.get("http_status"), 200)
        self.assertIs(bola.after.confidence, Confidence.REFUTED, bola.after.rationale)
        self.assertIn(bola.after.evidence.get("http_status"), (403, 404))
        self.assertTrue(bola.fixed)

    def test_regression_suite_is_green_after_the_fix(self) -> None:
        self.assertTrue(self.report.retests, "no retests ran")
        for retest in self.report.retests:
            self.assertTrue(retest.ok, f"{retest.name} failed: {retest.tail}")

    def test_the_whole_loop_reports_fixed(self) -> None:
        self.assertTrue(self.report.all_fixed)
        self.assertEqual(self.report.fix_source, "reference")


class AutonomousSynthesisLoop(unittest.TestCase):
    """The same loop, but the fix is *synthesized from source*, not fix.patch."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = run_remediation(_target(), synthesize=True)

    def test_a_patch_was_synthesized_not_referenced(self) -> None:
        self.assertEqual(self.report.fix_source, "synthesized")
        self.assertIsNotNone(self.report.fix_proposal, "synthesis abstained")
        self.assertEqual(self.report.fix_proposal.file, "app.py")
        # The synthesized patch scopes by the discovered tenant field -- and the
        # reference fix.patch played no part in producing it.
        self.assertIn("org_id = ?", self.report.fix_proposal.patched_source)

    def test_before_confirmed_after_refuted_with_the_synthesized_fix(self) -> None:
        bola = next(o for o in self.report.outcomes if o.candidate_kind == "bola")
        self.assertIs(bola.before.confidence, Confidence.CONFIRMED, bola.before.rationale)
        self.assertEqual(bola.before.evidence.get("http_status"), 200)
        self.assertIs(bola.after.confidence, Confidence.REFUTED, bola.after.rationale)
        self.assertIn(bola.after.evidence.get("http_status"), (403, 404))
        self.assertTrue(bola.fixed)

    def test_regression_suite_is_green_against_the_synthesized_fix(self) -> None:
        self.assertTrue(self.report.retests, "no retests ran")
        for retest in self.report.retests:
            self.assertTrue(retest.ok, f"{retest.name} failed: {retest.tail}")

    def test_the_whole_loop_reports_fixed(self) -> None:
        self.assertTrue(self.report.all_fixed)


if __name__ == "__main__":
    unittest.main()
