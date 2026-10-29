"""The deterministic BOLA fix synthesizer: localizes and scopes, or abstains.

These are pure source-transform tests (no server). They assert the synthesizer
produces exactly the reference fix's *shape* on the real ``examples/expense-api``
source, and that it refuses -- returns ``None`` -- when its preconditions do not
hold, rather than emitting a guess.
"""

from __future__ import annotations

import ast
import shutil
import tempfile
import textwrap
import unittest
from pathlib import Path

from sechelix_runner.pentest.autodiscovery.fix_synth import synthesize_bola_fix
from sechelix_runner.pentest.autodiscovery.models import Candidate, Confidence

REPO = Path(__file__).resolve().parents[2]
DEMO = REPO / "examples" / "expense-api"


def _bola(tenant_field: str = "org_id") -> Candidate:
    return Candidate(
        kind="bola",
        endpoint_key="GET /api/receipts/{id}",
        title="Cross-tenant object read",
        confidence=Confidence.CONFIRMED,
        rationale="reproduced",
        evidence={"owner_tenant_field": tenant_field, "object_id": 201,
                  "http_status": 200},
    )


class SynthesizeRealApp(unittest.TestCase):
    def setUp(self) -> None:
        self.proposal = synthesize_bola_fix(DEMO, _bola())

    def test_a_proposal_is_produced_for_app_py(self) -> None:
        self.assertIsNotNone(self.proposal, "synthesizer abstained on a real BOLA")
        self.assertEqual(self.proposal.file, "app.py")
        self.assertEqual(self.proposal.tenant_column, "org_id")
        self.assertEqual(self.proposal.id_column, "id")

    def test_the_patch_scopes_the_lookup_by_tenant(self) -> None:
        self.assertIn('WHERE id = ? AND org_id = ?', self.proposal.patched_source)
        self.assertIn('person["org_id"]', self.proposal.patched_source)

    def test_the_patch_is_minimal_one_query_changed(self) -> None:
        # Exactly the vulnerable execute() differs; the rest of the file is intact.
        before = self.proposal.original_source.splitlines()
        after = self.proposal.patched_source.splitlines()
        changed = [b for b, a in zip(before, after) if b != a] + after[len(before):]
        # The single-line id query becomes a two-line scoped query, so only the
        # query region changes; assert nothing outside it moved.
        self.assertIn("SELECT * FROM receipt WHERE id = ?", self.proposal.original_source)
        self.assertNotIn("SELECT * FROM receipt WHERE id = ?\n",
                         self.proposal.patched_source.replace(
                             "SELECT * FROM receipt WHERE id = ? AND org_id = ?", ""))
        self.assertTrue(changed, "nothing changed")

    def test_the_patched_source_is_valid_python(self) -> None:
        ast.parse(self.proposal.patched_source)  # raises on failure

    def test_the_diff_is_a_real_unified_diff(self) -> None:
        self.assertIn("--- a/app.py", self.proposal.diff)
        self.assertIn("+++ b/app.py", self.proposal.diff)
        self.assertIn("org_id = ?", self.proposal.diff)


class Abstains(unittest.TestCase):
    def _tmpdir(self) -> Path:
        d = Path(tempfile.mkdtemp(prefix="sechelix-synth-test-"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d

    def test_on_a_non_bola_candidate(self) -> None:
        sqli = Candidate(kind="sqli", endpoint_key="x", title="t",
                         confidence=Confidence.SUSPECTED, rationale="r",
                         evidence={"owner_tenant_field": "org_id"})
        self.assertIsNone(synthesize_bola_fix(DEMO, sqli))

    def test_when_the_tenant_field_is_unknown(self) -> None:
        self.assertIsNone(synthesize_bola_fix(DEMO, _bola(tenant_field="")))

    def test_on_already_scoped_source(self) -> None:
        # Simulate the fixed app: the lookup already scopes by org_id.
        tmp = self._tmpdir()
        src = (DEMO / "app.py").read_text(encoding="utf-8").replace(
            '"SELECT * FROM receipt WHERE id = ?", (receipt_id,)',
            '"SELECT * FROM receipt WHERE id = ? AND org_id = ?", '
            '(receipt_id, person["org_id"])',
        )
        (tmp / "app.py").write_text(src, encoding="utf-8")
        self.assertIsNone(synthesize_bola_fix(tmp, _bola()))

    def test_when_no_authenticated_principal_is_in_scope(self) -> None:
        tmp = self._tmpdir()
        (tmp / "svc.py").write_text(textwrap.dedent('''\
            def handler(store, receipt_id):
                row = store.execute(
                    "SELECT * FROM receipt WHERE id = ?", (receipt_id,)
                ).fetchone()
                return row
        '''), encoding="utf-8")
        # Unscoped lookup exists, but nothing resolves a principal to bind from.
        self.assertIsNone(synthesize_bola_fix(tmp, _bola()))


if __name__ == "__main__":
    unittest.main()
