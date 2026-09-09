"""Keep the demo honest.

The demo makes four claims in its README: the vulnerability is real, the decoy is
safe, the regression test is red before the fix, and the patch turns it green
without breaking anything. A demo that quietly stops doing what it says is worse
than no demo, so each claim is asserted here.

Nothing in this module touches the working tree: the patch is applied to a copy
in a temporary directory.
"""

import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples/expense-api"
PATCH = DEMO / "fix.patch"
RELATIVE = "examples/expense-api"


def run(argv, cwd):
    return subprocess.run(
        argv, cwd=str(cwd), capture_output=True, text=True, timeout=300
    )


def _load_demo_module(name):
    """Import a module from the demo directory without touching sys.path."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        f"_sechelix_demo_{name}", DEMO / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DemoShipsVulnerable(unittest.TestCase):
    """As shipped, the demo must actually demonstrate the thing."""

    def test_proof_script_runs_and_agrees_with_itself(self):
        result = run([sys.executable, "prove.py"], DEMO)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Candidate A : VERIFIED", result.stdout)
        self.assertIn("Candidate B : REFUTED (decoy)", result.stdout)

    def test_regression_test_is_red_before_the_fix(self):
        """A test that never failed is not evidence that a fix worked."""
        result = run([sys.executable, "test_tenancy.py"], DEMO)
        self.assertNotEqual(result.returncode, 0, "the demo is no longer vulnerable")
        self.assertIn("FAILED (failures=2)", result.stderr)
        self.assertIn("cross-tenant read succeeded", result.stderr)

    def test_controls_that_must_not_break_are_already_green(self):
        """6 of the 8 pass before the fix; only the two tenancy ones are red."""
        result = run([sys.executable, "test_tenancy.py", "-v"], DEMO)
        self.assertIn("Ran 8 tests", result.stderr)

    def test_decoy_refutation_is_structural_not_just_empirical(self):
        # Loaded by path under a private name: the repository has its own
        # top-level `reports` package, and a plain import would return whichever
        # one the rest of the suite imported first.
        reports = _load_demo_module("reports")
        for column in reports.SORTABLE_COLUMNS:
            resolved, _ = reports.resolve_sort(column, "asc")
            # Identity, not equality: the object reaching the query text is the
            # module constant, never a string derived from the request.
            self.assertIs(resolved, column)
        with self.assertRaises(reports.InvalidSort):
            reports.resolve_sort("id; DROP TABLE receipt--", "asc")


class FixIsMinimalAndSufficient(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(
            __import__("tempfile").mkdtemp(prefix="sechelix-demo-")
        )
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        target = self.tmp / RELATIVE
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(DEMO, target)
        self.demo = target
        # `git apply` resolves patch paths against the enclosing repository, not
        # the working directory. Without its own repo here, a temp directory that
        # happens to sit inside someone's repo makes git silently report
        # "Skipped patch" and exit 0 -- a passing test that patched nothing.
        run(["git", "init", "-q"], self.tmp)

    def apply(self, reverse=False):
        argv = ["git", "apply"] + (["-R"] if reverse else []) + [str(PATCH)]
        return run(argv, self.tmp)

    def test_patch_applies_cleanly(self):
        check = run(["git", "apply", "--check", str(PATCH)], self.tmp)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_patch_makes_the_regression_test_pass(self):
        self.assertEqual(self.apply().returncode, 0)
        result = run([sys.executable, "test_tenancy.py"], self.demo)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Ran 8 tests", result.stderr)
        self.assertIn("OK", result.stderr)

    def test_after_the_fix_the_proof_reports_candidate_a_refuted(self):
        self.assertEqual(self.apply().returncode, 0)
        result = run([sys.executable, "prove.py"], self.demo)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Candidate A : REFUTED (fix applied)", result.stdout)

    def test_patch_is_small(self):
        """'Smallest safe remediation' is a claim; hold it to a number."""
        body = PATCH.read_text(encoding="utf-8").splitlines()
        added = [l for l in body if l.startswith("+") and not l.startswith("+++")]
        removed = [l for l in body if l.startswith("-") and not l.startswith("---")]
        # Two changed lines of behaviour; the rest is the comment explaining why.
        code_added = [l for l in added if not l.lstrip("+").strip().startswith("#")]
        self.assertLessEqual(len(code_added), 3, code_added)
        self.assertLessEqual(len(removed), 2, removed)

    def test_patch_round_trips(self):
        self.assertEqual(self.apply().returncode, 0)
        self.assertEqual(self.apply(reverse=True).returncode, 0)
        result = run([sys.executable, "test_tenancy.py"], self.demo)
        self.assertNotEqual(result.returncode, 0, "reverting did not restore the bug")

    def test_fix_scopes_the_query_rather_than_filtering_afterwards(self):
        """The root cause is an unscoped query, so the fix must scope it."""
        self.assertEqual(self.apply().returncode, 0)
        source = (self.demo / "app.py").read_text(encoding="utf-8")
        self.assertIn("WHERE id = ? AND org_id = ?", source)
        self.assertNotIn('WHERE id = ?"', source)


if __name__ == "__main__":
    unittest.main()
